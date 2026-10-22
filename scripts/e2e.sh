#!/usr/bin/env bash
# End-to-end verification against the bundled Docker lab.
#
#   ./scripts/e2e.sh          # start lab, verify A/C/D, stop lab
#   KEEP=1 ./scripts/e2e.sh   # leave the lab running afterwards
#
# Chain E is expected to fail; it is reported but does not fail the script.
set -euo pipefail
cd "$(dirname "$0")/.."

KEEP="${KEEP:-0}"
export GOCACHE="${GOCACHE:-$PWD/.gocache}"
export GOPATH="${GOPATH:-$PWD/.gopath}"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }

go build -o bin/php2shell ./cmd/php2shell

compose=(docker compose -f lab/docker-compose.yml)
"${compose[@]}" up -d

cleanup() {
    if [ "$KEEP" != "1" ]; then
        "${compose[@]}" down --remove-orphans >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "== waiting for the lab"
for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:18080/index.php >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl -fsS http://127.0.0.1:18080/index.php >/dev/null || { echo "lab did not come up" >&2; exit 1; }

echo "== chain A"
./bin/php2shell verify chain-a --target http://127.0.0.1:18080

echo "== chain C"
./bin/php2shell verify chain-c --target http://127.0.0.1:18080 --attempts 5

echo "== chain D"
./bin/php2shell verify chain-d --target http://127.0.0.1:18081

echo "== chain E (experimental, failure expected)"
if ! ./bin/php2shell verify chain-e --target http://127.0.0.1:18080 --attempts 3; then
    echo "chain E: not reproduced (expected)"
fi

echo "== verify all (experimental excluded)"
./bin/php2shell verify all --fpm-target http://127.0.0.1:18080 --apache-target http://127.0.0.1:18081

echo "== WAF block"
./bin/php2shell waf serve --listen 127.0.0.1:18088 --upstream http://127.0.0.1:18080 >/tmp/p2s-e2e-waf.log 2>&1 &
waf_pid=$!
trap 'kill $waf_pid 2>/dev/null || true; cleanup' EXIT
sleep 1

benign=$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18088/index.php)
[ "$benign" = "200" ] || { echo "WAF broke a benign request: $benign" >&2; exit 1; }

set +e
./bin/php2shell verify chain-a --target http://127.0.0.1:18088 --stall=false >/tmp/p2s-e2e-block.log 2>&1
blocked=$?
set -e
[ "$blocked" -ne 0 ] || { echo "WAF did not block chain A" >&2; exit 1; }
grep -q "403" /tmp/p2s-e2e-block.log || { echo "WAF block did not return 403" >&2; exit 1; }

kill "$waf_pid" 2>/dev/null || true
wait "$waf_pid" 2>/dev/null || true

echo
echo "e2e passed: A, C, D confirmed; E experimental; WAF blocks"
