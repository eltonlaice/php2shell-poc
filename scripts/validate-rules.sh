#!/usr/bin/env bash
# Validate the shipped detection rules with real engines.
#
#   Suricata    -> jasonish/suricata image, suricata -T
#   ModSecurity -> owasp/modsecurity-crs image, httpd -t
#   Sigma       -> local sigma-cli, if installed (pip install sigma-cli)
#
# Docker is required for Suricata and ModSecurity. Sigma is skipped when
# sigma-cli is not on PATH.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

echo "== suricata"
docker run --rm \
    -v "$PWD/rules/suricata:/rules:ro" \
    jasonish/suricata:latest \
    suricata -T -S /rules/php2shell.rules

echo "== modsecurity"
docker run --rm \
    -v "$PWD/rules/modsecurity:/rules:ro" \
    --entrypoint httpd owasp/modsecurity-crs:apache \
    -t -f /rules/httpd-test.conf

echo "== sigma"
if command -v sigma >/dev/null 2>&1; then
    sigma check rules/sigma/php2shell.yaml
else
    echo "sigma-cli not found; install with: pip install sigma-cli"
fi
