#!/usr/bin/env bash
# Start the bundled lab. The compose file is committed, so this script is a
# convenience wrapper; docker compose up -d works on its own.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required" >&2
    exit 1
fi

docker compose up -d
echo
docker compose ps
echo
echo "FPM 8.2.34  http://127.0.0.1:18080"
echo "Apache 8.2.34 http://127.0.0.1:18081"
echo "FPM 8.2.35  http://127.0.0.1:18082 (patched, differential only)"
