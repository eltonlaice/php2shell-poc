#!/usr/bin/env bash
# Local equivalent of the CI checks. No network or Docker required.
set -euo pipefail
cd "$(dirname "$0")/.."

export GOCACHE="${GOCACHE:-$PWD/.gocache}"
export GOPATH="${GOPATH:-$PWD/.gopath}"

echo "== gofmt"
files=$(find . -name '*.go' -not -path './.git/*' -not -path './.gocache/*' -not -path './.gopath/*')
bad=$(gofmt -l $files)
if [ -n "$bad" ]; then
    echo "gofmt needed for:"
    echo "$bad"
    exit 1
fi

echo "== go vet"
go vet ./...

echo "== go test -race"
go test -race ./...

echo "== build"
go build -o bin/php2shell ./cmd/php2shell
./bin/php2shell version

echo "== rules"
./bin/php2shell rules check

echo "== compose"
docker compose -f lab/docker-compose.yml config --quiet

echo "all checks passed"
