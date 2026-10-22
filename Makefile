GOCACHE ?= $(CURDIR)/.gocache
GOPATH  ?= $(CURDIR)/.gopath
export GOCACHE
export GOPATH

BINARY := bin/php2shell

.PHONY: build test vet fmt rules check validate-rules e2e lab-up lab-down lab-status verify waf clean

build:
	go build -o $(BINARY) ./cmd/php2shell

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w $$(find . -name '*.go' -not -path './.gocache/*' -not -path './.gopath/*')

rules:
	go run ./cmd/php2shell rules check

check:
	./scripts/check.sh

validate-rules:
	./scripts/validate-rules.sh

e2e:
	KEEP=$(KEEP) ./scripts/e2e.sh

lab-up:
	docker compose -f lab/docker-compose.yml up -d

lab-down:
	docker compose -f lab/docker-compose.yml down --remove-orphans

lab-status:
	docker compose -f lab/docker-compose.yml ps

verify: build
	./$(BINARY) verify all

waf: build
	./$(BINARY) waf serve --listen 127.0.0.1:8080 --upstream http://127.0.0.1:18080

clean:
	rm -rf bin .gocache .gopath
