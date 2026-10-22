# php2shell-poc

[![Release](https://img.shields.io/github/v/release/eltonlaice/php2shell-poc?style=flat-square)](https://github.com/eltonlaice/php2shell-poc/releases)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

A Go toolkit for **CVE-2026-109618** and **CVE-2026-109619** (php2shell). It
provides a reproducible Docker lab, single-target verification for the public
attack chains, a WAF middleware for Go HTTP servers, and detection rules for
Suricata, Sigma and ModSecurity.

> **Authorized testing only.** The verification commands send exploit-shaped
> traffic. Use them only against systems you own or have written permission to
> test. The bundled lab runs intentionally vulnerable PHP and binds to
> `127.0.0.1` by default.

> **Independent implementation.** This is not the original research repository.
> The Python original is [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc);
> this project is an independent Go edition with its own verifiers and tooling.

## Contents

- [Overview](#overview)
- [Project status](#project-status)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
  - [verify](#verify)
  - [lab](#lab)
  - [waf](#waf)
  - [rules](#rules)
- [Library: WAF middleware](#library-waf-middleware)
- [Lab environment](#lab-environment)
- [Detection rules](#detection-rules)
- [Validation](#validation)
- [Architecture](#architecture)
- [Security considerations](#security-considerations)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [References](#references)
- [License](#license)

## Overview

The toolkit is organised around four capabilities:

| Capability | Description |
|------------|-------------|
| **Lab** | Four Docker containers: PHP 8.2.34 FPM, PHP 8.2.35 FPM (patched control), PHP 8.2.34 mod_php and nginx. |
| **Verification** | Single-target checks for chains A, C and D, plus an experimental chain E. Each command prints the evidence it observed. |
| **Mitigation** | A Go `http.Handler` middleware and reverse proxy that rejects the multipart request shapes used by the chains. |
| **Detection** | Suricata, Sigma and ModSecurity rules embedded in the binary and available as files. |

The verifiers are deliberately single-target. There is no target discovery,
CIDR scanning, concurrency across hosts, WAF evasion, payload encoding or
persistence. Non-local targets are refused unless `--allow-public` is passed.

## Project status

Verified on 2026-10-23 against the bundled lab:

| Chain | Target | Result | Observation |
|-------|--------|--------|-------------|
| A | FPM 8.2.34 | Confirmed | `uid=33(www-data)` via session injection and LFI |
| A | FPM 8.2.35 (patched) | Confirmed | Same result; this chain is an application-layer condition |
| C | FPM 8.2.34 | Confirmed | `__destruct` gadget fired after the handler mismatch |
| D | mod_php 8.2.34 | Partial | OOM in the multipart parser; no code execution attempted |
| E | FPM 8.2.34 | Not reproduced | Producer OOM observed; stale consumer state did not appear |
| all | A, C, D | Passing | Exits `0`; chain E is opt-in with `--experimental` |

The detailed command output is recorded in
[docs/VERIFICATION.md](docs/VERIFICATION.md). The detection rules load without
errors in Suricata 8.0.7, sigma-cli 3.1.0 and ModSecurity v3; see
[docs/RULES.md](docs/RULES.md).

## Requirements

- Go 1.22 or later (build and CLI).
- Docker 24+ with Compose v2 (lab only).
- Optional: Suricata, sigma-cli or ModSecurity for rule validation.

## Installation

Build from source:

```bash
git clone https://github.com/eltonlaice/php2shell-poc
cd php2shell-poc
go build -o bin/php2shell ./cmd/php2shell
```

Or install the CLI directly:

```bash
go install github.com/eltonlaice/php2shell-poc/cmd/php2shell@v0.1.1
```

## Quick start

```bash
# Start the lab (loopback only)
docker compose -f lab/docker-compose.yml up -d

# Verify chains A, C and D
go run ./cmd/php2shell verify all

# Optional: experimental chain E, expected to fail
go run ./cmd/php2shell verify chain-e
```

To run the full verification, including the WAF block test:

```bash
KEEP=1 make e2e
```

## Usage

```
php2shell verify <chain-a|chain-c|chain-d|chain-e|all> [flags]
php2shell lab <up|down|status|logs> [flags]
php2shell waf serve [flags]
php2shell rules <list|show|check>
php2shell version
```

### verify

Each verifier performs one specific check and reports whether the expected
evidence was observed. `OK` means that evidence was found; it is not a general
statement about the target's security.

| Chain | Vector | Preconditions | Evidence checked |
|-------|--------|---------------|------------------|
| `chain-a` | Multipart filename written to the session file, included through an LFI | An application LFI sink | Command output between markers |
| `chain-c` | Session handler mismatch leading to `__destruct` | Two directories with different `session.serialize_handler` values and a gadget class | Marker emitted by the destructor |
| `chain-d` | Multipart OOM in mod_php | An Apache mod_php endpoint | PHP memory exhaustion message (crash only) |
| `chain-e` | FPM stale `BG(unserialize)` state | Seeded session and a compatible worker | Stale-state warning (experimental; not reproduced) |

Common flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | `http://127.0.0.1:18080` | Target base URL |
| `--allow-public` | `false` | Permit a non-local target (authorized systems only) |
| `--command` | `id` | Command executed by chains A and C |
| `--session-dir` | `/tmp/sessions` | `session.save_path` on the target |
| `--stall` | `true` for chain A | Hold the upload open while triggering the LFI |
| `--attempts` | `3` | Retries for race-dependent steps |
| `--headers`, `--header-size` | `30000`, `512` | Chain D OOM amplification |
| `--size` | `24 MiB` | Chain E seeded session size |

Examples:

```bash
# Chain A against a target with session.upload_progress.cleanup=On
php2shell verify chain-a --target http://127.0.0.1:18080

# Chain A against a target with cleanup=Off
php2shell verify chain-a --target http://127.0.0.1:18080 --stall=false

# Chain C with five upload attempts
php2shell verify chain-c --target http://127.0.0.1:18080 --attempts 5

# Chain D (crash primitive only)
php2shell verify chain-d --target http://127.0.0.1:18081

# All non-experimental chains
php2shell verify all
```

Exit codes: `0` all selected chains confirmed, `1` at least one failed,
`2` usage error. `verify all` runs chains A, C and D. Add `--experimental` to
include chain E.

Chain C interpolates the command into a serialized gadget, so the command must
not contain `"`, `\` or NUL bytes. Chain A passes the command as a query
parameter and has no such restriction.

### lab

| Command | Description |
|---------|-------------|
| `php2shell lab up` | Start the containers |
| `php2shell lab down` | Stop and remove them |
| `php2shell lab status` | Show container status |
| `php2shell lab logs` | Show the last 100 log lines |

The compose file is committed; `docker compose up -d` works without
`lab/setup.sh`, which is only a convenience wrapper.

### waf

The `waf serve` command runs a reverse proxy in front of a PHP upstream:

```bash
php2shell waf serve \
  --listen 127.0.0.1:8080 \
  --upstream http://127.0.0.1:18080 \
  --max-body 8388608
```

It blocks multipart requests containing:

- a `PHPSESSID` form field (session ID in the body);
- a `PHP_SESSION_UPLOAD_PROGRESS` field;
- `<?`, `|O:`, `|a:`, `|C:` or `|s:` in an upload filename;
- optionally, a chunked multipart body (`--block-chunked`).

`--log-only` records violations without blocking. Blocked requests receive
`403` and a JSON list of violations.

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `127.0.0.1:8080` | Listen address |
| `--upstream` | `http://127.0.0.1:18080` | PHP upstream |
| `--log-only` | `false` | Observe without blocking |
| `--max-body` | `8388608` | Bytes buffered for inspection |
| `--session-name` | `PHPSESSID` | PHP session name |
| `--block-chunked` | `false` | Reject chunked multipart uploads |

### rules

```bash
php2shell rules list
php2shell rules show suricata
php2shell rules show sigma
php2shell rules show modsecurity
php2shell rules check
```

`rules check` validates Sigma UUIDs, numeric rule IDs and duplicates. Engine
validation is described in [docs/RULES.md](docs/RULES.md). The ModSecurity rules
use `ARGS_POST` and `FILES_NAMES`; enable `SecRequestBodyAccess On` and, for the
response rule, `SecResponseBodyAccess On`.

## Library: WAF middleware

The WAF is a public Go package:

```go
import "github.com/eltonlaice/php2shell-poc/waf"

cfg := waf.DefaultConfig()
cfg.LogOnly = false

srv := &http.Server{
    Addr:    ":8080",
    Handler: cfg.Handler(mux),
}
```

The middleware buffers at most `MaxBody` bytes, restores the request body before
calling the next handler, and never rewrites the request. It is a detection
control, not a replacement for patching PHP.

## Lab environment

| Service | Image | Host port | Purpose |
|---------|-------|-----------|---------|
| `fpm` | `php:8.2.34-fpm` | `127.0.0.1:18080` via nginx | Vulnerable FPM target |
| `fpm-patched` | `php:8.2.35-fpm` | `127.0.0.1:18082` via nginx | Patched control |
| `apache` | `php:8.2.34-apache` | `127.0.0.1:18081` | mod_php target (chain D) |
| `nginx` | `nginx:1.27-alpine` | `127.0.0.1:18080`, `:18082` | FastCGI front end |

Endpoints:

| Path | Purpose |
|------|---------|
| `/index.php` | Starts a session |
| `/vuln.php?page=` | LFI sink (chain A) |
| `/app/` | `php_serialize` handler |
| `/api/` | `php` handler with the `Evil` gadget |
| `/nosession.php` | Chain E consumer |
| `/session_oom.php` | Session decode OOM |
| `/seed_session.php` | Chain E seeder; requires `P2S_LAB=1` |

Ports bind to `127.0.0.1` by default. Setting `P2S_BIND=0.0.0.0` exposes the
lab to the network; use it only on an isolated network you control. See
[lab/README.md](lab/README.md) for the full endpoint and reset documentation.

## Detection rules

| File | Format | Rules | Focus |
|------|--------|-------|-------|
| `rules/suricata/php2shell.rules` | Suricata / Snort | 10 | Request body, response body, URI |
| `rules/sigma/php2shell.yaml` | Sigma | 4 | Web-server and proxy logs |
| `rules/modsecurity/php2shell.conf` | ModSecurity v2/v3 | 6 | Form fields, filenames, chunked bodies |

The rules are syntax-validated, not tested against live malicious traffic.
Deployment prerequisites, false positives and tuning guidance are in
[docs/RULES.md](docs/RULES.md).

## Validation

```bash
./scripts/check.sh            # gofmt, vet, race tests, build, rules, compose
./scripts/validate-rules.sh   # Suricata -T, sigma check, ModSecurity httpd -t
KEEP=1 ./scripts/e2e.sh
```

`scripts/e2e.sh` starts the lab, verifies chains A/C/D, records the expected
chain E failure, runs `verify all`, and checks that the WAF blocks chain A while
allowing benign traffic.

## Architecture

```
cmd/php2shell          CLI entry point
internal/cli           command parsing and output
internal/guard         target validation (loopback/private only by default)
internal/mp            byte-exact multipart builder
internal/probe         HTTP client and stalled-request support
internal/verify        chain A, C, D and E verifiers
waf                    public WAF middleware
rules                  embedded Suricata, Sigma and ModSecurity rules
lab                    Docker lab and PHP endpoints
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the request flow and design
decisions.

## Security considerations

- Targets are validated before any traffic is sent. Public addresses are
  refused unless `--allow-public` is set.
- The lab binds to loopback and its seeder endpoint requires `P2S_LAB=1`.
- The WAF is a best-effort detection control. It does not fix either CVE and can
  be bypassed by bodies larger than `MaxBody`, chunked encoding (unless
  blocked), or parser differences between Go and PHP.
- Chain A works on patched PHP when the application has an LFI. Patching PHP is
  necessary but not sufficient for that chain.
- The toolkit contains no scanning, evasion or persistence features.

## Limitations

- Chain E is not reproduced; it remains experimental and opt-in.
- Chain D demonstrates the OOM crash primitive only.
- Chain B is intentionally not implemented: it requires PHP-side code
  execution and `/proc/self/mem`, not an HTTP client primitive.
- Detection rules are engine-validated for syntax, not behaviourally tested
  against live attacks.
- The lab covers PHP 8.2.34 and 8.2.35, not the full historical version matrix.
- The shell scripts are tested on macOS and Linux; Windows is not tested.

## Contributing

Development setup, test requirements and detector guidelines are in
[CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities in the toolkit through
the private advisory flow described in [SECURITY.md](SECURITY.md).

## References

- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- [PHP security release](https://www.php.net/index.php#2026-10-20-1)
- [SANS ISC diary](https://isc.sans.edu/diary/rss/33440)
- [Original Python research](https://github.com/ikow/php2shell-poc)

## License

MIT. See [LICENSE](LICENSE). Use only against systems you are authorized to test.
