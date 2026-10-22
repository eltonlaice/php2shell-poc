# php2shell-poc — Go edition

A Go toolkit for **CVE-2026-109618 / CVE-2026-109619** (php2shell): a
reproducible Docker lab, verification routines for the public attack chains, a
Go WAF middleware, and the detection rules in one binary.

> **This is a lab and defence toolkit, not a scanner.** It talks to one target
> at a time and refuses non-local addresses unless you pass `--allow-public`.
> See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before running anything.

> **Not the original research repo.** The Python original is
> [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc); this is an
> independent Go edition with the same lab scope and its own verifiers.

## Why another php2shell repo?

The Python original is a research write-up with three scripts. This project is
the Go-shaped version:

- a **library** (`internal/waf`) you can drop in front of any Go HTTP server;
- a **CLI** that brings up the lab, verifies the chains and prints evidence;
- **tests** for every detection rule and verifier;
- **no third-party dependencies** — standard library only.

It is also honest about what it can prove: chain D is a crash primitive, chain
E is not reproduced, and chain B is deliberately absent (see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#why-chain-b-is-not-implemented)).

## Verified status

Tested on 2026-10-23 against the bundled lab (Docker, PHP 8.2.34 / 8.2.35):

| Chain | Target | Result | What was observed |
|-------|--------|--------|-------------------|
| A | FPM 8.2.34 `:18080` | **OK** | `uid=33(www-data)` through session injection + LFI |
| A | FPM 8.2.35 `:18082` | **OK** | same, confirming this chain is not fixed by the PHP patch |
| C | FPM 8.2.34 `:18080` | **OK** | `__destruct` gadget fired after the handler mismatch |
| D | mod_php 8.2.34 `:18081` | **partial** | OOM in the multipart parser; **no code execution attempted** |
| E | FPM 8.2.34 `:18080` | **not reproduced** | producer OOM observed, stale consumer state not reproduced |

Unit tests cover the request builders, the WAF, the guard and all four
verifiers. The end-to-end outputs are in [docs/VERIFICATION.md](docs/VERIFICATION.md).

## Quick start

Requirements: Go 1.22+ and Docker (for the lab only).

```bash
git clone https://github.com/eltonlaice/php2shell-poc
cd php2shell-poc

# 1. Start the lab (four containers)
docker compose -f lab/docker-compose.yml up -d

# 2. Verify the chains
go run ./cmd/php2shell verify chain-a
go run ./cmd/php2shell verify chain-c
go run ./cmd/php2shell verify chain-d
go run ./cmd/php2shell verify chain-e      # experimental, may fail
go run ./cmd/php2shell verify all
```

`verify all` expects the default lab ports. Use `--fpm-target` and
`--apache-target` if yours differ.

## Commands

```
php2shell verify <chain-a|chain-c|chain-d|chain-e|all> [flags]
php2shell lab <up|down|status|logs> [--dir lab]
php2shell waf serve [flags]
php2shell rules <list|show|check>
php2shell version
```

### verify

| Flag | Default | Meaning |
|------|---------|---------|
| `--target` | `http://127.0.0.1:18080` | target base URL |
| `--allow-public` | `false` | allow a non-local target (authorized systems only) |
| `--command` | `id` | command executed by chains A/C |
| `--session-dir` | `/tmp/sessions` | `session.save_path` on the target |
| `--stall` | `true` (chain A) | hold the upload open while triggering the LFI |
| `--attempts` | `3` | retries for race-dependent steps |
| `--headers`, `--header-size` | `30000`, `512` | chain D OOM amplification |
| `--size` | `24 MiB` | chain E seeded session size |

Examples:

```bash
# A: default cleanup=On target, with a stalled upload
php2shell verify chain-a --target http://127.0.0.1:18080

# A: target with session.upload_progress.cleanup=Off
php2shell verify chain-a --target http://127.0.0.1:18080 --stall=false

# C: lab endpoints with different serialize_handler values
php2shell verify chain-c --target http://127.0.0.1:18080 --attempts 5

# D: crash primitive only
php2shell verify chain-d --target http://127.0.0.1:18081

# E: experimental stale-state check
php2shell verify chain-e --target http://127.0.0.1:18080 --size 25165824
```

Exit codes: `0` all selected chains confirmed, `1` at least one failed,
`2` usage error. `verify all` currently exits `1` because chain E is not
confirmed; run the individual commands if you need a green run.

Chain C interpolates the command into a serialized gadget, so it must not
contain `"`, `\` or NUL bytes. Chain A passes the command as a query parameter
and has no such restriction.

### waf

Run the WAF as a reverse proxy in front of the lab (or any PHP upstream):

```bash
php2shell waf serve \
  --listen 127.0.0.1:8080 \
  --upstream http://127.0.0.1:18080 \
  --max-body 8388608
```

It blocks multipart requests that carry:

- a `PHPSESSID` form field (session id in the body);
- a `PHP_SESSION_UPLOAD_PROGRESS` field;
- `<?` or `|O:` / `|a:` / `|C:` / `|s:` in an upload filename;
- optionally, a chunked multipart body (`--block-chunked`).

`--log-only` observes without blocking. A blocked request returns `403` with a
JSON list of violations.

As a library:

```go
cfg := waf.DefaultConfig()
cfg.LogOnly = false
srv := &http.Server{
    Addr:    ":8080",
    Handler: cfg.Handler(mux),
}
```

### rules

```bash
php2shell rules list
php2shell rules show suricata
php2shell rules show sigma
php2shell rules show modsecurity
php2shell rules check        # UUID/ID validation and duplicates
```

The ModSecurity rules use `ARGS_POST` and `FILES_NAMES` (not `REQUEST_BODY`,
which is usually empty for multipart). Enable `SecRequestBodyAccess On`; the
response rule also needs `SecResponseBodyAccess On`.

## Lab

| Service | Image | Host port | Purpose |
|---------|-------|-----------|---------|
| `fpm` | `php:8.2.34-fpm` | `:18080` via nginx | vulnerable FPM target |
| `fpm-patched` | `php:8.2.35-fpm` | `:18082` via nginx | patched differential target |
| `apache` | `php:8.2.34-apache` | `:18081` | mod_php target (chain D) |
| `nginx` | `nginx:1.27-alpine` | `:18080`, `:18082` | FastCGI front end |

Endpoints include `/index.php` (session), `/vuln.php?page=` (LFI), `/app/` and
`/api/` (`.user.ini` handler mismatch), `/nosession.php` and
`/seed_session.php` (lab-only chain E seeder). See [lab/README.md](lab/README.md).

The compose file is committed, so `docker compose up -d` works without a setup
script. `lab/setup.sh` is only a convenience wrapper.

## Scope and non-goals

- No target lists, no CIDR scans, no concurrency across hosts.
- No WAF evasion, payload encoding, or persistence.
- No exploit for chain B: it needs PHP-side code execution, not an HTTP client.
- Chains D and E do not produce code execution here; they demonstrate the crash
  and stale-state primitives only.

## References

- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- [PHP security release](https://www.php.net/index.php#2026-10-20-1)
- [SANS ISC diary](https://isc.sans.edu/diary/rss/33440)
- [Original Python research](https://github.com/ikow/php2shell-poc)

## License

MIT. Use only against systems you are authorized to test.
