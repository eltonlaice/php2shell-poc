# Architecture

```
cmd/php2shell          CLI entry point
internal/cli           flag parsing, lab/waf/rules subcommands
internal/guard         refuses non-local targets by default
internal/mp            byte-exact multipart builder
internal/probe         HTTP client with a raw "stall" request mode
internal/verify        chains A, C, D, E
waf           http.Handler middleware
rules/                 embedded Suricata / Sigma / ModSecurity rules
lab/                   docker compose, PHP endpoints, nginx config
docs/                  this file, threat model, verification notes
```

## Verification flow

```
CLI flags
   │
   ▼
guard.Check(target)          loopback / private / link-local only
   │
   ▼
verify.ChainX(options)
   │
   ├── internal/mp   builds the multipart body (raw filenames)
   ├── internal/probe sends it, buffers the response
   └── marker check  extracts the command output or OOM/stale-state evidence
```

Each verifier returns a `Result` with `OK`, a one-line summary, evidence lines
and notes. `OK` means the specific primitive was observed, not that the target
is generally exploitable:

| Chain | `OK` means |
|-------|------------|
| A | command output appeared in the LFI response |
| C | `__destruct` output appeared after the handler-mismatch upload |
| D | PHP reported memory exhaustion while parsing the multipart body |
| E | a decode OOM was followed by stale session-state output |

## Why a custom multipart writer

`mime/multipart.Writer` escapes quotes in filenames. The session-injection
chains need the filename bytes to survive unchanged, including `"`, `|` and
`<?php`. `internal/mp` therefore writes the header block itself:

- filenames are written verbatim (CR/LF rejected to keep the request valid);
- part names are validated and quoted;
- extra part headers are supported for the OOM amplification strategy;
- `BytesHead` emits the parts without the closing boundary, which is what the
  `--stall` mode needs.

Go's own multipart *parser* still rejects unescaped quotes in filenames, which
is why the WAF also scans the raw body as a fallback.

## WAF middleware

`waf.Config.Handler(next)` only inspects `multipart/form-data` POST/PUT/PATCH
requests. It:

1. optionally rejects chunked multipart bodies (`BlockChunked`);
2. buffers at most `MaxBody` bytes, then restores the body exactly (prefix plus
   the unread remainder) before calling the next handler;
3. parses the multipart stream and flags:
   - a field named like the PHP session (`PHPSESSID` by default);
   - the `PHP_SESSION_UPLOAD_PROGRESS` field;
   - `<?` or `|O:`/`|a:`/`|C:`/`|s:` in a filename;
4. additionally scans the rest of the header line after every `filename="` in
   the raw body, so hand-crafted parts that break the MIME parser are still
   caught without inspecting binary file content;
5. blocks with `403` and a JSON body, or logs only when `LogOnly` is set.

The middleware is a mitigation for legacy stacks. It is not a fix for either
CVE: chain A still needs an LFI sink, and chain D does not use
`session.upload_progress` at all.

## Rules

The three rule files are compiled into the binary with `embed`. `rules.Validate`
checks that Sigma IDs are version-4 UUIDs and that Suricata/ModSecurity rule IDs
are numeric and unique. The ModSecurity rules use `ARGS_POST` and `FILES_NAMES`
rather than `REQUEST_BODY`, because multipart bodies are not exposed there in
the usual configurations.

## Why chain B is not implemented

Chain B (var_destroy use-after-free) requires running PHP code on the target to
trigger `unserialize()` and to reach `/proc/self/mem`. That is not an HTTP
client primitive, and the public "exploit" for it is a post-exploitation demo
with hardcoded offsets. Implementing it in Go would add attack surface without
verifying anything the Python original does not already show. The lab and docs
cover the primitive instead.

## Tests

- `internal/mp`: round-trip parsing, raw filename preservation, CR/LF rejection.
- `internal/guard`: loopback/private/public/scheme cases.
- `waf`: one test per rule, body restoration, log-only, chunked.
- `internal/verify`: `httptest` fakes for all four chains plus the public-target
  refusal.
- `rules`: embedded files validate and the expected rule counts are present.

The unit tests do not require Docker. End-to-end runs are documented in
[VERIFICATION.md](VERIFICATION.md).
