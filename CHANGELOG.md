# Changelog

## v0.1.0 — 2026-10-23

First public release of the Go edition.

### Added

- `php2shell` CLI: `verify`, `lab`, `waf`, `rules`, `version`.
- Docker lab with PHP 8.2.34 (FPM and mod_php) and 8.2.35 (patched).
- Chain A (session injection + LFI), chain C (handler mismatch) and chain D
  (mod_php OOM) verifiers with evidence output.
- Experimental chain E verifier (stale FPM state), opt-in with
  `verify all --experimental`.
- Go WAF middleware and reverse proxy (`waf serve`) for the request shapes used
  by the chains.
- Suricata, Sigma and ModSecurity rules, embedded in the binary.
- Local guard: non-local targets are refused unless `--allow-public` is set.
- `scripts/check.sh`, `scripts/e2e.sh`, `scripts/validate-rules.sh`.
- Unit tests for the multipart builder, guard, WAF, verifiers, CLI and probe.

### Verified

- Chain A on PHP 8.2.34 and on patched 8.2.35 (application-layer condition).
- Chain C on the lab gadget.
- Chain D OOM crash primitive (no code execution attempted).
- Rules load in Suricata 8.0.7, sigma-cli 3.1.0 and ModSecurity v3.

### Known limitations

- Chain E is not reproduced; the stale consumer state does not appear in the
  bundled configuration.
- Chain B is intentionally not implemented (requires PHP-side execution).
- Detection rules are syntax-validated, not tested against live malicious
  traffic.

### Security

- Lab ports bind to `127.0.0.1` by default (`P2S_BIND` is an explicit opt-in).
- `/seed_session.php` requires `P2S_LAB=1`, set by the compose file.
