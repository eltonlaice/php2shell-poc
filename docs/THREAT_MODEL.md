# Threat model and intended use

## Intended use

- Reproducing CVE-2026-109618 / CVE-2026-109619 in the bundled Docker lab.
- Checking that a staging deployment is patched, using a target you own.
- Putting the Go WAF in front of a legacy PHP stack while it is being patched.
- Shipping the embedded detection rules to an IDS/SIEM pipeline.

## Capabilities

| Capability | Where | Notes |
|------------|-------|-------|
| Upload a file with an attacker-controlled filename to a PHP endpoint | chain A/C | uses `session.upload_progress` |
| Request an arbitrary local file through an application LFI | chain A | the LFI must already exist in the app |
| Trigger a multipart parsing OOM | chain D | crash primitive, no code execution |
| Detect stale session state after a decode OOM | chain E | lab seeder required |
| Block the above request shapes at the HTTP layer | `internal/waf` | best effort, not a patch |
| Emit Suricata/Sigma/ModSecurity rules | `rules/` | templates, validate before deploying |

## Non-goals

- **No scanner.** There is no target list, no CIDR sweep, no concurrency across
  hosts, and no service discovery. Every command takes one target.
- **No generic exploit.** Chain A needs an LFI, chain C needs a handler mismatch
  and a usable `__destruct` gadget, chain D only produces a crash, chain E is
  experimental. Chain B is not implemented (see ARCHITECTURE.md).
- **No evasion.** There is no payload encoding, WAF-bypass logic or traffic
  obfuscation.
- **No persistence.** Nothing is installed on the target; the lab seeder writes
  one session file inside the lab container.

## Controls

1. `internal/guard` resolves the target and refuses anything that is not
   loopback, private or link-local. `--allow-public` is an explicit opt-in for
   systems the operator owns.
2. Verification is sequential and single-target, so a mistyped command cannot
   fan out.
3. The lab seeder endpoint (`/seed_session.php`) exists only in `lab/` and is
   labelled as non-attack tooling.
4. The WAF logs every match with method, path and remote address, so it can be
   run in `--log-only` mode before blocking.
5. The rules and code carry no exploit for chains D/E beyond the crash/state
   observations described above.

## Residual risk

- `--allow-public` removes the only hard guard. It exists for authorized
  testing; using it against third parties is unlawful in most jurisdictions.
- The WAF can be bypassed (body larger than `MaxBody`, chunked encoding unless
  blocked, parsing differences between Go and PHP). It is defence in depth.
- Chain A works on patched PHP when an LFI is present. Patching does not remove
  the application-layer condition.

## Legal

Use only on systems for which you have written authorization. The authors are
not responsible for misuse. The repository is MIT licensed; the licence does not
grant permission to access systems you do not own.
