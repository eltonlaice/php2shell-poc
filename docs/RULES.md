# Detection rules

Three formats, all embedded in the binary and available with
`php2shell rules show <kind>`.

| File | Format | Rules | Coverage |
|------|--------|-------|----------|
| `rules/suricata/php2shell.rules` | Suricata / Snort | 10 | request body, response body, URI |
| `rules/sigma/php2shell.yaml` | Sigma | 4 | web-server logs, proxy logs |
| `rules/modsecurity/php2shell.conf` | ModSecurity v2/v3 | 6 | form fields, filenames, chunked bodies |

## Validation status

Validated on 2026-10-23 with the engines below. This is **syntax and load
validation**, not a behavioural test against live traffic.

| Engine | Version | Command | Result |
|--------|---------|---------|--------|
| Suricata | 8.0.7 | `suricata -T -S rules/suricata/php2shell.rules` | configuration loaded, no warnings |
| Sigma | sigma-cli 3.1.0 / pySigma 1.5.1 | `sigma check rules/sigma/php2shell.yaml` | 0 errors, 0 condition errors, 0 issues |
| ModSecurity | v3, Apache 2.4.69 (OWASP CRS image) | `httpd -t -f rules/modsecurity/httpd-test.conf` | `Syntax OK` |

Reproduce with:

```bash
./scripts/validate-rules.sh
```

The script uses the `jasonish/suricata` and `owasp/modsecurity-crs:apache`
images for Suricata and ModSecurity, and a local `sigma` binary (install with
`pip install sigma-cli`) for Sigma. It skips Sigma when the binary is missing.

## Before deploying

- **ModSecurity**: enable `SecRequestBodyAccess On`. The response rule also
  needs `SecResponseBodyAccess On` and a matching `SecResponseBodyMimeType`.
  Rules use `ARGS_POST` and `FILES_NAMES`; `REQUEST_BODY` is usually empty for
  multipart requests in ModSecurity.
- **Suricata**: request-body inspection must be enabled (`request-body-limit`
  large enough for your uploads). Rules 1000103-1000105 look for a marker within
  512 bytes of `filename="`.
- **Sigma**: access logs must include the method, URI, status and byte count
  fields used by the rules. Body-based rules are not possible with standard
  access logs; that is why the Sigma set is smaller.

## Rule IDs

| Range | Owner |
|-------|-------|
| `1000101-1000199` | Suricata |
| `1000201-1000299` | ModSecurity |

Sigma IDs are version-4 UUIDs. `php2shell rules check` enforces UUID shape,
numeric IDs, and uniqueness; `scripts/validate-rules.sh` adds engine parsing.

## False positives and tuning

- `PHP_SESSION_UPLOAD_PROGRESS` is rare but legitimate progress-bar code
  exists. Test in `pass` mode before dropping.
- `PHPSESSID` as a form field is unusual in modern applications; legacy apps
  that submit it in a hidden input will be blocked.
- The filename rules (`<?`, `|O:`, `|a:`) are high signal but could fire on a
  security scanner's test files. Scope them to upload endpoints if needed.
- Blocking chunked multipart (`1000205`) can break legitimate streaming
  uploads; it is opt-in in the WAF (`--block-chunked`) but a `deny` rule in the
  ModSecurity file. Disable it if your clients stream uploads.

## What these rules do not do

They do not fix either CVE. Chain A needs an application LFI, chain D does not
use `session.upload_progress` at all, and chain E is still unconfirmed. Patch PHP
to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later.
