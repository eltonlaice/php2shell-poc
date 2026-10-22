# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |

## What this project is

`php2shell-poc` is a lab and defence toolkit for CVE-2026-109618 and
CVE-2026-109619. It contains verification routines that send exploit-shaped
traffic, a WAF middleware, and detection rules.

The bundled lab runs intentionally vulnerable PHP images. **Do not deploy the
lab to a public network.** By default the compose file binds to `127.0.0.1`
only; override `P2S_BIND` only on an isolated network you control.

## Reporting a vulnerability in this toolkit

Please use GitHub's private vulnerability reporting:

https://github.com/eltonlaice/php2shell-poc/security/advisories/new

Include a description, reproduction steps, and the affected command or
package. Do not open a public issue for a vulnerability in the toolkit itself.

This is a volunteer project: reports are handled on a best-effort basis and
there is no bug bounty.

## Scope

In scope:

- the Go CLI, verifiers, guard, WAF middleware, and rule files;
- unsafe defaults that could expose a user's lab or break a host;
- bypasses of the WAF rules shipped in `internal/waf` or `rules/`.

Out of scope:

- vulnerabilities in PHP itself (report those to the PHP project);
- misuse of the toolkit against systems the operator does not own;
- the lab's deliberately vulnerable endpoints (`/vuln.php`,
  `/seed_session.php`) when the lab is exposed against this policy.

## Safe harbour

Good-faith research on this toolkit, following this policy, is welcome. The
toolkit must not be used to access systems without written authorization.
