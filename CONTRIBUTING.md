# Contributing

Thanks for looking. This project is a lab and defence toolkit; contributions
that improve verification quality, detection coverage, or safety are welcome.

## Development

```bash
git clone https://github.com/eltonlaice/php2shell-poc
cd php2shell-poc
./scripts/check.sh          # gofmt, vet, race tests, build, rules, compose
./scripts/e2e.sh            # Docker lab: chains A/C/D plus WAF block test
```

`./scripts/e2e.sh` needs Docker and pulls the PHP images on first run. Set
`KEEP=1` to leave the lab running.

## Ground rules

- **Authorized testing only.** Do not add code whose only purpose is mass
  scanning, target discovery, WAF evasion, or persistence.
- Keep the default target guard in place. New commands that send attack-shaped
  traffic must go through `internal/guard` and accept `--allow-public` only as
  an explicit opt-in.
- Prefer standard library dependencies. The toolkit has no third-party
  modules today; discuss before adding one.
- Add a test for every new detector, verifier, and parser edge case.
- Update `docs/VERIFICATION.md` when a chain result changes.

## Detection rules

- Suricata SIDs live in `1000101-1000199`, ModSecurity IDs in
  `1000201-1000299`. Do not reuse an ID.
- Sigma rule IDs must be version-4 UUIDs; `php2shell rules check` enforces this.
- New ModSecurity rules should use `ARGS_POST`, `FILES_NAMES`, or
  `MULTIPART_*` collections. `REQUEST_BODY` is usually empty for multipart.
- State clearly in `docs/RULES.md` whether a rule was tested against a real
  engine.

## Commits and pull requests

- Keep commits focused; use the imperative mood.
- Describe what you ran (`make test`, `scripts/e2e.sh`, engine version).
- By contributing you agree that your contribution is licensed under MIT.

## Responsible use

The verifiers send traffic that looks like an attack. Never point them at a
system you do not own or have written permission to test. See
[SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
