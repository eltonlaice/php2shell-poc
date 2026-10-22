# Lab

Four containers, no host PHP required:

| Service | Image | Host port | Purpose |
|---------|-------|-----------|---------|
| `fpm` | `php:8.2.34-fpm` | via nginx `:18080` | vulnerable FPM target (chains A, C, E) |
| `fpm-patched` | `php:8.2.35-fpm` | via nginx `:18082` | patched differential target |
| `apache` | `php:8.2.34-apache` | `:18081` | mod_php target (chain D) |
| `nginx` | `nginx:1.27-alpine` | `:18080`, `:18082` | FastCGI front end |

## Endpoints

| Path | Behaviour |
|------|-----------|
| `/index.php` | `session_start()`, prints version and handler |
| `/vuln.php?page=FILE` | `include($page)` — LFI sink for chain A |
| `/nosession.php` | no `session_start()`, chain E consumer |
| `/session_oom.php` | decodes the session, OOMs on a large one |
| `/seed_session.php?sid=&size=` | **lab only** writes a large session file (requires `P2S_LAB=1`, set by compose) |
| `/app/upload.php` | `php_serialize` handler (`.user.ini`) |
| `/api/endpoint.php` | `php` handler plus the `Evil` gadget (`.user.ini`) |

All published ports bind to `127.0.0.1`. To expose the lab on an isolated
network, set `P2S_BIND=0.0.0.0` when starting compose; never do that on a public
interface, the images are intentionally vulnerable.

## Reset

```bash
docker compose down --remove-orphans
docker compose up -d
```

Session files live in `/tmp/sessions` inside the containers and disappear with
the containers.

## Notes

- `session.upload_progress.cleanup = Off` keeps the chain A entry alive without
  racing request shutdown. The verifier's `--stall` flag exercises the default
  `cleanup = On` behaviour instead.
- `pm.max_children = 2` lets the stalled upload and the LFI request run on
  different workers. Chain E needs the consumer on the producer's worker, so
  the verifier retries; set `pm.max_children = 1` for deterministic chain E
  runs, at the cost of chain A stall deadlocks.
- The patched container is for differential testing only. Chain A also works
  against it, because filename injection is a feature, not a memory bug.
