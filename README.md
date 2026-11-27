# traefik-logs

Small, fast terminal UI (ratatui) for watching live Traefik access logs —
what is happening right now, where the connections come from, and which
router/service misbehaves. Companion tool to
[rust-stalwart-log-tui](https://github.com/pva2007/rust-stalwart-log-tui),
for Traefik's default JSON access log format.

## Why not Grafana

No setup, no database, no HTTP: point it at a file or directory, it opens
instantly, follows rotation by itself and answers the usual questions:

- Is anything erroring right now? (req/s + 5xx/s chart, status classes)
- Who is hammering the box? (top clients with reverse DNS)
- Which host/router/service is slow? (avg / p95 / p99 / max latency per key)
- Is Traefik or the backend slow? (Overhead vs OriginDuration in the detail view)
- Are backends flapping? (RetryAttempts > 0 counter)

## Usage

```sh
# follow the current directory's access.log* (default)
traefik-logs

# a file, a directory, or several
traefik-logs /var/log/traefik
traefik-logs sample/

# only load the tail of the newest file, then follow
traefik-logs -n 5000 /var/log/traefik

# start filtered (same syntax as the in-app prompt)
traefik-logs -F 'errors host:example.de'
```

Polling-based (no inotify), 250 ms interval, so it also works over sshfs/nfs
and needs no special permissions. Handles logrotate: new files appearing in
the watched directory are picked up automatically, truncation restarts the
file.

Headless sanity check / scripting:

```sh
traefik-logs --print-stats sample/            # whole files
traefik-logs --print-stats --stats-window 300 sample/
```

## Keys

| Key | Action |
| --- | --- |
| `f` or `/` | filter prompt (Enter applies, Esc cancels) |
| `x` / `Esc` | clear filter |
| `Tab`, `1`-`7` | switch panel: Logs, Clients, Hosts, Routers, Services, Paths, Status |
| `↑↓` / `j k`, `g G`, PgUp/PgDn | move selection |
| `Enter` | Logs: request detail; other panels: drill into row (adds filter token) |
| `w` | stats window 1m → 5m → 15m → 1h |
| `d` | toggle reverse DNS for client IPs |
| `Space` | pause the live feed (lines are dropped, not buffered) |
| `r` | clear buffer and session totals |
| `?` | help |
| `q` | quit |

With reverse DNS enabled, client names carry two markers:

- `[self]` — the client IP is the server itself (internal traffic through
  Traefik, e.g. webmail hitting its own backend). Detected by matching the
  client IP against the addresses of the observed virtual hosts, or by its
  forward-confirmed PTR name sharing a domain with an observed host.
- `[local]` — non-routed address (loopback, RFC1918, docker, link-local);
  shown in the detail view, dropped in table cells to save columns.

## Filter syntax

Space-separated tokens, AND-combined:

- `status:5xx` `status:404` `status:>=500` — also `errors` (= 5xx)
- `method:GET`
- `host:x` `path:x` `router:x` `service:x` `ip:x` — substring matches
- anything else is a regex over the whole line: `approle|token`

## Fields used

Traefik JSON access log (`--accesslog.format=json`). Notes:

- `ClientHost` is shown as the client (the real IP when Traefik runs behind
  Cloudflare/a proxy with trusted forwarded headers); falls back to
  `ClientAddr`.
- `Duration` / `Overhead` / `OriginDuration` are nanoseconds; the latency
  panel shows total, the detail view splits proxy overhead vs backend time.
- Aborted connections report status `0` and are counted as `0/unk`.
