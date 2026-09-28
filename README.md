# Site Monitor

Checks every website and portal we host, checks the Hostinger VPS they run on, and when something breaks tells us **what is down, why, and how to fix it**, by email and/or Telegram.

```
[ DOWN  ] Client Portal  https://portal.example.com  no response
          CAUSE: Site down: Service nginx is failed (failed)
            - Also: RAM usage is 94% (threshold 90%)
          FIX: Restart nginx: sudo systemctl restart nginx  (then check why: sudo journalctl -u nginx -n 50 --no-pager)
```

## Why this must run on a different provider

The monitor has to be alive exactly when the VPS is not. If it runs on the monitored VPS, or on another server in the same Hostinger account, then:

- **If the account is suspended, the monitor goes down with it.** This has happened to us before, with no warning email. A monitor in the same account can't tell anyone.
- **Anything that takes the VPS down takes the monitor down too.** That includes a crash, a full disk, the OOM killer, a network outage or a reboot loop. It fails silently at the one moment you need it.
- **It can't see what customers see.** Checks from inside the server skip DNS, the public network, the firewall and certificate problems.

Run it on a small machine with a **different provider and a different account**: a $5 VM at DigitalOcean, Hetzner, AWS Lightsail or Oracle Cloud's free tier, or an always-on office machine. Nothing it needs lives on the VPS. SSH access is optional and only adds detail.

## What it checks

| Check | Detail |
|---|---|
| DNS | The hostname resolves |
| HTTP | Status code (default: anything < 400, or `expected_status`), response time, redirect chain, redirect loops |
| Content | `keyword` must appear on the page. `forbidden_keywords` must not (e.g. "Error establishing a database connection") |
| SSL | Certificate valid and not expiring. Warns at 14 days, critical at 3 days. On failure it still reads the expiry date |
| Domain | WHOIS expiry. Warns at 30 days. Cached 24h because registrars rate-limit |
| VPS ports | TCP 22 / 80 / 443. **All closed = VPS down or account suspended** |
| VPS over SSH (optional) | RAM %, CPU load, disk %, OOM kills (last 24h), systemd services (nginx/apache, mysql/mariadb, php-fpm, docker), pm2 apps, Docker containers. When a site fails, also the last 20 lines of the web-server error log |

Sites are checked in parallel, so 20+ sites finish in about the time of the slowest one.

## How problems are diagnosed

For a failing site, the first matching rule wins:

1. **DNS failure**: domain expired, not registered, or DNS misconfigured.
2. **All VPS ports unreachable**: VPS down or **account suspended**. Check the Hostinger panel and email, including spam.
3. **SSL error**: certificate expired, wrong hostname, self-signed, or incomplete chain.
4. **VPS up, site down**: checks in this order: disk full, failed services / pm2 / containers, OOM kills, RAM > 90 %, CPU overload, ports 80/443 closed. The error log is scanned for known signatures such as a dead php-fpm socket, "upstream timed out", or "No space left on device".
5. **HTTP status and content**: 5xx / 4xx (each explained), redirect loop, error text on the page, or the expected keyword missing.

Each diagnosis includes a concrete fix, for example `sudo systemctl restart nginx`.

**Warnings** don't mark a site as down: slow response (above `slow_threshold_ms`), SSL or domain expiring soon, and VPS disk / RAM / CPU / service problems.

## How alerts are sent

- **2 failures in a row** before a DOWN alert. This filters out one-off network blips.
- **DOWN**: sent immediately once confirmed. It includes the cause, the fixes, the evidence and the error-log lines.
- **Still down**: the same cause is repeated at most once every **30 minutes**. If the cause changes (e.g. nginx down becomes disk full), you get an alert right away.
- **RECOVERED**: sent on the first successful check. It includes the **downtime**, measured from the first failed check.
- **Warnings**: also need 2 sightings, then repeat at most once every 24 hours.
- **Batching**: everything from one cycle goes out as **one** message per channel. A VPS outage affecting 20 sites sends one email, not 20.
- **Delivery failures**: an alert only counts as "sent" if a channel delivered it. If email and Telegram both fail, the next cycle tries again.
- **Daily summary** at a configurable time: every site, uptime % over 24h, average response time, incidents, warnings, and VPS health.

All numbers above are configurable.

## Setup

Requires Python 3.10+.

```bash
git clone <this repo> site-monitor && cd site-monitor
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp config.example.yaml config.yaml                # edit: VPS IP, sites, recipients
cp .env.example .env                              # fill in the secrets
chmod 600 .env

python monitor.py check                           # one-off check, prints everything
python monitor.py test-alerts                     # sends a test email / Telegram message
python monitor.py run                             # scheduler + dashboard (http://host:8080)
```

### Commands

| Command | What it does |
|---|---|
| `monitor.py run [--no-dashboard]` | Long-running process: checks every N minutes, sends the daily report, purges old data nightly, serves the dashboard |
| `monitor.py check [--site NAME] [--json] [--save] [--alert]` | One cycle now. By default it saves nothing and sends nothing. `--alert` behaves exactly like a scheduled cycle. Exits with code 1 if any site is down |
| `monitor.py test-alerts` | Test message on every enabled channel. Reports OK or the exact error |
| `monitor.py report [--send]` | Prints the daily summary from stored history, and optionally sends it |

Global options: `-c/--config PATH`, `--env-file PATH`, `-v` (debug logging).

## Configuration

`config.yaml` holds everything except secrets. `config.example.yaml` documents every key. Unknown keys are rejected, so typos surface at startup.

| Section | Key settings |
|---|---|
| `general` | `check_interval_minutes` (5), `timezone`, `database`, `log_file`, `retention_days` (90) |
| `thresholds` | `ram_percent` (90), `disk_percent` (95), `disk_warn_percent` (85), `cpu_load_per_core` (2.0), `ssl_warn_days` (14), `ssl_critical_days` (3), `domain_warn_days` (30) |
| `defaults` | Applied to every site: `timeout`, `slow_threshold_ms`, `follow_redirects`, `check_ssl`, `check_domain` |
| `vps` | `host`, `ports`, and the optional `ssh` block (user, key, services, error logs) |
| `alerts` | `consecutive_failures` (2), `throttle_minutes` (30), `warning_repeat_hours` (24), plus the `email` and `telegram` blocks, each with `enabled` |
| `daily_report` | `enabled`, `time` ("09:00"), `channels` |
| `dashboard` | `enabled`, `host`, `port`, `username` |
| `sites[]` | `name`, `url`, plus any of: `keyword`, `forbidden_keywords`, `timeout`, `expected_status`, `headers`, `follow_redirects`, `max_redirects`, `slow_threshold_ms`, `check_ssl`, `check_domain`, `domain`, `on_vps`, `error_log`, `verify_ssl` |

Set `on_vps: false` for sites hosted somewhere else. They skip the VPS-based diagnosis.

**Secrets live only in `.env`** and are never read from `config.yaml`: `SMTP_PASSWORD`, `TELEGRAM_BOT_TOKEN`, `DASHBOARD_PASSWORD` and `SSH_KEY_PASSPHRASE`. The dashboard won't start without a password.

### Email

For Gmail, turn on 2-Step Verification and create an **App Password**. Put it in `SMTP_PASSWORD` and use `host: smtp.gmail.com, port: 465, security: ssl`. For other providers, use port 587 with `security: starttls`.

### Telegram

1. Message **@BotFather**, send `/newbot`, and copy the token into `TELEGRAM_BOT_TOKEN`.
2. Send your bot any message. For a group, add the bot to the group.
3. Open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `chat.id`. Group ids are negative.
4. Put the id in `alerts.telegram.chat_ids`, set `enabled: true`, then run `python monitor.py test-alerts`.

### SSH access to the VPS (optional, recommended)

Without SSH you still get every external check and the "VPS down / suspended" diagnosis. With SSH, alerts can name the actual cause (nginx dead, disk full, and so on) and include error-log lines.

Use a dedicated, **read-only** user and a dedicated key. Don't use root.

```bash
# on the monitoring machine
ssh-keygen -t ed25519 -f ~/.ssh/monitor_ed25519 -C site-monitor

# on the VPS
sudo adduser --disabled-password --gecos "" monitor
sudo usermod -aG adm,systemd-journal monitor      # read /var/log/* and the kernel journal (OOM kills)
sudo mkdir -p /home/monitor/.ssh
echo "<contents of monitor_ed25519.pub>" | sudo tee /home/monitor/.ssh/authorized_keys
sudo chown -R monitor:monitor /home/monitor/.ssh && sudo chmod 700 /home/monitor/.ssh && sudo chmod 600 /home/monitor/.ssh/authorized_keys
```

- RAM, CPU, disk, systemd service status and pm2 need no extra rights. pm2 only lists apps for the user it runs as, so run the monitor as that user if needed.
- Docker containers: membership in the `docker` group is root-equivalent, so don't add `monitor` to it. Instead, set `use_sudo: true` and allow only the exact read commands in `/etc/sudoers.d/monitor`. Alternatively, set `check_docker_containers: false`.
  ```
  monitor ALL=(root) NOPASSWD: /usr/bin/docker ps -a --format *, /usr/bin/journalctl -k *, /usr/bin/dmesg, /usr/bin/tail -n 20 -- /var/log/nginx/error.log
  ```
- The VPS host key is pinned in `data/known_hosts` on the first connection (trust on first use). If the key later changes, SSH checks stop with a "host key CHANGED" message. That means the VPS was rebuilt, or someone is intercepting the connection. After a rebuild, delete the old line.

## Dashboard

`http://<monitor-host>:8080`, protected by HTTP Basic auth (`dashboard.username` / `DASHBOARD_PASSWORD`). It refreshes every 30 seconds and shows:

- current status and diagnosis for every site, down sites first
- uptime, SSL and domain expiry
- a 24h sparkline per site, plus a larger response-time chart with down periods shaded
- VPS reachability, RAM, disk, CPU and services
- incident history

| Endpoint | Auth | Returns |
|---|---|---|
| `/api/status` | yes | Current status of every site and the VPS (JSON) |
| `/api/history?hours=24` | yes | Response-time series per site, plus VPS metrics |
| `/api/incidents?limit=50` | yes | Past and ongoing outages |
| `/healthz` | no | `{"ok": true}` while check cycles are running on schedule. Returns 503 if the scheduler stalls |

Basic auth sends the password with every request. Before exposing the dashboard to the internet, put it behind HTTPS (Caddy or nginx with Let's Encrypt), or restrict port 8080 to your office IP / VPN.

## Deployment

### systemd (Ubuntu/Debian VM)

```bash
sudo useradd --system --home /opt/site-monitor --shell /usr/sbin/nologin sitemonitor
sudo git clone <this repo> /opt/site-monitor && cd /opt/site-monitor
sudo python3 -m venv .venv && sudo .venv/bin/pip install -r requirements.txt
sudo cp config.example.yaml config.yaml && sudo cp .env.example .env    # edit both
sudo mkdir -p data logs ssh && sudo cp ~/.ssh/monitor_ed25519 ssh/      # key_file: ssh/monitor_ed25519
sudo chown -R sitemonitor:sitemonitor /opt/site-monitor && sudo chmod 600 .env ssh/*

sudo cp deploy/site-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now site-monitor
journalctl -u site-monitor -f
```

The unit restarts the process on failure. It runs sandboxed: it can only write to `data/` and `logs/`.

### Docker

```bash
cp config.example.yaml config.yaml && cp .env.example .env            # edit both
mkdir -p data logs ssh && cp ~/.ssh/monitor_ed25519 ssh/              # key_file: ssh/monitor_ed25519
UID=$(id -u) GID=$(id -g) docker compose up -d --build
docker compose logs -f
docker compose exec monitor python monitor.py test-alerts
```

The container runs as a non-root user. History and logs persist in `./data` and `./logs`. The Docker healthcheck calls `/healthz`, so it needs the dashboard enabled.

## Data and logs

- SQLite database `data/monitor.db` with these tables:
  - `sites`, `checks` (every result), `incidents` (start, end, cause)
  - `site_state` and `warning_alerts`: alert state, so a restart neither re-alerts nor forgets an outage
  - `vps_stats`, `whois_cache`
- Check and VPS-stat rows older than `retention_days` (90) are deleted every night at 03:30. **Incidents are kept.**
- Full diagnostic detail is stored only for failed or warned checks, which keeps the database small.
- Logs go to `logs/monitor.log`, rotated at 5 MB with 5 files kept, and also to stdout/journald.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

| Test file | Covers |
|---|---|
| `tests/test_diagnosis.py` | Every diagnosis rule and the priority between rules, using mocked results |
| `tests/test_alerts.py` | The consecutive-failure rule, 30-minute throttling, recovery with downtime, retry after a failed delivery, state surviving a restart |
| `tests/test_storage.py`, `tests/test_ssh_stats.py` | The database layer, and the remote-output parser run on realistic sample output |
| `tests/test_integration.py` | Config validation, a full cycle with mocked network calls (one crashing check must not stop the others), and dashboard auth / API |

## Project layout

```
monitor.py                 CLI entry point (run / check / test-alerts / report)
sitemonitor/
  config.py                config.yaml + .env loading and validation
  checks.py                DNS, HTTP, keyword, SSL, WHOIS, VPS TCP ports
  ssh_stats.py             VPS metrics + error logs over SSH (paramiko)
  diagnosis.py             raw results -> root cause + fix (pure functions)
  alerts.py                alert decisions, throttling, email + Telegram
  storage.py               SQLite
  runner.py                one concurrent check cycle
  scheduler.py             APScheduler jobs (checks, daily report, purge)
  report.py                daily summary
  dashboard.py             Flask app + JSON API
  templates/dashboard.html
deploy/site-monitor.service
Dockerfile, docker-compose.yml
```

## Troubleshooting

| Symptom | Likely reason |
|---|---|
| `test-alerts` says `(535, ... Username and Password not accepted)` | Gmail needs an App Password, not your normal password |
| Every site shows "VPS unreachable" but the VPS is fine | The monitor's own network is down, or the VPS firewall blocks the monitor's IP. Allow it, or check `vps.host` |
| "SSH authentication failed" | Wrong `user` or `key_file`, or the public key isn't in `authorized_keys` |
| "WHOIS returned no expiry date" | Some TLDs (e.g. many ccTLDs) hide it. Set `check_domain: false` for that site |
| Dashboard log says "Dashboard disabled" | `DASHBOARD_PASSWORD` is missing from `.env` |
| HTTP 429 or 403 only from the monitor | The site's firewall or WAF is rate-limiting the monitor. Allowlist its IP |
