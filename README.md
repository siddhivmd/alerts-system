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
| Security (optional) | Spam blacklists, Google Safe Browsing, crypto-miners, new PHP files, SSH brute force, outbound spam. See [Security early warning](#security-early-warning) |

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

## Watching the monitor itself (dead-man's switch)

A monitor can't report its own death. If the monitoring VM dies, freezes, crashes or runs out of disk, the result is silence, and silence looks exactly like "everything is fine". So the monitor checks in with an outside service after every cycle:

| What happens | Ping sent | What the outside service does |
|---|---|---|
| A normal cycle | `OK`, e.g. "2 up, 0 down, 0 alert event(s)" | Nothing |
| A cycle crashed | `/fail`, with the error | Alerts you immediately |
| The monitor runs but is broken, e.g. **disk full** or a locked database | `/fail`, e.g. "saving results failed ... disk full?" | Alerts you immediately |
| VM down, process dead, or frozen | **Nothing** | Alerts you after the grace period |
| The monitor's own internet is down | Nothing (a "monitor offline" cycle) | Alerts you after the grace period |

**Setup (free, about 5 minutes):**
1. Create an account at [healthchecks.io](https://healthchecks.io) and add a check.
   - **Period:** your `check_interval_minutes`, i.e. 5 minutes.
   - **Grace:** 10 minutes. That way one slow cycle doesn't raise an alarm.
2. Choose how healthchecks.io should alert you: email, Telegram, WhatsApp, Slack and others are available. Use a channel that **doesn't depend on the monitoring machine**.
3. Copy the check's ping URL into `.env` as `HEARTBEAT_URL=https://hc-ping.com/...`. Keep it secret: anyone with that URL could fake "I'm alive".
4. In `config.yaml`, set `heartbeat: enabled: true`, then run `python monitor.py run`. Within a cycle the check turns green on healthchecks.io.

Only real cycles ping: scheduled ones, or `check --alert`. A plain `monitor.py check` doesn't, so manual tests can't hide a dead scheduler.

**Second option: UptimeRobot (free) on `/healthz`.**
- `/healthz` returns **200** while check cycles run on schedule and save their results.
- It returns **503** if no cycle has run recently, or if the last one hit an internal error such as a full disk.
- It never shows internal details, because it's a public endpoint.
- This only works if UptimeRobot can reach the dashboard: set `DASHBOARD_PASSWORD`, put HTTPS in front, and point an HTTP monitor at `https://your-monitor-host/healthz`.

Using both is fine: the heartbeat catches everything, including a dead network, while `/healthz` also confirms the web server is up.

## For your clients: SLA reports and status pages

Group sites by customer with a `clients:` section and `client:` on each site (see `config.example.yaml`).

### Monthly SLA report per client

On the 1st of each month (`monthly_report`), each client gets a report for the previous month. For every site it shows:
- **uptime %** against the promised `sla_target`, e.g. "99.97% ✓ target 99.9% met"
- each incident: when it started, how long it took to fix, and the cause
- average response time
- SSL certificate and domain expiry

You also receive an **internal reliability report** with the numbers below.

- **Review before clients see anything.** By default (`send_to_clients: false`) every report is emailed to **you**, marked `[PREVIEW for <client>]`. Once you trust the reports, set `send_to_clients: true` and fill in each client's `report_to`.
- **PDF:** each report is also saved as HTML in `data/reports/YYYY-MM/<client>.html`. Open it in a browser and choose **Print → Save as PDF**.
- **Any month on demand:** `python monitor.py report --month 2026-09 [--client acme] [--send]`. Without `--send` it only prints the reports and saves the HTML files.
- **How uptime is measured:** it's the share of checks that weren't DOWN. Time when the monitor itself was offline has no checks, so it never counts against a client.
- **Limitation:** planned maintenance (`pause`) still counts as downtime in the uptime %.

### Public status page per client

Set `status_page.enabled: true` and `status_page: true` on a client. Then:
- **`/status/<client>`** shows "All systems operational" or "Outage", each site's `public_name`, a 30-day uptime bar (one block per day) and recent disruptions. It refreshes every minute. The page **never shows URLs, causes or server details**.
- **`/status/<client>.json`** is the same data as JSON, which the client can embed on their own site.
- **A custom address** such as `status.clientname.com`:
  1. Set the client's `status_domain`.
  2. Point that DNS name (an A or CNAME record) at the monitoring server.
  3. Let your reverse proxy pass it through. For example, with Caddy:
     ```
     status.clientname.com {
         reverse_proxy 127.0.0.1:8080
     }
     ```
     Caddy gets the HTTPS certificate automatically.
- **Needs a public server.** The status page has to be reachable from the internet, so it only works on the permanent server, behind a reverse proxy with `DASHBOARD_PASSWORD` set. The dashboard keeps its login; only `/status...` and `/healthz` are public.

### Reliability metrics (for you)

The dashboard's **Reliability, last 30 days** section, the internal monthly report and `/api/reliability?days=30` show, per site and per server:
- incidents and total downtime
- **MTTA** (mean time to acknowledge) and **MTTR** (mean time to recover)
- incidents nobody acknowledged
- **top causes**, e.g. "Service php8.2-fpm is failed ×8"

That tells you where to spend engineering time, or when to upgrade a VPS plan.

**Acknowledging** means "I'm on it". It records who responded and how fast, which is what MTTA measures. It also **stops the STILL DOWN reminders and the escalation** for that incident; a changed cause and the final RECOVERED message are still sent. You can acknowledge from the dashboard (the **Acknowledge** button on an open incident) or with `python monitor.py ack "Site name" --by YourName`.

### Other commands

| Command | What it does |
|---|---|
| `python monitor.py pause 2h [--site NAME] [--reason ...]` | Maintenance mode: mutes alerts for that long. Checks keep running. Use `resume` to end it early |
| `python monitor.py resume` | Ends maintenance mode |
| `python monitor.py accept-content [--site NAME]` | Accepts an intended page redesign, so it isn't flagged as possible defacement |

## Security early warning

Hosts suspend accounts for "malicious activity", meaning the server was sending spam, attacking other servers, or hosting malware. This almost always happens after a site gets hacked. These checks try to spot it before the host does. All of them are optional, and all of them only **read**; nothing on the server is changed.

| Check | Needs | Raises a warning when |
|---|---|---|
| **Spam blacklists** (Spamhaus, SpamCop, PSBL, UCEPROTECT) | Nothing; this is a DNS lookup of the VPS IP | The IP is listed. Critical: a listing usually means the server is sending spam |
| **Google malware/phishing check** | `security.safe_browsing: true` and an API key in `.env` (see the note below) | Google flags a site as malware or phishing. Chrome then shows visitors a red warning page |
| **Crypto-miners** | `vps.ssh` | A process matches known miner names or mining-pool addresses (`stratum+tcp://`) |
| **Programs running from temp folders** | `vps.ssh` | A process runs from `/tmp`, `/var/tmp` or `/dev/shm`, a classic malware location |
| **Unknown high-CPU processes** | `vps.ssh` | A process that isn't in `known_processes` uses more than 80% CPU |
| **New PHP files** | `vps.ssh` | A `.php` file in `web_roots` was created or changed in the last hour. Critical inside an `uploads` folder, where webshells are usually dropped |
| **SSH brute force** | `vps.ssh` | 100 or more failed SSH logins in an hour. The top attacking IPs are listed, and the fix suggests fail2ban |
| **Outbound spam** | `vps.ssh` | 20 or more open outbound mail connections (ports 25, 465, 587). This is typical of a hacked site sending spam |

The blacklist and Safe Browsing lookups are rate-limited, so they run once an hour and the result is reused in between. The SSH checks add four read-only commands (`ps`, `find`, `journalctl`, `ss`) to the existing SSH session, so they don't need a second connection. The results appear in the alert emails, in the **Security** panel on the dashboard, in the daily report, and in `monitor.py check`.

**To see a blacklist warning without a real problem:** `config.test.yaml` checks the address `127.0.0.2`. Every blacklist lists that address on purpose, as a test entry.

Notes:
- **Spamhaus refuses lookups that come through big public DNS servers** such as 8.8.8.8 or 1.1.1.1. The monitor then shows "refused the query" for Spamhaus, which is not the same as being listed. The fix is to use your hosting provider's DNS server, or a free Spamhaus DQS key.
- **Which Google API to use.** The default is `security.safe_browsing_provider: web_risk`, **Google Web Risk**, which is licensed for commercial use. Enable "Web Risk API" in a Google Cloud project and put the key in `.env` as `GOOGLE_WEB_RISK_KEY`. It has a free monthly quota and is paid beyond that, so check Google's current pricing. With hourly checks of a few dozen sites, usage stays small. The free **Safe Browsing API** (`safe_browsing_provider: safe_browsing`, key `GOOGLE_SAFE_BROWSING_KEY`) is still supported, but Google's terms allow it for **non-commercial use only**.
- **Deploying code triggers the new-PHP-file warning.** That's expected. Add folders you change often to `php_watch_ignore`.
- **Permissions:** the `monitor` user needs the `systemd-journal` group (already in the SSH setup below) to read SSH logins. It needs read access to the web folders to find new PHP files.

## More checks

| Check | How to enable | What it catches |
|---|---|---|
| **DNS hijack** | `expected_ip: [1.2.3.4]` on a site. IPs or ranges both work; for a site behind Cloudflare, list Cloudflare's ranges | DNS resolving **anywhere else** (changed nameservers or A record). The site is DOWN with the cause "DNS points to X, not your server", even if a page loads |
| **Login / transaction** | A `login:` block on a site (see `config.example.yaml`) | "The page loads but logging in is broken": a dead database, sessions that can't be written, a broken deploy. The monitor fetches the form, copies the CSRF token, posts a **test account**, and checks the logged-in page shows `expect_keyword`. Put the password in `.env` and refer to it as `env:NAME`; it never appears in logs or alerts |
| **Inodes** | Automatic over SSH (`df -i`) | "No space left on device" while `df -h` shows free space. That means too many small files, typically PHP sessions or cache. It's the diagnosed cause when a site fails, with a warning from 85% |
| **Disk trend** | Automatic over SSH (`thresholds.disk_full_warn_days`, default 7) | A straight-line fit over 7 days of disk history, e.g. "Disk 72% full and growing ~3%/day: full in about 9d". Needs at least 24h of history |
| **Domain expiry: RDAP first** | Automatic | RDAP (structured JSON from the registry) is tried first; the old WHOIS lookup is the fallback. More reliable, including for many ccTLDs |

### Several servers

Replace the `vps:` block with a `servers:` list and give each site `server: <name>`; sites without one use the first server. Each server is checked separately: its ports, SSH stats, error logs, blacklists, backups and disk trend. Each site is diagnosed with **its own** server's data, so web1's crashed nginx is never blamed for a site on web2. The dashboard and reports show one block per server. Existing `vps:` setups keep working unchanged.

## How alerts are sent

- **2 failures in a row** before a DOWN alert. This filters out one-off network blips.
- **Confirmed recovery (optional):** with `recovery_successes: 2`, a site must pass 2 checks in a row before RECOVERED is sent. The downtime still ends at the first good check.
- **Flapping:** if a site has `flap_threshold` (default 3) outages within `flap_window_minutes` (default 60), it's "flapping".
  - You get **one** FLAPPING alert instead of a DOWN/RECOVERED storm.
  - You get one "STABLE again" message once a full window passes without a new outage.
  - Every outage is still recorded for the reports.
  - If the site then stays down for a whole window, it's treated as a real outage and you're alerted normally.
- **The monitor's own internet is checked first.** Each cycle starts with a quick "canary" test: it connects to well-known hosts (`1.1.1.1`, `8.8.8.8`, `www.google.com`, `cloudflare.com`; set in `general.canary_hosts`). If none of them answer, the problem is the monitoring machine, not your sites. That cycle is skipped:
  - no sites are checked
  - no incidents are opened
  - nothing counts against uptime
  - no fake RECOVERED message is sent afterwards

  The offline period is logged, shown on the dashboard, and listed in the daily report as "Monitor offline (no checks ran)". No alert can be sent without internet, so use the watchdog heartbeat (`heartbeat:` with `HEARTBEAT_URL` in `.env`) to hear about it: the heartbeat pings stop, and healthchecks.io alerts you.
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
pip install -r requirements.lock                  # exact, tested versions (requirements.txt = ranges)

cp config.example.yaml config.yaml                # edit: VPS IP, sites, recipients
cp .env.example .env                              # fill in the secrets
chmod 600 .env

python monitor.py check                           # one-off check, prints everything
python monitor.py test-alerts                     # sends a test email / Telegram message
python monitor.py run                             # scheduler + dashboard (http://host:8080)
```

### Try it first, with no setup

`config.test.yaml` works immediately. It needs no secrets, no VPS and no email. It checks public websites, several of them broken on purpose, and prints alerts to the console instead of sending them:

```bash
python monitor.py -c config.test.yaml check            # see every diagnosis once
python monitor.py -c config.test.yaml check --alert    # run twice: the 2nd run prints the alert message
python monitor.py -c config.test.yaml run              # dashboard at http://127.0.0.1:8080, checks every minute
```

It uses its own database (`data/test.db`), so test history never mixes with real data.

### Everything is optional

The minimum config is **one site**. Everything else can be switched on later, one piece at a time:

| Feature | How to switch it on | If a required setting is missing |
|---|---|---|
| VPS port checks | `vps.enabled: true` and `vps.host` | Skipped with a warning |
| VPS stats over SSH | `vps.ssh.enabled: true`, plus `user` and an existing `key_file` | Skipped with a warning; the external checks still run |
| Email alerts | `alerts.email.enabled: true`, plus `host`, `to` and `SMTP_PASSWORD` | Skipped with a warning |
| Telegram alerts | `alerts.telegram.enabled: true`, plus `chat_ids` and `TELEGRAM_BOT_TOKEN` | Skipped with a warning |
| Console alerts | `alerts.console: true`. Alert text is written to the log; good for testing | Nothing needed |
| Daily report | `daily_report.enabled: true` | Logged if no listed channel is on |
| Dashboard login | `DASHBOARD_PASSWORD` in `.env` | The dashboard still runs, **without a login, on 127.0.0.1 only** |

Skipped features are listed at startup as `Config: ... off: missing ...`. Only genuine mistakes stop the monitor, such as an unknown key, a bad URL, or a time that isn't HH:MM. For email, `port` defaults from `security` (465 for `ssl`, 587 for `starttls`), and `from_addr` defaults to `username`.

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
| `vps` | `enabled`, `host`, `ports`, and the optional `ssh` block (enabled, user, key, services, error logs) |
| `alerts` | `consecutive_failures` (2), `throttle_minutes` (30), `warning_repeat_hours` (24), `console` (false), plus the `email` and `telegram` blocks, each with `enabled` |
| `daily_report` | `enabled`, `time` ("09:00"), `channels` (any of email, telegram, console) |
| `dashboard` | `enabled`, `host`, `port`, `username` |
| `sites[]` | `name`, `url`, plus any of: `keyword`, `forbidden_keywords`, `timeout`, `expected_status`, `headers`, `follow_redirects`, `max_redirects`, `slow_threshold_ms`, `check_ssl`, `check_domain`, `domain`, `on_vps`, `error_log`, `verify_ssl` |

Set `on_vps: false` for sites hosted somewhere else. They skip the VPS-based diagnosis.

**Secrets live only in `.env`** and are never read from `config.yaml`: `SMTP_PASSWORD`, `TELEGRAM_BOT_TOKEN`, `DASHBOARD_PASSWORD` and `SSH_KEY_PASSPHRASE`. All of them are optional; see "Everything is optional" above.

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

Bad parameters such as `?hours=abc` return a clear **400** error. Values out of range are clamped.

### Exposing it safely (HTTPS + lockout)

The dashboard uses HTTP Basic auth, so **the password travels with every request**. Over plain HTTP, anyone on the network path can read it. Don't open port 8080 to the internet.

- **Docker** publishes the port on `127.0.0.1` only. From elsewhere, either use an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 you@monitor-host`, then open http://127.0.0.1:8080), or turn on the **Caddy HTTPS front door**:
  1. Point a DNS name, e.g. `monitor.yourcompany.com`, at the server.
  2. Put `MONITOR_DOMAIN=monitor.yourcompany.com` in `.env`.
  3. In `config.yaml`, set `dashboard: {host: 0.0.0.0, trust_proxy: true}`.
  4. Run `docker compose --profile https up -d`.

  Caddy fetches and renews the Let's Encrypt certificate automatically (see `deploy/Caddyfile`).
- **systemd:** set `dashboard: {host: 127.0.0.1, trust_proxy: true}`, install Caddy on the server, and use `deploy/Caddyfile` with `reverse_proxy 127.0.0.1:8080`.
- **Lockout:** after `max_login_failures` (5) wrong passwords from one IP within `lockout_minutes` (15), that IP gets **429 Too Many Requests** for 15 minutes, even with the right password, so guessing can't continue. A successful login resets the count.
- **`trust_proxy: true`** only when a proxy is in front. The lockout then uses the client IP the proxy reports. Without a proxy, a client could fake that header.
- The monitor **warns at startup** whenever the dashboard listens on a public interface over plain HTTP.

## Deployment

### systemd (Ubuntu/Debian VM)

```bash
sudo useradd --system --home /opt/site-monitor --shell /usr/sbin/nologin sitemonitor
sudo git clone <this repo> /opt/site-monitor && cd /opt/site-monitor
sudo python3 -m venv .venv && sudo .venv/bin/pip install -r requirements.lock
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

## Tests, lint and CI

```bash
pip install -r requirements.lock -r requirements-dev.txt
ruff check .          # lint: pyflakes, pycodestyle, import order, bugbear, pyupgrade (pyproject.toml)
python -m pytest      # the whole suite, offline
```

**CI:** `.github/workflows/ci.yml` runs `ruff check` and `pytest` on every push and pull request, on Python 3.12 (the Docker image) and 3.13. It installs the exact versions from `requirements.lock`, so CI tests what you deploy.

**Dependencies:** `requirements.txt` lists what the code imports, with version ranges. `cryptography` and `Jinja2` are listed explicitly because the code uses them directly. `requirements.lock` pins **every** package, including indirect ones, to the exact version that passed the tests. The Dockerfile, the systemd steps and CI all install from the lock. After changing `requirements.txt`, regenerate the lock in a fresh virtualenv:

```bash
python -m venv .lockenv && .lockenv/bin/pip install -r requirements.txt
.lockenv/bin/pip freeze > requirements.lock     # keep the comment header, then run the tests
```

| Test file | Covers |
|---|---|
| `tests/test_diagnosis.py` | Every diagnosis rule and the priority between rules, using mocked results |
| `tests/test_alerts.py` | The consecutive-failure rule, 30-minute throttling, recovery with downtime, retry after a failed delivery, state surviving a restart |
| `tests/test_security.py` | Blacklist answers, including Spamhaus refusing a public resolver and ISP DNS hijacking; Safe Browsing matches and errors; miner, temp-folder and PHP-file detection; SSH brute force; outbound spam; caching. All offline |
| `tests/test_storage.py`, `tests/test_ssh_stats.py` | The database layer, and the remote-output parser run on realistic sample output |
| `tests/test_integration.py` | Config validation, a full cycle with mocked network calls (one crashing check must not stop the others), and dashboard auth / API |
| `tests/test_hardening.py` | Login lockout (including forged `X-Forwarded-For`), 400 on bad parameters, parallel port checks, the plain-HTTP warning |
| `tests/test_sla.py`, `tests/test_new_checks.py`, `tests/test_features.py` | SLA reports, status pages, acknowledgement, multiple servers, inodes, disk trend, DNS hijack, RDAP, flapping, login checks, WhatsApp, escalation, maintenance, defacement, backups |

## Project layout

```
monitor.py                 CLI entry point (run / check / test-alerts / report)
sitemonitor/
  config.py                config.yaml + .env loading and validation
  checks.py                DNS, HTTP, keyword, SSL, WHOIS, VPS TCP ports
  security.py              blacklists, Safe Browsing, miner / webshell / brute-force / spam signals
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
| Dashboard only opens on the monitor machine itself | No `DASHBOARD_PASSWORD` in `.env`, so it's limited to 127.0.0.1. Set a password to allow other machines |
| HTTP 429 or 403 only from the monitor | The site's firewall or WAF is rate-limiting the monitor. Allowlist its IP |
