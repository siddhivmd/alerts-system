"""Collect VPS health over SSH (key-based auth): RAM, CPU load, disk, OOM kills,
service status (systemd, pm2, docker) and web server error-log tails.

Everything is gathered in a single round trip with one POSIX-sh script whose
output is split into ``##SECTION`` blocks. If SSH is not configured or fails,
callers get a ``VpsStats`` with ``ok=False`` and an ``error`` - never an exception.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import re
import shlex
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .config import SecurityConfig, SshConfig

log = logging.getLogger(__name__)

# systemd states that mean "this service should be running but is not".
_BAD_ACTIVE = {"failed"}
_PM2_BAD = {"errored", "stopped", "stopping", "launching"}
# "Invalid user" and "Failed password for invalid user" describe the same attempt: count it once.
_FAILED_LOGIN = re.compile(r"Failed password for (?!invalid user)|Invalid user")
_FROM_IP = re.compile(r"from ((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)")


@dataclass
class VpsStats:
    ok: bool = False
    error: str | None = None
    ram_percent: float | None = None
    swap_percent: float | None = None
    cpu_load: float | None = None  # 1-minute load average
    cpu_load5: float | None = None
    cpu_cores: int | None = None
    uptime_seconds: float | None = None
    disk_percent: float | None = None  # root filesystem
    disks: dict[str, float] = field(default_factory=dict)  # mount -> used %
    oom_kills: int | None = None
    oom_window: str = "24h"
    oom_last: str | None = None
    services: dict[str, dict[str, str]] = field(default_factory=dict)  # name -> {active, sub, enabled}
    pm2: list[dict[str, Any]] = field(default_factory=list)
    docker: list[dict[str, str]] = field(default_factory=list)
    error_logs: dict[str, list[str]] = field(default_factory=dict)
    # security data (only collected when security checks are enabled)
    top_processes: list[dict[str, Any]] = field(default_factory=list)  # {pid, user, cpu, comm, args}
    new_php_files: list[str] = field(default_factory=list)
    failed_ssh_logins: int | None = None
    failed_ssh_window: str = "last hour"
    failed_ssh_top_ips: list[tuple[str, int]] = field(default_factory=list)
    outbound_smtp: int | None = None

    # ---- derived views used by the diagnosis engine
    @property
    def failed_services(self) -> list[str]:
        """Installed services that are failed, or enabled at boot but not running."""
        bad = []
        for name, st in self.services.items():
            if st.get("active") in _BAD_ACTIVE or (
                    st.get("active") == "inactive" and st.get("enabled") == "enabled"):
                bad.append(name)
        return sorted(bad)

    @property
    def pm2_problems(self) -> list[dict[str, Any]]:
        return [p for p in self.pm2 if p.get("status") in _PM2_BAD]

    @property
    def docker_problems(self) -> list[dict[str, str]]:
        out = []
        for c in self.docker:
            status = c.get("status", "")
            if c.get("state") in ("restarting", "dead") or "(unhealthy)" in status or (
                    c.get("state") == "exited" and not status.startswith("Exited (0)")):
                out.append(c)
        return out

    @property
    def load_per_core(self) -> float | None:
        if self.cpu_load is None or not self.cpu_cores:
            return None
        return self.cpu_load / self.cpu_cores

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["failed_services"] = self.failed_services
        d["pm2_problems"] = self.pm2_problems
        d["docker_problems"] = self.docker_problems
        return d


def _security_script(sec: SecurityConfig, sudo: str) -> str:
    """Read-only commands for the security checks (see security.py for how results are judged)."""
    roots = " ".join(shlex.quote(r) for r in sec.web_roots)
    find_php = (f"{sudo}find {roots} -xdev -type f \\( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \\) "
                f"-mmin -{int(sec.php_watch_minutes)} 2>/dev/null | head -n 200") if roots else ":"
    return f"""echo '##PROCS'; ps -eo pid=,user=,pcpu=,comm=,args= --sort=-pcpu 2>/dev/null | head -n 10
echo '##NEWPHP'; {find_php}
echo '##SSHFAIL'
if command -v journalctl >/dev/null 2>&1; then
  echo 'window=last hour'; {sudo}journalctl -u ssh -u sshd --since '1 hour ago' --no-pager -q 2>/dev/null | grep -E 'Failed password|Invalid user' | tail -n 5000
else
  echo 'window=recent log lines'; tail -n 5000 /var/log/auth.log /var/log/secure 2>/dev/null | grep -E 'Failed password|Invalid user'
fi
echo '##SMTPOUT'; ss -tn state established '( dport = :25 or dport = :465 or dport = :587 )' 2>/dev/null | tail -n +2 | wc -l
"""


def _stats_script(cfg: SshConfig, security: SecurityConfig | None = None) -> str:
    sudo = "sudo -n " if cfg.use_sudo else ""
    pm2 = "command -v pm2 >/dev/null 2>&1 && pm2 jlist 2>/dev/null" if cfg.check_pm2 else ":"
    docker = (f"command -v docker >/dev/null 2>&1 && {sudo}docker ps -a "
              "--format '{{.Names}}|{{.State}}|{{.Status}}' 2>/dev/null") if cfg.check_docker_containers else ":"
    sec = _security_script(security, sudo) if security is not None and security.enabled else ""
    return f"""export LC_ALL=C
echo '##MEM'; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo
echo '##LOAD'; cat /proc/loadavg; nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo
echo '##UPTIME'; cat /proc/uptime
echo '##DISK'; df -P -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null
echo '##OOM'
if command -v journalctl >/dev/null 2>&1; then
  echo 'window=24h'; {sudo}journalctl -k --since '24 hours ago' --no-pager -q 2>/dev/null | grep -i 'killed process' | tail -n 100
else
  echo 'window=since boot'; {sudo}dmesg 2>/dev/null | grep -i 'killed process' | tail -n 100
fi
echo '##UNITS'; systemctl list-units --type=service --all --no-legend --plain --no-pager 2>/dev/null
echo '##UNITFILES'; systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null
echo '##PM2'
{pm2}
echo '##DOCKER'
{docker}
{sec}echo '##END'
"""


def _sections(output: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in output.splitlines():
        if line.startswith("##") and line[2:].isupper():
            current = line[2:]
            sections[current] = []
        elif current:
            sections[current].append(line)
    return sections


def parse_stats(output: str, service_patterns: list[str]) -> VpsStats:
    """Parse the combined script output. Each section is parsed independently."""
    s = _sections(output)
    st = VpsStats(ok=True)

    try:
        mem = {}
        for line in s.get("MEM", []):
            key, val = line.split(":", 1)
            mem[key] = float(val.split()[0])
        if mem.get("MemTotal"):
            st.ram_percent = round(100 * (mem["MemTotal"] - mem.get("MemAvailable", 0)) / mem["MemTotal"], 1)
        if mem.get("SwapTotal"):
            st.swap_percent = round(100 * (mem["SwapTotal"] - mem.get("SwapFree", 0)) / mem["SwapTotal"], 1)
    except (ValueError, IndexError):
        log.warning("Could not parse memory stats")

    try:
        load = s.get("LOAD", [])
        parts = load[0].split()
        st.cpu_load, st.cpu_load5 = float(parts[0]), float(parts[1])
        st.cpu_cores = int(load[1].strip())
    except (ValueError, IndexError):
        log.warning("Could not parse load average")

    try:
        st.uptime_seconds = float(s.get("UPTIME", ["0"])[0].split()[0])
    except (ValueError, IndexError):
        pass

    for line in s.get("DISK", [])[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 6 and parts[4].endswith("%"):
            try:
                st.disks[parts[5]] = float(parts[4].rstrip("%"))
            except ValueError:
                continue
    st.disk_percent = st.disks.get("/")

    oom_lines = s.get("OOM", [])
    if oom_lines and oom_lines[0].startswith("window="):
        st.oom_window = oom_lines[0].split("=", 1)[1]
        oom_lines = oom_lines[1:]
    oom_lines = [line for line in oom_lines if line.strip()]
    st.oom_kills = len(oom_lines)
    st.oom_last = oom_lines[-1].strip()[:300] if oom_lines else None

    enabled: dict[str, str] = {}
    for line in s.get("UNITFILES", []):
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(".service"):
            enabled[parts[0][:-8]] = parts[1]
    for line in s.get("UNITS", []):
        parts = line.split(None, 4)
        if len(parts) < 4 or not parts[0].endswith(".service"):
            continue
        name = parts[0][:-8]
        if parts[1] == "not-found":
            continue
        if any(fnmatch.fnmatch(name, pat) for pat in service_patterns):
            st.services[name] = {"active": parts[2], "sub": parts[3], "enabled": enabled.get(name, "unknown")}
    # Enabled services that systemd has not loaded at all also count (never started since boot).
    for name, state in enabled.items():
        if name not in st.services and state == "enabled" and any(
                fnmatch.fnmatch(name, pat) for pat in service_patterns):
            st.services[name] = {"active": "inactive", "sub": "dead", "enabled": state}

    # pm2 may print banners like "[PM2] Spawning daemon" before the JSON list.
    for line in s.get("PM2", []):
        if not line.lstrip().startswith("["):
            continue
        try:
            procs = json.loads(line)
        except ValueError:
            continue
        if isinstance(procs, list):
            st.pm2 = [{"name": p.get("name"), "status": (p.get("pm2_env") or {}).get("status"),
                       "restarts": (p.get("pm2_env") or {}).get("restart_time")}
                      for p in procs if isinstance(p, dict)]
            break

    for line in s.get("DOCKER", []):
        parts = line.split("|", 2)
        if len(parts) == 3:
            st.docker.append({"name": parts[0], "state": parts[1], "status": parts[2]})

    _parse_security(s, st)
    return st


def _parse_security(s: dict[str, list[str]], st: VpsStats) -> None:
    """Security sections are only present when security checks are enabled."""
    for line in s.get("PROCS", []):
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        try:
            st.top_processes.append({"pid": int(parts[0]), "user": parts[1], "cpu": float(parts[2]),
                                     "comm": parts[3], "args": parts[4][:300] if len(parts) > 4 else parts[3]})
        except ValueError:
            continue

    st.new_php_files = [line.strip() for line in s.get("NEWPHP", []) if line.strip().startswith("/")]

    if "SSHFAIL" in s:
        lines = s["SSHFAIL"]
        if lines and lines[0].startswith("window="):
            st.failed_ssh_window = lines[0].split("=", 1)[1]
            lines = lines[1:]
        failed = [line for line in lines if _FAILED_LOGIN.search(line)]
        st.failed_ssh_logins = len(failed)
        ips = Counter(m.group(1) for line in failed if (m := _FROM_IP.search(line)))
        st.failed_ssh_top_ips = ips.most_common(3)

    smtp = [line.strip() for line in s.get("SMTPOUT", []) if line.strip()]
    if smtp and smtp[0].isdigit():
        st.outbound_smtp = int(smtp[0])


# --------------------------------------------------------------------------- SSH plumbing

def _connect(host: str, cfg: SshConfig):  # -> paramiko.SSHClient
    import paramiko

    client = paramiko.SSHClient()
    # Trust-on-first-use: the key is saved on first connect; a *changed* key is rejected
    # (BadHostKeyException) - it means the VPS was rebuilt or someone is intercepting.
    known = Path(cfg.known_hosts or "known_hosts")
    known.parent.mkdir(parents=True, exist_ok=True)
    known.touch(exist_ok=True)
    client.load_host_keys(str(known))
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=cfg.port, username=cfg.user, key_filename=cfg.key_file,
                   passphrase=cfg.key_passphrase, timeout=cfg.timeout, banner_timeout=cfg.timeout,
                   auth_timeout=cfg.timeout, allow_agent=False, look_for_keys=False)
    return client


def _run(client: Any, script: str, timeout: float) -> str:
    _, stdout, _ = client.exec_command(script, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace")


def _friendly_error(exc: Exception) -> str:
    name = type(exc).__name__
    if name == "BadHostKeyException":
        return ("SSH host key CHANGED - the VPS was reinstalled or the connection is being intercepted. "
                "If you rebuilt the VPS, delete its line from the known_hosts file.")
    if name == "AuthenticationException":
        return "SSH authentication failed (wrong user/key, or key not in authorized_keys)"
    if isinstance(exc, FileNotFoundError):
        return f"SSH key file not found: {exc.filename}"
    return f"SSH failed: {name}: {exc}"


def collect_stats(host: str, cfg: SshConfig, security: SecurityConfig | None = None) -> VpsStats:
    """Collect all VPS metrics (plus security data if enabled) in one SSH session. Never raises."""
    try:
        client = _connect(host, cfg)
    except Exception as exc:  # noqa: BLE001
        log.warning("SSH connect to %s failed: %s", host, exc)
        return VpsStats(ok=False, error=_friendly_error(exc))
    try:
        output = _run(client, _stats_script(cfg, security), timeout=cfg.timeout * 3)
        return parse_stats(output, cfg.services)
    except Exception as exc:  # noqa: BLE001
        log.warning("Collecting stats from %s failed: %s", host, exc)
        return VpsStats(ok=False, error=_friendly_error(exc))
    finally:
        client.close()


def fetch_error_logs(host: str, cfg: SshConfig, paths: list[str]) -> dict[str, list[str]]:
    """Return the last ``cfg.error_log_lines`` lines of each existing log in ``paths``."""
    if not paths:
        return {}
    sudo = "sudo -n " if cfg.use_sudo else ""
    n = int(cfg.error_log_lines)
    script = "\n".join(
        f"if [ -e {shlex.quote(p)} ]; then echo {shlex.quote('##LOG ' + p)}; {sudo}tail -n {n} -- {shlex.quote(p)} 2>&1; fi"
        for p in dict.fromkeys(paths))
    try:
        client = _connect(host, cfg)
    except Exception as exc:  # noqa: BLE001
        log.warning("SSH connect for error logs failed: %s", exc)
        return {}
    try:
        output = _run(client, script, timeout=cfg.timeout * 2)
    except Exception as exc:  # noqa: BLE001
        log.warning("Reading error logs failed: %s", exc)
        return {}
    finally:
        client.close()

    logs: dict[str, list[str]] = {}
    current: str | None = None
    for line in output.splitlines():
        if line.startswith("##LOG "):
            current = line[6:]
            logs[current] = []
        elif current is not None:
            logs[current].append(line[:500])
    return logs
