from sitemonitor.ssh_stats import parse_stats

SAMPLE = """##MEM
MemTotal:        4015636 kB
MemAvailable:     401563 kB
SwapTotal:       2097148 kB
SwapFree:        1048574 kB
##LOAD
3.10 2.50 1.90 2/345 12345
2
##UPTIME
86400.50 150000.00
##DISK
Filesystem     1024-blocks     Used Available Capacity Mounted on
/dev/sda1         80000000 77600000   2400000      97% /
/dev/sdb1         10000000  1000000   9000000      10% /backup
##OOM
window=24h
Sep 28 03:12:01 vps kernel: Out of memory: Killed process 812 (mysqld) total-vm:1800000kB
##UNITS
nginx.service           loaded active   running A high performance web server
mysql.service           loaded failed   failed  MySQL Community Server
php8.2-fpm.service      loaded active   running The PHP 8.2 FastCGI Process Manager
apache2.service         loaded inactive dead    The Apache HTTP Server
ssh.service             loaded active   running OpenBSD Secure Shell server
##UNITFILES
nginx.service           enabled  enabled
mysql.service           enabled  enabled
php8.2-fpm.service      enabled  enabled
apache2.service         disabled enabled
docker.service          enabled  enabled
##PM2
[PM2] Spawning PM2 daemon
[{"name":"api","pm2_env":{"status":"errored","restart_time":15}},{"name":"web","pm2_env":{"status":"online","restart_time":0}}]
##DOCKER
redis|running|Up 3 days
worker|restarting|Restarting (1) 5 seconds ago
oneshot|exited|Exited (0) 2 days ago
##END
"""


def test_parse_full_output():
    st = parse_stats(SAMPLE, ["nginx", "apache2", "mysql", "php*-fpm", "docker"])
    assert st.ok
    assert st.ram_percent == 90.0
    assert st.swap_percent == 50.0
    assert (st.cpu_load, st.cpu_cores, st.load_per_core) == (3.10, 2, 1.55)
    assert st.disk_percent == 97.0 and st.disks["/backup"] == 10.0
    assert st.oom_kills == 1 and "mysqld" in st.oom_last
    # ssh is not in the patterns; apache2 is disabled so inactive is fine; docker enabled but not loaded
    assert set(st.services) == {"nginx", "mysql", "php8.2-fpm", "apache2", "docker"}
    assert st.failed_services == ["docker", "mysql"]
    assert [p["name"] for p in st.pm2_problems] == ["api"]
    assert [c["name"] for c in st.docker_problems] == ["worker"]


def test_parse_tolerates_missing_sections():
    st = parse_stats("##MEM\ngarbage\n##END\n", ["nginx"])
    assert st.ok and st.ram_percent is None and st.services == {} and st.oom_kills == 0
