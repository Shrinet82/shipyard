import pytest

from shipyard.shellrules import Refused, check_container, check_host

OK_HOST = [
    "df -h", "df -h /", "df -h -T /var/log", "free -m", "uptime", "uptime -p", "uname -a", "ps aux", "ps -ef", "ss -tln", "ip -br addr",
    "ip route", "ls -l /var/log", "ls -lah /var/log/nginx", "du -sh /var/log", "cat /etc/os-release", "cat /proc/meminfo /proc/loadavg",
    "tail -n 50 /var/log/syslog", "tail -20 /var/log/syslog", "head -n 5 /var/log/dmesg", "head /var/log/syslog", "du /var/log", "systemctl status docker",
    "systemctl is-active ssh.service", "systemctl list-units --failed", "hostname", "date", "id",
]


@pytest.mark.parametrize("cmd", OK_HOST)
def test_allowed_host_commands(cmd):
    assert check_host(cmd.split()) == tuple(cmd.split())


INJECTIONS = [
    "df -h; id", "df -h && id", "df -h || id", "df -h | cat", "df $(id)", "df `id`", "df -h > /tmp/x", "df -h < /etc/shadow",
    "cat /etc/os-release\nid", "ls \"/var/log\"", "ls '/var/log'", "df -h &", "echo hi", "cat ~/coolify.env", "ls *", "ls /var/log/*",
    "cat /var/log/a{b,c}", "cat /var/log/a b;c",
]


@pytest.mark.parametrize("cmd", INJECTIONS)
def test_shell_metacharacters_are_never_accepted(cmd):
    with pytest.raises(Refused):
        check_host(cmd.split(" ")) if "\n" not in cmd else check_host([cmd])


PATHS_AND_BINARIES = [
    "cat /var/log/../../etc/shadow", "ls /var/log/../etc", "cat /etc/shadow", "cat /etc/passwd", "cat /home/ubuntu/coolify.env", "ls /home",
    "ls /", "ls /root", "cat /proc/self/environ", "cat /proc/1/environ", "tail -f /var/log/syslog", "tail -n 9999 /var/log/syslog",
    "tail -n 0 /var/log/syslog", "cat", "cat -n /etc/os-release", "du -sh /home", "df -h /home",
    "rm -rf /", "sudo id", "bash -c id", "sh", "python3 -c 1", "curl http://x", "wget http://x", "nc -l 1", "env", "printenv", "docker ps",
    "kubectl get secrets", "ssh localhost", "scp a b", "chmod 777 /", "kill 1", "reboot", "shutdown now", "tee /etc/x", "dd if=/dev/zero",
    "systemctl restart docker", "systemctl stop ssh", "systemctl status a;b", "systemctl status", "systemctl daemon-reload",
    "ps aux e", "ps -o cmd", "ip addr add 1.2.3.4/24 dev lo", "ip link set lo down", "ss -p", "free -x", "uptime -s",
    "hostname newname", "date -s 2020-01-01", "uname -x", "ls /var/log /etc /home",
]


@pytest.mark.parametrize("cmd", PATHS_AND_BINARIES)
def test_dangerous_or_out_of_scope_commands_are_refused(cmd):
    with pytest.raises(Refused):
        check_host(cmd.split())


def test_empty_and_overlong():
    with pytest.raises(Refused):
        check_host([])
    with pytest.raises(Refused):
        check_host(["ls"] + ["/var/log"] * 20)


def test_a_symlink_out_of_the_allowed_tree_is_refused_on_the_host():
    links = {"/var/log/evil": "/etc/shadow", "/var/log/fine": "/var/log/syslog"}
    resolve = lambda p: links.get(p, p)
    assert check_host(["cat", "/var/log/fine"], resolve)
    with pytest.raises(Refused):
        check_host(["cat", "/var/log/evil"], resolve)
    with pytest.raises(Refused):
        check_host(["ls", "/var/log/evil"], resolve)


OK_CONTAINER = [
    "ls -la /app", "ls /var/log", "cat /app/main.py", "cat /etc/os-release", "head -n 20 /app/main.py", "head -20 /app/main.py", "tail -n 50 /var/log/app.log",
    "wc -l /app/main.py", "stat /app/main.py", "file /app/main.py", "du -sh /app", "df -h", "df -h /", "find /app -name main.py -maxdepth 2", "find /var/log -type f -mtime 1",
    "grep -in error /var/log/app.log", "grep -c Traceback /var/log/app.log", "sort -n /app/data.txt", "uniq -c /app/data.txt", "cut -d, -f1 /app/a.csv",
    "diff /app/a /app/b", "md5sum /app/main.py", "sha256sum /app/main.py", "readlink -f /app/current", "realpath /app/current",
    "ps", "ps aux", "ps -ef", "top -bn1", "free -m", "uptime", "uptime -p", "uname -a", "hostname", "date", "id", "whoami", "pwd", "nproc", "vmstat", "lscpu",
    "which python3", "ss -tln", "netstat -tln", "ip addr", "ip -br a", "getent hosts db", "nslookup db", "ping -c 2 db",
    "curl -s http://localhost:8080/health", "curl -sI http://127.0.0.1:8080/", "wget -qO- http://localhost:8080/", "wget -qO- http://localhost/",
    "python3 --version", "python --version", "pip list", "pip freeze", "pip --version", "node --version", "npm ls --depth=0", "java -version", "go version",
    "ruby --version", "php --version", "nginx -t", "nginx -v", "apk info", "apk list --installed", "dpkg -l",
]


def test_there_are_about_fifty_allowed_diagnostics():
    from shipyard.shellrules import CONTAINER_RULES
    assert 45 <= len(CONTAINER_RULES) <= 60 and not {"rm", "mv", "cp", "sh", "bash", "env", "printenv", "kill", "chmod", "tee", "dd", "sed", "awk"} & set(CONTAINER_RULES)


@pytest.mark.parametrize("cmd", OK_CONTAINER)
def test_allowed_container_commands(cmd):
    assert check_container(cmd.split())


@pytest.mark.parametrize("cmd", [
    # the environment and shells
    "env", "printenv", "printenv DEMO_PASSWORD", "sh", "sh -c env", "bash", "python3 -c x", "node -e x", "echo $DEMO_PASSWORD", "ls /app; env", "id && env",
    # credentials and secret-looking files, by name and by place
    "cat /var/run/secrets/kubernetes.io/serviceaccount/token", "cat /app/.env", "cat /app/.env.production", "cat /etc/shadow", "cat /root/.ssh/id_rsa",
    "cat /app/server.pem", "cat /app/private.key", "cat /app/api_token.txt", "cat /app/secrets.json", "cat /app/credentials", "cat /home/u/.aws/credentials",
    "cat /proc/1/environ", "ls /proc/1", "cat /run/secrets/db", "cat /etc/ssh/ssh_host_rsa_key", "cat /home/u/.netrc",
    # places outside the app
    "ls /root", "cat /root/x", "ls /", "ls /proc", "cat /sys/kernel/x", "cat /app/../etc/shadow", "cat /app//x", "cat relative/path", "cat ~/x",
    # writes, deletes, installs, kills
    "rm /app/x", "rm -rf /", "mv /app/a /app/b", "cp /app/a /tmp/b", "chmod 777 /app", "kill 1", "tee /tmp/x", "dd if=/dev/zero of=/tmp/x", "sed -i s/a/b/ /app/x",
    "find /app -delete", "find /app -exec rm {} ;", "find /app -name x -fprint /tmp/y", "pip install requests", "pip uninstall x", "apk add curl", "apt-get install x",
    "npm install x", "npm run x", "touch /tmp/x", "mkdir /tmp/x", "wget http://localhost/ -O /tmp/x", "curl -o /tmp/x http://localhost/", "curl -X POST http://localhost/",
    "curl -d x http://localhost/", "curl http://evil.example/", "curl -s http://169.254.169.254/latest/meta-data/", "wget -qO- http://evil.example/",
    # options that turn a reader into something else
    "tail -f /var/log/a", "tail -F /var/log/a", "head -n 99999 /app/a", "ls -R / ", "grep -r error /app", "grep password /app/a.log", "grep $(id) /app/a",
    "ping -c 9 db", "ping db", "ps -o cmd", "top", "nginx -s stop", "nginx -g x", "ip route add x", "ss -K", "ssh host", "nc -l 1", "docker ps", "kubectl get pods", "sudo id",
])
def test_container_exec_refuses_what_could_leak_or_change_things(cmd):
    with pytest.raises(Refused):
        check_container(cmd.split())


def test_etc_os_release_resolves_through_its_usual_symlink():
    assert check_container(["cat", "/etc/os-release"], lambda p: "/usr/lib/os-release")


def test_symlinks_inside_the_container_cannot_lead_to_a_refused_file():
    links = {"/app/current": "/app/releases/3", "/app/config": "/app/.env", "/tmp/x": "/etc/shadow", "/app/out": "/proc/1/environ", "/app/up": "/root/.ssh/id_rsa"}
    resolve = lambda p: links.get(p, p)                      # noqa: E731
    assert check_container(["cat", "/app/current"], resolve)
    for p in ("/app/config", "/tmp/x", "/app/out", "/app/up"):
        with pytest.raises(Refused):
            check_container(["cat", p], resolve)
    with pytest.raises(Refused, match="could not be resolved"):
        check_container(["cat", "/app/x"], lambda p: "")


def test_every_token_must_be_plain():
    for bad in (["ls", "/app/$(id)"], ["ls", "/app/a b"], ["ls", "/app/`id`"], ["ls", "/app/a;id"], ["ls", "/app/a|id"], ["ls", "/app/a>x"], ["ls", "/app/'x'"], [], ["ls"] * 13):
        with pytest.raises(Refused):
            check_container(bad)


def test_the_wrapper_copy_of_the_rules_is_the_same_file():
    from pathlib import Path
    root = Path(__file__).parent.parent
    assert (root / "shipyard/shellrules.py").read_text() == (root / "deploy/ops-shell/shellrules.py").read_text()
