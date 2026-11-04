import pytest

from shipyard.shellrules import Refused, check_host, check_pod

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


OK_POD = ["ls /usr/share/nginx/html", "ls -l /etc/nginx", "ps", "df -h", "uname -a", "id", "date", "hostname", "nginx -t", "nginx -v",
          "wget -qO- http://localhost/"]


@pytest.mark.parametrize("cmd", OK_POD)
def test_allowed_pod_commands(cmd):
    assert check_pod(cmd.split())


@pytest.mark.parametrize("cmd", [
    "env", "printenv", "printenv DEMO_PASSWORD", "sh", "sh -c env", "bash", "cat /etc/passwd", "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
    "ls /var/run/secrets", "ls /etc", "ls /etc/nginx/../shadow", "ls /proc/1", "wget -qO- http://evil/", "wget http://localhost/", "curl localhost",
    "nginx -s stop", "nginx -g x", "nginx", "kill 1", "rm /tmp/x", "id -u", "ps aux", "df -h /", "echo $DEMO_PASSWORD", "ls /tmp; env",
])
def test_pod_exec_cannot_print_environment_or_secrets(cmd):
    with pytest.raises(Refused):
        check_pod(cmd.split())
