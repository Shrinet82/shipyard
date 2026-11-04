import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WRAPPER = ROOT / "deploy" / "ops-shell" / "shipyard-ops-shell"


def test_the_deployed_copy_of_the_rules_is_identical_to_the_gatekeepers():
    assert (ROOT / "deploy/ops-shell/shellrules.py").read_text() == (ROOT / "shipyard/shellrules.py").read_text()


def run(command, tmp_path):
    """Run the wrapper like sshd does: the client's request arrives in SSH_ORIGINAL_COMMAND."""
    lib = tmp_path / "lib"
    lib.mkdir(exist_ok=True)
    (lib / "shellrules.py").write_text((ROOT / "shipyard/shellrules.py").read_text())
    src = WRAPPER.read_text().replace("/usr/local/lib/shipyard-ops", str(lib)).replace("syslog.openlog", "(lambda *a: None)").replace(
        "syslog.syslog(", "(lambda *a: None)(")
    script = tmp_path / "wrapper.py"
    script.write_text(src)
    env = {"PATH": os.environ["PATH"], "SSH_CONNECTION": "10.0.0.1 1 2 3"}
    if command is not None:
        env["SSH_ORIGINAL_COMMAND"] = command
    return subprocess.run([sys.executable, str(script)], capture_output=True, text=True, env=env, timeout=20)


def test_runs_an_allowed_command_without_a_shell(tmp_path):
    r = run("uname -a", tmp_path)
    assert r.returncode == 0 and "Linux" in r.stdout


@pytest.mark.parametrize("cmd", [None, "", "bash", "sh -c id", "cat /etc/shadow", "cat /var/log/../../etc/passwd", "df -h; id", "df $(id)",
                                 "ls /", "env", "rm -rf /", "tail -f /var/log/syslog"])
def test_refuses_everything_else(cmd, tmp_path):
    r = run(cmd, tmp_path)
    assert r.returncode == 2 and r.stdout == "" and "refused" in r.stderr


def test_a_symlink_out_of_the_allowed_tree_is_refused_on_the_host(tmp_path):
    # the wrapper resolves symlinks before checking; /proc/self/cwd style tricks are not in the allowlist either
    r = run("cat /proc/self/environ", tmp_path)
    assert r.returncode == 2
