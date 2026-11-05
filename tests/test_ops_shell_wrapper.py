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


UUID = "z8cybq0yiyc71g2czyaa9eci"


@pytest.mark.parametrize("cmd", [f"container-exec {UUID}", "container-exec", "container-exec x ls /app", f"container-exec {UUID} env", f"container-exec {UUID} sh -c id",
                                 f"container-exec {UUID} cat /app/.env", f"container-exec {UUID} rm /app/x", f"container-exec {UUID} cat /etc/shadow",
                                 f"container-exec {UUID} ls /app; id", f"container-exec {UUID} ls $(id)", f"container-exec UPPERCASE ls /app"])
def test_container_exec_is_refused_before_sudo_is_ever_called(cmd, tmp_path):
    r = run(cmd, tmp_path)
    assert r.returncode == 2 and r.stdout == "" and "refused" in r.stderr


def test_a_valid_container_exec_goes_to_the_root_helper_as_an_argument_list(tmp_path):
    shim = tmp_path / "bin"
    shim.mkdir()
    (shim / "sudo").write_text("#!/bin/sh\necho \"sudo got: $@\"\n")
    (shim / "sudo").chmod(0o755)
    lib = tmp_path / "lib"
    lib.mkdir(exist_ok=True)
    (lib / "shellrules.py").write_text((ROOT / "shipyard/shellrules.py").read_text())
    src = WRAPPER.read_text().replace("/usr/local/lib/shipyard-ops", str(lib)).replace("syslog.openlog", "(lambda *a: None)").replace("syslog.syslog(", "(lambda *a: None)(")
    src = src.replace('"env={\"PATH\": \"/usr/bin:/bin\"', '"env={\"PATH\": \"/usr/bin:/bin\"')
    script = tmp_path / "w.py"
    script.write_text(src.replace('env={"PATH": "/usr/bin:/bin", "LANG": "C"})\n    except subprocess.TimeoutExpired:\n        print("refused: the command took too long"', f'env={{"PATH": "{shim}:/usr/bin:/bin", "LANG": "C"}})\n    except subprocess.TimeoutExpired:\n        print("refused: the command took too long"'))
    r = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=20,
                       env={"PATH": os.environ["PATH"], "SSH_CONNECTION": "10.0.0.1 1 2 3", "SSH_ORIGINAL_COMMAND": f"container-exec {UUID} tail -n 20 /var/log/app.log"})
    assert r.returncode == 0 and f"sudo got: -n /usr/local/sbin/shipyard-container-exec {UUID} tail -n 20 /var/log/app.log" in r.stdout


def test_the_root_helper_refuses_everyone_but_the_ops_account(tmp_path):
    helper = ROOT / "deploy/ops-shell/shipyard-container-exec"
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "shellrules.py").write_text((ROOT / "shipyard/shellrules.py").read_text())
    src = helper.read_text().replace("/usr/local/lib/shipyard-ops", str(lib)).replace("syslog.openlog", "(lambda *a: None)").replace("syslog.syslog(", "(lambda *a: None)(")
    script = tmp_path / "h.py"
    script.write_text(src)
    for sudo_user in ("", "ubuntu", "root"):
        r = subprocess.run([sys.executable, str(script), UUID, "ls", "/app"], capture_output=True, text=True, timeout=20,
                           env={"PATH": os.environ["PATH"], "SUDO_USER": sudo_user})
        assert r.returncode == 2 and "refused" in r.stderr
    r = subprocess.run([sys.executable, str(script), UUID, "env"], capture_output=True, text=True, timeout=20, env={"PATH": os.environ["PATH"], "SUDO_USER": "shipyard-ops"})
    assert r.returncode == 2 and "not allowed" in r.stderr
    r = subprocess.run([sys.executable, str(script), "BAD", "ls", "/app"], capture_output=True, text=True, timeout=20, env={"PATH": os.environ["PATH"], "SUDO_USER": "shipyard-ops"})
    assert r.returncode == 2 and "not a Coolify application id" in r.stderr
