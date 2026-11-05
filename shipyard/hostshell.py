"""Run an allowlisted diagnostic on a host over SSH.

The key we connect with is locked on the host to one forced command (a wrapper that applies the same
allowlist, runs the command without a shell, as an unprivileged user, with a timeout and an output cap).
So the check here is the first of two; a stolen key never gets further than the second.
"""
from __future__ import annotations

import re
import subprocess
from typing import Callable, Sequence

from .shellrules import Refused, check_container, check_host


class ShellError(Exception):
    pass


Runner = Callable[[Sequence[str], float], "tuple[int, str, str]"]


def _runner(argv: Sequence[str], timeout: float) -> tuple[int, str, str]:
    try:
        p = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, shell=False)
    except subprocess.TimeoutExpired:
        raise ShellError(f"the command timed out after {int(timeout)} s") from None
    except OSError as exc:
        raise ShellError(f"could not start ssh: {exc}") from None
    return p.returncode, p.stdout, p.stderr


class HostShell:
    def __init__(self, hosts: dict[str, dict], timeout: float = 25.0, runner: Runner | None = None):
        self.hosts, self.timeout = hosts, timeout
        self._run = runner or _runner

    def run(self, host: str, argv: Sequence[str]) -> list[str]:
        try:
            argv = check_host(argv)
        except Refused as exc:
            raise ShellError(str(exc)) from None
        return self._ssh(host, " ".join(argv))

    def container_exec(self, host: str, app_uuid: str, argv: Sequence[str]) -> list[str]:
        """Run an allowlisted diagnostic inside a Coolify application's container, through the same forced-command key. The far side
        finds the container from the application's uuid, resolves symlinks inside it and applies the same rules again."""
        if not re.fullmatch(r"[a-z0-9]{20,32}", app_uuid):
            raise ShellError("that is not a Coolify application id")
        try:
            argv = check_container(argv)
        except Refused as exc:
            raise ShellError(str(exc)) from None
        return self._ssh(host, f"container-exec {app_uuid} " + " ".join(argv))

    def _ssh(self, host: str, remote: str) -> list[str]:
        cfg = self.hosts.get(host)
        if cfg is None:
            raise ShellError(f"unknown host {host!r}")
        cmd = ["ssh", "-i", cfg["key_file"], "-p", str(cfg.get("port", 22)), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
               "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new", cfg["ssh"], "--", remote]
        rc, out, err = self._run(cmd, self.timeout)
        if rc != 0:
            raise ShellError((err.strip().splitlines() or [f"the command exited with status {rc}"])[-1][:300])
        return out.splitlines()
