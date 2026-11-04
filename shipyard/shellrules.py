"""Allowlists for the two places a person can run a command: the production VM and a pod.

Self-contained (standard library only) on purpose. The same file is copied next to the forced-command
wrapper on the production VM, so the allowlist is enforced there as well as in the Gatekeeper: a stolen
SSH key still yields only these read-only diagnostics.

Every check works on an argument list. No shell ever sees a command, so `;`, `&&`, `|`, `$()`, quotes and
redirects are not "escaped", they are simply not accepted.
"""
from __future__ import annotations

import re
from typing import Callable, Sequence

SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._/=:,@%+-]{1,120}$")
MAX_TOKENS = 12
MAX_LINES = 500

ALLOWED_DIRS = ("/var/log",)
ALLOWED_FILES = frozenset({"/proc/loadavg", "/proc/meminfo", "/proc/cpuinfo", "/proc/uptime", "/proc/version",
                           "/etc/os-release", "/etc/hostname"})
UNIT = re.compile(r"^[A-Za-z0-9@._-]{1,80}$")

Resolver = Callable[[str], str]


class Refused(ValueError):
    """The command is not allowed; the message says why, in words safe to show in chat."""


def _path(p: str, resolve: Resolver | None, dirs_ok: bool = True) -> str:
    """An absolute path inside the allowed files and directories, after symlinks are resolved on the host."""
    if not p.startswith("/") or ".." in p.split("/"):
        raise Refused(f"path {p!r} is not allowed")
    real = resolve(p) if resolve else p
    in_dir = any(real == d or real.startswith(d + "/") for d in ALLOWED_DIRS)
    if real in ALLOWED_FILES or in_dir:
        return real
    raise Refused(f"path {p!r} is not allowed (diagnostics may read /var/log and a few /proc and /etc files)")


def _flags(args: Sequence[str], allowed: set[str], name: str) -> None:
    bad = [a for a in args if a not in allowed]
    if bad:
        raise Refused(f"{name}: option or argument {bad[0]!r} is not allowed")


def _split(args: Sequence[str]) -> tuple[list[str], list[str]]:
    flags = [a for a in args if a.startswith("-")]
    rest = [a for a in args if not a.startswith("-")]
    return flags, rest


# --- the production VM -------------------------------------------------------------

def _df(a, r):
    flags, rest = _split(a)
    _flags(flags, {"-h", "-k", "-m", "-T", "-i", "-H"}, "df")
    if len(rest) > 1:
        raise Refused("df: at most one path")
    for p in rest:
        if p != "/":
            _path(p, r)


def _free(a, r):
    _flags(a, {"-m", "-h", "-g", "-k"}, "free")


def _uptime(a, r):
    _flags(a, {"-p"}, "uptime")


def _uname(a, r):
    _flags(a, {"-a", "-r", "-n", "-m"}, "uname")


def _ps(a, r):
    if list(a) not in (["aux"], ["-ef"], ["-e"], ["auxf"], []):
        raise Refused("ps: only `aux`, `-ef` or `-e`")


def _ss(a, r):
    _flags(a, {"-t", "-l", "-n", "-u", "-s", "-tln", "-ltn", "-tlnu", "-ltnu", "-lntu"}, "ss")


def _ip(a, r):
    if list(a) not in (["addr"], ["a"], ["route"], ["link"], ["-br", "addr"], ["-br", "a"], ["-br", "link"]):
        raise Refused("ip: only addr, route and link views")


def _ls(a, r):
    flags, rest = _split(a)
    _flags(flags, {"-l", "-a", "-la", "-lh", "-lah", "-h"}, "ls")
    if not rest or len(rest) > 2:
        raise Refused("ls: give one or two paths")
    for p in rest:
        _path(p, r)


def _du(a, r):
    flags, rest = _split(a)
    _flags(flags, {"-s", "-h", "-sh"}, "du")
    if len(rest) != 1:
        raise Refused("du: give one path")
    _path(rest[0], r)


def _cat(a, r):
    if not 1 <= len(a) <= 3 or any(x.startswith("-") for x in a):
        raise Refused("cat: give one to three files, no options")
    for p in a:
        _path(p, r, dirs_ok=False)


def _lines(a, r, name):
    args = list(a)
    if len(args) == 3 and args[0] == "-n" and args[1].isdigit() and 0 < int(args[1]) <= MAX_LINES:
        args = args[2:]
    elif len(args) == 2 and re.fullmatch(r"-\d{1,3}", args[0]) and 0 < int(args[0][1:]) <= MAX_LINES:
        args = args[1:]
    if len(args) != 1 or args[0].startswith("-"):
        raise Refused(f"{name}: use `{name} [-n N] <file>` with N up to {MAX_LINES} (no -f)")
    _path(args[0], r, dirs_ok=False)


def _systemctl(a, r):
    args = list(a)
    if args == ["list-units", "--failed"]:
        return
    if len(args) == 2 and args[0] in ("status", "is-active") and UNIT.match(args[1]):
        return
    raise Refused("systemctl: only `status <unit>`, `is-active <unit>` and `list-units --failed`")


def _none(name):
    def rule(a, r):
        if a:
            raise Refused(f"{name}: takes no arguments")
    return rule


HOST_RULES = {
    "df": _df, "free": _free, "uptime": _uptime, "uname": _uname, "ps": _ps, "ss": _ss, "ip": _ip,
    "ls": _ls, "du": _du, "cat": _cat, "tail": lambda a, r: _lines(a, r, "tail"), "head": lambda a, r: _lines(a, r, "head"),
    "systemctl": _systemctl, "hostname": _none("hostname"), "date": _none("date"), "id": _none("id"),
}


def check_host(argv: Sequence[str], resolve: Resolver | None = None) -> tuple[str, ...]:
    """Return argv if it is an allowed diagnostic for the production VM, else raise Refused."""
    argv = _tokens(argv)
    rule = HOST_RULES.get(argv[0])
    if rule is None:
        raise Refused(f"{argv[0]!r} is not an allowed command (allowed: {', '.join(sorted(HOST_RULES))})")
    rule(argv[1:], resolve)
    return argv


# --- a pod ------------------------------------------------------------------------

POD_DIRS = ("/usr/share/nginx", "/etc/nginx", "/tmp")


def _pod_ls(a, r):
    flags, rest = _split(a)
    _flags(flags, {"-l", "-a", "-la", "-lh", "-lah", "-h"}, "ls")
    if not rest or len(rest) > 2:
        raise Refused("ls: give one or two paths")
    for p in rest:
        if not p.startswith("/") or ".." in p.split("/") or not any(p == d or p.startswith(d + "/") for d in POD_DIRS):
            raise Refused(f"path {p!r} is not allowed in a pod ({', '.join(POD_DIRS)})")


POD_RULES = {
    "ls": _pod_ls,
    "ps": lambda a, r: _flags(a, set(), "ps"),
    "df": lambda a, r: _flags(a, {"-h"}, "df"),
    "uname": lambda a, r: _flags(a, {"-a", "-r"}, "uname"),
    "id": _none("id"), "date": _none("date"), "hostname": _none("hostname"),
    "nginx": lambda a, r: _flags(a, {"-t", "-v"}, "nginx") if len(a) == 1 else (_ for _ in ()).throw(Refused("nginx: only -t or -v")),
    "wget": lambda a, r: None if list(a) == ["-qO-", "http://localhost/"] else (_ for _ in ()).throw(Refused("wget: only the pod's own page")),
}


def check_pod(argv: Sequence[str]) -> tuple[str, ...]:
    """Return argv if it is allowed inside a pod. Never env, printenv, cat or a shell: those could print secrets."""
    argv = _tokens(argv)
    rule = POD_RULES.get(argv[0])
    if rule is None:
        raise Refused(f"{argv[0]!r} is not allowed in a pod (allowed: {', '.join(sorted(POD_RULES))})")
    rule(argv[1:], None)
    return argv


def _tokens(argv: Sequence[str]) -> tuple[str, ...]:
    argv = tuple(argv)
    if not argv:
        raise Refused("no command given")
    if len(argv) > MAX_TOKENS:
        raise Refused(f"too many arguments (at most {MAX_TOKENS})")
    for t in argv:
        if not SAFE_TOKEN.match(t):
            raise Refused("the command contains characters that are not allowed (no quotes, pipes, ; & $ ` or redirects)")
    return argv
