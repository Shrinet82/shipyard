"""Allowlists for the three places a person can run a command: the production VM, a pod and an app container.

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


# --- inside an app container or a pod ---------------------------------------------------
#
# About fifty read-only diagnostics, the kind an operator reaches for first: look at files and logs, see processes, memory, disk and
# sockets, resolve a name, hit the app's own health page, ask a runtime for its version. Nothing here writes, deletes, installs,
# starts a shell or prints the environment. Paths must sit under the app's usual directories, symlinks are resolved inside the
# container and checked again, and files that usually hold secrets are refused by name. What does get through is redacted before it
# reaches chat.

CONTAINER_ROOTS = ("/app", "/srv", "/opt", "/var/www", "/var/log", "/etc", "/tmp", "/home", "/workspace", "/code", "/usr/src",
                   "/usr/share", "/usr/local", "/data")
CONTAINER_FILES = frozenset({"/usr/lib/os-release", "/proc/loadavg", "/proc/meminfo", "/proc/cpuinfo", "/proc/uptime", "/proc/version", "/proc/stat",
                             "/proc/net/dev", "/proc/net/tcp", "/proc/net/tcp6"})
# A path is refused when any of these appears in it (lower-cased): files and folders that usually hold credentials.
SECRET_MARKERS = (".env", ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", "id_rsa", "id_ed25519", "id_ecdsa", "secret", "token",
                  "credential", "password", "shadow", ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".aws", ".ssh", ".docker",
                  ".kube", "kubeconfig", ".htpasswd", ".pgpass", ".my.cnf", "/run/secrets", "/var/run/secrets", "/etc/ssl/private",
                  "/etc/ssh", "serviceaccount", ".gnupg", ".vault", "private")
HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,60}[A-Za-z0-9])?$")
LOCAL_URL = re.compile(r"^https?://(localhost|127\.0\.0\.1)(:\d{1,5})?(/[A-Za-z0-9._~/%=+,:@-]*)?$")


def _cpath(p: str, resolve: Resolver | None) -> str:
    """An absolute path in an app container: under the usual roots, not a credentials file, and the same after symlinks."""
    if not p.startswith("/") or ".." in p.split("/") or "//" in p:
        raise Refused(f"path {p!r} is not allowed")

    def judge(path: str) -> None:
        low = path.lower()
        if any(m in low for m in SECRET_MARKERS):
            raise Refused(f"path {p!r} looks like it holds credentials, so it is not shown")
        if path in CONTAINER_FILES or any(path == r or path.startswith(r + "/") for r in CONTAINER_ROOTS):
            return
        raise Refused(f"path {p!r} is outside the app's folders ({', '.join(CONTAINER_ROOTS[:6])}, ...)")
    judge(p)
    if resolve is not None:
        real = resolve(p)
        if not real.startswith("/"):
            raise Refused(f"path {p!r} could not be resolved")
        judge(real)
    return p


def _shortflags(token: str, letters: str) -> bool:
    return len(token) > 1 and token[0] == "-" and token[1] != "-" and all(ch in letters for ch in token[1:])


def _spec(name: str, *, short: str = "", long: tuple[str, ...] = (), valued: dict[str, int] | None = None, paths: tuple[int, int] = (0, 0),
          text_args: tuple[int, int] = (0, 0)):
    """A rule from a description: allowed short flags (combinable) and long flags, flags that take a number (with a cap), how many
    path arguments, and how many other plain arguments (patterns, names)."""
    valued = valued or {}

    def rule(args, resolve):
        flags_seen, plain, i = 0, [], 0
        args = list(args)
        while i < len(args):
            t = args[i]
            if t in valued:
                if i + 1 >= len(args) or not args[i + 1].isdigit() or not 0 < int(args[i + 1]) <= valued[t]:
                    raise Refused(f"{name}: {t} needs a number up to {valued[t]}")
                i += 2
                continue
            if re.fullmatch(r"-\d{1,4}", t) and "-N" in valued and 0 < int(t[1:]) <= valued["-N"]:
                i += 1
                continue
            if t.startswith("-"):
                if t in long or _shortflags(t, short):
                    flags_seen += 1
                    i += 1
                    continue
                raise Refused(f"{name}: option {t!r} is not allowed")
            plain.append(t)
            i += 1
        path_args = [p for p in plain if p.startswith("/")]
        other = [p for p in plain if not p.startswith("/")]
        lo, hi = paths
        if not lo <= len(path_args) <= hi:
            raise Refused(f"{name}: give {lo if lo == hi else f'{lo} to {hi}'} path(s)")
        if not text_args[0] <= len(other) <= text_args[1]:
            raise Refused(f"{name}: unexpected arguments")
        for p in path_args:
            _cpath(p, resolve)
    return rule


_df_rule = _spec("df", short="hkTi", paths=(0, 1))


def _c_df(a, r):
    args = list(a)
    _df_rule(args[:-1] if args and args[-1] == "/" else args, r)          # `df -h /` is the usual question


def _c_find(a, r):
    args = list(a)
    if not args or not args[0].startswith("/"):
        raise Refused("find: start with a path")
    _cpath(args[0], r)
    i, ok = 1, {"-name", "-iname", "-type", "-maxdepth", "-mindepth", "-mtime", "-mmin", "-size", "-newer", "-user", "-perm"}
    while i < len(args):
        t = args[i]
        if t not in ok or i + 1 >= len(args):
            raise Refused(f"find: only {', '.join(sorted(ok))} are allowed (no -exec, -delete or -fprint)")
        if t == "-maxdepth" and not (args[i + 1].isdigit() and int(args[i + 1]) <= 6):
            raise Refused("find: -maxdepth up to 6")
        if t == "-newer":
            _cpath(args[i + 1], r)
        elif "/" in args[i + 1] and t in ("-name", "-iname"):
            raise Refused("find: a name pattern has no slashes")
        i += 2
    return None


def _c_grep(a, r):
    args = list(a)
    flags = [x for x in args if x.startswith("-")]
    rest = [x for x in args if not x.startswith("-")]
    bad = [f for f in flags if not _shortflags(f, "inclvEFwHhsq")]            # no -r: only the files named, each path-checked
    if bad or len(rest) < 2:
        raise Refused("grep: `grep [-inclvEFwHhsq] <pattern> <path> ...`")
    if not re.fullmatch(r"[A-Za-z0-9 ._:,=@%+-]{1,80}", rest[0]):
        raise Refused("grep: the pattern may hold letters, digits and . _ : , = @ % + -")
    if any(m in rest[0].lower() for m in SECRET_MARKERS):
        raise Refused("grep: not for searching out credentials")
    for p in rest[1:]:
        _cpath(p, r)


def _c_ps(a, r):
    if list(a) not in (["aux"], ["-ef"], ["-e"], ["auxf"], [], ["-o", "pid,ppid,etime,comm"], ["-o", "pid,rss,comm"]):
        raise Refused("ps: only `aux`, `-ef`, `-e` or `-o pid,ppid,etime,comm`")


def _c_ip(a, r):
    if list(a) not in (["addr"], ["a"], ["route"], ["link"], ["-br", "addr"], ["-br", "a"], ["-br", "link"]):
        raise Refused("ip: only addr, route and link views")


def _c_ss(a, r):
    _flags(a, {"-t", "-l", "-n", "-u", "-s", "-p", "-tln", "-ltn", "-tlnu", "-ltnu", "-lntu", "-tlnp", "-ltnp"}, "ss")


def _c_netstat(a, r):
    _flags(a, {"-t", "-l", "-n", "-tln", "-ltn", "-tlnp", "-an", "-rn"}, "netstat")


def _c_getent(a, r):
    if len(a) != 2 or a[0] not in ("hosts", "ahosts") or not HOSTNAME.match(a[1]):
        raise Refused("getent: only `getent hosts <name>`")


def _c_nslookup(a, r):
    if len(a) != 1 or not HOSTNAME.match(a[0]):
        raise Refused("nslookup: give one host name")


def _c_ping(a, r):
    args = list(a)
    if len(args) == 3 and args[0] == "-c" and args[1].isdigit() and 0 < int(args[1]) <= 3 and HOSTNAME.match(args[2]):
        return
    raise Refused("ping: only `ping -c N <host>` with N up to 3")


def _c_curl(a, r):
    args = list(a)
    allowed = {"-s", "-S", "-sS", "-I", "-i", "-sI", "-si", "-L", "-k"}
    urls = [x for x in args if not x.startswith("-")]
    flags = [x for x in args if x.startswith("-")]
    if any(f not in allowed for f in flags) or len(urls) != 1 or not LOCAL_URL.match(urls[0]):
        raise Refused("curl: only a GET of the app's own address, e.g. `curl -s http://localhost:8080/health`")


def _c_wget(a, r):
    args = list(a)
    if len(args) == 2 and args[0] in ("-qO-", "-qO", "-q") and LOCAL_URL.match(args[1]):
        return
    if len(args) == 3 and args[:2] == ["-q", "-O-"] and LOCAL_URL.match(args[2]):
        return
    raise Refused("wget: only `wget -qO- http://localhost:PORT/path`")


def _version(name: str, forms: tuple[tuple[str, ...], ...]):
    def rule(a, r):
        if tuple(a) not in forms:
            raise Refused(f"{name}: only " + " or ".join("`" + name + " " + " ".join(f) + "`" for f in forms))
    return rule


def _c_pip(a, r):
    if list(a) not in (["list"], ["freeze"], ["--version"], ["-V"], ["list", "--format=freeze"]):
        raise Refused("pip: only list, freeze and --version")


def _c_npm(a, r):
    if list(a) not in (["ls"], ["ls", "--depth=0"], ["list", "--depth=0"], ["--version"], ["-v"]):
        raise Refused("npm: only ls and --version")


def _c_apk(a, r):
    if list(a) not in (["info"], ["list", "--installed"], ["info", "-v"], ["--version"]):
        raise Refused("apk: only info and list --installed")


def _c_dpkg(a, r):
    if list(a) not in (["-l"], ["--list"], ["--version"]):
        raise Refused("dpkg: only -l")


def _c_nginx(a, r):
    if list(a) not in (["-t"], ["-v"], ["-T"]):
        raise Refused("nginx: only -t or -v")


def _c_which(a, r):
    if len(a) != 1 or not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", a[0]):
        raise Refused("which: give one command name")


def _c_top(a, r):
    if list(a) not in (["-bn1"], ["-b", "-n1"], ["-bn", "1"]):
        raise Refused("top: only `top -bn1`")


def _c_sortuniq(name: str):
    return _spec(name, short="nrufbc", paths=(1, 1))


def _c_cut(a, r):
    args = list(a)
    if len(args) == 3 and args[0].startswith("-d") and len(args[0]) == 3 and args[1].startswith("-f") and re.fullmatch(r"-f[0-9,-]{1,12}", args[1]) \
            and args[2].startswith("/"):
        _cpath(args[2], r)
        return
    raise Refused("cut: only `cut -d<char> -f<fields> <path>`")


CONTAINER_RULES = {
    # files and logs
    "ls": _spec("ls", short="lahRtrS1p", paths=(0, 3)), "cat": _spec("cat", short="n", paths=(1, 3)),
    "head": _spec("head", valued={"-n": MAX_LINES, "-N": MAX_LINES}, paths=(1, 1)), "tail": _spec("tail", valued={"-n": MAX_LINES, "-N": MAX_LINES}, paths=(1, 1)),
    "wc": _spec("wc", short="lwcm", paths=(1, 3)), "stat": _spec("stat", short="c", paths=(1, 3)), "file": _spec("file", short="b", paths=(1, 3)),
    "du": _spec("du", short="shak", paths=(1, 2)), "df": _c_df, "find": _c_find, "grep": _c_grep,
    "sort": _c_sortuniq("sort"), "uniq": _c_sortuniq("uniq"), "cut": _c_cut, "diff": _spec("diff", short="u", paths=(2, 2)),
    "md5sum": _spec("md5sum", paths=(1, 3)), "sha256sum": _spec("sha256sum", paths=(1, 3)),
    "readlink": _spec("readlink", short="f", paths=(1, 1)), "realpath": _spec("realpath", paths=(1, 1)),
    # the machine
    "ps": _c_ps, "top": _c_top, "free": _spec("free", short="mhgk"), "uptime": _spec("uptime", short="p"), "uname": _spec("uname", short="arnm"),
    "hostname": _spec("hostname"), "date": _spec("date", long=("-u",)), "id": _spec("id"), "whoami": _spec("whoami"), "pwd": _spec("pwd"),
    "nproc": _spec("nproc"), "vmstat": _spec("vmstat", short="s"), "lscpu": _spec("lscpu"), "which": _c_which,
    # the network, as the app sees it
    "ss": _c_ss, "netstat": _c_netstat, "ip": _c_ip, "getent": _c_getent, "nslookup": _c_nslookup, "ping": _c_ping,
    "curl": _c_curl, "wget": _c_wget,
    # what runs here
    "python3": _version("python3", (("--version",), ("-V",))), "python": _version("python", (("--version",), ("-V",))),
    "pip": _c_pip, "pip3": _c_pip, "node": _version("node", (("--version",), ("-v",))), "npm": _c_npm,
    "java": _version("java", (("-version",), ("--version",))), "go": _version("go", (("version",),)),
    "ruby": _version("ruby", (("--version",), ("-v",))), "php": _version("php", (("--version",), ("-v",))),
    "nginx": _c_nginx, "apk": _c_apk, "dpkg": _c_dpkg,
}


def check_container(argv: Sequence[str], resolve: Resolver | None = None) -> tuple[str, ...]:
    """Return argv if it is an allowed diagnostic inside an app container or a pod, else raise Refused.

    `resolve` maps a path to its real path inside that container (readlink -f there), so a symlink cannot lead to a refused file."""
    argv = _tokens(argv)
    rule = CONTAINER_RULES.get(argv[0])
    if rule is None:
        raise Refused(f"{argv[0]!r} is not allowed here (allowed: {', '.join(sorted(CONTAINER_RULES))})")
    rule(argv[1:], resolve)
    return argv


check_pod = check_container


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
