"""Chat command grammar. Deterministic: no language model in the trust path."""
from __future__ import annotations

import re
from dataclasses import dataclass

VERBS = {"status", "deploy", "restart", "rollback", "approve", "deny", "audit", "whoami", "help"}

# Leading mentions: "@gatekeeper", "<@123>", "<@&123>", optionally followed by , or :
_MENTION = re.compile(r"^\s*(?:(?:@[A-Za-z0-9._-]+|<@[&!]?\d+>)\s*[,:]?\s*)+")


@dataclass(frozen=True)
class Command:
    verb: str          # a VERBS member, or "unknown"
    args: tuple[str, ...]
    raw: str = ""


# verb -> (min args, max args)
ARITY = {
    "status": (0, 1), "deploy": (1, 1), "restart": (1, 1), "rollback": (1, 2),
    "approve": (1, 1), "deny": (1, 1), "audit": (0, 1), "whoami": (0, 0), "help": (0, 0),
}

USAGE = {
    "status": "`status [app]`", "deploy": "`deploy <app>`", "restart": "`restart <app>`",
    "rollback": "`rollback <app> [image-tag]`", "approve": "`approve <id>`", "deny": "`deny <id>`",
    "audit": "`audit [count]`", "whoami": "`whoami`", "help": "`help`",
}


def parse(body: str, addressed: bool) -> Command | None:
    """Return a command if the message is for the Gatekeeper, else None.

    A message is for the Gatekeeper only when it mentions it (`addressed`). Switch owns the
    `!` prefix for its own commands, so it is deliberately not used here.
    """
    text = (body or "").strip()
    if not addressed:
        return None
    rest = _MENTION.sub("", text, count=1)
    parts = rest.split()
    if not parts:
        return Command("help", (), text)
    verb = parts[0].lower()
    if verb not in VERBS:
        return Command("unknown", tuple(parts[:1]), text)
    return Command(verb, tuple(parts[1:]), text)


def arity_ok(cmd: Command) -> bool:
    lo, hi = ARITY[cmd.verb]
    return lo <= len(cmd.args) <= hi
