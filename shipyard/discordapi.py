"""A read-only look at a Discord server's channels.

Switch's bot already sits in the server. The Gatekeeper uses the same bot token for exactly one call, `GET /guilds/{id}/channels`, to learn which
channels exist, so the room sync can tell when a channel was deleted in Discord and can link to a channel that is already there instead of making
a second one with the same name. There is no method for writing: the class has no way to send anything but that GET.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any

API = "https://discord.com/api/v10"
TEXT_CHANNEL = 0
_ID = re.compile(r"^\d{5,25}$")


class DiscordError(Exception):
    """Discord refused or is unreachable; the message is safe to show (it never holds the token)."""


class Discord:
    def __init__(self, token: str, timeout: float = 10.0):
        if not token:
            raise DiscordError("no Discord bot token")
        self._token, self.timeout = token, timeout

    def channels(self, guild_id: str) -> list[dict[str, Any]]:
        """Every channel of the server the bot can see: id, name, type (0 is a text channel)."""
        if not _ID.match(str(guild_id)):
            raise DiscordError("that is not a Discord server id")
        req = urllib.request.Request(f"{API}/guilds/{guild_id}/channels", method="GET",
                                     headers={"Authorization": f"Bot {self._token}", "User-Agent": "DiscordBot (https://github.com/Shrinet82/shipyard, 1)"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                rows = json.loads(r.read())
        except urllib.error.HTTPError as exc:
            raise DiscordError(f"Discord answered {exc.code} for the server's channel list") from None
        except (urllib.error.URLError, OSError, ValueError):
            raise DiscordError("Discord is unreachable") from None
        return [{"id": str(c["id"]), "name": str(c.get("name", "")), "type": c.get("type")} for c in rows if isinstance(c, dict) and "id" in c]


def token_from(path: str) -> str:
    """The bot token out of an env file (DISCORD_BOT_TOKEN=...)."""
    try:
        for line in open(path):
            if line.startswith("DISCORD_BOT_TOKEN="):
                return line.strip().split("=", 1)[1].strip().strip("'\"")
    except OSError:
        pass
    return ""
