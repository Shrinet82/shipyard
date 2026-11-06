"""Add Discord as a chat app: the bot token, the right switches, the invite, the server, and Switch's bridge to it.

What a person has to do is only what Discord makes them do: create the bot, switch on two toggles, press the invite link. Everything else is read
from Discord itself (the application id for the link, which toggles are on, which server the bot joined) and checked before moving on.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Callable

from .discordapi import Discord, DiscordError

# View Channels, Send Messages, Send Messages in Threads, Manage Webhooks, Manage Channels, Manage Roles, Read Message History, Attach Files, Add Reactions
PERMISSIONS = (1 << 10) | (1 << 11) | (1 << 38) | (1 << 29) | (1 << 4) | (1 << 28) | (1 << 16) | (1 << 15) | (1 << 6)
MESSAGE_CONTENT = (1 << 18) | (1 << 19)        # GATEWAY_MESSAGE_CONTENT, or its LIMITED form on a bot that is not verified
SERVER_MEMBERS = (1 << 14) | (1 << 15)         # GATEWAY_GUILD_MEMBERS, or LIMITED


class DiscordSetupError(Exception):
    pass


def invite_url(app_id: str) -> str:
    return f"https://discord.com/oauth2/authorize?client_id={app_id}&scope=bot%20applications.commands&permissions={PERMISSIONS}"


def missing_switches(flags: int) -> list[str]:
    out = []
    if not flags & MESSAGE_CONTENT:
        out.append("Message Content Intent")
    if not flags & SERVER_MEMBERS:
        out.append("Server Members Intent")
    return out


class DiscordSetup:
    def __init__(self, home: Path, gateway: Callable[[], Any], *, ask: Callable[[str, str], str], secret: Callable[[str], str], say: Callable[[str], None] = print,
                 discord: Callable[[str], Any] = Discord, sleep: Callable[[float], None] = time.sleep, now: Callable[[], float] = time.time,
                 wait: float = 600.0):
        self.home, self.gateway, self._ask, self._secret, self.say = home, gateway, ask, secret, say
        self.make, self.sleep, self.now, self.wait = discord, sleep, now, wait

    def token(self) -> tuple[str, Any, dict[str, Any]]:
        env = os.environ.get("DISCORD_BOT_TOKEN", "")
        for attempt in range(3):
            if not env:
                self.say("  Create the bot: https://discord.com/developers/applications → New Application → Bot → Reset Token, and copy the token.")
            token = env or self._secret("Discord bot token (input hidden): ").strip()
            env = ""
            try:
                client = self.make(token)
                return token, client, client.application()
            except DiscordError as exc:
                self.say(f"  {exc}. Check the token and try again." if attempt < 2 else f"  {exc}.")
        raise DiscordSetupError("Discord did not accept the bot token")

    def switches(self, client: Any, app: dict[str, Any]) -> None:
        for _ in range(4):
            missing = missing_switches(app["flags"])
            if not missing:
                return
            self.say(f"  In the Developer Portal → your application → Bot, switch ON: {', '.join(missing)}. Then save.")
            self._ask("  Press Enter when they are on", "")
            app = client.application()
        raise DiscordSetupError(f"{', '.join(missing_switches(app['flags']))} is still off; the bot would receive empty messages")

    def server(self, client: Any, app: dict[str, Any]) -> dict[str, str]:
        guilds = client.guilds()
        if not guilds:
            self.say(f"  Add the bot to your Discord server: {invite_url(app['id'])}")
            self.say("  I am waiting for it to join (Ctrl-C to stop)...")
            end = self.now() + self.wait
            while not guilds:
                if self.now() > end:
                    raise DiscordSetupError("the bot did not join a server in time; open the link above and run this again")
                self.sleep(3)
                guilds = client.guilds()
        if len(guilds) == 1:
            return guilds[0]
        for i, g in enumerate(guilds, 1):
            self.say(f"  {i}. {g['name']}")
        pick = self._ask("  Which server? (number)", "1").strip()
        return guilds[int(pick) - 1] if pick.isdigit() and 0 < int(pick) <= len(guilds) else guilds[0]

    def connect(self, token: str, guild: dict[str, str], display_name: str) -> str:
        gw = self.gateway()
        status, apps = gw.call("GET", "/collaborations")
        for a in apps if status == 200 and isinstance(apps, list) else []:
            if a.get("bridge_type") == "discord" and a.get("display_name") == display_name:
                return str(a.get("bridge_id") or a.get("id") or "")
        status, made = gw.call("POST", "/collaborations", {"bridge_type": "discord", "display_name": display_name,
                                                           "connection_config": {"bot_token": token, "guild_id": guild["id"], "agent_roles": True}})
        if status not in (200, 201) or not isinstance(made, dict):
            raise DiscordSetupError(f"Switch would not connect Discord ({status}): {str(made)[:160]}")
        return str(made.get("bridge_id") or made.get("id") or "")

    def run(self, display_name: str) -> dict[str, str]:
        token, client, app = self.token()
        self.say(f"  Discord accepted the bot ({app['name'] or app['id']}).")
        self.switches(client, app)
        guild = self.server(client, app)
        self.say(f"  The bot is in {guild['name']}.")
        path = self.home / "discord.env"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"DISCORD_BOT_TOKEN={token}\n")
        bridge = self.connect(token, guild, display_name)
        self.say(f"  Switch is connected to {guild['name']} (bridge {bridge[:8]}).")
        return {"guild_id": guild["id"], "guild_name": guild["name"], "bridge_id": bridge, "token_file": str(path)}
