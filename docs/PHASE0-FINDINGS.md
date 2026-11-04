# Phase 0 findings

Tested on 2026-11-04 against Switch server 0.31.0 (agent-protocol revision 9), standalone
Docker stack on `shipyard-build` (Mumbai). Probe: `spikes/probe_gatekeeper.py`.

## Answered

| # | Answer | Evidence |
|---|---|---|
| Q1 | **Yes.** A custom agent registers (`POST /agents`, registration token), opens `GET /agents/{id}/events` (SSE) and receives `connection_state`, `subscription_changed`, `room_join`, `message`. The WebSocket route `/agents/{id}/connection/ws` also exists (upgrade returned 101). The hosted docs call SSE deprecated, but 0.31.0 serves both. | Probe output |
| Q2 | **Yes, at two levels.** Each `message` carries `sender` = `@switch-mattermost-<bridge id>-<platform username>:localhost` and `sender_name`. The Gateway REST API lists a bridge's external users with `external_user_id`, `external_username` and `claimed_by`, so roles can key on the real platform id. The sender id is set by Switch from the platform account, never from message text. | Probe output; `core/switch_core/gateway/collaborations.py` |
| Q3 | **Yes, via `list_participants`**, which returns `type: agent \| user` per participant. `sender_kind` and `on_behalf_of` are also on the message. Switch's docs say to treat sender ids as opaque, so classify by participant type, not by parsing the id. | Probe output; `agent-protocol.md` |
| Q4 | **Partly.** Messages in a bridged channel reach the agent, whoever posted them. Whether a bot or webhook post is treated as a message from a participant is untested for Discord. `addressed` was `false` for an `@mention` from an unclaimed/non-owner account, and Switch itself replied "You're not permitted to direct messages to me". Switch's addressing policy therefore already enforces who may talk to an agent. | Probe output |
| Q8 | **A template is one YAML file** (`version`, `params`, `agent`, `room`, `kickoff`), with `provider` one of `claude`, `codex`, `opencode`. Shipyard ships its template in `templates/`. Antigravity is not a built-in provider. | `docs/TEMPLATES.md`, `examples/` |
| Q9 | **Yes.** `post_message` (after `invite_agent_to_room` and `connect_to_room`) posts into the room as the agent; Mattermost shows it as a bot post. | Probe output |

## Coolify (4.6.0)

| # | Answer | Evidence |
|---|---|---|
| Q5 | **No exec or shell tool.** The MCP server at `/mcp` lists 81 tools; the closest is `manage_scheduled_task`, which can run commands in containers, so the Gatekeeper must treat it as dangerous. Exec stays SSH via the Gatekeeper. | `tools/list` |
| Q6 | **Half answered.** About 48 tools carry `readOnlyHint`; the rest are marked destructive. The Ops Agent's read-only access is enforced client-side with an `enabled_tools` allow-list built from those hints (minus `get_env_values`). Whether a Read-only API token makes Coolify itself refuse writes is **untested**: the token used so far has Read, Write, Deploy and Read Sensitive. | `tools/list`; Codex `config.toml` |

Exit check passed on Mattermost: `@ops-agent status` returned the real state of the demo app
("demo-app: running") by calling Coolify's MCP.

### Wiring an MCP server into a Switch-managed Codex agent

- The controller copies the machine's `~/.codex/config.toml` into every Codex session, so MCP
  config set there applies to **all agents on that machine**. Per-agent tool sets need
  `install-service --separate-users` (each agent its own Linux user and home).
- `--env-file` on `install-service` did not put `COOLIFY_TOKEN` into the Codex process, so
  `bearer_token_env_var` fails silently and the tools just vanish. A literal
  `http_headers = { Authorization = "Bearer ..." }` in the 0600 config file works.
- A malformed `config.toml` also makes the agent report "no tools available" with no error.
  Test the file first with `codex exec --skip-git-repo-check ... </dev/null` (without
  `</dev/null` it waits on stdin), then restart the controller.
- Agent working directories must exist before the agent is created.

## Q7: where agents run (answered: headless controller works)

The headless `switch-agent-controller` works on the build VM with no desktop Console, and
agents can be created entirely through the Gateway API. Verified end to end: `@ops-agent` in a
Mattermost channel got a reply from Codex (provider `codex`, 0.166.0) running on the VM.

Steps that worked, in order:
1. Install Node 22, `@openai/codex` and the controller tarball for the pinned release.
2. Turn on agent management: `FEATURE_FLAGS_ENABLED=agent_management` and a 32+ char
   `CONTROLLER_TOKEN_SECRET` in the Switch `.env`, then recreate the `switch` container.
   Without it `/gateway/management/*` returns 404.
3. `POST /gateway/auth/login` as the admin, `POST /gateway/management/enrollment-codes`,
   then `switch-agent-controller enroll --server http://localhost:8000 --code <code>`.
4. `codex login --device-auth` on the VM (interactive, done by the user).
5. `switch-agent-controller install-service` (systemd user unit; `loginctl enable-linger`).
6. `POST /gateway/management/agents` with `{name, description, controller_id,
   desired_state, definition: {provider, instructions, directory, auto_mode, auto_approve}}`.
   **The `directory` must already exist on the machine** (`definition_invalid` otherwise), and
   the controller does not retry after that error: restart the service.
7. `POST /gateway/rooms` with `agent_names` and `user_names` creates the room and mirrors it
   into Mattermost.

Not yet used: `install-service --separate-users`, which runs each agent as its own Linux user
that sees only its own directory. Candidate for Phase 3 isolation.

## Design decisions these answers force

1. **Identity source:** roles in `shipyard.yaml` key on the Switch `sender` id, resolved to a platform user through the Gateway's external-user list. No need for a separate bot.
2. **Two layers of access control exist.** Switch's addressing policy decides who may talk to an agent; the Gatekeeper decides who may act through it. Both are needed.
3. **Agents inherit their owner's permissions** (`identity-and-access.md`). The Ops Agent must therefore be owned by a low-privilege Gateway user, and hold no write credentials. This is already the plan, and now has a concrete requirement.
4. **Addressing policy is set by the agent's owner or an admin** (`PUT /agents/{id}/addressing-policy` on the Gateway), not by the agent. The Phase 4 dashboard can do this through the Gateway API.

## Discord (verified)

- Connect with `POST /gateway/collaborations`, body `{bridge_type: "discord", display_name,
  connection_config: {bot_token, guild_id, agent_roles}}`. The server id can be read from the
  bot token (`GET /users/@me/guilds`). Both privileged intents (Server Members, Message
  Content) must be on, or the bot receives empty messages.
- A Discord channel becomes a Switch room only when someone posts in it **after** the
  connection is live. Agents are then added with `POST /gateway/rooms/{id}/agents`.
- Switch records the real numeric Discord user id as `external_user_id`
  (`GET /gateway/collaborations/{bridge}/users`), plus the username and who has claimed it.
  Claiming (`POST .../identities`) linked the Discord account to the Switch admin user
  without a confirmation code for this bridge.
- Exit check: `@ops-agent status` in `#ops-base` returned the real Coolify state of
  `demo-app`, on Discord, through Codex on the build VM and the read-only Coolify tools.

## Spend

About $0.34 after 1.4 hours (t3.xlarge $0.1792/h, t3.medium $0.0448/h, plus an estimate for
disks and public IPv4), against a $1.25 budget for 5 hours. Both VMs are still running.

## Open for Phase 1

- Q6 second half: create a Read-only Coolify token and check that Coolify itself refuses write
  tools. The Gatekeeper should hold a separate token with Deploy and Write but not
  Read Sensitive.
- The Ops Agent currently uses a full-access token, limited to read-only tools only by the
  Codex `enabled_tools` allow-list. Replace it with the read-only token.
- Both agents share one Codex config (`~/.codex/config.toml`) on the build VM. Per-agent
  tool sets need `install-service --separate-users`.
- A human-versus-agent check with two real agents (the participant `type` field is the plan).
