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

## Needs a Coolify admin account first (the user registers it)

| # | State |
|---|---|
| Q5 | Coolify's docs describe no exec endpoint. Unconfirmed until we can read the API reference on a running instance. Fallback is SSH via the Gatekeeper. |
| Q6 | Coolify's docs describe no read-only MCP mode. Read-only must come from the API token's permissions; test after the first token is created. If tokens can't be read-only, the Gatekeeper's own Coolify adapter does all reads. |

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

## Open

- Discord end to end (needs the user's bot token).
- Q5, Q6 (above).
- Q7 controller install and enrollment.
- A human-versus-agent check with two real agents.
