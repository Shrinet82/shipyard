# Phase 0 scope: Foundation

Phase 1 does not start until every box in the exit gate at the bottom is checked.
No AWS resource is created without the user approving its spec and 5-hour cost first.

## AWS (profile `new-account`)

Region and sizes are pending approval. Proposed, Mumbai (`ap-south-1`), Ubuntu 24.04:

| Resource | Spec | 5 h cost |
|---|---|---|
| `shipyard-build` | t3.xlarge (4 vCPU, 16 GB), 80 GB gp3, 4 GB swap | $0.90 + disk $0.05 |
| `shipyard-coolify` | t3.medium (2 vCPU, 4 GB), 40 GB gp3 | $0.22 + disk $0.02 |
| Public IPv4 x2 | auto-assigned, no Elastic IP | $0.05 |
| Key pair `shipyard-dev` | new ed25519 key, `~/.ssh/shipyard-dev` | free |
| Security group `shipyard-sg` | below | free |
| **Total** | | **about $1.25** |

Security group: SSH 22 and Coolify UI 8000 from the user's current IP only; all traffic
between the two VMs; nothing else open. Switch and Mattermost bind to 127.0.0.1 and are
reached through an SSH tunnel. Every resource is tagged `Project=shipyard`.

Parked cost (instances stopped): disks only, about $0.36/day. Public IPs change on each
start. Teardown (terminate everything) after judging.

## Work items

1. **AWS**: key pair, security group, two instances, swap on the build VM. (Claude, after approval)
2. **Build VM**: Docker, Switch server pinned to one version with the `collab` profile
   (Mattermost). Required env: `AGENT_REGISTRATION_TOKEN`, `SECRET_KEYS`, `GATEWAY_ADMIN_EMAIL`,
   `GATEWAY_ADMIN_PASSWORD`. (Claude)
3. **Coolify VM**: install Coolify, deploy a small demo app with a deliberately breakable build.
   Create an API token. (Claude; the user logs in once to set the admin account)
4. **Agents**: Ops Agent and Repo Agent from one template, Claude Code as provider, build VM
   onboarded as a remote host. Rooms `#demo-ops`, `#demo-maintainers`. (Claude; the user
   authenticates Claude Code on the VM)
5. **Chat**: Mattermost for local tests, Discord for the exit check. (the user creates the Discord
   server and bot application and shares the bot token; Claude wires it in)
6. **Ops Agent reads Coolify** through Coolify's read-only MCP.
7. **GitHub**: repo `shipyard` created and pushed. (Claude, with the user's `gh` login)

## Day-1 questions (each needs a written answer, with evidence, before Phase 1)

| # | Question | How we test it | Fallback if the answer is no |
|---|---|---|---|
| Q1 | Can a custom agent connect over WebSocket (`/agents/{id}/connection/ws`) and receive room messages? | Minimal client, post in a room, see the event | None; this is blocking |
| Q2 | Does a `message` event carry the platform user id (Discord/Mattermost id)? | Log raw events from a Discord and a Mattermost user | Gatekeeper gets identity from its own Discord/Slack bot |
| Q3 | Can the Gatekeeper tell human senders from agent senders? | Same raw events, one message from an agent | Same fallback as Q2 |
| Q4 | Do webhook-style (bot) posts in chat reach agents? | Post as a bot into the room | Gatekeeper receives webhooks directly (already the plan) |
| Q5 | Does Coolify expose an exec endpoint? | Check API docs and the MCP tool list | Exec over SSH on the ops VM |
| Q6 | Does the Coolify MCP offer read-only mode, and what can the token do? | Create a read-only token, list tools | Wrap reads in our own adapter |
| Q7 | Can Console on Linux, or a headless controller, run agents on the build VM? | Onboard the VM | Console on the user's laptop with the VM as remote host |
| Q8 | Is a Switch "template" a file we can ship, and what does it contain? | Read `examples/` and the docs | Ship a setup script instead |
| Q9 | Does `x-switch-connection-id` and `post_message` let the Gatekeeper reply in a room as itself? | Post from the client in Q1 | None; blocking |

## Exit gate

- [x] In Discord, `@ops-agent status` returns the real Coolify app status (Nov 4, 16:52 IST).
- [x] Q1 to Q9 answered in `docs/PHASE0-FINDINGS.md`, each with evidence. Q6 is half answered:
      the read-only token test is deferred to the start of Phase 1, when the Gatekeeper's
      own tokens are created.
- [x] Design decisions that depend on the answers are written down (identity source, how
      webhooks arrive, how exec works).
- [x] Repo on GitHub, build VM and Coolify VM reachable by SSH, a stop/start script for both.
- [x] Total spend so far recorded: about $0.34 after 1.4 hours (estimate, see findings).
