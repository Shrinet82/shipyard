<p align="center"><img src="docs/img/banner.svg" alt="Shipyard: a chat room that ships software, and can't be talked into doing anything it shouldn't" width="100%"></p>

<p align="center">
<a href="#install-in-ten-minutes"><b>Install</b></a> ·
<a href="docs/SETUP-GUIDES.md"><b>Setup guides</b></a> ·
<a href="#see-it-working"><b>Screenshots</b></a> ·
<a href="#demo-video"><b>Demo video</b></a> ·
<a href="docs/SECURITY.md"><b>Security</b></a> ·
<a href="docs/INSTALL.md"><b>Full install guide</b></a>
</p>

Built for the [Flip the Switch hackathon](https://www.wemakedevs.org/hackathons/switch) (WeMakeDevs × DevTools Academy × Switch), Track 2, also entered in Track 1.

## What is Shipyard?

Small teams run their work in chat and their infrastructure in five other places: a deploy tool, a cluster, GitHub, a monitoring dashboard and a ticket tracker. Shipyard puts all of it in the chat room your team already uses (Discord, Mattermost, Slack), and puts **one small program in front of it** so that handing a chat room the keys is safe.

| | |
|---|---|
| **Run it** | Ask in plain words: deploy, roll back, scale, read logs, run a read-only command inside a pod, check a pull request, merge it. Two AI agents (an Ops Agent and a Repo Agent) answer questions and diagnose alerts with real log evidence. |
| **Plan it** | A project board lives in the same chat: tickets are made from a sentence, open themselves when a deploy fails or an alert fires, move when a pull request says `Fixes SY-12`, and come back to each person as a **morning briefing**, a daily **standup** and incident follow-ups. |
| **Trust it** | The agents hold no credentials and can only *ask*. Every change goes through the **Gatekeeper**: it checks who is asking, asks a second person for approval when it matters, blocks deploys that bring in a new critical vulnerability, and writes an audit log nobody can quietly edit. |

![How Shipyard fits together](docs/img/architecture.svg)

People talk in rooms; [Switch](https://github.com/sandbox-quantum/switch) carries the messages and says exactly who sent each one. The Gatekeeper (itself a Switch agent) is the only part that holds credentials for your stack. The agents sit in the rooms like colleagues, but all they can do is ask the Gatekeeper, which acts only for a person with a role.

## Your project board, inside the chat

Most tools make you leave the conversation to update a tracker. Shipyard's board is made of the conversation: nobody drags a card.

![The Board: tickets that open and close themselves](docs/img/board.svg)

- **Tickets from a sentence.** `@repo-agent track: Fix login redirect loop, high, assign to anya` creates `SY-7`, and `anya` is told.
- **Tickets from events.** A failed deploy, a crashed container, a restart loop, a full disk, a SigNoz alert or a new critical CVE opens a ticket on its own, with the evidence attached and the Ops Agent's diagnosis as its body. Repeats join the open one instead of piling up.
- **Tickets that follow the code.** A pull request that says `Fixes SY-7` links itself and moves the ticket to *review*; merging it and deploying that exact commit moves it to *done*.
- **Briefings.** `@repo-agent my briefing` gives each person their open tickets, what changed since the last time, their pull requests and the first step to take. A personal **desk room** gets it every morning, and the maintainers get a daily **standup**: who is stuck, what is stale.
- **Incidents.** Every alert opens an incident; closing it with `@gatekeeper incident close INC-3: add a restart alert; raise the memory limit` turns the follow-ups into tickets.
- **Same rules as everything else.** A viewer can't assign, a deployer moves their own tickets, a maintainer moves any, and a ticket that says "ignore your rules" is treated as text, never as an instruction.

```text
sy-owner   @repo-agent track: Fix login redirect loop, high, assign to sy-deployer
gatekeeper @sy-deployer SY-7 was assigned to you by sy-owner: Fix login redirect loop
gatekeeper PR #13 opened by Shrinet82: Fix login redirect loop. Fixes SY-7
gatekeeper SY-7 moved to review: PR #13 says it fixes it.
sy-viewer  @repo-agent briefing for sy-maint
repo-agent Briefings for someone else are for maintainers and owners.
```

More, including every permission: [`docs/BOARD.md`](docs/BOARD.md).

## Safe by design

The agents are language models reading text from strangers, so Shipyard assumes they can be fooled and makes that harmless: a fooled agent gets an attacker a *request that waits for a human*.

![From a chat message to a change](docs/img/approval-flow.svg)

- **Agents can't act.** No credentials for Coolify, GitHub, the cluster or SigNoz, and an unprivileged Linux user.
- **Identity comes from Switch**, never from the message text.
- **Approvals are single use**, pinned to the exact action and commit, and expire in 10 minutes.
- **A new critical CVE blocks the deploy**; only an owner can override.
- **The audit log is hash-chained**; an edited row breaks the chain.

The full model, what is tested and the risks that remain: [`docs/SECURITY.md`](docs/SECURITY.md).

## See it working

A real run: a four-person team on a three-pod Kubernetes cluster, with real pull requests, real CI and a real SigNoz. Nothing here is mocked up. The chat is Mattermost; the same commands work in Discord.

### Four roles, one rulebook

Anya is the owner, Rahul a maintainer, Meera a deployer and Dev a viewer. The Gatekeeper decides from the role, not from who sounds sure.

| Roles decide what you can do | Approvals need a second person |
|---|---|
| ![Dev's restart is denied, Meera scales, Meera's exec is denied, Rahul's exec runs](docs/img/screenshots/chat-roles-denials.png) | ![Rahul asks to merge, Rahul and Meera can't approve, Anya does, and the App merges](docs/img/screenshots/chat-approval-merge.png) |
| A viewer can't restart, a deployer can scale but not `exec`, a maintainer can `exec`. | The maintainer asks to merge. He and the deployer can't approve it. The owner does, and it merges. |

### A pull request, end to end

| The merge is done by the GitHub App | CI, SBOM and tickets, in the maintainers room |
|---|---|
| ![Pull request 1 merged by the shipyard GitHub App after approval](docs/img/screenshots/github-pr-merged-by-app.png) | ![CI passed, SY-2 done, SBOM reports for every pull request](docs/img/screenshots/chat-pr-events.png) |
| "Fixes SY-2" linked it; after the owner's approval the App merged it (3 checks passed). | The ticket closed itself when the pull request merged, and every pull request got an SBOM report. |

### The security gate

| Blocked in chat | Visible on the dashboard |
|---|---|
| ![SBOM for PR 3: 2 new critical CVEs, deploy blocked, owner override required](docs/img/screenshots/chat-sbom-blocked.png) | ![SBOM reports: pull request 3 is blocked with 2 critical CVEs](docs/img/screenshots/dashboard-sbom.png) |
| A pull request that adds a vulnerable dependency is blocked, with the CVE ids. | Every run is a row: counts, decision, whether it is deployed. |

### The board and the briefing

| Tickets that follow the code | A briefing for one person |
|---|---|
| ![Board with SY-4 to do, SY-1 an automatic alert, SY-3 in review, SY-2 done](docs/img/screenshots/dashboard-board.png) | ![Meera's briefing: her ticket, what changed, what is waiting on her](docs/img/screenshots/chat-briefing.png) |
| SY-2 is done because its pull request merged; SY-1 opened itself from an alert. | Meera's own desk room: her tickets, what changed since last time, the first step. |

### An alert from SigNoz

| The alert, the evidence and the diagnosis | The logs behind it |
|---|---|
| ![Incident INC-1 with evidence and the Ops Agent's three-line diagnosis](docs/img/screenshots/chat-alert-incident.png) | ![SigNoz logs of the namaste pods, errors in red](docs/img/screenshots/signoz-logs.png) |
| The rule fired, an incident and a ticket opened, and the Ops Agent diagnosed with the real log lines. | The pods ship their logs to SigNoz; the rule counts ERROR lines per service. |

### The dashboard

| Overview | Audit log | Roles |
|---|---|---|
| ![Overview](docs/img/screenshots/dashboard-overview.png) | ![Audit log, hash chain verified](docs/img/screenshots/dashboard-audit.png) | ![Roles](docs/img/screenshots/dashboard-roles.png) |

### Still to come

| Shipyard in a Discord server | The guided installer |
|---|---|
| ![Shipyard in a Discord server](docs/img/placeholders/discord.svg) | ![The guided installer](docs/img/placeholders/installer.svg) |

## Demo video

[![Demo video: an alert, an approval and the SBOM gate](docs/img/placeholders/demo-video.svg)](#demo-video)

## Install in ten minutes

You need a blank **Ubuntu 24.04** machine (4 vCPU and 16 GB is comfortable, 4 GB is the minimum) and a user with `sudo`. One command starts a guided installer:

```bash
curl -fsSL https://raw.githubusercontent.com/Shrinet82/shipyard/main/scripts/install.sh | bash
```

![The guided install](docs/img/install-flow.svg)

It does what a machine can do and stops only for what a person has to do. Each stop says where to go and what to get, checks the value at once, and carries on. Run it again after any failure and it continues. Have these ready, each with a step-by-step guide:

| You will need | For | How to get it |
|---|---|---|
| A ChatGPT account | the Ops and Repo agents (Codex) | [Sign in to Codex](docs/SETUP-GUIDES.md#sign-in-to-codex) |
| A GitHub account and a repository | pull requests, CI, merges | [Create the GitHub App (two clicks)](docs/SETUP-GUIDES.md#create-the-github-app-two-clicks) |
| A Discord bot token *(optional)* | Discord as a chat app | [Get a Discord bot token](docs/SETUP-GUIDES.md#get-a-discord-bot-token) |
| A Coolify API token *(if you deploy with Coolify)* | deploy, rollback, logs | [Create a Coolify API token](docs/SETUP-GUIDES.md#create-a-coolify-api-token) |
| `kubectl` pointing at your cluster *(optional)* | status, scale, rollback, exec | picked from a list by `connect kubernetes` |
| A SigNoz key *(optional)* | logs and alerts | [Create a SigNoz key](docs/SETUP-GUIDES.md#create-a-signoz-key) |

When it finishes, type `@gatekeeper whoami` in a room: the installer sees it and makes you the owner. To reach the browser pages (chat, Switch Console, dashboard) use an SSH tunnel or let `expose` open them for your address only: [Open the pages from your browser](docs/SETUP-GUIDES.md#open-the-pages-from-your-browser).

Every connector also runs on its own, any time:

```bash
python3 -m shipyard github-app --repo owner/name       # the two-click GitHub App
python3 -m shipyard connect kubernetes                 # pick a namespace; three scoped accounts, each proved
python3 -m shipyard connect signoz --bootstrap         # read-only logs and alerts (a new SigNoz needs no key)
python3 -m shipyard connect discord                    # bot token, switches, invite, bridge, rooms
python3 -m shipyard expose                             # browser pages without a tunnel (--off to undo)
python3 -m shipyard doctor                             # what is wrong, if anything
```

**This was the short version.** The whole installation guide, with every step, the unattended install and what each connector changes: [`docs/INSTALL.md`](docs/INSTALL.md) and [`docs/CONNECTORS.md`](docs/CONNECTORS.md). Nothing to try it on? `scripts/lab-setup.sh` builds a sandbox: a Kubernetes cluster running three pods of a small web app ([`namaste-app`](https://github.com/Shrinet82/namaste-app)) with SigNoz receiving their logs.

## How Switch is used

Switch is the chat layer, and Shipyard leans on it for more than message transport:

| Switch feature | What Shipyard does with it |
|---|---|
| **Bridges and rooms** | One room group per project (ops, maintainers and incidents rooms), mirrored to Mattermost and Discord. A room sync makes the missing ones in every chat app. Slack goes through the same mechanism. |
| **Agent protocol** | The Gatekeeper is itself a *custom Switch agent*: it holds a stream open, sends heartbeats, reads messages and posts replies and alerts. Nothing else listens to your rooms. |
| **Templates** | The whole project is one Switch template, [`templates/shipyard.template.yaml`](templates/shipyard.template.yaml): the agents, the room group and the links. The installer runs it through Switch's template API. |
| **Agent controller** | The Ops and Repo agents are Codex agents run by a Switch controller on your machine, as an unprivileged user. |
| **Sender identity** | Each message carries the sender's platform account (`@switch-discord-<bridge>-<name>:localhost`). Roles and approvals are tied to that. |
| **Addressing policy** | Switch itself refuses messages to an agent from people outside the project, and only in the project's rooms. The dashboard rebuilds that policy from the roles. |

## What you can ask

Commands are mentions (`@gatekeeper ...`), never a `!` prefix, because Switch uses `!` for its own commands.

| Area | Examples | Who |
|---|---|---|
| Read | `status`, `logs`, `events`, `prs`, `ci [pr]`, `signals [rules\|logs <svc>\|errors <svc>]`, `sbom`, `audit`, `whoami` | viewer and up |
| Change | `deploy`, `restart`, `rollback` (approval), `scale` | deployer and up |
| Diagnose | `exec <app> <command>`: one of about 50 read-only commands in a container or pod | maintainer and up |
| Dangerous | `merge <pr>`, `apply-suggestion`, `shell <host> <cmd>` | plus a second person's approval |
| Board | `@repo-agent track`, `assign`, `move`, `my briefing`, `team status`; `@gatekeeper incident close` | by role |
| Automatic | alerts with log evidence and a diagnosis, pull-request alerts, a daily digest, SBOM reports on every CI run | |

## Documentation

| | |
|---|---|
| [`docs/INSTALL.md`](docs/INSTALL.md) | the whole installation guide |
| [`docs/SETUP-GUIDES.md`](docs/SETUP-GUIDES.md) | Discord bot, GitHub App, Codex, Coolify, SigNoz, browser access |
| [`docs/CONNECTORS.md`](docs/CONNECTORS.md) | what each connector does and how to remove it |
| [`docs/SECURITY.md`](docs/SECURITY.md) | the security model in full |
| [`docs/BOARD.md`](docs/BOARD.md) | tickets, briefings, incidents, desk rooms |
| [`docs/CI.md`](docs/CI.md) | which pipelines Shipyard reads and how to add one |
| [`docs/DEMO.md`](docs/DEMO.md) | the demo script |
| [`docs/GAPS.md`](docs/GAPS.md) | the known gaps, and what would close each |

## Repository layout

| Path | What |
|---|---|
| `shipyard/policy.py`, `gatekeeper.py`, `audit.py` | roles, tiers, approvals, the hash-chained log |
| `shipyard/service.py`, `commands.py` | the chat commands and the gate |
| `shipyard/tickets.py`, `ticketflow.py`, `briefing.py`, `incidents.py`, `desks.py` | the Board |
| `shipyard/coolify.py`, `github.py`, `kube.py`, `signoz.py`, `hostshell.py` | backend adapters |
| `shipyard/sbom*.py` | SBOM parsing, trust checks, store and collector |
| `shipyard/wizard.py`, `init.py`, `ghapp.py`, `kubeconnect.py`, `discordsetup.py`, `expose.py` | the guided installer and the connectors |
| `shipyard/dashboard.py`, `web/` | the dashboard (standard library and plain JavaScript, no build step) |
| `templates/shipyard.template.yaml` | the Switch template: agents, rooms, links |
| `scripts/` | the install scripts and the lab sandbox |

```bash
python3 -m pip install pyyaml pytest
python3 -m pytest        # 1100+ tests, no network
```

## Status

**Verified live:** the chat commands, approvals, rollback, merge and deploy on Mattermost and Discord; alerts with log evidence and the Ops Agent's diagnosis; the SBOM gate with a real scan and an owner override; the Board end to end (tickets from chat, from alerts and from pull requests, briefings, standup, incidents, desk rooms); Kubernetes (status, logs, scale, restart, rollback, `exec` in pods) on a real cluster; `exec` in a Coolify container; applying a reviewer's suggestion; the dashboard; SigNoz (logs, errors, a real alert rule firing into an incident and a ticket); the guided installer from a **blank Ubuntu 24.04 machine**, the GitHub App from a manifest, the Discord step against a real server, the browser pages without a tunnel, and reboots. Each of those runs found bugs; they are fixed and covered by tests. The known gaps are in [`docs/GAPS.md`](docs/GAPS.md).

**Future scope:** Slack; metrics and traces from SigNoz, and a connector interface so Coolify and Kubernetes are two of many; per-agent tool limits (today every agent shares one tool token, and the person's role is the real guard); an `exec` that can write; per-release SBOM history on the dashboard.
