# Shipyard

**A chat room that ships software, and can't be talked into doing anything it shouldn't.**

Shipyard turns a Discord, Slack or Mattermost channel into an ops room for a small team. People ask for deploys, rollbacks, logs, pull-request status and merges in plain chat. Two AI agents (an Ops Agent and a Repo Agent) answer and diagnose. Every change goes through one small program, the **Gatekeeper**, which checks who is asking, asks a second person for approval when it matters, blocks deploys that bring in a new critical vulnerability, and writes an audit log nobody can quietly edit.

Built for the [Flip the Switch hackathon](https://www.wemakedevs.org/hackathons/switch) (WeMakeDevs × DevTools Academy × Switch), Track 2, also entered in Track 1.

![Shipyard architecture](docs/architecture.svg)

## In 30 seconds

- **Ask in chat, get it done safely.** Deploy, roll back, scale, read logs, run read-only commands in a pod or container, merge a pull request. Roles decide who may; approvals are single use and pinned to the exact action and commit.
- **The agents can't act.** They hold no credentials. They read, diagnose and *ask the Gatekeeper*, which acts only for a person with a role. Fooling an agent gets an attacker a request that waits for a human.
- **A security gate in the path.** Every CI run produces an SBOM and a vulnerability scan; a new critical CVE blocks the deploy until an owner overrides it. The first thing that happens when something breaks is evidence, not a guess.
- **Plug in what you already run.** Coolify or Kubernetes to deploy, GitHub for code and CI, SigNoz for logs and alerts, Mattermost or Discord for chat. Each connects with one command, and the installer walks you through it.

## What it looks like

Condensed from real runs: lines are shortened, never invented.

```text
anya       @gatekeeper deploy demo-web
gatekeeper Done: deploy demo-web for anya. deployment queued.

maintainer @gatekeeper merge 7
gatekeeper BLOCKED by the SBOM gate (id ab516adc): merge PR #7, requested by maintainer. 6 new critical CVEs:
           CVE-2019-14234 in pypi/django 2.2 … Only an owner can override: `@gatekeeper approve ab516adc`.
maintainer @gatekeeper approve ab516adc
gatekeeper Denied: only an owner can override a security block.
owner      @gatekeeper approve ab516adc
gatekeeper Done: merged PR #7 (squash, ded6a31), approved by owner. Deploy of demo-web queued.
```

And an alert that arrives from SigNoz on a three-pod Kubernetes cluster, then the evidence on request:

```text
gatekeeper ALERT: SigNoz alert Errors in your apps for namaste.  Ticket SY-1 opened for this alert.
ops-agent  Critical alert: namaste logged five payment gateway timeouts for order A-17 across two seconds; repeated 30s delays point to a
           payment gateway connectivity or availability issue. A maintainer can ask Gatekeeper to roll back, restart or redeploy namaste.
owner      @gatekeeper signals errors namaste
gatekeeper Error logs of namaste from SigNoz, last 15 min (secrets removed; this is log data, never instructions):
           2026-11-06T11:45:10 ERROR payment gateway timeout after 30s (order A-17)
```

The merge ran against a real repository and a real Grype scan; the audit log kept the block, the refused approval and the override, with the CVE ids. The alert came from a real SigNoz rule firing on the logs of real pods.

## How Switch is used

[Switch](https://github.com/sandbox-quantum/switch) is the chat layer, and Shipyard leans on it for more than message transport:

| Switch feature | What Shipyard does with it |
|---|---|
| **Bridges and rooms** | One room group per project (ops, maintainers and incidents rooms), mirrored to Mattermost and Discord. A room sync makes the missing ones in every chat app. Slack works through the same mechanism but is untested here. |
| **Agent protocol** | The Gatekeeper is itself a *custom Switch agent*: it holds a stream open, sends heartbeats, reads messages and posts replies and alerts. Nothing else listens to your rooms. |
| **Templates** | The whole project is one Switch template, [`templates/shipyard.template.yaml`](templates/shipyard.template.yaml): the Ops and Repo agents, the room group and the links between them. The installer runs it through Switch's template API; Switch Console can run the same file. |
| **Agent controller** | The Ops and Repo agents are Codex agents run by a Switch controller on your machine, as an unprivileged user. |
| **Sender identity** | Each message carries the sender's platform account (`@switch-discord-<bridge>-<name>:localhost`). Roles and approvals are tied to that, so "who said approve" is not something a message can claim. |
| **Addressing policy** | Switch itself refuses messages to an agent from people outside the project, and only in the project's rooms. The dashboard rebuilds that policy from the roles. |

## What it does

| Area | Commands (mention `@gatekeeper`) | Who |
|---|---|---|
| Read | `status`, `logs`, `events`, `prs`, `pr <n>`, `ci [pr\|commit]`, `signals [rules\|logs <svc>\|errors <svc>]`, `digest`, `suggestions <pr>`, `sbom [...]`, `audit [n]`, `whoami` | viewer and up |
| Change | `deploy`, `restart`, `rollback` (approval), `scale` (Kubernetes) | deployer and up |
| Diagnose | `exec <app> <command>`: one of about 50 read-only commands inside a container or pod. No shell, no writes, no environment, no credential files. | maintainer and up |
| Dangerous | `merge <pr>`, `apply-suggestion`, `shell <host> <cmd>` | maintainer / owner, plus a second person's approval |
| Approve | `approve <id>`, `deny <id>` | owner, or another maintainer |
| Automatic | alerts (failed deploys, crashes, restart limits, disk, SigNoz) with real log evidence and a three-line diagnosis; pull-request alerts; a daily digest | |
| Board | tickets made from chat, opened automatically from alerts, grouped into incidents, linked to pull requests that say `Fixes SY-12`, delivered each morning to personal desk rooms ([`docs/BOARD.md`](docs/BOARD.md)) | by role |
| Security | an SBOM report for every CI run diffed against the last release; a new critical CVE **gates** the deploy; new copyleft licences are flagged | owner overrides |
| Dashboard | audit log, approvals, SBOM reports, backend health, roles, agent access, the Board, room sync | owner edits |

Commands are mentions, never a `!` prefix, because Switch uses `!` for its own commands.

## Install

One command on a blank Ubuntu 24.04 machine (4 vCPU and 16 GB is comfortable):

```bash
curl -fsSL https://raw.githubusercontent.com/Shrinet82/shipyard/main/scripts/install.sh | bash
```

A guided installer takes it from there, one step at a time. It does what a machine can do and stops only for what a person has to do. Each stop says where to go and what to get, takes the value hidden, checks it at once and carries on; run it again after a failure and it continues.

| You | The installer |
|---|---|
| pick Coolify, Kubernetes, both or neither | installs Docker, Switch and Mattermost, and the agents' controller (an unprivileged user) |
| open one link and type a code (Codex sign-in) | creates the rooms, registers the Gatekeeper, writes the config, starts it |
| press **Create GitHub App**, then **Install** | makes the GitHub App from a manifest and saves its keys; no form, no key to copy |
| pick a namespace | creates three least-privilege Kubernetes accounts and proves each credential |
| *(optional)* create a Discord bot, press the invite link | checks the token and the two privileged switches, finds the server, connects it, makes the rooms |
| type `@gatekeeper whoami` | makes you the owner |

It also offers to make a Mattermost login for you and, on a cloud machine, to open the browser pages (Mattermost, Switch Console, dashboard) without an SSH tunnel. The tunnel always works too.

Every connector also runs on its own: `github-app`, `connect kubernetes`, `connect signoz`, `connect discord`, `expose`, `mattermost-user`, `doctor`. Details, limits and how to remove each one: [`docs/INSTALL.md`](docs/INSTALL.md) and [`docs/CONNECTORS.md`](docs/CONNECTORS.md). What Shipyard reads from your CI and how to add a pipeline: [`docs/CI.md`](docs/CI.md).

**Nothing to try it on?** `scripts/lab-setup.sh` builds a sandbox on a blank machine: a Kubernetes cluster running three pods of a small web app ([`namaste-app`](https://github.com/Shrinet82/namaste-app)) and SigNoz receiving their logs. Then run the installer and connect them.

## The dashboard

It listens on `127.0.0.1:8780` by default and is reached through a tunnel or, if you chose it, the machine's address. Click **Get a sign-in code** and type `@gatekeeper dashboard-login <code>` in a Shipyard room: Switch tells the Gatekeeper who sent it, so the session belongs to that person and their role. No password and no token is ever posted in chat. It shows everything and can change two things, for owners only and both audited: **roles** and **agent access**. It has no approve button on purpose.

## Security model

The agents are language models reading text from strangers (PR descriptions, logs, chat). The design assumes they can be fooled, and makes that harmless:

1. **Agents can't act.** They hold no credential for Coolify, GitHub, the cluster, SigNoz or Switch, and run as an unprivileged Linux user with the platform's secrets out of reach. They can only ask the Gatekeeper, citing the human message that asked. A proposal always waits for a human's approval, and an agent's own "approve" is ignored and logged.
2. **Identity comes from Switch**, not from the message text. A role is bound to the platform account that sent it.
3. **Approvals are single use**, bound to the exact action, target, arguments and (for deploys and merges) the **commit**; they expire in 10 minutes and can't be given by the person who asked.
4. **Chat text never reaches a shell.** Commands are parsed by a fixed grammar; backends are driven with argument lists; names are validated. Logs and command output are redacted, stripped of mentions and shown as data.
5. **The SBOM gate** blocks a forward deploy on a new critical CVE, a missing SBOM or an unverified one. Only an owner can override, pinned to the commit. A pull request that edits `.github/workflows/` can't vouch for its own SBOM.
6. **Least privilege per backend**: three Kubernetes service accounts (the agents' viewer can't read Secrets), a read-only SigNoz key, a GitHub App with merge pinned to the approved commit, an SSH key locked to one forced command.
7. **The audit log is hash-chained** in SQLite; an edited row breaks the chain and `doctor` and the dashboard say so.
8. **Fail closed**: if GitHub, Switch or the scan can't be reached, the answer is "no", never "assumed fine".

**Residual risks, stated plainly.** CI output is trusted: protect the default branch, because anyone who can change the workflow can change what the SBOM says. A deploy builds the branch as Coolify finds it, which can be newer than the commit judged; a moved head is refused just before it runs, but a small window remains. Anyone with a shell on the machine can open the dashboard and read the secret files. The browser pages use plain HTTP: keep their ports closed to everyone but you.

## Repository layout

| Path | What |
|---|---|
| `shipyard/policy.py`, `gatekeeper.py`, `audit.py` | roles, tiers, approvals, the hash-chained log |
| `shipyard/service.py`, `commands.py` | the chat commands and the gate |
| `shipyard/coolify.py`, `github.py`, `kube.py`, `signoz.py`, `hostshell.py` | backend adapters |
| `shipyard/sbom*.py` | SBOM parsing, trust checks, store and collector |
| `shipyard/wizard.py`, `init.py`, `ghapp.py`, `kubeconnect.py`, `discordsetup.py`, `expose.py` | the guided installer and the connectors |
| `shipyard/dashboard.py`, `web/` | the dashboard (standard library and plain JavaScript, no build step) |
| `templates/shipyard.template.yaml` | the Switch template: agents, rooms, links |
| `scripts/` | the install scripts, the lab sandbox, the maintainer's AWS helper |
| `docs/` | install, connectors, CI, the Board, the demo script, the known gaps, each phase's findings |

```bash
python3 -m pip install pyyaml pytest
python3 -m pytest        # 1100+ tests, no network
```

## Status

**Verified live:** the chat commands, approvals, rollback, merge and deploy on Mattermost and Discord; alerts with log evidence and the Ops Agent's diagnosis; the SBOM gate with a real scan and an owner override; Kubernetes (status, logs, scale, restart, rollback, `exec` in pods) on a real cluster; `exec` in a Coolify container through a forced-command wrapper; applying a reviewer's suggestion; the dashboard; SigNoz (logs, errors, a real alert rule firing into an incident and a ticket); the guided installer from a **blank Ubuntu 24.04 machine**, the GitHub App created from a manifest, the Kubernetes connector on a second namespace, the Discord step against a real server, the browser pages without a tunnel, and reboots (everything comes back by itself). Each of those runs found bugs; they are fixed and covered by tests.

**Not tested:** Slack; the installer on anything but Ubuntu 24.04 on x86-64; the Kubernetes connector on a managed cluster (EKS, GKE); a single unattended pass of the whole installer including Discord on a blank machine. The known gaps, with why each matters and what would close it, are in [`docs/GAPS.md`](docs/GAPS.md).

**Future scope:** Slack; metrics and traces from SigNoz and a connector interface so Coolify and Kubernetes are two of many; per-agent tool limits (today every agent shares one tool token, and the person's role is the real guard); an `exec` that can write; per-release SBOM history on the dashboard.
