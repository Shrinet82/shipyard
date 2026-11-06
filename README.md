# Shipyard

**A chat room that ships software, and can't be talked into doing anything it shouldn't.**

Shipyard turns a Discord, Slack or Mattermost channel into an ops room for a small team. People ask for deploys, rollbacks, logs, pull-request status and merges in plain chat. Two AI agents (an Ops Agent and a Repo Agent) answer and diagnose. Every change goes through one small program, the **Gatekeeper**, which checks who is asking, asks a second person for approval when it matters, blocks deploys that bring in a new critical vulnerability, and writes an audit log nobody can quietly edit.

Built for the [Flip the Switch hackathon](https://www.wemakedevs.org/hackathons/switch) (WeMakeDevs × DevTools Academy × Switch), Track 2, also entered in Track 1.

![Shipyard architecture](docs/architecture.svg)

## What it looks like

Condensed from real runs; the merge exchange at the end is exactly what the Gatekeeper said.

```text
anya      @gatekeeper deploy demo-web
gatekeeper Done: deploy demo-web for anya. deployment queued.

coolify   ALERT: deployment failed for demo-web  (last 40 log lines, secrets removed)
ops-agent The build fails at line 4: requirements.txt is not in the image. Options: roll back, or fix the COPY.
rahul     @gatekeeper rollback demo-web
gatekeeper Approval needed (id 9a3d745b): rollback demo-web, requested by rahul. An owner can reply `@gatekeeper approve 9a3d745b`.
owner     @gatekeeper approve 9a3d745b
gatekeeper Done: rollback demo-web for rahul, approved by owner.

maintainer @gatekeeper merge 7
gatekeeper BLOCKED by the SBOM gate (id ab516adc): merge PR #7, requested by maintainer. 6 new critical CVEs:
           CVE-2019-14234 in pypi/django 2.2 … Only an owner can override: `@gatekeeper approve ab516adc`.
maintainer @gatekeeper approve ab516adc
gatekeeper Denied: only an owner can override a security block.
owner     @gatekeeper approve ab516adc
gatekeeper Done: merged PR #7 (squash, ded6a31), approved by owner. Deploy of demo-web queued.
```

The merge exchange ran on a build VM against a real repository and a real Grype scan. The audit log kept the block, the refused approval and the override, with the CVE ids.

## How Switch is used

[Switch](https://github.com/sandbox-quantum/switch) is the chat layer, and Shipyard leans on it for more than message transport:

| Switch feature | What Shipyard does with it |
|---|---|
| **Bridges and rooms** | One room group per project (ops and maintainers rooms), mirrored to Discord and Mattermost. Slack works through the same bridge mechanism but is untested here. |
| **Agent protocol** | The Gatekeeper is itself a *custom Switch agent*: it holds a stream open, sends heartbeats, reads messages and posts replies and alerts. Nothing else listens to your rooms. |
| **Templates** | The whole project is one Switch template, [`templates/shipyard.template.yaml`](templates/shipyard.template.yaml): the Ops and Repo agents, a room group with an ops, an incidents and a maintainers room, and the links between them. `shipyard init` runs it through Switch's template API; Switch Console can run the same file from its Templates page. |
| **Agent controller** | The Ops Agent and Repo Agent are Codex agents run by a Switch controller on your machine. The template creates them, or reuses the ones Switch already has. |
| **Sender identity** | Each message carries the sender's platform account (`@switch-discord-<bridge>-<name>:localhost`). Roles and approvals are tied to that, so "who said approve" is not something a message can claim. |
| **Addressing policy** | Switch itself refuses messages to an agent from people outside the project, and only in the project's rooms. The dashboard's *Agent access* page rebuilds that policy from the roles. |

## What it does

| Area | Commands (mention `@gatekeeper`) | Who |
|---|---|---|
| Read | `status`, `logs`, `events`, `prs`, `pr <n>`, `ci [pr|commit]`, `signals [rules|logs <svc>|errors <svc>]`, `digest`, `suggestions <pr>`, `sbom [pr\|commit\|release-tag\|app\|live]`, `audit [n]`, `whoami` | viewer and up |
| Change | `deploy`, `restart`, `rollback` (approval), `scale` (Kubernetes) | deployer and up |
| Diagnose | `exec <app> <command>`: one of about 50 read-only commands inside the app's Coolify container or Kubernetes pod (`ls`, `cat`, `tail`, `grep`, `ps`, `df`, `curl http://localhost:PORT/health`, a runtime's `--version`, ...). No shell, no writes, no deletes, no environment, no credential files. | maintainer and up |
| Dangerous | `merge <pr>`, `apply-suggestion <pr> <n\|all>` (a reviewer's suggested change, committed to the PR branch), `shell <host> <cmd>` (owner) | maintainer / owner, plus a second person's approval |
| Approve | `approve <id>`, `deny <id>` | owner, or another maintainer |
| Automatic | deploy-failure and crash **alerts** with real log evidence and a three-line diagnosis; **PR alerts** (opened, CI red or green, conflicts, stale); a **daily digest** per maintainer | |
| Board | tickets in the Gatekeeper's database, made and moved from chat through the Repo Agent (`@repo-agent track: ...`, `assign`, `move`, `my briefing`, `team status`), opened automatically from failed deploys, stopped or crashed apps, restart limits, high disk use and SBOM blocks, grouped into incidents (`@gatekeeper incident close INC-3: follow-up; follow-up` makes a follow-up ticket), linked to pull requests that say `Fixes SY-12`, delivered each morning to personal desk rooms (`@gatekeeper desks create`); see [`docs/BOARD.md`](docs/BOARD.md) | by role |
| Room sync | every chat app the project is used on gets the whole set of rooms (ops, maintainers, incidents, one desk per member): the dashboard's Switch rooms page previews what is missing and creates it through Switch on an owner's say-so (`@gatekeeper rooms`, `rooms sync`); alerts ask the Ops Agent once and copy its diagnosis to every app's alert rooms; with a read-only Discord bot token it also notices a room whose Discord channel was deleted (Switch does not) and makes it again, and links a channel that already exists instead of duplicating it | owner |
| Security | an **SBOM report** for every CI run, diffed against the last deployed release, posted in the maintainers and ops rooms with the deploy plan; critical CVEs **gate** the deploy; new copyleft or unknown **licences** are flagged (report only) | owner overrides |
| Dashboard | audit log, pending approvals, SBOM reports, backend health, roles and agent access | owner edits roles |

Commands are mentions, never a `!` prefix, because Switch uses `!` for its own commands.

## Install

One command on a blank Ubuntu 24.04 machine (4 vCPU and 16 GB is comfortable; 4 GB is the minimum):

```bash
curl -fsSL https://raw.githubusercontent.com/Shrinet82/shipyard/main/scripts/install.sh | bash
```

It installs Python and git, clones this repository to `~/shipyard`, and starts the **guided installer** (`python3 -m shipyard install`). It looks at what is really on the machine, does what a machine can do, and stops only for what a person has to do. Each stop says where to go and what to get, takes the value hidden, checks it at once and carries on. Run it again after any failure: it continues from where things stand.

| Step | What happens by itself | What you do |
|---|---|---|
| Check the machine | disk, memory, sudo | nothing |
| Where does Shipyard deploy? | | pick Coolify, Kubernetes, both, or neither |
| Switch and Mattermost | installs Docker, Switch 0.31.0 and Mattermost; Switch comes back after a reboot | nothing |
| The agents | installs Node, the Codex CLI and the controller, run as an unprivileged user | open one link and type the code Codex shows |
| Shipyard | lists your rooms to pick; registers the Gatekeeper; writes the config; starts it | the **Coolify token** (it names the page to create it and checks it at once) |
| GitHub | **creates the GitHub App from a manifest**: you press *Create GitHub App*, then *Install* on your repository. The keys are saved for you | two clicks |
| Connectors | **Kubernetes**: `connect kubernetes` lists your namespaces and deployments, creates least-privilege accounts and kubeconfigs, and proves each credential. **SigNoz**: `connect signoz` | pick a namespace; paste a read-only SigNoz key |
| You | waits for you to type `@gatekeeper whoami` in any room, asks "is this you?", and makes you the owner | type one message |

Unattended: `python3 -m shipyard install --answers answers.yaml` asks nothing (see [`docs/answers.example.yaml`](docs/answers.example.yaml)); `--dry-run` checks every credential and prints the config without writing a file.

Each connector also works on its own, after the install:

```bash
python3 -m shipyard github-app --repo owner/name        # the two-click GitHub App (--org for an organisation)
python3 -m shipyard connect kubernetes                  # pick a namespace; --dry-run shows what it would create
python3 -m shipyard connect signoz --url http://signoz:8080
python3 -m shipyard doctor                              # what is wrong, if anything
```

What each connector does, what it needs and how to remove it: [`docs/CONNECTORS.md`](docs/CONNECTORS.md).

**Coolify** is installed on its own machine (the guided installer asks for its address and token, it does not install it): `curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash`. Create the root account **within 10 minutes**; if the page says the setup window is closed, run `docker restart coolify` on that machine and reload. In Settings enable **API access** and **MCP**, then create an API token with *read, read:sensitive, write and deploy*. After it finishes, in Coolify: Notifications → Webhook → the URL that `python3 -m shipyard webhook-url --host <this machine's private address>` prints.

**Getting the pieces** (each is a one-time job; the steps that worked are in [`docs/PHASE0-FINDINGS.md`](docs/PHASE0-FINDINGS.md) and [`docs/PHASE2.md`](docs/PHASE2.md)):

- *Switch*: run the server in Docker, enable `agent_management`, connect Discord or use the bundled Mattermost, and enroll a controller if you want the agents.
- *GitHub App by hand* (the installer does this for you, see above): webhooks **off**; repository permissions Contents (read and write), Pull requests (read and write), Actions (read), Checks (read), Commit statuses (read), Issues (read). Install it on the one repository.
- *CI*: [`docs/CI.md`](docs/CI.md) explains which pipelines Shipyard reads and how to add one (`required_checks`, the SBOM workflow, and `@gatekeeper ci` to list what ran). Add the `sbom` job from [`shipyard-demo`'s workflow](https://github.com/Shrinet82/shipyard-demo/blob/main/.github/workflows/ci.yml) (Syft and Grype, actions pinned by commit). Mark `test` and `sbom` as required checks.
- *Kubernetes (optional)*: `python3 -m shipyard connect kubernetes` (see above). `scripts/install-k8s-demo.sh` is only for a throwaway k3d cluster with a demo workload.
- *Production shell (optional)*: lets `exec` run allowlisted diagnostics inside a Coolify container. On the machine that runs Shipyard, make a key: `ssh-keygen -t ed25519 -N '' -f ~/.ssh/shipyard-ops`. On the Coolify machine run `sudo bash deploy/ops-shell/install.sh "$(cat shipyard-ops.pub)" <Shipyard machine's private address>` (it adds the forced-command key, the root helper and a sudoers rule). Then in `shipyard.yaml` add `hosts: {prod: {ssh: shipyard-ops@<Coolify private address>, key_file: ~/.ssh/shipyard-ops}}` and, on the project, `exec_host: prod`. The allowlist is enforced three times (Gatekeeper, SSH wrapper, root helper).
- *First deploy and the SBOM gate*: the first release of an app has no baseline, so every critical vulnerability counts as new and the deploy is blocked. An owner overrides it once (`@gatekeeper approve <id>`); that release becomes the baseline, and later releases are compared with it. A maintainer cannot override.
- *Reboots*: `install-switch.sh` adds a `switch-stack` systemd unit (the compose file has no restart policy), `install-controller.sh` a `switch-agents` unit, and `init` enables lingering for the Gatekeeper's user service; after a reboot everything comes back by itself. Coolify's containers restart on their own.

**Discord**: in Switch Console (`ssh -L 8000:localhost:8000 <the Switch machine>`, then http://localhost:8000), add the Discord app with your bot token, then press **Sync rooms** on the Shipyard dashboard's *Switch rooms* page: it makes the missing rooms and desk rooms in Discord. To let it notice channels deleted in Discord (Switch does not), set `discord: {token_file: ~/discord.env}` in `shipyard.yaml` (a file with `DISCORD_BOT_TOKEN=`; read only).

**Adding a room later** (for example an incidents room): add its id under `rooms:` in `shipyard.yaml` (`incidents:` for alerts), restart the Gatekeeper, then press **Sync from roles** on the dashboard's *Agent access* page. Until you do, Switch tells the Gatekeeper it may not address the agents in the new room, so the Ops Agent never wakes there. With an incidents room, an alert goes to it and to the ops rooms; the Ops Agent is asked once, in the incidents room.

## The dashboard

It listens on `127.0.0.1:8780` only. Reach it through a tunnel:

```bash
scripts/vm.sh tunnel        # or: ssh -L 8780:localhost:8780 <machine>
```

Open `http://localhost:8780`, click **Get a sign-in code**, and type `@gatekeeper dashboard-login <code>` in a Shipyard room. Switch tells the Gatekeeper who sent it, so the session belongs to that person and their role. No password and no token is ever posted in chat. (`python3 -m shipyard dashboard-token` prints a token for whoever has a shell on the machine.)

It shows everything and can change two things, for owners only and both audited: **roles** and **agent access** (Switch's addressing policy, with a preview before anything is applied). It has no approve button on purpose.

## Security model

The agents are language models reading text from strangers (PR descriptions, logs, chat). The design assumes they can be fooled, and makes that harmless:

1. **Agents can't act.** They hold no credential for Coolify, GitHub, the cluster or Switch, and run as an unprivileged Linux user with the platform's secrets out of reach. Codex's account connectors (GitHub, Figma, ...) are switched off for them (`[features] apps = false`): a trial agent showed they would otherwise inherit whatever the Codex login had connected. They can only ask the Gatekeeper, citing the human message that asked. A proposal always waits for a human's approval, and an agent's own "approve" is ignored and logged.
2. **Identity comes from Switch**, not from the message text. A role is bound to the platform account that sent it.
3. **Approvals are single use**, bound to the exact action, target and arguments (and, for deploys and merges, the **commit**), expire in 10 minutes, and can't be given by the person who asked (except an owner, or the person an agent acted for).
4. **Chat text never reaches a shell.** Commands are parsed by a fixed grammar; backends are driven with argument lists; names, namespaces and replica counts are validated. Logs and command output are redacted, stripped of mentions and shown as data.
5. **The SBOM gate** blocks a forward deploy on a new critical CVE, a missing SBOM or an unverified one. Only an owner can override, pinned to the commit. Rollbacks are never gated. A pull request that edits `.github/workflows/` can't vouch for its own SBOM, so it is "unverified".
6. **Least privilege per backend**: three Kubernetes service accounts (the agents hold only the one that can't read Secrets), a GitHub App with merge pinned to the approved commit, an SSH key locked to one forced command.
7. **The audit log is hash-chained** in SQLite; an edited row breaks the chain and the dashboard says so.
8. **Fail closed**: if GitHub, Switch or the scan can't be reached, the answer is "no", never "assumed fine".

**Residual risks, stated plainly.** CI output is trusted: protect the default branch (required reviews, CODEOWNERS on `.github/`), because anyone who can change the workflow can change what the SBOM says. A deploy builds the branch as Coolify finds it, which can be newer than the commit judged; the approval is pinned and a moved head is refused just before it runs, but a small window remains. Anyone with a shell on the machine can open the dashboard and read the secret files.

The permission model is tested with attack cases (forged approvals, replays, agents approving, hostile package and log text, path tricks, bad zips, cross-origin requests): see `tests/`.

## Repository layout

| Path | What |
|---|---|
| `shipyard/policy.py`, `gatekeeper.py`, `audit.py` | roles, tiers, approvals, the hash-chained log |
| `shipyard/service.py`, `commands.py` | the chat commands and the gate |
| `shipyard/coolify.py`, `github.py`, `kube.py`, `hostshell.py` | backend adapters |
| `shipyard/sbom*.py` | SBOM parsing, trust checks, store and collector |
| `shipyard/dashboard.py`, `web/` | the dashboard (standard library and plain JavaScript, no build step) |
| `shipyard/init.py` | the installer and `doctor` |
| `templates/shipyard.template.yaml` | the Switch template: agents, rooms, links |
| `shipyard/suggestions.py` | reading and applying reviewers' suggested changes |
| `docs/` | the scope and results of each phase, pinned tools, the architecture image |

```bash
python3 -m pip install pyyaml pytest
python3 -m pytest        # 775 tests, no network
```

## Status

Built in five phases during the hackathon, then extended. Verified live on Mattermost: alerts, approvals, rollback, merge and deploy, Kubernetes, shell, the SBOM gate, the dashboard, `exec` in a pod, release names (`sbom demo-web`, `sbom live`), licence flags (read back through the dashboard API; the chat line is covered by tests), and applying a reviewer's suggestion (a commit by the GitHub App to the PR branch, crediting the reviewer). On Discord the commands, approvals, rollback and merge were verified. The installer was run on a clean Ubuntu VM (t3.large, then terminated): Switch's stack took about 6 minutes to pull and start, `scripts/install.sh` 25 seconds, and from `whoami` to the owner's first real command 16 seconds; that run found and fixed three bugs.

`exec` in a **Coolify container** runs through the forced-command wrapper and a root-owned helper (`deploy/ops-shell/`) that sudo allows for the `shipyard-ops` account only: verified live (`ls`, `ps`, `cat /etc/os-release` ran inside the demo container; `env`, `.env` files and shells were refused, and every call is logged to syslog).

The known gaps, with why each matters and what would close it, are in [`docs/GAPS.md`](docs/GAPS.md).

**Future scope:** a Slack run (Switch bridges Slack the same way, but it is untested here); more commands for `exec`, and an `exec` that is allowed to write (today nothing in the list changes anything); applying suggestions from a fork's pull request; per-release SBOM history on the dashboard.
