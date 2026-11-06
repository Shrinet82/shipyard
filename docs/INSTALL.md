# Installing Shipyard, in detail

This is the long version of the install. The README has the short one.


One command on a blank Ubuntu 24.04 machine (4 vCPU and 16 GB is comfortable; 4 GB is the minimum). Requirements: a user with `sudo` (a password is fine, it is asked once), `systemd`, and internet access. Tested on Ubuntu 24.04 on x86-64 only; other Linux systems and macOS are not tested, and nothing in the install path is tied to a particular username or cloud account.

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
| Your login | the bundled Mattermost starts with no ordinary user, so it offers to **make you one** and puts you in the project's rooms (the password is shown once) | pick a username, save the password |
| You | waits for you to type `@gatekeeper whoami` in any room, asks "is this you?", and makes you the owner | type one message |
| Discord (optional) | **checks the bot token, which privileged switches are on, finds the server the bot joined**, connects it to Switch, makes the rooms and adds you as owner there | create the bot at the Developer Portal, switch on two toggles, press the invite link |

Unattended: `python3 -m shipyard install --answers answers.yaml` asks nothing (see [`docs/answers.example.yaml`](answers.example.yaml)); `--dry-run` checks every credential and prints the config without writing a file.

The browser pages of the bundled Mattermost (8065), Switch Console (8000) and the Shipyard dashboard (8780) listen on the machine itself by default. At the owner step the installer offers to **make them reachable from your browser without a tunnel** (`python3 -m shipyard expose`; the default answer is yes on a cloud machine such as AWS, whose firewall blocks everything until you allow it, and no elsewhere). It listens on the machine's address for those three pages only (never the database) and then tells you to allow TCP 8065, 8000 and 8780 **for your own address only** in the cloud firewall, because the pages use plain HTTP. `python3 -m shipyard expose --off` takes it back. The tunnel always keeps working too: `ssh -L 8065:localhost:8065 -L 8780:localhost:8780 <the machine>`, then open `http://localhost:8065`.

Each connector also works on its own, after the install:

```bash
python3 -m shipyard github-app --repo owner/name        # the two-click GitHub App (--org for an organisation)
python3 -m shipyard connect kubernetes                  # pick a namespace; --dry-run shows what it would create
python3 -m shipyard connect signoz --url http://signoz:8080
python3 -m shipyard connect discord                     # bot token, switches, invite, bridge, rooms
python3 -m shipyard expose                              # browser pages without a tunnel (--off to undo, --only mattermost to choose)
python3 -m shipyard mattermost-user anya                # a login in the bundled Mattermost (password shown once)
python3 -m shipyard doctor                              # what is wrong, if anything
```

What each connector does, what it needs and how to remove it: [`docs/CONNECTORS.md`](CONNECTORS.md).

**Coolify** is installed on its own machine (the guided installer asks for its address and token, it does not install it): `curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash`. Create the root account **within 10 minutes**; if the page says the setup window is closed, run `docker restart coolify` on that machine and reload. In Settings enable **API access** and **MCP**, then create an API token with *read, read:sensitive, write and deploy*. After it finishes, in Coolify: Notifications → Webhook → the URL that `python3 -m shipyard webhook-url --host <this machine's private address>` prints.

**Getting the pieces** (each is a one-time job; the steps that worked are in [`docs/PHASE0-FINDINGS.md`](PHASE0-FINDINGS.md) and [`docs/PHASE2.md`](PHASE2.md)):

- *Switch*: run the server in Docker, enable `agent_management`, connect Discord or use the bundled Mattermost, and enroll a controller if you want the agents.
- *GitHub App by hand* (the installer does this for you, see above): webhooks **off**; repository permissions Contents (read and write), Pull requests (read and write), Actions (read), Checks (read), Commit statuses (read), Issues (read). Install it on the one repository.
- *CI*: [`docs/CI.md`](CI.md) explains which pipelines Shipyard reads and how to add one (`required_checks`, the SBOM workflow, and `@gatekeeper ci` to list what ran). Add the `sbom` job from [`shipyard-demo`'s workflow](https://github.com/Shrinet82/shipyard-demo/blob/main/.github/workflows/ci.yml) (Syft and Grype, actions pinned by commit). Mark `test` and `sbom` as required checks.
- *Kubernetes (optional)*: `python3 -m shipyard connect kubernetes` (see above). `scripts/install-k8s-demo.sh` is only for a throwaway k3d cluster with a demo workload.
- *Production shell (optional)*: lets `exec` run allowlisted diagnostics inside a Coolify container. On the machine that runs Shipyard, make a key: `ssh-keygen -t ed25519 -N '' -f ~/.ssh/shipyard-ops`. On the Coolify machine run `sudo bash deploy/ops-shell/install.sh "$(cat shipyard-ops.pub)" <Shipyard machine's private address>` (it adds the forced-command key, the root helper and a sudoers rule). Then in `shipyard.yaml` add `hosts: {prod: {ssh: shipyard-ops@<Coolify private address>, key_file: ~/.ssh/shipyard-ops}}` and, on the project, `exec_host: prod`. The allowlist is enforced three times (Gatekeeper, SSH wrapper, root helper).
- *First deploy and the SBOM gate*: the first release of an app has no baseline, so every critical vulnerability counts as new and the deploy is blocked. An owner overrides it once (`@gatekeeper approve <id>`); that release becomes the baseline, and later releases are compared with it. A maintainer cannot override.
- *Reboots*: `install-switch.sh` adds a `switch-stack` systemd unit (the compose file has no restart policy), `install-controller.sh` a `switch-agents` unit, and `init` enables lingering for the Gatekeeper's user service; after a reboot everything comes back by itself. Coolify's containers restart on their own.

**Discord**: the installer offers it as a step; later, `python3 -m shipyard connect discord`. See [`docs/CONNECTORS.md`](CONNECTORS.md). To let the room sync notice channels deleted in Discord, set `discord: {token_file: ~/discord.env}` in `shipyard.yaml` (the step does this).

**Adding a room later** (for example an incidents room): add its id under `rooms:` in `shipyard.yaml` (`incidents:` for alerts), restart the Gatekeeper, then press **Sync from roles** on the dashboard's *Agent access* page. Until you do, Switch tells the Gatekeeper it may not address the agents in the new room, so the Ops Agent never wakes there. With an incidents room, an alert goes to it and to the ops rooms; the Ops Agent is asked once, in the incidents room.

