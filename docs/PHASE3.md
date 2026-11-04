# Phase 3 scope: Kubernetes and the ops VM shell

Phase 4 does not start until every box in the exit gate at the bottom is checked.

## Facts established (Nov 4, 2026)

| Question | Answer |
|---|---|
| Does the build VM have room for a cluster? | Yes: 9 GB of 15.8 GB RAM free, 66 GB disk free, load 0.1, Docker usable by the `ubuntu` user without sudo. `kubectl`, `k3d` and `helm` are not installed; Node 22 and `npx` are. Downloads from GitHub and `dl.k8s.io` work. |
| Versions to pin | k3d `v5.9.0`; kubectl from `dl.k8s.io` (stable is `v1.37.2`); `kubernetes-mcp-server` `0.1.2` (npm package, pinned, never `@latest`). |
| How is the Kubernetes MCP server configured? | By a TOML file, not flags: `read_only = true`, a `kubeconfig`, `denied_resources`, `toolsets`. Transport is stdio by default. Its own docs say "the Kubernetes API server remains authoritative", so the credential's RBAC is the real limit; the server's settings are a second fence. |
| Does Kubernetes already give us a safe read role? | Yes: the built-in `view` role reads pods, logs, deployments, events and ConfigMaps, and **excludes Secrets and `pods/exec`**. Bound to a ServiceAccount in one namespace it is exactly the viewer. |
| Which commands does rollback need? | `kubectl rollout undo` reads ReplicaSets and patches the Deployment: `get`/`list` on replicasets and `patch` on deployments, nothing cluster-wide. |
| Running the MCP server unpinned | Declined during scoping: an unpinned `npx ...@latest` is code from the internet. Everything below is pinned and checksummed. |

## Design decisions

1. **One namespace per project** (`demo`), one cluster (k3d on the build VM). The project config maps each app name to a backend, so the
   same chat commands work on Coolify and on Kubernetes; the Gatekeeper picks the adapter from the app, not from the command.
2. **Three credentials, three ServiceAccounts, least privilege each**, all restricted to the project namespace:

   | ServiceAccount | RBAC | Held by |
   |---|---|---|
   | `shipyard-viewer` | built-in `view` (no Secrets, no exec) | Gatekeeper reads and the **agents' MCP server** |
   | `shipyard-deployer` | `view` plus `patch` on deployments and `deployments/scale`, `get`/`list` on replicasets | the Gatekeeper only |
   | `shipyard-ops` | `get`/`list` pods plus `create` on `pods/exec` | the Gatekeeper only, for owner-approved exec |

   The agents hold **only the viewer**. "A viewer cannot read Secrets even if the Gatekeeper is bypassed" is then a property of the cluster,
   tested directly against the Kubernetes API, not of our code.
3. **The Gatekeeper drives `kubectl` with an argument list, never a shell string.** Names are validated, namespaces come from config
   (never from chat), replicas are capped, and the kubeconfig is chosen per action. No chat text reaches a shell.
4. **Shell on the production VM, defence in depth.** `shell prod <command>` is owner-only and needs approval. The Gatekeeper connects over
   SSH with a dedicated key that is **locked to one forced command**: a root-owned wrapper on the Coolify VM that allows only a fixed
   list of diagnostics (`df`, `free`, `uptime`, `ps`, `ss`, `ip`, `uname`, `du`, `ls`, `tail`, `head`, `cat`, `systemctl status`), only
   on allowed paths (`/var/log`, `/proc`, a few `/etc` files), as an unprivileged user with no sudo, no tty and no forwarding, with a
   timeout and an output cap. The allowlist is enforced on both ends, so a stolen key still yields only read-only diagnostics.
5. **Pod exec** (`exec <app> <command>`) is owner-only with approval, uses the `shipyard-ops` credential, a short allowlist
   (`ls`, `ps`, `df`, `uname`, `id`, `date`, `hostname`) and never `env`, `printenv` or reads of mounted secrets.
6. **Coolify container exec is a stretch and not planned.** It needs Docker access, which is root-equivalent on that VM. Only if time
   allows, and only through a root-owned wrapper that validates the container name and the command.
7. **Output is evidence, not instructions.** Logs, events and command output go through the Phase 2 redaction and mention-defusing before they
   reach chat or an agent.
8. **Agents cannot shell or exec.** `request_action` stays limited to Coolify actions and the two repo reads; Kubernetes reads reach agents
   through the read-only MCP server instead.
9. **Supply chain.** Binaries are pinned and verified against published checksums, and recorded in the repo. This is also the sort of
   thing Phase 4's SBOM report will show.

## Command surface (same words on both backends)

| Command | Coolify app | Kubernetes app | Role | Approval |
|---|---|---|---|---|
| `status [app]` | state | deployment ready/available, pods | viewer | no |
| `logs <app> [lines]` | container logs, redacted | pod logs, redacted | viewer | no |
| `events <app>` | recent deployments | Kubernetes events | viewer | no |
| `restart <app>` | restart | rollout restart | deployer | no |
| `rollback <app> [tag]` | previous image | rollout undo | deployer | yes |
| `scale <app> <n>` | not supported | scale, `n` capped at 10 | deployer | no |
| `deploy <app>` | deploy | not supported (use restart or rollback) | deployer | no |
| `shell prod <cmd...>` | | | owner | yes |
| `exec <app> <cmd...>` | stretch | pod exec | owner | yes |

## Work items

| # | Item | Done when |
|---|---|---|
| 1 | Install pinned `kubectl` and `k3d`, create the cluster, namespace `demo`, demo workload and a Secret | `kubectl get nodes` ready; memory checked |
| 2 | Three ServiceAccounts, RBAC and kubeconfigs (mode 0600) | `kubectl auth can-i` matrix as designed |
| 3 | Config: app backends, hosts, kubernetes block; commands `logs`, `events`, `scale`, `shell`, `exec` | `load_config` validates; tests |
| 4 | Kubernetes adapter (argument lists, name checks, caps) and backend routing | tests with a fake runner; live on k3d |
| 5 | Same commands on a Coolify app: `logs`, `events` | live |
| 6 | Kubernetes MCP server for agents (pinned, `read_only`, `denied_resources`, viewer kubeconfig) | the Ops Agent answers from the cluster; a write attempt is refused |
| 7 | Production VM shell: wrapper, restricted user, restricted key, Gatekeeper SSH call | live: allowed command runs, others refused on both ends |
| 8 | Pod exec | live with approval |
| 9 | Policy: `k8s.rollback` needs approval; shell and exec owner-only; tests | tests |
| 10 | Docs, plan doc, push | updated |

## Attack cases

- `scale demo-k8s 9999`, `scale demo-k8s -1`, `scale demo-k8s 1;rm -rf /`: refused (cap, number check, name check).
- An app name or namespace smuggled through chat: unknown apps are refused, and namespaces never come from chat.
- `shell prod cat /var/log/../../etc/shadow`, `shell prod cat ~/coolify.env`, `shell prod ls /home`: refused by the Gatekeeper and again by the wrapper.
- `shell prod df -h; id`, `shell prod df && curl x|sh`, `$(...)` and backticks: refused: no shell ever sees them.
- `exec demo-k8s env`, `exec demo-k8s cat /var/run/secrets/...`: refused.
- A deployer or maintainer asks for `shell` or `exec`: denied. An agent asks: unsupported.
- A viewer asks for Secrets through any path: the Kubernetes API says Forbidden (the agents' MCP credential cannot read them).
- The agents' MCP server asked to scale, delete or exec: refused by `read_only`, and would be refused by RBAC anyway.
- Stolen SSH key used for a different command or with a tty: the forced command ignores it.
- Cluster unreachable or a token revoked: the action fails and nothing is reported as done.

## Exit gate

- [ ] The same chat commands work on a Coolify app and a Kubernetes app: `status`, `logs`, `events`, `restart`, `rollback` (with approval) and `scale` for Kubernetes.
- [ ] A viewer cannot read Secrets even if the Gatekeeper is bypassed: shown with the viewer credential against the API and through the agents' MCP server.
- [ ] `shell prod df -h` runs for the owner after approval; the attack cases above are refused.
- [ ] `exec` in a pod runs for the owner after approval.
- [ ] All attack cases pass as automated tests, and the live ones are run once by hand.

## Cut order if time runs short

Pod exec first, then the Kubernetes write actions (`restart`, `rollback`, `scale`), then the production shell. The read path, the RBAC proof
and `logs`/`events` on both backends stay, because they carry the exit gate. Phase 5 is never cut.

## What the owner has to do

Nothing is blocking. Two small things carry over: the **Read-only Coolify token** for the Ops Agent (still open from Phase 2), and
approval to download and install the pinned tools above on the build VM.
