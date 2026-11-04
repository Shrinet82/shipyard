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

10. **Agent isolation (added after testing).** Asked to report file sizes, the Ops Agent could read the full-access Coolify token
    (103 bytes) and the cluster-admin kubeconfig (2,995 bytes): agents ran as the platform's own Linux user. They now run as a dedicated
    unprivileged user (`agentrun`: no sudo, no Docker, `/home/ubuntu`, `/root` and `/etc/shipyard` hidden by the service unit). The only
    credentials they hold are the Gatekeeper's request tool and the read-only, Secret-blind Kubernetes viewer. They hold no Coolify, GitHub
    or cluster-admin credential at all, so the read-only Coolify token is no longer needed for them.

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

## Results (Nov 4, 2026, live on the build VM, Mattermost with a test account per role)

| Check | Result |
|---|---|
| `status` for all three apps | Coolify and Kubernetes apps in one reply |
| `logs`, `events` on a Coolify app and a Kubernetes app | both work; secrets in logs are redacted and mentions defused |
| Viewer `restart demo-k8s` | Denied: needs role deployer or above |
| Deployer `restart`, `scale demo-k8s 3` | ran |
| `scale demo-k8s 9999`, `scale demo-k8s 1;rm` | Failed with nothing changed; Denied for the invalid value |
| `deploy demo-k8s`, `scale demo-web 2` | "not supported", with the right command suggested |
| Deployer `rollback demo-k8s`, then self-approval, then owner | approval needed; denied; ran. `rollback demo-k8s 1` changed the image from 1.28 to 1.27 |
| Maintainer, deployer or viewer: `shell prod df -h`, `exec demo-k8s id` | Denied: needs role owner or above |
| Owner: `shell prod cat /etc/shadow`, `df -h; id` | refused before anyone was asked |
| Owner: `shell prod df -h`, then approve | ran on the production VM; the disk table came back redacted |
| Owner: `exec demo-k8s env` | refused (not in the pod allowlist); `exec demo-k8s id` ran after approval |
| Real attempts per credential | viewer: logs yes, exec/Secret/scale no. Deployer: scale yes, exec/Secret no. Ops: exec yes, logs/Secret/scale no |
| Stolen SSH key for `shipyard-ops` | wrapper refused `cat /etc/shadow`, `../` paths, `;`, `bash`, `env`, `sudo`, no command; tty refused; stdio port forward "administratively prohibited"; every call logged on the VM |
| Agent MCP server (read-only, denied Secrets) | 13 tools, none able to change anything; pods listed; Secret refused |
| **Both MCP fences switched off, viewer credential only** | Secret read, object create and Deployment delete: all Forbidden by the API server. (Pod delete and exec returned "not found" for the made-up pod name, so they are covered by the direct `kubectl` tests above.) |
| Isolation | as `agentrun`: `/home/ubuntu/coolify.env`, `switch/.env`, `admin.kubeconfig` all "Permission denied"; `docker ps` refused; `sudo` asks for a password |
| Isolated agents' real work | the Ops Agent listed pods and was refused the Secret through its tools, read a status through the Gatekeeper, and diagnosed an alert |

## Findings

- `kubectl auth can-i` is unreliable for subresources (it said the ops credential could not exec while it could); real attempts are the test.
- The plain `rollback` goes to the previous *revision*, and `restart` creates a revision, so right after a restart "previous" is the same image.
  `rollback <app> <revision>` picks one.
- **Codex's command sandbox cannot start for the isolated user** (`bwrap: loopback: Failed RTM_NEWADDR`), even without the unit restrictions.
  So these agents have no working shell. That is the safe direction for agents whose job is MCP tools, and the OS blocks file reads anyway.
- Coolify's `get_logs` returns a JSON wrapper; an empty log is now shown as empty.
- Switch's built-in separate-user mode takes provider logins from its Console or API keys, so a ChatGPT sign-in is awkward there; a dedicated Linux user
  with a hardened service unit gave the same isolation with a one-time login.
- The Gatekeeper's `shell` and `exec` run no model-written text: owner, approval, allowlist, argument lists, a second allowlist on the host.

## Exit gate

- [x] The same chat commands work on a Coolify app and a Kubernetes app: `status`, `logs`, `events`, `restart`, `rollback` (with approval) and `scale` for Kubernetes.
- [x] A viewer cannot read Secrets even if the Gatekeeper is bypassed: shown with the viewer credential against the API and through the agents' MCP server with its own fences off.
- [x] `shell prod df -h` runs for the owner after approval; the attack cases above are refused.
- [x] `exec` in a pod runs for the owner after approval.
- [x] All attack cases pass as automated tests (417), and the live ones were run by hand.
- [x] Agents cannot read the platform's secrets: shown before (it could) and after (it cannot).

## Open

- Coolify container exec was left out on purpose (it needs root-equivalent Docker access).
- The Switch stack runs as root through Docker and the agents' MCP token sits in their own config: by design, the token only grants `request_action`.
