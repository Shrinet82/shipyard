# Security model

Shipyard is built on one assumption: **the agents can be fooled.** They are language models reading text written by strangers (pull-request descriptions, logs, chat). So the design makes a fooled agent harmless instead of trying to make it unfoolable.

## The rules

1. **Agents can't act.** They hold no credential for Coolify, GitHub, the cluster, SigNoz or Switch, and run as an unprivileged Linux user with the platform's secrets out of reach (`InaccessiblePaths` for the installing user's home, `/root` and `/etc/shipyard`). Codex's account connectors (GitHub, Figma, ...) are switched off for them (`[features] apps = false`): a trial agent showed they would otherwise inherit whatever the Codex login had connected. They can only ask the Gatekeeper, citing the human message that asked. A proposal always waits for a human's approval, and an agent's own "approve" is ignored and logged.
2. **Identity comes from Switch**, not from the message text. Each message carries the sender's platform account; a role is bound to that account. A viewer who asks an agent to act "on behalf of the owner" is refused and logged.
3. **Approvals are single use**, bound to the exact action, target, arguments and, for deploys and merges, the **commit**. They expire in 10 minutes and can't be given by the person who asked (except an owner, or the person an agent acted for). Deleting a ticket needs a second person.
4. **Chat text never reaches a shell.** Commands are parsed by a fixed grammar; backends are driven with argument lists; names, namespaces and replica counts are validated. Logs, SigNoz output and command output are redacted (keys, tokens, passwords, connection strings), stripped of mentions and code fences, and shown as data.
5. **The SBOM gate** blocks a forward deploy on a new critical CVE, a missing SBOM or an unverified one. Only an owner can override, pinned to the commit. Rollbacks are never gated. A pull request that edits `.github/workflows/` can't vouch for its own SBOM, so it is "unverified". The first release has no baseline, so every critical CVE counts as new until an owner overrides once.
6. **Least privilege per backend.**
   - Kubernetes: three service accounts in a `shipyard-system` namespace, bound only in your namespace: viewer (the built-in `view` role, which can't read Secrets), deployer (patch deployments and scale), ops (`pods/exec` only). The connector proves each credential with `kubectl auth can-i` before it finishes.
   - GitHub: an App with the permissions it needs; merge is pinned to the approved commit.
   - SigNoz: a Viewer key; the connector can only read.
   - Coolify containers: an SSH key locked to one forced command, enforced three times (Gatekeeper, wrapper, root helper).
   - `exec`: about 50 read-only commands, no shell, no writes, no environment, no credential files.
7. **The audit log is hash-chained** in SQLite; an edited row breaks the chain, and `doctor` and the dashboard say so. Every denial, approval, override and role change is a row.
8. **Fail closed.** If GitHub, Switch or the scan can't be reached, the answer is "no", never "assumed fine".
9. **The dashboard has no approve button**, listens on the machine only unless an owner chooses otherwise (`dashboard.allow_remote`, set only by `shipyard expose`), accepts only `localhost` and the one published address as its Host, refuses cross-origin writes, and uses a strict content-security policy with no inline scripts. Sessions come from a code typed in chat, so no password or token is ever posted.

## What is tested

The permission model is tested with attack cases: forged approvals, replays, an agent approving its own request, hostile package and log text, mention injection, path tricks, bad zips, cross-origin requests, a Host-header rebind, and tickets that tell the agent to ignore its rules. See `tests/` (1100+ tests, no network).

## Residual risks, stated plainly

- **CI output is trusted.** Protect the default branch (required reviews, CODEOWNERS on `.github/`): anyone who can change the workflow can change what the SBOM says.
- **A deploy builds the branch as Coolify finds it**, which can be newer than the commit judged. The approval is pinned and a moved head is refused just before it runs, but a small window remains.
- **Anyone with a shell on the machine** can open the dashboard and read the secret files.
- **The browser pages use plain HTTP.** If you open them to the network (`shipyard expose`), allow their ports from your own address only; on a machine without a cloud firewall prefer the SSH tunnel.
- **Every agent shares one tool token**; the agent name is self-reported. The person's role is the real guard, and per-agent limits are future work (see [GAPS.md](GAPS.md)).

The full list of gaps, with why each matters and what would close it: [GAPS.md](GAPS.md).
