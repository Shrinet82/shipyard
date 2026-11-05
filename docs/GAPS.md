# Known gaps report

As of Nov 5, 2026, after the Switch template, exec, suggestions, licence and incidents-room work. Each entry says what the gap is,
why it matters, what would close it, and a rough effort. "Verified live" means it ran on the build VM; "tested" means only the
automated tests (779, no network) cover it.

## 1. Security and trust

| # | Gap | Why it matters | Fix | Effort |
|---|---|---|---|---|
| S1 | **Agents hold Switch's own tools.** A trial agent listed 247 Switch tools, including create, delete, post and run-template verbs. Switch limits them by the agent owner's permissions (an agent can only manage agents if its owner enables "can manage agents", which is off by default), but we have not tested what an agent can actually do with them. | The README's "agents hold no credential" is true for Coolify, GitHub and the cluster. It is not a statement about Switch's own tools, and the wording should say so. | Test a probe agent against the Switch tools (can it create a room, post as someone else, run a template?), then either rely on Switch's permissions and say so, or restrict the tool set. | 1-2 h |
| S2 | **Codex account connectors were enabled** for the agents (GitHub, Figma and others, inherited from the Codex login). Now switched off with `[features] apps = false`; `init` writes it. We saw tool names disappear but did not test whether the GitHub connector was actually usable before. | If the login had GitHub connected, an agent could have acted on GitHub outside the Gatekeeper. | Fixed. Optional: ask the Codex account owner whether any connector is linked, and unlink it at the source. | 10 min |
| S3 | **CI output is trusted.** The SBOM comes from the repository's own workflow. A change to the workflow is marked "unverified", but anyone who can push to the default branch can change what the SBOM says. | The gate is only as strong as the default branch's protection. | Branch protection and CODEOWNERS on `.github/` (documented). Signed attestations are future scope. | out of scope |
| S4 | **A deploy builds the branch as Coolify finds it**, which can be newer than the commit judged. The approval is pinned and a moved head is refused just before the deploy, but a window remains. | A commit pushed between the check and Coolify's clone is not judged. | Deploy a specific commit through Coolify if its API allows it. | 2 h, unknown if possible |
| S5 | **`exec` filters credential files by name and redacts output**, but it cannot know what is inside a file called `config.json`. | A secret stored in an ordinary-looking file could reach chat. | The allowlist is narrow by design; output redaction catches common token shapes. Per-app path allow lists would tighten it. | 1 h |
| S6 | **Anyone with a shell on the VM can open the dashboard** and read the secret files. | The dashboard and secrets sit on the same machine. | Accepted; documented in the README. | n/a |
| S7 | **`add-owner` is not audited**, because a second process writing the audit chain could fork it. | The first owner of a new install leaves no audit row. | Have the running Gatekeeper accept the first owner over a local socket. | 1-2 h |

## 2. Built and tested, not yet seen live

| # | Item | What was seen |
|---|---|---|
| L1 | The licence line in a **chat reply** | Flags were read back through the dashboard API (19 on the live main report). The chat line is covered by tests. |
| L2 | **Deploy plan posted in the ops room** when a merge is asked in the maintainers room | Tests only. |
| L3 | `sbom <git tag>` | Tests only. `sbom demo-web` and `sbom live` ran live. |
| L4 | **An agent proposing `exec`** | Tests only. The agents' MCP tool description was updated, but the **Ops Agent's instructions in Switch still do not mention `exec`**, so it will not know to use it. |
| L5 | The **Switch rooms page in a browser** | The API ran live. The page was never opened against the live data. |
| L6 | **Room links** from the Switch template | Switch accepted the template with its links. Switch has no endpoint to read them back, so nobody has seen them. |
| L7 | **Template-created agents inside `shipyard init`** | A template creating an agent ran live (a throwaway probe agent). `init` with agent creation has not run on a clean machine; the clean-VM run reused rooms only. |

## 3. Discord

Verified on Discord: commands, approvals, rollback and merge. **Not run on Discord:** the SBOM gate and override, `exec`, apply-suggestion, licence flags,
the incidents room (it exists only on Mattermost; Switch's Discord bridge can create channels), and the dashboard sign-in. Slack was never run; it is
listed as future scope.

## 4. Product gaps

| # | Gap | Notes |
|---|---|---|
| P1 | **A new room needs "Sync from roles"** on the dashboard, or Switch refuses the Gatekeeper's mention of the agents there (found when the incidents room was added). | Documented in the README. `init` creates rooms for new installs but does not run the sync for agents that already exist. A doctor check could warn. |
| P2 | **No LICENSE file** in the repository. | The hackathon may expect one. This is your decision. |
| P3 | **Coolify token** is full access (needed by the Gatekeeper for deploy, rollback and logs). The agents hold none. | Low priority. |
| P4 | **SBOM history** is stored per commit but the dashboard lists them flat, with no per-release timeline. | Future scope. |
| P5 | **`exec` has no write commands** by design. | Future scope if wanted. |
| P7 | **Nothing from the Board has been run on Discord.** | Details in `docs/BOARD.md`. |
| P8 | **GitHub webhooks are built and were tested live, but the firewall rule is closed again**, so polling does the work. | Reopen port 8766 for GitHub's webhook ranges when wanted. |
| P9 | **Switch has no threads for agents**, so a member without a desk room gets their briefing right under the standup, not in a thread. | Documented in `docs/BOARD.md`. |
| P6 | **The demo repo has leftover open PRs** (#4, #5 with an applied suggestion, #9 the workflow-edit demo). | Clean up before recording, or reuse them. |

## 5. Submission items not done

Demo video (script in `docs/DEMO.md`), blog post (`docs/BLOG.md`) and #HowISwitch post (`docs/HOWISWITCH.md`) are drafts; nothing is recorded or
published. Submission on WeMakeDevs for Track 2 and Track 1 is not done. Target: by 8 PM IST on Nov 7.

## Suggested order

1. S1 (what can an agent do with Switch's own tools) and L4 (teach the Ops Agent about `exec`): both affect what is claimed.
2. A Discord run-through of the gate, `exec`, suggestions and the incidents room, which also closes L1 to L3 where Discord and Mattermost share code.
3. L5 and L6 by looking at them.
4. P2, P6, then recording.
