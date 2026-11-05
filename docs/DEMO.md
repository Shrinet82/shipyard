# Demo video: script and preparation

Target length: about 3 minutes (the hackathon asks for a short video). Record the screen with two windows side by side:
**Discord** (the room) on the left, the **dashboard** (`http://localhost:8780`) on the right. Everything below is something that has run
for real on this build; the replies in quotes are what the Gatekeeper actually answered.

## Before recording (10 minutes, do once)

Tunnel and sign-in:

```bash
scripts/vm.sh tunnel                       # leave running; the dashboard is then at http://localhost:8780
```

Open the dashboard, click **Get a sign-in code**, type `@gatekeeper dashboard-login <code>` in the room. (Do this before recording; a session lasts 8 hours.)

Three pull requests on the demo repository, so each scene has something to act on:

```bash
cd <your clone of Shrinet82/shipyard-demo>
# 1. a clean change
git checkout -q main && git pull -q && git checkout -q -b demo-clean && sed -i 's/FOOTER = "v[0-9]*"/FOOTER = "v9"/' app.py && git commit -qam "Bump the footer (demo)" && git push -q origin demo-clean && gh pr create --fill --base main --head demo-clean
# 2. a change that adds a vulnerable dependency (demo only)
git checkout -q main && git checkout -q -b demo-vuln && sed -i 's|WORKDIR /app|WORKDIR /app\n# demo only: deliberately old and vulnerable\nRUN pip install --no-cache-dir "Django==2.2.0"|' Dockerfile && git commit -qam "Add Django 2.2.0 (demo only)" && git push -q origin demo-vuln && gh pr create --fill --base main --head demo-vuln
# 3. a reviewer's suggestion on the clean PR (use the PR number and head sha it printed)
gh api repos/Shrinet82/shipyard-demo/pulls/<n>/comments -f body=$'Nit:\n```suggestion\nFOOTER = "v10"\n```' -f commit_id=<head sha> -f path=app.py -F line=5 -f side=RIGHT
```

Wait about 90 seconds for CI to finish on both, so the SBOM reports are ready. To have an alert ready, break a build on purpose
the way the demo repo's PR "Install dependencies from requirements.txt" did (a `COPY requirements.txt` that does not exist), merge it,
and let the deployment fail; Coolify's webhook then posts the alert. Record that part separately and cut to it, because the build takes a minute.

Roles for the scenes (check with `@gatekeeper whoami`): you are the **owner**; have a **viewer** account (a second Discord account, or
use the Mattermost test users) for the one "refused" shot.

## The script

| Time | On screen | You say | Type |
|---|---|---|---|
| 0:00 | The Discord room | "A chat room that ships software, and can't be talked into doing anything it shouldn't. It is built on Switch." | |
| 0:12 | Same | "Switch gives me the rooms, the agents, and who is speaking. The Gatekeeper is a custom Switch agent: it decides what is allowed." | `@gatekeeper whoami` → "Your role in demo: owner." |
| 0:25 | Viewer account | "A viewer asks for a deploy." | `@gatekeeper deploy demo-web` → "Denied: … needs role deployer" |
| 0:35 | The alert (pre-recorded) | "A build breaks. The alert arrives with the real log lines, secrets removed, and the Ops Agent diagnoses it in three lines. It cannot change anything." | |
| 0:55 | Room | "Rolling back is a change that needs a second pair of eyes." | `@gatekeeper rollback demo-web` → approval id; then as owner: `@gatekeeper approve <id>` → "Done: rollback …" |
| 1:10 | Maintainers room | "Every pull request gets an SBOM from CI, scanned and compared with what is deployed." | `@gatekeeper sbom <clean pr number>` → "… clear to deploy" |
| 1:20 | Same | "Merging goes through checks and an approval; the deploy plan and the report are posted in the ops room too." | `@gatekeeper merge <clean pr>`, then approve |
| 1:40 | Room | "Now the dependency with a critical vulnerability." | `@gatekeeper merge <vuln pr>` → "BLOCKED by the SBOM gate … new critical CVEs …" |
| 1:52 | Same | "A maintainer cannot approve this. Only the owner can override." | maintainer: `approve <id>` → "Denied: only an owner can override a security block"; owner: `approve <id>` → merged and deployed |
| 2:15 | Room | "The agents may run safe, read-only commands inside the app's container. Not the environment, not credentials." | `@gatekeeper exec demo-web ls -la /app` (runs); `@gatekeeper exec demo-web env` (refused) |
| 2:30 | Room | "A reviewer wrote a suggested change. A maintainer asks, a second person approves, and the Gatekeeper commits it." | `@gatekeeper suggestions <clean pr>`, `apply-suggestion <clean pr> 1`, approve |
| 2:45 | Dashboard | "Everything is in the audit log, hash-chained: the block, the refused approval and the override, with the CVE ids. The dashboard can't approve anything." | Audit page (filter `gate_override`), then SBOM detail, then Switch rooms |
| 3:05 | Terminal | "Install is one command: on a machine that already runs Switch it took 25 seconds, and the Switch template creates the rooms, the links and the agents." | `curl -fsSL …/install.sh \| bash` (sped up) |
| 3:15 | Title card | "Shipyard. github.com/Shrinet82/shipyard." | |

If the video must be under three minutes, drop the viewer shot (0:25) and the suggestion scene (2:30); both are in the README.

## What each scene proves (so you can answer questions)

- *Viewer refused / owner-only override*: roles come from the platform account Switch reports, not from what a message says.
- *Alert and diagnosis*: the Gatekeeper receives Coolify's webhook itself, gathers and redacts the evidence, then asks the Ops Agent, which has no credentials.
- *Rollback approval*: approvals are single use, tied to the exact action, expire in 10 minutes, and can't be given by the requester.
- *Block*: the SBOM comes from CI; a new critical CVE, a missing SBOM, or a pull request that edits the workflow blocks the deploy.
- *exec*: about 50 commands, no shell, no writes, paths under the app's folders, symlinks resolved inside the container, credential files refused, output redacted.
- *Suggestion*: it is a human reviewer's text; the agents write no code.

## Things not to claim

Slack was not run. The Discord run covers commands, approvals, rollback and merge; the gate, `exec` and suggestions were verified on
Mattermost, so run them once on Discord before recording and say what you saw.
