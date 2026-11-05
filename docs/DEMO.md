# Demo video: script and preparation

Target length: 4 minutes (the hackathon asks for a short video; the cut list at the end brings it to 3). Record the screen with three windows ready and
switch between them: **Discord** (the rooms), the **Shipyard dashboard** (`http://localhost:8780`) and **Switch Console** (Switch's own web UI,
`http://<build VM public address>:8000`). Everything below has run for real on this build; replies in quotes are what the system actually answered.

## Before recording (15 minutes, do once)

Open the dashboard tunnel (and Mattermost's, if you want to show it) and leave it running:

```bash
scripts/vm.sh tunnel mattermost            # dashboard http://localhost:8780, Mattermost http://localhost:8065
```

Sign in: on the dashboard click **Get a sign-in code**, then type `@gatekeeper dashboard-login <code>` in a Discord room (a session lasts 8 hours).

**Clean the board.** The board still holds test tickets. On the **Board** page use each card's "⋯" menu: move SY-2, SY-3 to Cancelled, SY-4 to To do and then Cancelled.
SY-1 and SY-5 (Done) can stay as history. Cancelled tickets are hidden from the board.

**Pull requests on the demo repository**, so each scene has something to act on (replace `SY-n` with a ticket you create in scene 4):

```bash
cd <your clone of Shrinet82/shipyard-demo>
# 1. a clean change that says which ticket it fixes
git checkout -q main && git pull -q && git checkout -q -b demo-clean && sed -i 's/FOOTER = "v[0-9]*"/FOOTER = "v9"/' app.py && git commit -qam "Bump the footer (demo). Fixes SY-n" && git push -q origin demo-clean && gh pr create --fill --base main --head demo-clean
# 2. a change that adds a vulnerable dependency (demo only)
git checkout -q main && git checkout -q -b demo-vuln && sed -i 's|WORKDIR /app|WORKDIR /app\n# demo only: deliberately old and vulnerable\nRUN pip install --no-cache-dir "Django==2.2.0"|' Dockerfile && git commit -qam "Add Django 2.2.0 (demo only)" && git push -q origin demo-vuln && gh pr create --fill --base main --head demo-vuln
# 3. a reviewer's suggestion on the clean PR (use the PR number and head sha it printed)
gh api repos/Shrinet82/shipyard-demo/pulls/<n>/comments -f body=$'Nit:\n```suggestion\nFOOTER = "v10"\n```' -f commit_id=<head sha> -f path=app.py -F line=5 -f side=RIGHT
```

Wait about 90 seconds for CI to finish on both, so the SBOM reports are ready. For the alert, either break a build on purpose (a `COPY requirements.txt` that does not exist),
or fire the same event Coolify would send, from the build VM (this is what the live tests used):

```bash
scripts/vm.sh ssh build 'S=$(cat ~/gatekeeper-webhook.secret); A=$(cat ~/demo-web.uuid); curl -s -X POST localhost:8766/hooks/coolify/$S -d "{\"event\":\"restart_limit_reached\",\"application_uuid\":\"$A\",\"restart_count\":10,\"max_restart_count\":10}"'
```

Roles for the scenes (check with `@gatekeeper whoami`): you are the **owner**. You need a **viewer** or **deployer** account for the "refused" shots (a second Discord account,
or the Mattermost test users `sy-viewer`, `sy-maint`). The person you add in scene 3 can be that account.

## The script

| Time | On screen | You say | Type / do |
|---|---|---|---|
| 0:00 | Discord `#ops-base` | "A chat room that ships software and can't be talked into doing anything it shouldn't. It is built on Switch." | |
| 0:10 | Switch Console: Agents, Rooms | "Switch gives me the rooms, the agents, and who is really speaking. Here are the agents and which rooms they live in." | |
| 0:20 | Discord | "The Gatekeeper is a custom Switch agent. It decides what is allowed, by the speaker's role." | `@gatekeeper whoami` → "Your role in demo: owner." |
| 0:30 | Viewer account | "A viewer asks for a deploy." | `@gatekeeper deploy demo-web` → "Denied: … needs role deployer" |
| 0:40 | Dashboard → Roles | "Four roles: viewer, deployer, maintainer, owner. The owner adds someone here; they type `whoami` and paste what it prints." | Add a member with a role, Save; Agent access → **Sync from roles** |
| 1:00 | Discord `#demo-incidents` | "A restart limit is hit. The alert arrives with the real log lines, secrets removed. It opens an incident and a ticket by itself, and the Ops Agent diagnoses it in three lines. It cannot change anything." | (fire the alert) |
| 1:25 | Dashboard → Board | "The ticket is on the board, marked auto. The diagnosis is its description." | Open the new card; show the timeline |
| 1:40 | Discord | "Closing the incident turns follow-ups into a ticket." | `@gatekeeper incident close INC-n: add a restart alert; raise the memory limit` |
| 1:55 | Discord `#demo-maintainers` | "Tickets are made from chat. Only the Repo Agent talks to the Board, and who is asking decides what is allowed." | `@repo-agent track: footer says v8, high` → "Created SY-n"; `@repo-agent assign SY-n to <name>` |
| 2:10 | Dashboard → Board | "The same ticket, with a viewer unable to move it." | Drag the card; show the greyed "⋯" for the viewer |
| 2:20 | Discord | "A pull request that says Fixes SY-n links itself and moves the ticket to review. Merging asks for a second person." | `@gatekeeper sbom <pr>`, `@gatekeeper merge <pr>`, then `approve <id>` |
| 2:40 | Discord | "Now the dependency with a critical vulnerability. A maintainer cannot approve it. Only the owner can override." | `@gatekeeper merge <vuln pr>` → "BLOCKED by the SBOM gate…"; maintainer `approve <id>` → "Denied"; owner `approve <id>` |
| 3:05 | Discord | "The agents may run safe, read-only commands inside the container. Not the environment, not credentials." | `@gatekeeper exec demo-web ls -la /app` (runs); `@gatekeeper exec demo-web env` (refused) |
| 3:20 | Dashboard → Overview, Audit, Switch rooms | "My tickets with a first step; the audit log is hash-chained and the dashboard cannot approve anything. Rooms stay in step with every chat app." | Overview "My tickets"; Audit filtered `gate_override`; Switch rooms → Sync rooms preview |
| 3:45 | Terminal | "Install is one command; the Switch template creates the rooms, links and agents." | `curl -fsSL …/install.sh \| bash` (sped up) |
| 3:55 | Title card | "Shipyard. github.com/Shrinet82/shipyard." | |

Cut list for 3 minutes: drop the viewer shot (0:30), the incident-close line (1:40), the suggestion scene (not in this table; it is in the README) and the install clip.

## Who can do what (the roles, for questions)

| | viewer | deployer | maintainer | owner |
|---|---|---|---|---|
| Read status, logs, PRs, audit; see the board | yes | yes | yes | yes |
| Create and comment on tickets | yes | yes | yes | yes |
| Deploy, restart, roll back (the "change" tier; a rollback also needs an approval) | no | yes | yes | yes |
| Take an unassigned ticket; move or finish a ticket assigned to them | no | yes | yes | yes |
| Edit a ticket | their own | their own and assigned | any | any |
| Move, assign or reassign any ticket; cancel; reopen; team status; close incidents | no | no | yes | yes |
| `exec` in a container; ask for a merge | no | no | yes | yes |
| Approve someone else's dangerous request | no | no | yes | yes |
| Approve their own request, override an SBOM block, delete a ticket request | no | no | no | yes |
| Edit roles, sync agent access, sync rooms, make desk rooms | no | no | no | yes |

A person's dashboard has the same pages for every role. What differs is what is enabled: the Roles and Agent access pages and the Sync rooms button are read-only or absent for anyone
who is not an owner, and on the Board each card's "⋯" menu is greyed out, with the reason, for moves the role may not make. Nothing on the dashboard approves anything: approvals are
only given in chat.

## What Switch does and what the Gatekeeper does

- **Switch**: knows who is speaking (the id comes from the platform account, never from message text), keeps the rooms and links, decides which people may address which agent in which
  rooms (the addressing policy, synced from the roles on the Agent access page), and runs each agent in its own process on an isolated controller as its own Linux user.
- **The Gatekeeper**: the only thing that holds the Coolify, GitHub and cluster credentials, and the only one that acts. Agents hold none; they can only ask it, and it decides by the role of the
  human who wrote the message they cite.
- **Honest limit**: both agents are offered the same set of requests, and the agent's name in a request is self-reported (it is used for the audit log). Which agent does what is steered by their
  instructions and by which rooms Switch lets each one be addressed in; it is not a per-agent rule inside the Gatekeeper.

## What each scene proves (so you can answer questions)

- *Viewer refused / owner-only override*: roles come from the platform account Switch reports, not from what a message says.
- *Alert, incident, ticket*: the Gatekeeper receives Coolify's webhook itself, gathers and redacts the evidence, opens one incident and one ticket per alert (repeats join them), then asks the Ops Agent, which has no credentials.
- *Rollback and merge approvals*: single use, tied to the exact action, expire in 10 minutes, and can't be given by the requester (for ticket deletion not even an owner can approve their own).
- *Block*: the SBOM comes from CI; a new critical CVE, a missing SBOM, or a pull request that edits the workflow blocks the deploy.
- *exec*: about 50 commands, no shell, no writes, paths under the app's folders, symlinks resolved inside the container, credential files refused, output redacted.
- *Board*: a ticket moves only by the matrix for the caller's role and the fixed workflow; a merged fix is done only when a deploy contains its commit.

## Things not to claim

Slack was not run. The Discord run covers commands, approvals, rollback, merge, the Board, the incidents room, desk rooms and the room sync; the SBOM gate, `exec` and suggestions were verified on
Mattermost, so run them once on Discord before recording and say what you saw. Do not say the agents are restricted one by one: see the honest limit above.
