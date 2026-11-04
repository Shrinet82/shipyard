# Phase 4 scope: SBOM reports, the deploy gate and the dashboard

Phase 5 does not start until every box in the exit gate at the bottom is checked.

## Facts established (Nov 4, 2026)

| Question | Answer |
|---|---|
| Can the GitHub App see CI runs and artifacts? | Yes. It lists the repo's workflow runs and the artifacts endpoint answers (0 artifacts, because our CI makes none yet). It already holds `Actions: read`, so no new permission is needed. |
| Versions to pin | `anchore/sbom-action` v0.24.3 (Syft v1.56.0), `anchore/scan-action` v7.4.2 (Grype v0.121.1), `actions/upload-artifact` v7.0.2. In the workflow they are pinned by **commit SHA**, not tag. |
| GitHub's own SBOM export as a fallback? | `GET /dependency-graph/sbom` returns 404 for the demo repo (no dependency manifest) and carries no CVE data anyway. **Dropped.** A commit with no CI SBOM is reported as "no SBOM" and gated. |
| Where do CVE severities come from? | From Grype's advisory data only. Shipyard has no scoring engine, no CVE database of its own. |
| The threat I found while scoping | The SBOM is produced by the PR's own workflow, and a PR can edit the workflow to upload a clean fake. A gate that blindly trusts the artifact is bypassable. See "Trust" below. |

## Design decisions

1. **CI makes the SBOM and the scan; Shipyard collects, compares and decides.** A new `sbom` job in the demo repo's workflow builds the image,
   runs Syft (SPDX and CycloneDX) and Grype on the SBOM with `fail-build: false`, and uploads three artifacts: `sbom-spdx`,
   `sbom-cyclonedx`, `grype-report`. Required checks become `test` and `sbom`, so a merge waits for it.
2. **Collector, by polling** (no public endpoint, as in Phase 2). For each open PR head and each push to the default branch the Gatekeeper
   looks up the workflow run for that exact commit, and when it has finished successfully downloads the three artifacts.
3. **Trust.** An SBOM is accepted only if all hold: the run is from this repository (not a fork), its `head_sha` equals the commit being
   judged, the workflow is the expected one and succeeded, artifact names are on an allowlist, and **the PR does not touch
   `.github/workflows/`**. A PR that changes the workflow gets "unverified SBOM" and is gated like a critical finding. Residual risk,
   stated plainly in the README: CI output is trusted, so protect the workflow with branch protection or CODEOWNERS; signed attestations are out of scope.
4. **Safe parsing.** Downloaded zips are limited (size, file count, uncompressed size, no path traversal, no nested archives), JSON is
   depth- and size-limited, and package counts are capped. All names and advisory text that reach chat are redacted, defused and fenced.
5. **Report.** Packages added, removed and upgraded since the last *deployed* release (matched by package URL); CVEs by severity with a
   "new" mark for those absent from the last release; fix versions when known; the decision. Chat gets a short Markdown summary; the dashboard
   serves the full JSON and a static HTML report. Reports are kept per commit on disk, with an index in SQLite.
6. **Baseline = the last release the Gatekeeper deployed.** Each deploy (from a merge or a `deploy` command) records the commit and its report.
7. **The gate.** A **new critical CVE**, a missing SBOM, or an unverified one blocks the forward deploy. It applies to `merge` (which deploys)
   and `deploy` for repository-backed apps. Rollback, restart and scale are not gated: they are the recovery path.
   The approval prompt says what blocked it and lists the CVE ids. **Only the owner can override**; a maintainer's approval is refused. The
   approval is pinned to the commit, single-use, and expires like any other. The override is audited with the CVE ids (`gate_blocked`, `gate_override`).
8. **Dashboard: small, inside the Gatekeeper, no framework.** Server-rendered pages from the Python standard library plus a little vanilla
   JavaScript, instead of Next.js. Reasons: no build step or Node dependency to install (the Phase 5 installer stays short), less
   memory, a smaller attack surface, and about three hours saved. It can be swapped for Next.js later because it only calls a JSON API.
9. **Dashboard security.** Listens on `127.0.0.1` only, reached through an SSH tunnel. Every API call needs a bearer token (a file readable
   only by the Gatekeeper's user); no cookies, so no CSRF. All output is escaped, with a strict Content-Security-Policy. **It cannot approve
   anything**: approvals exist only in chat, where the sender's identity is verified.
10. **What the dashboard shows and edits.**
    - Read-only: audit log (with the hash-chain check and the gate events), pending approvals, SBOM reports (list, diff, CVEs, JSON and HTML),
      backend health (Coolify, Kubernetes, GitHub App, Switch, the production host, agents online).
    - Editable by the owner: **roles** (an overlay file the Gatekeeper reloads at once; refuses to remove the last owner; audited) and **agent
      access** (Switch's addressing policy, rebuilt from the roles through the Gateway API: the same logic as `sync_addressing.py`).
11. **Out of scope, kept out on purpose:** our own CVE database, signing SBOMs, licence policy editing, and the stretch item "apply a reviewer's
    suggested change to a PR branch" (cut first).

## Command surface additions

| Command | What it does | Role |
|---|---|---|
| `sbom` | the latest stored report (add a PR number or a commit to pick another) | viewer |
| `merge <n>` | now also checks the SBOM gate; a block turns the approval into an owner-only override | maintainer, then owner |
| `deploy <app>` | for repository-backed apps, the same gate on the branch head | deployer, then owner on a block |

Reports are also posted without being asked: to the maintainers room when CI finishes on a PR, and to the ops room with the deploy plan.

## Work items

| # | Item | Done when |
|---|---|---|
| 1 | Demo repo: `sbom` job, pinned actions, required checks, deliberately vulnerable PR and a clean PR | artifacts appear on a run |
| 2 | Artifact download (zip safety limits) and parsers for SPDX, CycloneDX and Grype JSON | tests with real files |
| 3 | Diff, report text, severities, "new" marking, storage per commit | tests |
| 4 | Trust checks (fork, sha, workflow, allowlist, workflow-changed PR) | tests incl. attack cases |
| 5 | Collector in the poller; chat posting; `sbom` command | live |
| 6 | Release records and the gate on `merge` and `deploy`; owner-only override; audit events | live and tests |
| 7 | Dashboard API and pages (audit, approvals, SBOM, health) | opens through a tunnel |
| 8 | Roles editor and agent-access sync | role change takes effect and is audited |
| 9 | Docs, plan doc, push | updated |

## Demo plan

A baseline release first: `main` gets the new workflow, CI produces its SBOM, and the Gatekeeper deploys it (this becomes the baseline).
Then two PRs: **#7**, a deliberately vulnerable dependency added to the image (labelled "demo only"), expected to carry a critical CVE;
and **#8**, a harmless bump with no new CVEs. #7 shows the report, the block, a maintainer's refused approval, the owner's override,
and the audit trail; #8 sails through.

## Attack cases

- Artifact zips with `../` paths, a zip bomb, too many files, nested archives, non-JSON, deeply nested JSON, a 100,000-package SBOM: refused.
- Artifacts from a fork's PR, from another commit, from another workflow, or with an unexpected name: ignored.
- A PR that edits `.github/workflows/` and uploads a clean fake SBOM: "unverified", gated.
- Package names or advisory text containing `@gatekeeper deploy demo-web` or a Discord mention: defused, nothing runs.
- A maintainer approves the override: refused. The same override reused, or used after a new commit: refused.
- A direct `deploy` while the branch head has a critical CVE or no SBOM: gated like a merge.
- GitHub unreachable while collecting: no report, and the deploy stays blocked rather than assumed safe.
- Dashboard: no token or a wrong token gets 401; script tags in an audit row or a package name render as text; `../` in a report path is refused;
  an unknown role, an unknown project, a malformed identity, or removing the last owner is refused; there is no approve endpoint.

## Exit gate

- [x] A CI run's SBOM and scan are collected and reported in chat, with packages added, removed and upgraded, and CVEs by severity.
- [x] A PR adding a package with a new critical CVE: the report says deploy blocked; a maintainer's approval is refused; the owner's override
      merges and deploys; the audit log shows the block and the override with the CVE ids.
- [x] A clean PR passes with no gate.
- [x] `@gatekeeper sbom` shows stored reports.
- [x] The dashboard (through a tunnel, with its token) shows the audit log with the gate events, pending approvals, SBOM reports with JSON and HTML,
      and backend health; the owner changes a role and syncs agent access, both audited.
- [x] All attack cases pass as automated tests, and the live ones are run once by hand.

## Cut order if time runs short

The stretch item first, then the dashboard's editing (roles, agent access), then the HTML report, then the dashboard's health page. The SBOM
pipeline, the gate and the read-only audit and SBOM pages carry the exit gate and stay. Phase 5 is never cut.

## Estimate

About eight hours: pipeline and parsers 2.5, gate 1.5, dashboard 3, live runs and docs 1.

## What the owner has to do

- **One decision:** the dashboard as a small built-in page (recommended) or Next.js (about three hours more and an extra build to install).
- **One approval:** a deliberately vulnerable dependency in a PR on the public demo repo. It may trigger GitHub Dependabot alert emails to you.
  It is labelled "demo only" and is never merged to the default deploy without the override scenario.

## Results (Nov 5, 2026)

Built and verified live on the build VM, in Mattermost. Automated tests: 535 pass (about 120 of them are new in this phase).

### What was built

| Piece | Where |
|---|---|
| Artifact download (redirect followed **without** our credentials, 25 MB cap) and PR file list | `shipyard/github.py` |
| Safe zip and JSON reading, SPDX / CycloneDX / Grype parsing, diff by package URL, trust checks, report text and HTML | `shipyard/sbom.py` |
| Per-commit report store, release records, baseline | `shipyard/sbomstore.py` |
| Collector (polls PR heads and the default branch, posts to the maintainers rooms) | `shipyard/sbomwatch.py` |
| The gate on `merge`, `deploy` and agent-proposed deploys; owner-only override; `sbom` command | `shipyard/service.py`, `shipyard/gatekeeper.py` |
| Dashboard API, sign-in, role editor, agent-access sync, health | `shipyard/dashboard.py`, `dashauth.py`, `members.py`, `access.py`, `health.py` |
| Dashboard pages (no framework, no build step, text-only rendering) | `shipyard/web/` |

### How it behaves (live)

- **Baseline.** `deploy demo-web` on a clean `main` head ran at once and recorded release `77a7745`.
- **Clean PR #8.** The report was posted, `merge 8` asked for the usual approval with no gate, a second person approved, it merged and deployed, and the release moved to the merged commit with PR #8's report as its baseline.
- **Vulnerable PR #7** (Django 2.2.0). Grype found **6 new critical CVEs**. `merge 7` answered `BLOCKED by the SBOM gate` with the CVE ids. The maintainer's approval was refused (`only an owner can override a security block`), the owner's approval merged and deployed, a replay was refused, and the audit log has `gate_blocked`, `approval_rejected` and `gate_override` rows with the CVE ids.
- **Dashboard** through `scripts/vm.sh tunnel`: signed in with a device code typed in chat; overview, audit (chain verified), approvals, SBOM list and detail with downloads, backends (Coolify, Kubernetes, GitHub rate limit, Switch, production host disk, agents), roles and agent access. A role removal took effect in chat at once, the preview showed the two policy changes, the sync applied them, and the next preview was empty.
- **Workflow-editing PR #9** (adds a comment to `ci.yml`): CI was green and produced a clean-looking SBOM, but the report said `SBOM unverified: this change edits .github/workflows/` and `merge 9` was `BLOCKED` with an owner-only override. The approval was then denied.
- **Hand-run attacks:** no token, a wrong token, a foreign `Host` header and a cross-origin POST were all refused.

### Deviations from the scope, and why

1. **Sign-in is a device code, not a token posted in chat.** The design says to ask the Gatekeeper for a token in chat. A token in chat history is a secret in a log that others can read. Instead the dashboard shows a code, the person types `@gatekeeper dashboard-login <code>`, Switch tells us who typed it, and only the browser that asked for the code collects the session. The design's token field stays as a second way in, fed by `python -m shipyard dashboard-token --identity <id>` run on the VM.
2. **Identities are shown as account names with the platform**, parsed from Switch's sender id, not as `discord:4182…`. The full id is on the Roles page, because that is what is pasted to add someone.
3. **System fonts instead of Google Fonts.** The page loads nothing from another origin, so the CSP can say `default-src 'none'` plus `'self'`.
4. **Versions are not release tags.** Rows are labelled by pull request or branch and short commit, as the demo repo has no release tags.
5. **"Agents online"** is "registered in Switch and the runner service active". Switch does not expose a live flag for on-demand (Codex CLI) agents.

### Residual risks, stated plainly

- **CI output is trusted.** The SBOM comes from the repository's own workflow. A change to `.github/workflows/` cannot vouch for itself (gated as unverified), but anyone who can push to the default branch can change the workflow. Protect the branch (required reviews, CODEOWNERS on `.github/`). Signed attestations are out of scope.
- **A deploy builds the branch as it is when Coolify pulls it**, which can be a commit newer than the one judged. The approval is pinned to the judged commit, and a moved head is refused just before the deploy runs, but the window between that check and Coolify's clone remains. On a protected default branch it is small.
- **The dashboard is reachable by anyone with a shell on the VM** (it listens on loopback only). The `dashboard-token` command is for exactly those people.
