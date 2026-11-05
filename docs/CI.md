# CI: what Shipyard sees, and how to add a pipeline

Shipyard reads CI from **GitHub**, through the GitHub App, and uses it in three ways. Each has its own setting, so adding a pipeline means deciding which of the three it is for.

| Use | What Shipyard looks at | Where you set it |
|---|---|---|
| **Merge check** (is CI green?) | the *check runs* on the PR's head commit, by name | `required_checks` under the project's `repo:` |
| **SBOM gate** (may this deploy?) | the artifacts of one workflow | `sbom.workflow` and the artifact names below |
| **Questions** (what runs, who started it, what did it produce?) | every workflow, check run and artifact | nothing to set: the `ci` command |

Shipyard does not discover pipelines by itself for the first two. A new job is **ignored by merge checks until you name it**, and a new workflow is **ignored by the SBOM gate unless it is the configured one**. This is on purpose: a pipeline someone adds in a PR must not be able to turn the checks green or write its own SBOM.

## Asking what CI exists

In any project room (any member may ask, viewers included), or ask the Repo Agent in plain words:

```
@gatekeeper ci            every workflow in the repository, its latest run, and what Shipyard does with it
@gatekeeper ci 16         one pull request: every check, every workflow run (who started it, when, its link) and its artifacts
@gatekeeper ci a1b2c3d    the same for a commit
```

Example of `ci 16`:

```
CI for PR #16 (commit 5862800): 3 check(s), 2 workflow run(s)
- check e2e: in_progress (not required, so merge ignores it)
- check sbom: success (required for merge)
- check test: success (required for merge)
- run CI [.github/workflows/ci.yml]: success, pull_request on footer, started by anya, https://github.com/o/r/actions/runs/10
    artifacts: sbom-spdx (2.4 MB), grype-report (87 KB); its SBOM is read by the gate
- run Nightly e2e [.github/workflows/e2e.yml]: failure, schedule on main, started by github-actions[bot], https://github.com/o/r/actions/runs/11
    artifacts: playwright-trace (4 KB, expired); not the SBOM workflow, so the gate does not read it
```

It also says plainly when a required check **never reported** on the commit (the usual sign that a workflow was renamed or is disabled) and when the SBOM workflow ran but **its artifacts are missing**. It only reads: nobody can start, re-run or change a pipeline through it.

## Several pipelines: a worked example

A repository with four pipelines: unit tests, lint, a nightly end-to-end run, and the SBOM scan.

1. **Make each one a check GitHub knows.** Every job in a GitHub Actions workflow already is. Note each job's `name:`, because that is what you list.
2. **Decide which must be green to merge.** In `shipyard.yaml`:

   ```yaml
   projects:
     demo:
       repo:
         name: owner/repo
         app: demo-web
         required_checks: [test, lint, sbom]    # e2e runs at night, so it does not block merges
   ```

   Restart the Gatekeeper (`systemctl --user restart shipyard-gatekeeper`). Until you do, `lint` is shown as *not required, so merge ignores it* in `ci <pr>`.
3. **Mark the same names as required in GitHub** (branch protection), so people cannot merge around Shipyard.
4. **Point the SBOM gate at the one workflow that produces the SBOM**:

   ```yaml
   sbom:
     workflow: .github/workflows/ci.yml
   ```

   That workflow must upload artifacts named `sbom-spdx` and `grype-report` (and may upload `sbom-cyclonedx`). The match is a path *prefix*, so `.github/workflows/ci.yml` does not match `ci-extra.yml`, but `.github/workflows/ci` would match both. The run must come from a push or a pull request and must succeed. Copy the `sbom` job from [`shipyard-demo`'s workflow](https://github.com/Shrinet82/shipyard-demo/blob/main/.github/workflows/ci.yml) (Syft and Grype, actions pinned by commit).
5. **Check it**: `@gatekeeper ci` should list all four workflows, and `@gatekeeper ci <a PR>` should show every required check as present.

## Adding a new pipeline later

| You added | Do this |
|---|---|
| a job in the existing workflow that must block merges | add its `name:` to `required_checks`, restart the Gatekeeper |
| a job that is informational | nothing; it shows up in `ci <pr>` as *not required* |
| a new workflow file | nothing for merge checks beyond the above; it appears in `ci` by itself |
| a new workflow that should produce the SBOM | upload `sbom-spdx` and `grype-report` from it and change `sbom.workflow` to its path |
| a PR that edits `.github/workflows/` | the SBOM gate marks that PR's SBOM as **untrusted** until an owner reviews it |

## Limits

- **GitHub only.** Shipyard sees what GitHub Actions, or any tool that reports a *check run* to GitHub, shows. A CI that only sets a legacy commit status (some Jenkins setups) is not read.
- **One repository per project**, and the GitHub App must be installed on it.
- The `ci` listing shows the artifacts of the **eight** newest runs on a commit and the 30 newest runs in the repository, and says when it stops there. Expired artifacts are listed as expired. Shipyard never downloads an artifact except the SBOM ones the gate uses.
- Who started a run is what GitHub reports (the triggering actor). A scheduled run shows `github-actions[bot]`.
