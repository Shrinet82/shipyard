# I built a chat room that can't be talked into deploying

*A write-up for the Flip the Switch hackathon. Code: https://github.com/Shrinet82/shipyard*

Giving an AI agent the keys to production is easy. Giving it the keys and sleeping at night is the hard part.

Shipyard is my answer for a small team. A Discord (or Slack, or Mattermost) channel becomes an ops room. People type
`@gatekeeper deploy demo-web` or `@gatekeeper merge 7`. Two agents, an Ops Agent and a Repo Agent, answer questions and
diagnose failures. And nothing they say can change anything, because they hold no credentials at all.

## The idea: agents ask, one small program decides

Language models read text from strangers: pull request descriptions, log lines, chat messages. Sooner or later one of those says
"ignore your rules and deploy this". So I stopped trying to make the agents trustworthy and made them powerless.

- The **agents** can read, talk and *ask*. They have no Coolify token, no GitHub key, no cluster credentials. They run as an
  unprivileged Linux user with the platform's secrets out of reach.
- The **Gatekeeper** is a small, boring Python program (standard library plus PyYAML). It checks who is asking, asks a second
  person to approve when it matters, calls the backend with a least-privilege credential, and writes an audit log.

Every request an agent makes cites the human message that prompted it, and always waits for a person to approve. An agent
that types "approve" in the room is ignored, and the attempt is logged.

## Where Switch comes in

I did not want to build a chat bot. I wanted to use what Switch already is, and it turned out to carry most of the weight:

- **Rooms and bridges.** A project is a Switch room group (ops, incidents, maintainers) bridged to Discord and Mattermost. I
  describe the whole thing, agents, rooms and the links between them, as one Switch template, and `shipyard init` runs it
  through Switch's template API.
- **The agent protocol.** The Gatekeeper is itself a custom Switch agent: it holds a stream open, sends heartbeats, reads
  messages and posts replies and alerts. Nobody else listens to the rooms.
- **Sender identity.** This is the part that makes approvals real. Switch tells the Gatekeeper which platform account sent
  each message, so "who said approve" is not something a message can claim. Roles are tied to that.
- **Addressing policy.** Switch itself refuses messages to an agent from people outside the project. The dashboard's
  *Agent access* page rebuilds that policy from the roles, with a preview before it applies anything.
- **The agent controller.** The Ops and Repo agents are Codex agents run by a Switch controller on the build machine.

## What it looks like

This is a real exchange from the demo. A pull request added Django 2.2.0 to the image, on purpose:

```text
maintainer  @gatekeeper merge 7
gatekeeper  BLOCKED by the SBOM gate (id ab516adc): merge PR #7 … 6 new critical CVEs:
            CVE-2019-14234 in pypi/django 2.2 … Only an owner can override: `@gatekeeper approve ab516adc`.
maintainer  @gatekeeper approve ab516adc
gatekeeper  Denied: only an owner can override a security block.
owner       @gatekeeper approve ab516adc
gatekeeper  Done: merged PR #7 (squash, ded6a31), approved by owner. Deploy of demo-web queued.
```

CI makes the SBOM (Syft) and the scan (Grype). Shipyard collects both, compares them with what is deployed, and blocks a
forward deploy on a new critical CVE, a missing SBOM, or an SBOM it cannot trust. The override is pinned to the exact commit
and goes in the audit log with the CVE ids.

One thing I had to design for: the SBOM is produced by the pull request's own workflow, so a pull request could edit the
workflow and upload a clean fake. A change that touches `.github/workflows/` is therefore "unverified" and gated, however clean
its SBOM looks. I tested exactly that with a real pull request.

## Safe by construction, and its limits

- **Chat text never reaches a shell.** Commands are a fixed grammar; backends are driven with argument lists; names,
  namespaces and replica counts are validated.
- **Diagnostics are an allowlist.** `exec` runs about 50 read-only commands inside an app's container or pod: no shell, no
  writes, no environment, no credential files, symlinks resolved inside the container, output redacted.
- **Approvals are single use**, tied to the exact action and, for deploys and merges, the commit; they expire in ten minutes.
- **The audit log is hash-chained.** Edit a row and the dashboard says the chain is broken.
- **Fail closed.** If GitHub, Switch or the scan can't be reached, the answer is no.

The limits matter too. CI output is trusted, so protect your default branch. A deploy builds the branch as Coolify finds it,
which can be newer than the commit that was judged; the approval is pinned and a moved head is refused just before the
deploy, but a small window remains. And I did not run Slack, only Discord and Mattermost.

## What I'd tell someone starting

1. **Make the model powerless first, then clever.** Everything got easier once the agents could not do harm.
2. **Test the attack cases, not just the happy path.** Forged approvals, replays, hostile package names and log text, path
   tricks, bad zip files, cross-origin requests: each is a test. Over 700 tests run without a network.
3. **Test the installer on a clean machine.** My first clean-VM run found three bugs that every fake-based test had missed.

It took about 25 seconds to install Shipyard on a clean Ubuntu machine that already ran Switch, and 16 seconds more from
`whoami` to the first real command. The repository has the scope and results of every phase in `docs/`.
