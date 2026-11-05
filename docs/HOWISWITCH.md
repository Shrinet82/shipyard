# #HowISwitch post (drafts)

## Short (for X / LinkedIn / Discord)

Built **Shipyard** for #FlipTheSwitch: a Discord channel that ships software and can't be talked into doing anything it shouldn't.

Switch does the heavy lifting: rooms and bridges, a custom agent (the Gatekeeper), real sender identity for approvals, and
addressing policy. The AI agents hold zero credentials; they can only ask, and a human approves.

A PR adding a vulnerable package got blocked by the SBOM gate. A maintainer's approval was refused; only the owner's override
merged it. All in the audit log.

Code: https://github.com/Shrinet82/shipyard  #HowISwitch

## Longer (for the hackathon form or a thread)

**How I switched:** I started from "agents with tools" and switched to "agents that can only ask". Switch made that practical:

1. The Gatekeeper is a custom Switch agent on the agent protocol, so it sees every message and posts alerts directly.
2. Switch's sender identity tells it which platform account spoke, so approvals can't be faked by text.
3. A Switch template creates the project's agents, rooms and the links between them in one run.
4. Switch's addressing policy keeps the agents answering project members only, and the dashboard rebuilds it from the roles.

Result: deploys, rollbacks, merges, safe diagnostics inside containers, SBOM reports with a deploy gate, and reviewer suggestions
applied to PR branches, all from chat, all behind roles, approvals and a tamper-evident audit log.

Honest limits: tested on Discord and Mattermost, not Slack; CI output is trusted, so protect your default branch.
