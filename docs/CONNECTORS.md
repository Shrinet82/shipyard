# Connectors: GitHub, Kubernetes, SigNoz, Discord

Each one is a command you can run at any time. They all follow the same rules: your own credential is used once, Shipyard keeps only a least-privilege credential of its own (mode `0600`), `shipyard.yaml` is changed through a checked edit (a backup `shipyard.yaml.bak` is kept, and a change that would break the config is refused), and the Gatekeeper restarts when it is done.

## GitHub App (two clicks)

```bash
python3 -m shipyard github-app --repo owner/name          # add --org my-org to own the App under an organisation
```

1. It prints one address, `http://localhost:8767/`. Open it in a browser on the machine. On a remote machine forward the port first: `ssh -L 8767:localhost:8767 <machine>`.
2. GitHub shows the **Shipyard-xxxx** App already filled in (name, permissions, events). Press **Create GitHub App**.
3. Shipyard receives the App id, the private key and the webhook secret from GitHub and saves them next to the config. Press **Install** and pick the repository. Shipyard waits until the App can see it, then writes `github:` and the project's `repo:` into the config.

This is GitHub's *manifest flow*: the code GitHub sends back is valid for one hour and works once. The setup page listens on `127.0.0.1` only, checks a random `state`, and the private key is never printed.

Permissions the App asks for: contents and pull requests (read and write, to merge after approval), actions, checks, commit statuses and issues (read). Webhooks start **off**; Shipyard polls GitHub. To turn them on, pass `--webhook-url http://<public address>:8766/hooks/github` and open that port to GitHub's addresses (an infrastructure change you approve).

## Kubernetes

```bash
python3 -m shipyard connect kubernetes                    # pick a namespace and deployments from a list
python3 -m shipyard connect kubernetes --namespace shop --deployments all --yes
python3 -m shipyard connect kubernetes --dry-run          # print what would be created, change nothing
```

Needs `kubectl` on this machine, pointing at the cluster, with rights to create service accounts and role bindings (your admin access; used once, never stored). It creates:

| Account | Rights, in your namespace only | Used for |
|---|---|---|
| `shipyard-viewer` | the built-in `view` role (cannot read Secrets) | `status`, `logs`, `events` |
| `shipyard-deployer` | `view`, plus patch deployments and their scale | `restart`, `rollback`, `scale` |
| `shipyard-ops` | get and list pods, `pods/exec` | allowlisted `exec` inside a pod |

The accounts live in a `shipyard-system` namespace; only the role bindings are in yours. It writes `~/kube/{viewer,deployer,ops}.kubeconfig`, then checks each credential with `kubectl auth can-i` (the viewer must not read Secrets or exec, the deployer must not delete or read Secrets, the ops account must not delete pods) and stops if any answer is wrong. Run it again for another namespace.

Requirements and limits: the cluster's API server must be reachable from the machine, and its kubeconfig entry must carry the certificate authority (Shipyard refuses to talk to a server it cannot verify). Only tested on k3d here, not on EKS or GKE.

To remove: delete the `shipyard-*` role bindings and roles in your namespace and the `shipyard-system` namespace, and the `kubernetes:` block and apps from the config.

## SigNoz (read only)

```bash
python3 -m shipyard connect signoz --url http://signoz:8080
```

Create the key in SigNoz first: Settings → Service Accounts → New, role **Viewer**, add a key (it expires; set it as long as you like). Shipyard asks for it hidden, checks the address and the key, and saves it as `~/signoz.env`.

In chat (any project member, read only):

```
@gatekeeper signals                      what is firing now
@gatekeeper signals rules                the alert rules and their state
@gatekeeper signals logs <service> [minutes]      recent logs of a service
@gatekeeper signals errors <service> [minutes]    the error-level lines only
```

Log lines are redacted, defused (no mentions, no code fences) and clipped like Coolify's. The Ops and Repo agents can ask for the same through the Gatekeeper (`signoz.read`); they have no SigNoz key.

**Alerts into Shipyard:** the command prints a webhook address with a secret in it. In SigNoz: Settings → Notification channels → New → Webhook, paste it, then add the channel to your alert rules. A firing alert then posts its evidence (the alert's labels and the service's recent error logs) in the incidents room, opens an incident and a Board ticket, and asks the Ops Agent for a diagnosis, the same as a Coolify alert. The address is reachable from your VPC only; do not open it to the internet. `service_map: {signoz-name: app}` in the config maps SigNoz service names to your apps.

SigNoz's `foundryctl` installer can run it on the same machine: `curl -fsSL https://signoz.io/foundry.sh | bash`, a `casting.yaml` with `flavor: compose, mode: docker`, then `foundryctl cast -f casting.yaml` (UI on port 8080, OTLP on 4317 and 4318). It needs about 4 GB of memory of its own.

Not done: SigNoz traces and metrics queries, and creating alert rules from chat. The connector reads alerts, rules and logs.

## Discord

```bash
python3 -m shipyard connect discord
```

Discord makes you do three things by hand, once; Shipyard checks each one before it goes on:

1. **Create the bot.** [discord.com/developers/applications](https://discord.com/developers/applications) → New Application → Bot → Reset Token. Paste the token when asked (hidden). Shipyard asks Discord about it at once, so a wrong token is caught here.
2. **Switch on two toggles** under Bot → Privileged Gateway Intents: *Message Content Intent* and *Server Members Intent*. Shipyard reads the application's flags from Discord and tells you which one is still off; without them the bot would receive empty messages.
3. **Press the invite link** Shipyard prints (it carries the application id and exactly the permissions the bridge uses, never Administrator). Shipyard then waits until the bot appears in a server, so there is **no server id to copy**; with several servers it asks which.

It then saves the token as `~/discord.env` (mode 0600), connects the server to Switch (a bridge named `<project> Discord`; run again and it reuses it), restarts the Gatekeeper, asks the room sync to make `#<project>-ops`, `-maintainers` and `-incidents` in Discord, and waits for you to type `@gatekeeper whoami` in Discord so it can add you as an owner there.

Needs: an owner already set (type `@gatekeeper whoami` in Mattermost first, or run `python3 -m shipyard add-owner`), because the room sync is an owner action. Not tested here against a live Discord bot with this exact flow; the bridge call and the invite flow follow Switch's own Discord setup guide.

## A Mattermost login

The bundled Mattermost starts with only the admin account Switch uses. `python3 -m shipyard mattermost-user <name>` makes an ordinary user, adds them to the team and the project's rooms and shows the password once. The installer offers it before it waits for your first `@gatekeeper whoami`. The browser pages listen on the machine itself; see the tunnel line in the README.

## Browser pages without a tunnel (`expose`)

```bash
python3 -m shipyard expose            # Mattermost :8065, Switch Console :8000 and the dashboard :8780 on the machine's address
python3 -m shipyard expose --only mattermost
python3 -m shipyard expose --off      # this machine only again
```

What it changes: a docker compose override (`~/switch/shipyard-expose.yml`) that replaces the loopback-only port mapping of just Mattermost and Switch (Postgres and the Switch gateway stay on the machine), a restart of the Switch stack (about a minute), and in `shipyard.yaml` `dashboard.bind: 0.0.0.0`, `dashboard.allow_remote: true` and `dashboard.public_url`. The dashboard then accepts only `localhost` and the published address as its Host, and still refuses a non-loopback bind unless `allow_remote` is set. Mattermost's live connection is allowed from both `localhost:8065` and the public address, so the tunnel keeps working (a different origin is refused; checked with a websocket handshake).

What it cannot do is open your cloud firewall. Allow TCP 8065, 8000 and 8780 **from your own address only** (AWS: EC2 → Security groups → Inbound rules → Add rule → Custom TCP → Source: My IP). The pages use plain HTTP, so passwords and sessions are readable by anyone on the path: never open them to everyone, and prefer the tunnel on a machine without a cloud firewall. The address is found from the AWS metadata (or an outside lookup); pass `--host` otherwise.
