# Connectors: GitHub, Kubernetes, SigNoz

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
