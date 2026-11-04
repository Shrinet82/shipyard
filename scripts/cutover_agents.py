# Move the Ops and Repo agents to the isolated controller and give them their own, minimal tool config.
# Run on the build VM after scripts/isolate_agents.sh and the agentrun Codex login. Needs /tmp/gw.py (a Gateway admin login helper).
exec(open("/tmp/gw.py").read())
import subprocess
GK_TOKEN = open(os.path.expanduser("~/gatekeeper-mcp.token")).read().strip()
cfg = f'''# The isolated agents' own tools. Credentials here are the agents' ONLY ones: the Gatekeeper's request tool and a
# read-only, Secret-blind Kubernetes viewer. No Coolify, GitHub, cluster-admin or Switch admin credential.
[mcp_servers.gatekeeper]
url = "http://127.0.0.1:8765/mcp"
http_headers = {{ Authorization = "Bearer {GK_TOKEN}" }}

[mcp_servers.k8s]
command = "kubernetes-mcp-server"
args = ["--config", "/home/agentrun/.config/kubernetes-mcp-server/config.toml"]
'''
subprocess.run(["sudo", "-u", "agentrun", "tee", "/home/agentrun/.codex/config.toml"], input=cfg.encode(), stdout=subprocess.DEVNULL, check=True)
subprocess.run(["sudo", "chmod", "600", "/home/agentrun/.codex/config.toml"], check=True)
for a in ("ops-agent", "repo-agent"):
    subprocess.run(["sudo", "-u", "agentrun", "mkdir", "-p", f"/home/agentrun/agents/{a}"], check=True)
s, ctrls = call("GET", "/management/controllers")
rows = ctrls if isinstance(ctrls, list) else ctrls.get("controllers", [])
new = [c for c in rows if c["name"] == "shipyard-agents"][0]["id"]
print("new controller:", new[:8], [(c["name"], c.get("state")) for c in rows])
for name, aid in (("ops-agent", "1c842e5f-8bd3-4f77-af2e-3cae2ec14949"), ("repo-agent", "9ab699e9-62d3-47b3-98f8-0d1820771ec6")):
    s, cur = call("GET", f"/management/agents/{aid}")
    d = cur["definition"]
    d["directory"] = f"/home/agentrun/agents/{name}"
    s, r = call("PUT", f"/management/agents/{aid}", {"controller_id": new, "desired_state": "running", "definition": d})
    print(name, "->", s, (r or {}).get("controller_name") if isinstance(r, dict) else r)
