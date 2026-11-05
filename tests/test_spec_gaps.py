"""The parts of the Board spec that were first left out: more alert sources, incidents, personal desk rooms, GitHub webhooks."""
import dataclasses
import hashlib
import hmac
import json
import socket
import time
import urllib.request

import pytest
from test_board_flow import BoardGitHub, DEP, INC, MAINT, MAINTAINER, NOW, OPS, OWNER, VIEWER, env as board_env, mkpr, watcher  # noqa: F401

from shipyard.access import AgentAccess
from shipyard.clusterwatch import ClusterWatcher
from shipyard.desks import Desks, DeskError, slug, username_of
from shipyard.incidents import Incidents, parse_items
from shipyard.policy import Role
from shipyard.webhook import github_signature_ok, serve

BRIDGE = "00000000-0000-0000-0000-000000000000"
ANYA = f"@switch-mattermost-{BRIDGE}-anya:localhost"
OSCAR = f"@switch-mattermost-{BRIDGE}-oscar:localhost"
RAHUL = f"@switch-mattermost-{BRIDGE}-rahul:localhost"


class FakeGateway:
    def __init__(self):
        self.calls, self.fail, self.bridges = [], False, {}

    def call(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "GET" and path.startswith("/rooms/"):
            return 200, {"bridge_id": self.bridges.get(path.rsplit("/", 1)[1], BRIDGE), "group_id": "group-1"}
        if method == "POST" and path == "/rooms":
            if self.fail:
                return 403, "no"
            return 201, {"id": f"desk-room-{len([c for c in self.calls if c[0] == 'POST'])}"}
        return 404, "?"


@pytest.fixture
def env(board_env, tmp_path):
    e = board_env
    e.svc.incidents = Incidents(e.gk.db, e.gk.lock, e.gk.audit, e.clock)
    e.gw = FakeGateway()
    e.desks_file = tmp_path / "desks.json"
    e.svc.desks = Desks(e.cfg, e.desks_file, e.gk.audit, lambda: e.gw)
    e.cfg.policy.members["demo"].update({OSCAR: Role.OWNER, ANYA: Role.DEPLOYER, RAHUL: Role.VIEWER})
    e.svc.names.update({OSCAR: "oscar", ANYA: "anya", RAHUL: "rahul"})
    return e


def alerts(env):
    return [t for t in env.in_room(INC) if t.startswith("ALERT")]


def hook(env, event, **extra):
    env.svc.on_coolify_event({"event": event, **extra})


# --- more alert sources -------------------------------------------------------------------------------------------------

def test_restart_limit_opens_an_alert_an_incident_and_a_ticket(env):
    hook(env, "restart_limit_reached", application_uuid="web-uuid", restart_count=10, max_restart_count=10)
    text = env.in_room(INC)[0]
    assert "restart limit reached for demo-web" in text and "Incident INC-1 opened" in text and "Restarted 10 times" in text
    assert "restart limit reached for demo-web" in env.in_room(OPS)[0]
    t = env.t.get("demo", OWNER, "SY-1")
    assert t["title"] == "Investigate: restart limit reached on demo-web" and t["priority"] == "high" and t["labels"] == ["ops"] and t["source"] == "alert"
    assert ("incident", "INC-1") in [(l["kind"], l["ref"]) for l in t["links"]]


def test_the_same_alert_again_joins_the_open_incident_and_ticket(env):
    hook(env, "restart_limit_reached", application_uuid="web-uuid", restart_count=10, max_restart_count=10)
    env.clock.t += 700                                               # past the ten-minute window that drops repeats
    hook(env, "restart_limit_reached", application_uuid="web-uuid", restart_count=11, max_restart_count=10)
    assert len(env.t.list("demo", OWNER)["tickets"]) == 1 and "Incident INC-1 is still open" in alerts(env)[-1] and len(alerts(env)) == 2
    assert [i["key"] for i in env.svc.incidents.open_list("demo")] == ["INC-1"]


def test_a_high_disk_alert_is_about_the_server_and_needs_no_application(env):
    hook(env, "high_disk_usage", server_uuid="srv-1", server_name="prod-1", disk_usage=91, threshold=80)
    assert "disk over threshold for prod-1" in env.in_room(INC)[0] and "disk 91% used, threshold 80%" in env.in_room(INC)[0]
    assert env.t.get("demo", OWNER, "SY-1")["title"] == "Investigate: disk over threshold on prod-1"
    hook(env, "high_disk_usage", server_uuid="srv-1", server_name="prod-1", disk_usage=92, threshold=80)       # within the hour: dropped
    assert len(alerts(env)) == 1


def test_a_restarted_container_is_found_by_its_application_uuid(env):
    hook(env, "container_restarted", container_name="web-uuid-171000000000", server_name="prod-1", server_uuid="srv-1")
    assert "container crashed and was restarted automatically for demo-web" in env.in_room(INC)[0]
    assert env.t.get("demo", OWNER, "SY-1")["title"] == "Investigate: container crashed on demo-web"
    hook(env, "container_restarted", container_name="someone-elses-container-1")                               # not one of ours
    assert len(alerts(env)) == 1


def test_the_webhook_listener_now_accepts_the_new_events():
    from shipyard.webhook import EVENTS
    assert {"restart_limit_reached", "container_restarted", "high_disk_usage"} <= EVENTS


# --- the cluster ------------------------------------------------------------------------------------------------------------

class FakeKube:
    def __init__(self):
        self.pods, self.nodes = [], []

    def problems(self, namespace, name, limit):
        return self.pods

    def logs(self, namespace, name, lines=40):
        return ["panic: out of memory"]

    def disk_pressure(self, namespace):
        return self.nodes


def k8s_env(env):
    from shipyard.config import K8sApp
    proj = env.cfg.projects["demo"]
    env.cfg.projects["demo"] = dataclasses.replace(proj, k8s_apps={"demo-k8s": K8sApp("shop", "web")})
    env.svc.cfg = env.cfg
    return FakeKube()


def test_the_cluster_watcher_raises_a_restart_alert_once_an_hour(env):
    kube = k8s_env(env)
    kube.pods = [{"pod": "web-abc", "kind": "restart_limit", "restarts": 7, "waiting": "CrashLoopBackOff"}]
    w = ClusterWatcher(env.svc, kube)
    assert w.poll_once() == 1 and w.poll_once() == 0
    assert "restart limit reached for demo-k8s" in env.in_room(INC)[0] and "Pod web-abc: 7 restarts, CrashLoopBackOff" in env.in_room(INC)[0]
    env.clock.t += 3700
    assert w.poll_once() == 1
    assert len(env.t.list("demo", OWNER)["tickets"]) == 1                                     # the open ticket took the repeat


def test_the_cluster_watcher_reports_node_disk_pressure_and_crashes(env):
    kube = k8s_env(env)
    kube.pods = [{"pod": "web-x", "kind": "container_crashed", "restarts": 2, "waiting": "CrashLoopBackOff"}]
    kube.nodes = ["node-1"]
    assert ClusterWatcher(env.svc, kube).poll_once() == 2
    titles = sorted(t["title"] for t in env.t.list("demo", OWNER)["tickets"])
    assert titles == ["Investigate: container crashed on demo-k8s", "Investigate: disk over threshold on node node-1"]


def test_kube_problems_reads_pods_and_disk_pressure():
    from shipyard.kube import Kube
    pods = {"items": [{"metadata": {"name": "a"}, "status": {"containerStatuses": [{"restartCount": 9, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}},
                      {"metadata": {"name": "b"}, "status": {"containerStatuses": [{"restartCount": 1, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}},
                      {"metadata": {"name": "c"}, "status": {"containerStatuses": [{"restartCount": 0, "state": {"running": {}}}]}}]}
    dep = {"spec": {"selector": {"matchLabels": {"app": "w"}}}}
    nodes = {"items": [{"metadata": {"name": "n1"}, "status": {"conditions": [{"type": "DiskPressure", "status": "True"}]}},
                       {"metadata": {"name": "n2"}, "status": {"conditions": [{"type": "DiskPressure", "status": "False"}]}}]}

    def run(argv, timeout):
        text = " ".join(argv)
        return 0, json.dumps(pods if " pods " in text else nodes if " nodes " in text else dep), ""
    k = Kube({"viewer": "/v"}, runner=run)
    assert k.problems("shop", "web", 5) == [{"pod": "a", "kind": "restart_limit", "restarts": 9, "waiting": "CrashLoopBackOff"},
                                            {"pod": "b", "kind": "container_crashed", "restarts": 1, "waiting": "CrashLoopBackOff"}]
    assert k.disk_pressure("shop") == ["n1"]
    assert Kube({"viewer": "/v"}, runner=lambda a, t: (1, "", "forbidden")).disk_pressure("shop") == []        # no cluster-wide read: nothing, not an error


# --- incidents ------------------------------------------------------------------------------------------------------------

def test_parse_items_takes_lines_or_semicolons():
    assert parse_items(": add a disk alert; rotate logs ;") == ["add a disk alert", "rotate logs"]
    assert parse_items("\n- add a disk alert\n* [ ] rotate logs\n\n[x] write the runbook") == ["add a disk alert", "rotate logs", "write the runbook"]
    assert parse_items("   ") == []


def _alert(env):
    hook(env, "restart_limit_reached", application_uuid="web-uuid", restart_count=10, max_restart_count=10)


def test_closing_an_incident_turns_its_action_items_into_a_follow_up_ticket(env):
    _alert(env)
    env.say(MAINTAINER, "incident close INC-1: add a restart alert; raise the memory limit", room=INC)
    reply = env.last(INC)
    assert reply.startswith("INC-1 closed. Follow-ups are on the Board as SY-2")
    t = env.t.get("demo", OWNER, "SY-2")
    assert t["title"] == "Follow-ups from incident INC-1" and t["body"] == "- [ ] add a restart alert\n- [ ] raise the memory limit"
    assert t["priority"] == "medium" and t["labels"] == ["incident"] and t["source"] == "incident"
    assert ("incident", "INC-1") in [(l["kind"], l["ref"]) for l in t["links"]]
    events = [r["event"] for r in env.gk.audit.recent("demo", 50)]
    assert "incident_opened" in events and "incident_closed" in events and env.gk.audit.verify()
    assert env.svc.incidents.open_list("demo") == []


def test_closing_takes_a_multiline_list(env):
    _alert(env)
    env.say(OWNER, "incident close INC-1\n- first\n- second", room=INC)
    assert env.t.get("demo", OWNER, "SY-2")["body"] == "- [ ] first\n- [ ] second"


def test_only_a_maintainer_or_owner_closes_an_incident(env):
    _alert(env)
    env.say(DEP, "incident close INC-1: x", room=INC)
    assert "needs a maintainer or owner" in env.last(INC) and len(env.svc.incidents.open_list("demo")) == 1
    env.say(VIEWER, "incident close INC-1: x", room=INC)
    assert len(env.svc.incidents.open_list("demo")) == 1


def test_closing_with_no_items_makes_no_ticket_and_closing_twice_is_refused(env):
    _alert(env)
    env.say(OWNER, "incident close INC-1", room=INC)
    assert "No follow-ups were named" in env.last(INC) and len(env.t.list("demo", OWNER)["tickets"]) == 1
    env.say(OWNER, "incident close INC-1: again", room=INC)
    assert "already closed" in env.last(INC)
    env.say(OWNER, "incident close INC-9: x", room=INC)
    assert "can't find INC-9" in env.last(INC)


def test_a_closed_incident_lets_the_next_alert_open_a_new_one(env):
    _alert(env)
    env.say(OWNER, "incident close INC-1", room=INC)
    env.clock.t += 700
    _alert(env)
    assert "Incident INC-2 opened" in alerts(env)[-1]


def test_incident_list_and_input_limits(env):
    _alert(env)
    env.say(DEP, "incident list", room=INC)
    assert "INC-1" in env.last(INC)
    env.say(OWNER, "incident close INC-1: " + "; ".join(f"item {i}" for i in range(13)), room=INC)
    assert "at most 12 action items" in env.last(INC) and len(env.svc.incidents.open_list("demo")) == 1


# --- the second person for delete (the spec's rule) ----------------------------------------------------------------------

def test_delete_needs_a_second_person_even_for_an_owner(env):
    env.call(OWNER, "ticket_create", title="doomed")
    r = env.call(OWNER, "ticket_delete", key="SY-1")
    env.say(OWNER, f"approve {r['approval_id']}")
    assert "Denied" in env.last() and env.t.get("demo", OWNER, "SY-1")
    env.say(OSCAR, f"approve {r['approval_id']}")                      # another owner is a second person
    assert "Done: SY-1 deleted" in env.last()


# --- personal desk rooms -----------------------------------------------------------------------------------------------------

def test_username_and_slug():
    assert username_of(ANYA) == "anya" and username_of("@switch-x-owner:localhost") is None
    assert slug("Anya.Dev_1") == "anya-dev-1" and slug("!!!") == "member"


def test_desks_are_private_rooms_with_the_member_and_the_owners(env):
    made, problems = env.svc.desks.create(env.cfg.projects["demo"], OSCAR)
    assert sorted(made) == ["demo-desk-anya", "demo-desk-oscar", "demo-desk-rahul"] and not problems
    posts = [c[2] for c in env.gw.calls if c[0] == "POST"]
    anya = next(b for b in posts if b["name"] == "demo-desk-anya")
    assert anya["channel_type"] == "channel_private" and anya["user_names"] == ["anya", "oscar"] and anya["agent_names"] == ["repo-agent", "gatekeeper"]
    assert anya["bridge_id"] == BRIDGE and anya["group_id"] == "group-1"
    assert env.cfg.desks["demo"][ANYA].startswith("desk-room-") and json.loads(env.desks_file.read_text())["demo"][ANYA] == env.cfg.desks["demo"][ANYA]
    assert env.svc.desks.missing(env.cfg.projects["demo"]) == []
    assert "desk_created" in [r["event"] for r in env.gk.audit.recent("demo", 50)]


def test_a_member_on_another_chat_app_gets_a_desk_there_or_a_clear_problem(env):
    other = "11111111-1111-1111-1111-111111111111"
    drew = f"@switch-discord-{other}-drew:localhost"
    env.cfg.policy.members["demo"][drew] = Role.OWNER
    made, problems = env.svc.desks.create(env.cfg.projects["demo"], OSCAR, [drew, ANYA])
    assert made == ["demo-desk-anya"] and "no room on their chat app" in problems[0]
    env.gw.bridges[OPS] = other                                        # now the ops room is on the other app and the maintainers/incidents rooms are not
    made, problems = env.svc.desks.create(env.cfg.projects["demo"], OSCAR, [drew])
    posted = [c[2] for c in env.gw.calls if c[0] == "POST"][-1]
    assert made == ["demo-desk-drew"] and posted["bridge_id"] == other and posted["user_names"] == ["drew"]        # only owners of that chat app are added


def test_desks_survive_a_restart_and_make_their_rooms_part_of_the_project(env, tmp_path):
    env.svc.desks.create(env.cfg.projects["demo"], OSCAR)
    room = env.cfg.desks["demo"][ANYA]
    env.cfg.desks.clear()
    assert env.cfg.project_for_room(room) is None
    Desks(env.cfg, env.desks_file, env.gk.audit, None).load()
    assert env.cfg.project_for_room(room).name == "demo" and env.cfg.desk_owner(room) == ANYA


def test_one_failed_desk_does_not_stop_the_rest_and_no_gateway_is_a_clear_error(env):
    env.gw.fail = True
    made, problems = env.svc.desks.create(env.cfg.projects["demo"], OSCAR)
    assert made == [] and len(problems) == 3 and "403" in problems[0]
    with pytest.raises(DeskError):
        Desks(env.cfg, env.desks_file, env.gk.audit, None).create(env.cfg.projects["demo"], OSCAR)


def test_the_desks_command_is_for_owners(env):
    env.say(MAINTAINER, "desks create")
    assert "only an owner" in env.last() and not env.cfg.desks
    env.say(OSCAR, "desks")
    assert "0 made, 3 members without one" in env.last()
    env.say(OSCAR, "desks create")
    assert "Created 3 desk room(s)" in env.last() and "Sync from roles" in env.last()


def test_a_desk_answers_only_a_few_commands(env):
    env.svc.desks.create(env.cfg.projects["demo"], OSCAR)
    room = env.cfg.desks["demo"][ANYA]
    env.say(ANYA, "deploy demo-web", room=room)
    assert "personal desk" in env.last(room)
    env.say(ANYA, "whoami", room=room)
    assert "Your id is" in env.last(room)


def test_the_standup_sends_each_member_their_briefing_in_their_desk_or_under_the_standup(env):
    env.svc.desks.create(env.cfg.projects["demo"], OSCAR)
    del env.cfg.desks["demo"][OSCAR]                                    # oscar has no desk
    env.call(OWNER, "ticket_create", title="for anya", assignee="anya", priority="high")
    env.call(OWNER, "ticket_create", title="for oscar", assignee="oscar")
    from shipyard.ticketflow import StandupScheduler
    import datetime as dt
    env.cfg = dataclasses.replace(env.cfg, standup_at="09:00")
    env.svc.cfg = env.cfg
    env.clock.t = dt.datetime(2026, 11, 6, 9, 5, tzinfo=dt.timezone(dt.timedelta(hours=5, minutes=30))).timestamp()
    assert StandupScheduler(env.svc, env.flow).tick() == 1
    desk = env.cfg.desks["demo"][ANYA]
    assert "Briefing for anya" in env.in_room(desk)[0] and "SY-1" in env.in_room(desk)[0]
    maint = env.in_room(MAINT)
    assert maint[0].startswith("Standup for demo") and any("Briefing for oscar" in t and "SY-2" in t for t in maint[1:])
    assert not any("Briefing for rahul" in t for t in maint) and env.in_room(env.cfg.desks["demo"][RAHUL]) == []        # nothing to say: skipped
    assert "Briefing for anya" not in "".join(maint)                                                                   # one person's briefing is not in the shared room


def _access(env):
    return AgentAccess(env.cfg, lambda: None, env.gk.db, env.gk.lock, env.gk.audit)


def test_the_repo_agent_policy_admits_only_the_member_and_the_owners_in_a_desk(env):
    env.svc.desks.create(env.cfg.projects["demo"], OSCAR)
    uid = {ANYA: "u-anya", OSCAR: "u-oscar", RAHUL: "u-rahul"}
    prefix = f"@switch-mattermost-{BRIDGE}-"
    world = {"agents": {"repo-agent": {"id": "a1"}, "ops-agent": {"id": "a2"}, "gatekeeper": {"id": "a3"}},
             "prefixes": {prefix: [{"id": v, "external_username": k[len(prefix):].split(":")[0]} for k, v in uid.items()]}}
    env.cfg = dataclasses.replace(env.cfg, managed_agents=("repo-agent", "ops-agent"), allow_agents=("gatekeeper",))
    acc = AgentAccess(env.cfg, lambda: None, env.gk.db, env.gk.lock, env.gk.audit)
    desired = acc._desired(env.cfg.projects["demo"], world)
    rules = desired["policies"]["repo-agent"]["rules"]
    desk_rule = next(r for r in rules if r["rooms"] == [env.cfg.desks["demo"][ANYA]])
    assert desk_rule["users"] == ["u-anya", "u-oscar"]
    assert not any(isinstance(r["rooms"], list) and env.cfg.desks["demo"][ANYA] in r["rooms"] for r in desired["policies"]["ops-agent"]["rules"])
    for r in rules:
        if isinstance(r["rooms"], list) and r["rooms"] != [env.cfg.desks["demo"][ANYA]] and len(r["rooms"]) > 1:
            assert env.cfg.desks["demo"][ANYA] not in r["rooms"]


# --- GitHub webhooks -----------------------------------------------------------------------------------------------------------

SECRET = b"s" * 32


def sign(body, secret=SECRET):
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def test_signature_check():
    body = b'{"a": 1}'
    assert github_signature_ok(SECRET, body, sign(body))
    assert not github_signature_ok(SECRET, body, sign(body, b"x" * 32)) and not github_signature_ok(SECRET, body, "") and not github_signature_ok(SECRET, body + b" ", sign(body))


@pytest.fixture
def listener():
    got = []
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = serve("c" * 24, lambda p: None, "127.0.0.1", port, SECRET, lambda event, payload: got.append((event, payload)))
    yield got, port
    srv.shutdown()


def send(port, event, payload, signature=None, path="/hooks/github"):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, method="POST",
                                 headers={"X-GitHub-Event": event, "X-Hub-Signature-256": signature if signature is not None else sign(body), "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def wait_for(got, n=1):
    for _ in range(100):
        if len(got) >= n:
            return
        time.sleep(0.02)


def test_the_listener_takes_only_correctly_signed_github_events(listener):
    got, port = listener
    payload = {"action": "opened", "repository": {"full_name": "o/r"}}
    assert send(port, "pull_request", payload) == 202
    wait_for(got)
    assert got == [("pull_request", payload)]
    assert send(port, "pull_request", payload, signature="sha256=" + "0" * 64) == 404 and send(port, "pull_request", payload, signature="") == 404
    assert send(port, "push", payload) == 202 and send(port, "ping", payload) == 202
    time.sleep(0.1)
    assert len(got) == 1


def test_github_webhook_is_off_without_a_secret():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = serve("c" * 24, lambda p: None, "127.0.0.1", port)
    try:
        assert send(port, "pull_request", {}) == 404
    finally:
        srv.shutdown()


def test_webhook_fixtures_drive_the_board_exactly_as_polling_does(env):
    """PR opened, CI, merged, closed: the payload only names the repository; the state is read from GitHub."""
    w = watcher(env)
    env.svc.github_hooks.append(w.on_hook)
    env.call(OWNER, "ticket_create", title="checkout breaks")
    env.call(OWNER, "ticket_create", title="second")
    repo = {"repository": {"full_name": "o/r"}}
    env.gh.set(mkpr(26, "Fixes SY-1", author="depgh"), "red", ("test",))                       # opened, CI red
    env.svc.on_github_hook("pull_request", {"action": "opened", **repo})
    g = env.t.get("demo", OWNER, "SY-1")
    assert g["status"] == "review" and g["links"][0]["meta"]["ci"] == "red"
    env.gh.set(mkpr(26, "Fixes SY-1", author="depgh"), "green")                                 # CI turns green
    env.svc.on_github_hook("check_run", {"action": "completed", **repo})
    assert env.t.get("demo", OWNER, "SY-1")["links"][0]["meta"]["ci"] == "green"
    env.gh.set(dataclasses.replace(mkpr(26, "Fixes SY-1", state="merged", author="depgh"), merge_sha="m" * 40), "green")
    env.svc.on_github_hook("pull_request", {"action": "closed", **repo})                        # merged
    g = env.t.get("demo", OWNER, "SY-1")
    assert g["status"] == "review" and any(e["to"] == "merged in PR #26" for e in g["events"]) and g["links"][0]["meta"]["merge_sha"] == "m" * 40
    env.gh.set(mkpr(27, "Closes SY-2", author="depgh"), "green")
    env.svc.on_github_hook("pull_request", {"action": "opened", **repo})
    assert env.t.get("demo", OWNER, "SY-2")["status"] == "review"
    env.gh.set(mkpr(27, "Closes SY-2", state="closed", author="depgh"), "green")                # closed without merging
    env.svc.on_github_hook("pull_request", {"action": "closed", **repo})
    g = env.t.get("demo", OWNER, "SY-2")
    assert g["status"] == "doing" and any("closed without merging" in c["body"] for c in g["comments"])


def test_a_webhook_for_another_repository_is_ignored(env):
    w = watcher(env)
    env.call(OWNER, "ticket_create", title="x")
    env.gh.set(mkpr(30, "Fixes SY-1"), "green")
    w.on_hook("pull_request", {"repository": {"full_name": "evil/other"}})
    w.on_hook("pull_request", {})
    assert env.t.get("demo", OWNER, "SY-1")["status"] == "todo"
