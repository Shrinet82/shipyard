"""Room sync: every chat app the project is used on gets the whole set of rooms."""
import dataclasses
import json

import pytest
from test_board_dashboard import api  # noqa: F401  (the dashboard fixture)
from test_board_flow import DEP, INC, MAINT, MAINTAINER, OPS, OWNER, VIEWER, env as board_env  # noqa: F401
from test_spec_gaps import ANYA, BRIDGE, OSCAR, env  # noqa: F401  (the fixture, with desks and incidents)

from shipyard.policy import Role
from shipyard.roomsync import RoomSync, RoomSyncError

DISCORD = "11111111-1111-1111-1111-111111111111"
DREW = f"@switch-discord-{DISCORD}-drew:localhost"
D_OPS, D_PRS = "d-ops", "d-prs"


class World:
    """A fake Switch: the rooms, the two chat apps and the agents."""

    def __init__(self):
        self.rooms = [{"id": r, "name": n, "bridge_id": BRIDGE, "bridge_type": "mattermost", "group_id": None} for r, n in ((OPS, "demo-ops"), (MAINT, "demo-maintainers"), (INC, "demo-incidents"))]
        self.rooms += [{"id": D_OPS, "name": "ops-base", "bridge_id": DISCORD, "bridge_type": "discord", "group_id": "g-d"}, {"id": D_PRS, "name": "demo-prs", "bridge_id": DISCORD, "bridge_type": "discord", "group_id": "g-d"}]
        self.apps = [{"bridge_id": BRIDGE, "bridge_type": "mattermost", "display_name": "Mattermost"}, {"bridge_id": DISCORD, "bridge_type": "discord", "display_name": "ShipYard"}]
        self.agents = [{"id": "a-ops", "name": "ops-agent"}, {"id": "a-repo", "name": "repo-agent"}, {"id": "a-gk", "name": "gatekeeper"}]
        self.calls, self.fail, self.n = [], False, 0

    def call(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "GET" and path == "/rooms":
            return 200, self.rooms
        if method == "GET" and path == "/collaborations":
            return 200, self.apps
        if method == "GET" and path == "/agents":
            return 200, self.agents
        if method == "GET" and path.startswith("/rooms/"):
            r = next(x for x in self.rooms if x["id"] == path.rsplit("/", 1)[1])
            return 200, {"bridge_id": r["bridge_id"], "group_id": r["group_id"]}
        if method == "POST" and path == "/rooms":
            if self.fail:
                return 403, "no"
            self.n += 1
            room = {"id": f"new-{self.n}", "name": body["name"], "bridge_id": body["bridge_id"], "bridge_type": "x", "group_id": body.get("group_id")}
            self.rooms.append(room)
            return 201, {"id": room["id"]}
        if method == "POST" and path.endswith("/agents"):
            return 200, {}
        return 404, "?"


@pytest.fixture
def sync(env, tmp_path):  # noqa: F811
    w = World()
    p = env.cfg.projects["demo"]
    env.cfg.projects["demo"] = dataclasses.replace(p, ops_rooms=p.ops_rooms | {D_OPS}, maintainer_rooms=p.maintainer_rooms | {D_PRS})
    env.cfg.policy.members["demo"][DREW] = Role.OWNER
    env.svc.names[DREW] = "drew"
    env.world, env.synced = w, []
    from shipyard.desks import Desks
    env.svc.desks = Desks(env.cfg, tmp_path / "desks2.json", env.gk.audit, lambda: w)
    env.rooms_file = tmp_path / "rooms.json"
    env.rs = RoomSync(env.cfg, env.rooms_file, env.gk.audit, lambda: w, env.svc.desks, lambda project, actor: env.synced.append((project.name, actor)))
    env.svc.roomsync = env.rs
    return env


def test_plan_finds_what_discord_is_missing_and_nothing_on_mattermost(sync):
    plan = sync.rs.plan(sync.cfg.projects["demo"])
    assert [(i["app"], i["kind"], i["op"], i["name"], i["group"]) for i in plan] == [("ShipYard", "incidents", "create", "demo-incidents", "g-d")]


def test_a_room_switch_already_has_by_that_name_is_adopted_not_duplicated(sync):
    sync.world.rooms.append({"id": "old-inc", "name": "demo-incidents", "bridge_id": DISCORD, "bridge_type": "discord", "group_id": None})
    plan = sync.rs.plan(sync.cfg.projects["demo"])
    assert plan[0]["op"] == "adopt" and plan[0]["room_id"] == "old-inc"
    out = sync.rs.apply(sync.cfg.projects["demo"], OWNER)
    assert out["rooms"] == ["#demo-incidents (ShipYard)"] and not [c for c in sync.world.calls if c[:2] == ("POST", "/rooms") and c[2]["name"] == "demo-incidents"]
    assert ("POST", "/rooms/old-inc/agents", {"agent_ids": ["a-ops", "a-gk"]}) in sync.world.calls


def test_apply_creates_the_room_through_switch_listens_in_it_and_remembers_it(sync):
    out = sync.rs.apply(sync.cfg.projects["demo"], OWNER)
    assert out["rooms"] == ["#demo-incidents (ShipYard)"] and not out["problems"]
    post = next(c[2] for c in sync.world.calls if c[:2] == ("POST", "/rooms"))
    assert post == {"name": "demo-incidents", "description": "Alerts with real log evidence, and the Ops Agent's diagnosis.", "agent_names": ["ops-agent", "gatekeeper"],
                    "bridge_id": DISCORD, "group_id": "g-d"}
    p = sync.cfg.projects["demo"]
    assert "new-1" in p.incident_rooms and sync.cfg.project_for_room("new-1").name == "demo" and p.room_names["new-1"] == "#demo-incidents (ShipYard)"
    assert json.loads(sync.rooms_file.read_text()) == {"demo": {"incidents": {"new-1": "#demo-incidents (ShipYard)"}}}
    assert "rooms.sync" in [r["action"] for r in sync.gk.audit.recent("demo", 50)] and sync.gk.audit.verify()
    assert sync.rs.plan(sync.cfg.projects["demo"]) == []                       # a second run has nothing to do
    assert sync.rs.apply(sync.cfg.projects["demo"], OWNER)["rooms"] == []


def test_apply_also_makes_the_desks_on_each_members_own_app_and_syncs_agent_access(sync):
    out = sync.rs.apply(sync.cfg.projects["demo"], OWNER)
    assert "demo-desk-drew" in out["desks"] and "demo-desk-anya" in out["desks"] and out["agent_access_synced"] is True
    assert sync.synced == [("demo", OWNER)]
    desk = next(c[2] for c in sync.world.calls if c[0] == "POST" and c[1] == "/rooms" and c[2]["name"] == "demo-desk-drew")
    assert desk["bridge_id"] == DISCORD and desk["user_names"] == ["drew"]


def test_the_overlay_is_applied_again_after_a_restart(sync, tmp_path):
    sync.rs.apply(sync.cfg.projects["demo"], OWNER)
    fresh = dataclasses.replace(sync.cfg.projects["demo"], incident_rooms=frozenset({INC}))
    sync.cfg.projects["demo"] = fresh
    assert "new-1" not in fresh.incident_rooms
    RoomSync(sync.cfg, sync.rooms_file, None, None).load()
    assert "new-1" in sync.cfg.projects["demo"].incident_rooms and sync.cfg.projects["demo"].room_names["new-1"] == "#demo-incidents (ShipYard)"


def test_a_refusal_from_switch_is_reported_and_nothing_is_remembered(sync):
    sync.world.fail = True
    out = sync.rs.apply(sync.cfg.projects["demo"], OWNER)
    assert out["rooms"] == [] and "403" in out["problems"][0] and not sync.rooms_file.exists()
    with pytest.raises(RoomSyncError):
        RoomSync(sync.cfg, sync.rooms_file, None, None).plan(sync.cfg.projects["demo"])


# --- alerts and diagnosis with two chat apps -------------------------------------------------------------------------------------

def _two_apps(sync):
    sync.rs.apply(sync.cfg.projects["demo"], OWNER)
    sync.in_room("new-1")
    return "new-1"


def test_an_alert_asks_the_agent_once_and_the_diagnosis_is_copied_to_the_other_apps(sync):
    new = _two_apps(sync)
    sync.svc.on_coolify_event({"event": "restart_limit_reached", "application_uuid": "web-uuid", "restart_count": 10, "max_restart_count": 10})
    asks = [(r, t) for r, t in sync.posts if t.startswith("ALERT") and "diagnose" in t]
    assert len(asks) == 1 and asks[0][0] == min(sync.cfg.projects["demo"].incident_rooms)           # one request, in the first incidents room
    main = asks[0][0]
    other = new if main != new else INC
    assert any(t.startswith("ALERT") and "copied here" in t for t in sync.in_room(other)) and any("copied here" in t for t in sync.in_room(OPS))
    sync.svc.handle_event({"type": "message", "room_id": main, "payload": {"message_id": "x1", "sender": "@agent:localhost", "sender_name": "ops-agent", "sender_kind": None,
                                                                         "body": "The app restarts in a loop; roll it back.", "addressed": False}})
    for room in (other, OPS):
        assert any(t.startswith("Ops Agent's diagnosis") and "roll it back" in t for t in sync.in_room(room))
    assert not any(t.startswith("Ops Agent's diagnosis") for t in sync.in_room(main))                # not echoed back where it was said
    assert "roll it back" in sync.t.get("demo", OWNER, "SY-1")["body"]


# --- the dashboard and the chat command --------------------------------------------------------------------------------------------

def test_the_dashboard_previews_and_syncs_for_owners_only(sync, api):  # noqa: F811
    api.dash.roomsync = sync.rs
    assert api.api("GET", "/api/me")[1]["roomsync"] is True
    for who in ("viewer", "dep", "maint"):
        assert api.api("POST", "/api/rooms/preview", who, {})[0] == 403 and api.api("POST", "/api/rooms/sync", who, {})[0] == 403
    s, d = api.api("POST", "/api/rooms/preview", "owner", {})
    assert s == 200 and d["changes"][0] == {"op": "+", "agent": "ShipYard", "text": "#demo-incidents: incidents room"} and any(c["agent"] == "desks" for c in d["changes"])
    assert not [c for c in sync.world.calls if c[:2] == ("POST", "/rooms")]                          # a preview creates nothing
    s, d = api.api("POST", "/api/rooms/sync", "owner", {})
    assert s == 200 and d["rooms"] == ["#demo-incidents (ShipYard)"] and d["agent_access_synced"] is True
    api.dash.roomsync = None
    assert api.api("POST", "/api/rooms/preview", "owner", {})[0] == 404


def test_the_rooms_command_is_for_owners_and_previews_before_it_syncs(sync):
    sync.say(MAINTAINER, "rooms")
    assert "only an owner" in sync.last()
    sync.say(OWNER, "rooms")
    assert "Missing: ShipYard: #demo-incidents: incidents room" in sync.last() and not [c for c in sync.world.calls if c[:2] == ("POST", "/rooms")]
    sync.say(OWNER, "rooms sync")
    assert "Created #demo-incidents (ShipYard)" in sync.last() and "Agent access was synced" in sync.last()
    sync.say(OWNER, "rooms")
    assert "Every chat app has the full set of rooms" in sync.last() or "Missing: desks" in sync.last()
