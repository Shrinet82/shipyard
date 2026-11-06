import os
import textwrap

import pytest
import yaml

from shipyard.confedit import ConfigEditError, edit_config, project_of, set_github
from shipyard.config import load_config

BASE = """
projects:
  demo:
    rooms: {ops: [r1], maintainers: [r2]}
    apps: {demo-web: web-uuid}
    members: {}
actions:
  coolify.status: read
"""


@pytest.fixture
def conf(tmp_path):
    f = tmp_path / "shipyard.yaml"
    f.write_text(textwrap.dedent(BASE))
    return f


def test_edit_keeps_a_backup_and_writes_privately(conf):
    original = conf.read_text()
    edit_config(conf, lambda raw: raw["projects"]["demo"]["apps"].update({"other": "u2"}))
    assert yaml.safe_load(conf.read_text())["projects"]["demo"]["apps"] == {"demo-web": "web-uuid", "other": "u2"}
    assert (conf.parent / "shipyard.yaml.bak").read_text() == original
    assert oct(conf.stat().st_mode & 0o777) == "0o600" and oct((conf.parent / "shipyard.yaml.bak").stat().st_mode & 0o777) == "0o600"
    assert [p.name for p in conf.parent.iterdir()] == ["shipyard.yaml", "shipyard.yaml.bak"]


def test_a_change_that_would_break_the_config_is_refused_and_nothing_changes(conf):
    before = conf.read_text()
    with pytest.raises(ConfigEditError, match="would break"):
        edit_config(conf, lambda raw: raw["projects"].clear() or raw.update({"projects": "nonsense"}))
    assert conf.read_text() == before and [p.name for p in conf.parent.iterdir()] == ["shipyard.yaml"]


def test_missing_and_damaged_files(tmp_path):
    with pytest.raises(ConfigEditError, match="does not exist"):
        edit_config(tmp_path / "nope.yaml", lambda raw: None)
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [unclosed")
    with pytest.raises(ConfigEditError, match="not valid YAML"):
        edit_config(bad, lambda raw: None)


def test_set_github_adds_the_app_and_the_repo(conf):
    edit_config(conf, lambda raw: set_github(raw, None, app_id="55", installation="66", key_file="/k.pem", repo="o/r", deploy="demo-web"))
    cfg = load_config(conf)
    assert cfg.github.app_id == "55" and cfg.github.installation_id == "66"
    assert cfg.projects["demo"].repo.name == "o/r" and cfg.projects["demo"].repo.app == "demo-web"
    assert cfg.projects["demo"].repo.required_checks == ("test", "sbom")
    with pytest.raises(ConfigEditError, match="no project"):
        project_of({"projects": {"demo": {}}}, "other")
