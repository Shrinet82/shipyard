"""Change shipyard.yaml from a command (connect kubernetes, github-app, connect signoz) without breaking it.

The file is read, changed in memory, checked by the real config loader, saved with a backup next to it (mode 0600), and only then replaced.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable

import yaml

from .config import load_config


class ConfigEditError(Exception):
    pass


def edit_config(path: str | Path, change: Callable[[dict[str, Any]], None], backup: bool = True) -> Path:
    path = Path(os.path.expanduser(str(path)))
    if not path.exists():
        raise ConfigEditError(f"{path} does not exist; run the installer first")
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigEditError(f"{path} is not valid YAML: {exc}") from None
    change(raw)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(yaml.safe_dump(raw, sort_keys=False))
        os.chmod(tmp, 0o600)
        try:
            load_config(tmp)                                           # refuse a result Shipyard cannot read
        except Exception as exc:                                       # noqa: BLE001 - any failure means the edit is bad
            raise ConfigEditError(f"the change would break the config ({exc}); nothing was written") from None
        if backup:
            shutil.copy2(path, str(path) + ".bak")
            os.chmod(str(path) + ".bak", 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return path


def project_of(raw: dict[str, Any], name: str | None) -> tuple[str, dict[str, Any]]:
    projects = raw.get("projects") or {}
    if not projects:
        raise ConfigEditError("the config has no project")
    name = name or next(iter(projects))
    if name not in projects:
        raise ConfigEditError(f"there is no project {name!r} (has: {', '.join(projects)})")
    return name, projects[name]


def set_github(raw: dict[str, Any], project: str | None, *, app_id: str, installation: str, key_file: str, repo: str, deploy: str | None = None) -> None:
    _, p = project_of(raw, project)
    raw["github"] = {**(raw.get("github") or {}), "app_id": app_id, "installation_id": installation, "private_key_file": key_file, "poll_seconds": 60}
    p["repo"] = {**(p.get("repo") or {}), "name": repo, "required_checks": (p.get("repo") or {}).get("required_checks", ["test", "sbom"]),
                 "merge_method": "squash", "branch": (p.get("repo") or {}).get("branch", "main"), **({"app": deploy} if deploy else {})}
