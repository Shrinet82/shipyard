"""SBOM reports: safe artifact handling, parsing, diff, trust and the deploy decision.

CI produces the SBOM (Syft) and the scan (Grype). We only read them, compare with the last release, and decide.
We have no CVE database and no scoring: every severity is the scanner's. Everything inside an artifact is
untrusted text: zips are size- and name-checked, JSON is bounded, and anything that reaches chat is redacted,
defused and fenced.
"""
from __future__ import annotations

import html as _html
import io
import json
import re
import zipfile
import zlib
from dataclasses import dataclass
from typing import Any, Iterable

from .evidence import defuse, redact

SEVERITIES = ("critical", "high", "medium", "low")
MAX_JSON_BYTES = 40 * 1024 * 1024
MAX_ZIP_FILES = 3
MAX_PACKAGES = 20_000
MAX_FINDINGS = 20_000
EXPECTED_ARTIFACTS = {"sbom-spdx": "spdx", "sbom-cyclonedx": "cyclonedx", "grype-report": "scan"}
COMMIT = re.compile(r"^[0-9a-f]{7,40}$")


class SbomError(ValueError):
    """The artifact is unusable or unsafe; the message is safe to show."""


# --- safe reading ---------------------------------------------------------------------

def read_artifact_json(blob: bytes) -> bytes:
    """The one JSON file inside an artifact zip, or SbomError. Declared sizes are never trusted."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except (zipfile.BadZipFile, ValueError):
        raise SbomError("the artifact is not a zip file") from None
    infos = zf.infolist()
    if len(infos) != 1:
        raise SbomError(f"the artifact must hold exactly one file, it holds {len(infos)}")
    info = infos[0]
    name = info.filename
    if info.is_dir() or name.startswith("/") or ".." in name.split("/") or "\\" in name or "\x00" in name:
        raise SbomError("the artifact has an unsafe file name")
    if (info.external_attr >> 16) & 0o170000 == 0o120000:
        raise SbomError("the artifact holds a symbolic link")
    if info.flag_bits & 0x1:
        raise SbomError("the artifact is encrypted")
    if not name.endswith(".json"):
        raise SbomError("the artifact file is not JSON")
    if info.file_size > MAX_JSON_BYTES:
        raise SbomError("the artifact file is too large")
    try:
        with zf.open(info) as f:
            data = f.read(MAX_JSON_BYTES + 1)      # a lying header cannot make us read more
    except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError):
        raise SbomError("the artifact is corrupt or uses an unsupported format") from None
    if len(data) > MAX_JSON_BYTES:
        raise SbomError("the artifact file is too large")
    return data


def load_json(data: bytes) -> Any:
    try:
        return json.loads(data)
    except (ValueError, RecursionError):
        raise SbomError("the file is not valid, reasonably shaped JSON") from None


# --- packages ---------------------------------------------------------------------------

_PURL = re.compile(r"^pkg:([A-Za-z0-9.+-]+)/(?:([^/@?#]+(?:/[^/@?#]+)*)/)?([^/@?#]+)(?:@([^?#]*))?")


def purl_key(purl: str | None) -> tuple[str, str] | None:
    """(key without version, version) from a package URL, or None."""
    m = _PURL.match(purl or "")
    if not m:
        return None
    typ, ns, name, ver = m.groups()
    return f"{typ}/{name}", (ver or "")


def _pkg_map(rows: Iterable[tuple[str, str, str | None]]) -> dict[str, list[str]]:
    out: dict[str, set[str]] = {}
    for count, (name, version, purl) in enumerate(rows):
        if count >= MAX_PACKAGES:
            raise SbomError("the SBOM lists too many packages")
        pk = purl_key(purl)
        key, ver = pk if pk else (f"unknown/{name}", version)
        out.setdefault(key, set()).add(ver or version or "")
    return {k: sorted(v) for k, v in sorted(out.items())}


def parse_sbom(doc: Any) -> tuple[str, dict[str, list[str]]]:
    """(format label, {package key: [versions]}) from an SPDX or CycloneDX JSON document."""
    if not isinstance(doc, dict):
        raise SbomError("the SBOM is not a JSON object")
    if str(doc.get("spdxVersion", "")).startswith("SPDX-"):
        rows = []
        for p in doc.get("packages") or []:
            purl = next((r.get("referenceLocator") for r in p.get("externalRefs", []) if r.get("referenceType") == "purl"), None)
            rows.append((str(p.get("name", "?")), str(p.get("versionInfo", "")), purl))
        return str(doc["spdxVersion"]), _pkg_map(rows)
    if doc.get("bomFormat") == "CycloneDX":
        rows = [(str(c.get("name", "?")), str(c.get("version", "")), c.get("purl"))
                for c in doc.get("components") or [] if c.get("type") != "file"]
        return f"CycloneDX {doc.get('specVersion', '')}".strip(), _pkg_map(rows)
    raise SbomError("the SBOM is neither SPDX nor CycloneDX JSON")


# --- findings ---------------------------------------------------------------------------

def parse_grype(doc: Any) -> list[dict[str, Any]]:
    """Findings from a Grype JSON report: id, severity, package, installed and fixed versions."""
    if not isinstance(doc, dict) or not isinstance(doc.get("matches"), list):
        raise SbomError("the scan report is not a Grype report")
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for i, m in enumerate(doc["matches"]):
        if i >= MAX_FINDINGS:
            raise SbomError("the scan report lists too many findings")
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        sev = str(v.get("severity", "unknown")).lower()
        sev = sev if sev in SEVERITIES else "negligible" if sev == "negligible" else "unknown"
        pk = purl_key(a.get("purl"))
        key = pk[0] if pk else f"{a.get('type', 'unknown')}/{a.get('name', '?')}"
        entry = {"id": str(v.get("id", "?")), "severity": sev, "key": key, "name": str(a.get("name", "?")),
                 "version": str(a.get("version", "")), "fixed": [str(x) for x in (v.get("fix") or {}).get("versions", [])][:6],
                 "url": str(v.get("dataSource", ""))[:200], "new": False}
        seen[(entry["id"], key, entry["version"])] = entry
    return sorted(seen.values(), key=lambda e: (SEVERITIES.index(e["severity"]) if e["severity"] in SEVERITIES else 9, e["id"], e["key"]))


# --- diff and report ------------------------------------------------------------------------

def diff_packages(old: dict[str, list[str]] | None, new: dict[str, list[str]]) -> dict[str, list[Any]]:
    if old is None:
        return {"added": [], "removed": [], "upgraded": []}
    added = [[k, v] for k in new if k not in old for v in new[k]]
    removed = [[k, v] for k in old if k not in new for v in old[k]]
    upgraded = [[k, ", ".join(old[k]), ", ".join(new[k])] for k in new if k in old and old[k] != new[k]]
    return {"added": added, "removed": removed, "upgraded": upgraded}


def evaluate_trust(*, run: dict[str, Any] | None, repo: str, sha: str, workflow: str, artifacts: set[str],
                   pr_files: list[str] | None) -> dict[str, Any]:
    """May we believe this SBOM? It came from CI that the change under review could have edited."""
    reasons: list[str] = []
    if run is None:
        return {"ok": False, "reasons": ["no CI run was found for this commit"]}
    if (run.get("head_repository") or {}).get("full_name", "").lower() != repo.lower():
        reasons.append("the CI run is from a fork")
    if run.get("head_sha") != sha:
        reasons.append("the CI run is for a different commit")
    if not str(run.get("path", "")).startswith(workflow):
        reasons.append(f"the CI run is not the expected workflow ({workflow})")
    if run.get("event") not in ("pull_request", "push"):
        reasons.append("the CI run was not started by a push or pull request")
    if run.get("conclusion") != "success":
        reasons.append("the CI run did not succeed")
    if not {"sbom-spdx", "grype-report"} <= artifacts:
        reasons.append("the expected artifacts are missing")
    if pr_files and any(f.startswith(".github/workflows/") for f in pr_files):
        reasons.append("this change edits .github/workflows/, so the SBOM it produced cannot be trusted until an owner reviews it")
    return {"ok": not reasons, "reasons": reasons}


def build_report(*, commit: str, repo: str, pr: int | None, ref: str, run: dict[str, Any] | None, workflow: str,
                 sbom_doc: Any, grype_doc: Any, baseline: dict[str, Any] | None, trust: dict[str, Any], now: float) -> dict[str, Any]:
    fmt, packages = parse_sbom(sbom_doc)
    findings = parse_grype(grype_doc)
    known = {(f["id"], f["key"]) for f in (baseline or {}).get("findings", [])}
    for f in findings:
        f["new"] = (f["id"], f["key"]) not in known
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    blocking = [f for f in findings if f["severity"] == "critical" and f["new"]]
    report = {
        "commit": commit, "repo": repo, "pr": pr, "ref": ref, "run_id": (run or {}).get("id"), "workflow": workflow,
        "collected_at": now, "format": fmt, "package_count": sum(len(v) for v in packages.values()),
        "packages": packages, "findings": findings, "counts": counts,
        "fixable": sum(1 for f in findings if f["fixed"]),
        "baseline": (baseline or {}).get("commit"),
        "diff": diff_packages((baseline or {}).get("packages"), packages),
        "trust": trust, "blocking": blocking, "reasons": list(trust.get("reasons", [])),
    }
    report["decision"] = "unverified" if not trust["ok"] else "blocked" if blocking else "clear"
    return report


def rebase(report: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
    """The same report judged against a (possibly newer) baseline: what is "new" depends on what is deployed now."""
    out = dict(report)
    findings = [dict(f) for f in report["findings"]]
    known = {(f["id"], f["key"]) for f in (baseline or {}).get("findings", [])}
    for f in findings:
        f["new"] = (f["id"], f["key"]) not in known
    blocking = [f for f in findings if f["severity"] == "critical" and f["new"]]
    out.update(findings=findings, blocking=blocking, baseline=(baseline or {}).get("commit"),
               diff=diff_packages((baseline or {}).get("packages"), report["packages"]))
    trust = report.get("trust") or {"ok": False, "reasons": ["no trust record"]}
    out["decision"] = "unverified" if not trust["ok"] else "blocked" if blocking else "clear"
    if report.get("decision") == "no_sbom":
        out["decision"] = "no_sbom"
    return out


def gate_reasons(report: dict[str, Any] | None) -> list[str]:
    """Why a forward deploy of this commit must wait for an owner, in words for chat. Empty = go ahead."""
    if report is None or report["decision"] == "no_sbom":
        return ["there is no SBOM for this commit" + (f" ({report['reasons'][0]})" if report and report.get("reasons") else "")]
    if report["decision"] == "clear":
        return []
    if report["decision"] == "unverified":
        return ["the SBOM is unverified: " + "; ".join(report["reasons"])]
    ids = ", ".join(f"{f['id']} in {f['key']} {f['version']}" for f in report["blocking"][:5])
    return [f"{len(report['blocking'])} new critical CVE{'s' if len(report['blocking']) != 1 else ''}: {ids}"]


# --- text for people ------------------------------------------------------------------------------

def _t(text: Any, limit: int = 90) -> str:
    return defuse(redact(str(text)))[:limit]


def summary(report: dict[str, Any], label: str | None = None) -> str:
    """A short Markdown summary for chat."""
    c, d = report["counts"], report["diff"]
    where = label or (f"PR #{report['pr']}" if report.get("pr") else f"commit {report['commit'][:7]}")
    head = f"SBOM for {_t(where)} (commit {report['commit'][:7]}): {report['package_count']} packages, {_t(report['format'])}."
    if report["baseline"]:
        head += (f" Since {report['baseline'][:7]}: {len(d['added'])} added, {len(d['removed'])} removed, "
                 f"{len(d['upgraded'])} upgraded.")
    else:
        head += " No earlier release to compare with."
    new_crit = len(report["blocking"])
    sev = (f"CVEs: {c['critical']} critical" + (f" ({new_crit} new)" if new_crit else "") + f", {c['high']} high, "
           f"{c['medium']} medium, {c['low']} low; {report['fixable']} have a fixed version available.")
    decision = report.get("decision", "clear")
    why = gate_reasons(report)
    if decision == "blocked":
        tail = "Decision: deploy blocked, owner override required. " + _t(why[0], 300)
    elif decision == "unverified":
        tail = "Decision: deploy blocked, SBOM unverified. " + _t(why[0], 300)
    elif decision == "no_sbom":
        tail = "Decision: deploy blocked, no SBOM. " + _t(why[0], 300)
    else:
        tail = "Decision: clear to deploy."
    return "\n".join([head, sev, tail])


def render_html(report: dict[str, Any]) -> str:
    """A standalone report page. Every value is escaped; the page is served with a strict CSP."""
    e = lambda v: _html.escape(str(v), quote=True)  # noqa: E731
    c = report["counts"]
    rows = "".join(
        f"<tr><td>{e(f['id'])}</td><td class='sev {e(f['severity'])}'>{e(f['severity'])}{' · new' if f['new'] else ''}</td>"
        f"<td>{e(f['key'])}</td><td>{e(f['version'])}</td><td>{e(', '.join(f['fixed']) or 'not fixed yet')}</td></tr>"
        for f in report["findings"][:400])
    d = report["diff"]
    changes = ([f"<li class='add'>+ {e(k)} {e(v)}</li>" for k, v in d["added"][:200]] +
               [f"<li class='rem'>− {e(k)} {e(v)}</li>" for k, v in d["removed"][:200]] +
               [f"<li class='up'>↑ {e(k)} {e(a)} → {e(b)}</li>" for k, a, b in d["upgraded"][:200]])
    trust = "".join(f"<li>{e(r)}</li>" for r in report["reasons"]) or "<li>All trust checks passed.</li>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>SBOM {e(report['commit'][:7])}</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;margin:32px;color:#111827;max-width:1000px}}h1{{font-size:22px}}
.tiles span{{display:inline-block;margin:0 14px 8px 0;padding:8px 12px;border:1px solid #E2E5EA;border-radius:8px}}
table{{border-collapse:collapse;width:100%}}td,th{{border-top:1px solid #E2E5EA;padding:6px 8px;text-align:left}}
.sev.critical{{color:#B42318;font-weight:700}}.sev.high{{color:#9A5B00;font-weight:600}}.add{{color:#137A3B}}.rem{{color:#B42318}}.up{{color:#9A5B00}}
code{{font-family:ui-monospace,monospace}}</style></head><body>
<h1>SBOM report <code>{e(report['commit'][:12])}</code> · {e(report['decision'])}</h1>
<p>{e(report['repo'])} · {e(report['format'])} · {e(report['package_count'])} packages · baseline {e((report['baseline'] or 'none')[:12])}</p>
<div class="tiles"><span>Critical <b>{c['critical']}</b></span><span>High <b>{c['high']}</b></span><span>Medium <b>{c['medium']}</b></span><span>Low <b>{c['low']}</b></span></div>
<h2>Where this came from</h2><ul>{trust}</ul>
<h2>Changes since the last release</h2><ul>{''.join(changes) or '<li>None.</li>'}</ul>
<h2>Vulnerabilities (from the CI scan report)</h2>
<table><tr><th>Id</th><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed in</th></tr>{rows}</table>
<p>Severities are the scanner's, as CI produced them.</p></body></html>"""
