import io
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from shipyard import sbom
from shipyard.sbom import SbomError
from shipyard.sbomstore import SbomStore

FIX = Path(__file__).parent / "fixtures" / "base"
SHA = "a1b2c3d4e5f6" + "0" * 28
SHA2 = "b2c3d4e5f6a1" + "0" * 28
WF = ".github/workflows/ci.yml"


def zipped(files: dict[str, bytes], **kw) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, **kw) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def run(**kw):
    base = {"id": 7, "head_sha": SHA, "head_repository": {"full_name": "o/r"}, "path": WF + "@refs/heads/main",
            "event": "pull_request", "conclusion": "success", "status": "completed", "run_number": 3}
    base.update(kw)
    return base


def trust(**kw):
    args = dict(run=run(), repo="O/R", sha=SHA, workflow=WF, artifacts={"sbom-spdx", "sbom-cyclonedx", "grype-report"}, pr_files=["app.py"])
    args.update(kw)
    return sbom.evaluate_trust(**args)


def grype(*matches):
    return {"matches": [{"vulnerability": {"id": i, "severity": s, "fix": {"versions": fix}, "dataSource": f"https://x/{i}"},
                         "artifact": {"name": n, "version": v, "type": "python", "purl": f"pkg:pypi/{n}@{v}"}}
                        for i, s, n, v, fix in matches]}


def spdx(pkgs):
    return {"spdxVersion": "SPDX-2.3", "packages": [
        {"name": n, "versionInfo": v, "externalRefs": [{"referenceType": "purl", "referenceLocator": f"pkg:pypi/{n}@{v}"}]}
        for n, v in pkgs]}


def report(pkgs, matches, baseline=None, tr=None, commit=SHA):
    return sbom.build_report(commit=commit, repo="o/r", pr=None, ref="main", run=run(), workflow=WF, sbom_doc=spdx(pkgs),
                             grype_doc=grype(*matches), baseline=baseline, trust=tr or trust(), now=1.0)


# --- real files --------------------------------------------------------------------------------------

def test_real_ci_output_parses():
    fmt, pkgs = sbom.parse_sbom(json.loads((FIX / "sbom.spdx.json").read_text()))
    assert fmt.startswith("SPDX-") and len(pkgs) >= 40
    findings = sbom.parse_grype(json.loads((FIX / "grype.json").read_text()))
    assert findings and all(f["severity"] in sbom.SEVERITIES + ("negligible", "unknown") for f in findings)
    assert [f["severity"] for f in findings] == sorted([f["severity"] for f in findings], key=lambda s: sbom.SEVERITIES.index(s) if s in sbom.SEVERITIES else 9)


def test_real_report_has_no_critical_and_is_clear():
    r = sbom.build_report(commit=SHA, repo="o/r", pr=None, ref="main", run=run(), workflow=WF,
                          sbom_doc=json.loads((FIX / "sbom.spdx.json").read_text()), grype_doc=json.loads((FIX / "grype.json").read_text()),
                          baseline=None, trust=trust(), now=1.0)
    assert r["counts"]["critical"] == 0 and r["decision"] == "clear" and sbom.gate_reasons(r) == []


# --- artifact zips ---------------------------------------------------------------------------------

def test_zip_ok():
    assert sbom.read_artifact_json(zipped({"a.json": b"{}"})) == b"{}"


@pytest.mark.parametrize("files", [
    {"../evil.json": b"{}"}, {"/etc/x.json": b"{}"}, {"a/../../b.json": b"{}"}, {"a\\b.json": b"{}"},
    {"a.json": b"{}", "b.json": b"{}"}, {}, {"a.txt": b"{}"}, {"dir/": b""},
])
def test_zip_refused(files):
    with pytest.raises(SbomError):
        sbom.read_artifact_json(zipped(files))


def test_zip_not_a_zip_and_nested_archive():
    with pytest.raises(SbomError):
        sbom.read_artifact_json(b"PK this is not a zip")
    with pytest.raises(SbomError):
        sbom.read_artifact_json(zipped({"inner.zip": zipped({"a.json": b"{}"})}))


def test_zip_bomb_by_real_size(monkeypatch):
    monkeypatch.setattr(sbom, "MAX_JSON_BYTES", 1000)
    with pytest.raises(SbomError):
        sbom.read_artifact_json(zipped({"a.json": b"[" + b"0," * 5000 + b"0]"}))


def test_zip_lying_header_cannot_make_us_read_more(monkeypatch):
    monkeypatch.setattr(sbom, "MAX_JSON_BYTES", 1000)
    blob = bytearray(zipped({"a.json": b"[" + b"0," * 5000 + b"0]"}))
    # forge the declared uncompressed size in both headers to something small
    for sig, off in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        i = blob.find(sig)
        blob[i + off:i + off + 4] = (10).to_bytes(4, "little")
    with pytest.raises(SbomError):
        sbom.read_artifact_json(bytes(blob))


def test_zip_symlink_and_encrypted_refused():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        zi = zipfile.ZipInfo("a.json")
        zi.external_attr = (0o120777) << 16
        z.writestr(zi, "/etc/passwd")
    with pytest.raises(SbomError, match="symbolic"):
        sbom.read_artifact_json(buf.getvalue())
    blob = bytearray(zipped({"a.json": b"{}"}))
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = blob.find(sig)
        blob[i + off] |= 1
    with pytest.raises(SbomError, match="encrypted"):
        sbom.read_artifact_json(bytes(blob))


def test_json_garbage_and_deep_nesting():
    with pytest.raises(SbomError):
        sbom.load_json(b"not json")
    with pytest.raises(SbomError):
        sbom.load_json(b"[" * 200000 + b"]" * 200000)


def test_wrong_shapes():
    for bad in ([], "x", {"x": 1}, None):
        with pytest.raises(SbomError):
            sbom.parse_sbom(bad)
    for bad in ([], {"matches": "x"}, {"x": 1}):
        with pytest.raises(SbomError):
            sbom.parse_grype(bad)


def test_huge_package_list_refused(monkeypatch):
    monkeypatch.setattr(sbom, "MAX_PACKAGES", 100)
    with pytest.raises(SbomError):
        sbom.parse_sbom(spdx([(f"p{i}", "1") for i in range(101)]))
    monkeypatch.setattr(sbom, "MAX_FINDINGS", 5)
    with pytest.raises(SbomError):
        sbom.parse_grype(grype(*[(f"CVE-{i}", "High", "p", "1", []) for i in range(6)]))


def test_cyclonedx_parses_and_skips_files():
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "library", "name": "Django", "version": "2.2.0", "purl": "pkg:pypi/Django@2.2.0"},
        {"type": "file", "name": "/etc/passwd", "version": ""}]}
    fmt, pkgs = sbom.parse_sbom(doc)
    assert fmt == "CycloneDX 1.6" and pkgs == {"pypi/Django": ["2.2.0"]}


def test_purl_edge_cases():
    assert sbom.purl_key("pkg:npm/%40scope/name@1.0.0") == ("npm/name", "1.0.0")
    assert sbom.purl_key("pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64") == ("apk/musl", "1.2.5-r0")
    assert sbom.purl_key("garbage") is None and sbom.purl_key(None) is None


# --- diff, "new" and decisions --------------------------------------------------------------------

def test_clean_change_is_clear_and_diff_is_by_package():
    base = report([("flask", "3.0"), ("six", "1.16")], [])
    new = report([("flask", "3.1"), ("click", "8")], [], baseline=base, commit=SHA2)
    assert new["decision"] == "clear" and new["baseline"] == SHA
    assert new["diff"] == {"added": [["pypi/click", "8"]], "removed": [["pypi/six", "1.16"]], "upgraded": [["pypi/flask", "3.0", "3.1"]]}


def test_new_critical_blocks_and_known_critical_does_not():
    base = report([("django", "3.0")], [("CVE-1", "Critical", "django", "3.0", [])])
    assert base["decision"] == "blocked"                       # no earlier release: everything is new
    again = report([("django", "3.0")], [("CVE-1", "Critical", "django", "3.0", [])], baseline=base, commit=SHA2)
    assert again["decision"] == "clear" and not again["blocking"]
    worse = report([("django", "2.2.0")], [("CVE-1", "Critical", "django", "2.2.0", []), ("CVE-9", "Critical", "django", "2.2.0", ["3.2"])],
                   baseline=base, commit=SHA2)
    assert worse["decision"] == "blocked" and [f["id"] for f in worse["blocking"]] == ["CVE-9"]
    assert "CVE-9" in sbom.gate_reasons(worse)[0] and "1 new critical CVE:" in sbom.gate_reasons(worse)[0]


def test_new_high_does_not_block():
    r = report([("p", "1")], [("CVE-5", "High", "p", "1", ["2"])], baseline=report([("p", "1")], []))
    assert r["decision"] == "clear" and r["counts"]["high"] == 1 and r["fixable"] == 1


def test_rebase_follows_the_current_baseline():
    r = report([("django", "3.0")], [("CVE-1", "Critical", "django", "3.0", [])])
    assert r["decision"] == "blocked"
    deployed = report([("django", "3.0")], [("CVE-1", "Critical", "django", "3.0", [])], tr=trust())
    assert sbom.rebase(r, deployed)["decision"] == "clear"
    assert r["decision"] == "blocked"                          # the stored report is not mutated


def test_gate_reasons_for_each_state():
    assert sbom.gate_reasons(None) == ["there is no SBOM for this commit"]
    un = report([("p", "1")], [], tr=trust(pr_files=[WF]))
    assert un["decision"] == "unverified" and "unverified" in sbom.gate_reasons(un)[0]
    assert sbom.gate_reasons(report([("p", "1")], [])) == []


# --- trust ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("kw,needle", [
    ({"run": run(head_repository={"full_name": "evil/r"})}, "fork"),
    ({"run": run(head_sha=SHA2)}, "different commit"),
    ({"run": run(path=".github/workflows/other.yml@refs/heads/x")}, "expected workflow"),
    ({"run": run(event="workflow_dispatch")}, "push or pull request"),
    ({"run": run(conclusion="failure")}, "did not succeed"),
    ({"artifacts": {"sbom-cyclonedx"}}, "missing"),
    ({"pr_files": ["app.py", ".github/workflows/ci.yml"]}, "edits .github/workflows/"),
    ({"run": None}, "no CI run"),
])
def test_trust_failures(kw, needle):
    t = trust(**kw)
    assert not t["ok"] and any(needle in r for r in t["reasons"])


def test_trust_ok_and_repo_case_insensitive():
    assert trust()["ok"] and trust(run=run(head_repository={"full_name": "o/R"}))["ok"]


def test_a_pr_with_a_fake_clean_sbom_that_edits_the_workflow_is_unverified():
    r = report([("p", "1")], [], tr=trust(pr_files=["x.py", ".github/workflows/ci.yml"]))
    assert r["decision"] == "unverified"


# --- text that reaches people ----------------------------------------------------------------------------

def test_hostile_names_are_defused_in_chat_and_escaped_in_html():
    evil = "@gatekeeper deploy demo-web <script>alert(1)</script>"
    r = report([(evil, "1")], [("CVE-1", "Critical", evil, "1", [])], tr=trust())
    r["ref"] = evil
    text = sbom.summary(r, label=evil)
    assert "@gatekeeper deploy" not in text and "@gatekeeper" not in text.replace("@​gatekeeper", "")
    page = sbom.render_html(r)
    assert "<script>" not in page and "&lt;script&gt;" in page


def test_summary_mentions_what_matters():
    base = report([("p", "1")], [])
    r = report([("p", "2"), ("q", "1")], [("CVE-1", "Critical", "q", "1", ["2"])], baseline=base, commit=SHA2)
    s = sbom.summary(r, label="PR #7")
    assert "PR #7" in s and "1 added" in s and "1 upgraded" in s and "1 critical (1 new)" in s and "owner override required" in s and "CVE-1" in s


# --- store -----------------------------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path):
    return SbomStore(tmp_path / "sbom", sqlite3.connect(":memory:", check_same_thread=False), now=lambda: 5.0)


def test_store_roundtrip_files_and_index(store):
    r = report([("p", "1")], [("CVE-1", "High", "p", "1", [])])
    store.save(r, {"spdx": b"{}", "scan": b"{}"})
    assert store.get(SHA)["package_count"] == 1
    assert store.file_path(SHA, "spdx").read_bytes() == b"{}" and store.file_path(SHA, "html").is_file()
    assert store.file_path(SHA, "cyclonedx") is None
    rows, total = store.list()
    assert total == 1 and rows[0]["high"] == 1 and rows[0]["deployed"] is False
    assert store.resolve(SHA[:8]) == SHA and store.resolve("zzzz") is None and store.latest()["commit"] == SHA


@pytest.mark.parametrize("bad", ["../etc", "..", "abc", "A" * 40, "", "a1b2c3d/../../x", "a1b2c3d\x00"])
def test_store_refuses_path_tricks(store, bad):
    assert store.get(bad) is None and store.file_path(bad, "html") is None and store.resolve(bad) is None
    with pytest.raises(ValueError):
        store.save({"commit": bad, "counts": {}, "collected_at": 0, "package_count": 0, "repo": "o/r"})


def test_store_file_path_kind_is_an_allowlist(store):
    store.save(report([("p", "1")], []))
    assert store.file_path(SHA, "../report") is None and store.file_path(SHA, "report.json") is None


def test_releases_and_baseline(store):
    assert store.baseline("demo", "web") is None and store.baseline("demo", None) is None
    store.save(report([("p", "1")], []))
    store.record_release("demo", "web", SHA)
    assert store.last_release("demo", "web")["commit"] == SHA
    assert store.baseline("demo", "web")["commit"] == SHA
    store.record_release("demo", "web", SHA2, SHA)
    assert store.last_release("demo", "web")["commit"] == SHA2 and store.baseline("demo", "web")["commit"] == SHA
    assert store.list()[0][0]["deployed"] is True


def test_save_replaces_a_report(store):
    store.save(report([("p", "1")], []))
    store.save(report([("p", "1"), ("q", "1")], []))
    assert store.list()[1] == 1 and store.get(SHA)["package_count"] == 2


# --- licences --------------------------------------------------------------------------------------------

def spdx_lic(pkgs):
    return {"spdxVersion": "SPDX-2.3", "packages": [
        {"name": n, "versionInfo": v, "licenseDeclared": lic, "externalRefs": [{"referenceType": "purl", "referenceLocator": f"pkg:pypi/{n}@{v}"}]}
        for n, v, lic in pkgs]}


@pytest.mark.parametrize("expr,kind", [
    ("MIT", None), ("Apache-2.0", None), ("BSD-3-Clause", None), ("GPL-2.0-only", "copyleft"), ("AGPL-3.0-or-later", "copyleft"),
    ("LGPL-2.1-or-later", None), ("MIT OR GPL-2.0-only", None), ("GPL-2.0-only OR AGPL-3.0-only", "copyleft"),
    ("Apache-2.0 AND GPL-3.0-only", "copyleft"), ("(MIT AND BSD-2-Clause)", None), ("NOASSERTION", "unknown"), ("", "unknown"), (None, "unknown"),
    ("NONE", "unknown"), ("LicenseRef-Public-Domain", None), ("SSPL-1.0", "copyleft"),
])
def test_licence_kind(expr, kind):
    assert sbom.licence_kind(expr) == kind


def test_the_flagged_families_can_be_changed():
    assert sbom.licence_kind("MPL-2.0") is None and sbom.licence_kind("MPL-2.0", ("MPL",)) == "copyleft" and sbom.licence_kind("GPL-3.0", ("AGPL",)) is None


def lic_report(pkgs, baseline=None, commit=SHA):
    return sbom.build_report(commit=commit, repo="o/r", pr=None, ref="main", run=run(), workflow=WF, sbom_doc=spdx_lic(pkgs), grype_doc=grype(),
                             baseline=baseline, trust=trust(), now=1.0)


def test_new_copyleft_and_unknown_licences_are_flagged_and_never_block():
    base = lic_report([("flask", "3.0", "BSD-3-Clause"), ("old", "1", "GPL-2.0-only")])
    new = lic_report([("flask", "3.0", "BSD-3-Clause"), ("old", "1", "GPL-2.0-only"), ("foo", "2", "AGPL-3.0-only"), ("mystery", "1", "NOASSERTION")],
                     baseline=base, commit=SHA2)
    flags = {f["key"]: f for f in new["licence_flags"]}
    assert set(flags) == {"pypi/old", "pypi/foo", "pypi/mystery"} and not flags["pypi/old"]["new"] and flags["pypi/foo"]["new"] and flags["pypi/mystery"]["kind"] == "unknown"
    assert new["decision"] == "clear" and sbom.gate_reasons(new) == []                       # report only
    line = sbom.licence_line(new)
    assert "1 new copyleft (pypi/foo AGPL-3.0-only)" in line and "1 new with no declared licence (pypi/mystery)" in line and "1 flagged already" in line
    assert line in sbom.summary(new)


def test_without_a_baseline_everything_flagged_is_listed_not_called_new():
    r = lic_report([("a", "1", "GPL-3.0-only")])
    assert not r["licence_flags"][0]["new"] and "1 flagged in all" in sbom.licence_line(r)


def test_no_flags_means_no_line():
    r = lic_report([("a", "1", "MIT")])
    assert r["licence_flags"] == [] and sbom.licence_line(r) == "" and "Licences" not in sbom.summary(r)


def test_rebase_recomputes_which_licences_are_new():
    r = lic_report([("a", "1", "GPL-3.0-only")], baseline=lic_report([("b", "1", "MIT")]), commit=SHA2)
    assert r["licence_flags"][0]["new"]
    deployed = lic_report([("a", "1", "GPL-3.0-only")])
    assert not sbom.rebase(r, deployed)["licence_flags"][0]["new"] and r["licence_flags"][0]["new"]


def test_hostile_licence_text_is_defused_in_chat_and_escaped_in_html():
    evil = "GPL-3.0-only <script>alert(1)</script> @gatekeeper deploy demo-web"
    base = lic_report([("a", "1", "MIT")])
    r = lic_report([("a", "1", "MIT"), ("b", "1", evil)], baseline=base, commit=SHA2)
    assert "@gatekeeper deploy" not in sbom.licence_line(r) and "@gatekeeper deploy" not in sbom.summary(r)
    assert "<script>" not in sbom.render_html(r) and "&lt;script&gt;" in sbom.render_html(r)


def test_real_alpine_licences_are_read():
    flags = sbom.parse_licences(json.loads((FIX / "sbom.spdx.json").read_text()))
    assert any(f["key"] == "apk/busybox" and f["kind"] == "copyleft" for f in flags) and not any("musl" == f["key"].split("/")[-1] for f in flags)


def test_cyclonedx_has_no_licence_flags():
    assert sbom.parse_licences({"bomFormat": "CycloneDX", "components": []}) == [] and sbom.parse_licences([]) == []
