"""The install path must work for anyone: no one's username, account, key or machine written into it."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAINTAINER_ONLY = {"scripts/vm.sh", "scripts/mm_test.py", "scripts/cutover_agents.py"}      # the author's lab helpers, not run by an installer
BAD = re.compile(r"/home/ubuntu|ubuntu@|:-ubuntu\b|new-account|shipyard-dev|ap-south-1")


def install_files():
    for p in [*(ROOT / "scripts").glob("*.sh"), *(ROOT / "shipyard").glob("*.py"), *(ROOT / "deploy").rglob("*")]:
        if p.is_file() and str(p.relative_to(ROOT)) not in MAINTAINER_ONLY:
            yield p


def test_no_username_aws_account_key_or_region_is_written_into_the_install_path():
    hits = [f"{p.relative_to(ROOT)}:{n}: {line.strip()[:100]}" for p in install_files() for n, line in enumerate(p.read_text(errors="ignore").splitlines(), 1) if BAD.search(line)]
    assert not hits, "\n".join(hits)


def test_the_agents_sandbox_hides_the_home_of_whoever_installs_not_a_fixed_user():
    text = (ROOT / "scripts/isolate_agents.sh").read_text()
    assert "PLATFORM_USER=${PLATFORM_USER:-$USER}" in text and "PLATFORM_HOME" in text and "-/home/ubuntu" not in text


def test_kubectl_is_fetched_for_the_machines_own_architecture():
    for name in ("lab-setup.sh", "install-k8s-demo.sh"):
        assert "linux/amd64" not in (ROOT / "scripts" / name).read_text(), name
