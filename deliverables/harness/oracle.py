"""STUB evidence gathering. Real version: check out the diff in a sandbox,
run the build and tests, re-run the declared lockfile command, run the agent's
regression test against old and new versions, query coverage and the advisory DB.
Here those results are read from fixtures/ so the run is deterministic.

The approved-fixes list is real logic: it records agent-written tests a human
has reviewed, keyed by (CVE, package, target version, test fingerprint)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import Evidence, Proposal

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
DEFAULT_APPROVALS = FIXTURES / "approved_fixes.json"


def _is_test(path: str) -> bool:
    from .policy import _is_test  # single definition of "test file"
    return _is_test(path)


def test_fingerprint(p: Proposal) -> str | None:
    """Hash of the test code the agent added. Changing one character changes it."""
    lines = [l for c in p.changes if c.op in ("add", "modify") and _is_test(c.path) for l in c.added]
    if not lines:
        return None
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def is_approved(p: Proposal, cve: str, approvals: list[dict], fingerprint: str | None) -> bool:
    if fingerprint is None or p.dependency is None:
        return False
    return any(a["cve"] == cve and a["package"] == p.dependency.package
               and a["to_version"] == p.dependency.to_version
               and a["test_fingerprint"] == fingerprint for a in approvals)


def gather(p: Proposal, cve: str, fixtures: Path = FIXTURES, approvals_path: Path = DEFAULT_APPROVALS) -> Evidence:
    runs = json.loads((fixtures / "sandbox_runs.json").read_text())
    advisories = json.loads((fixtures / "advisories.json").read_text())
    approvals = json.loads(approvals_path.read_text())["approved"] if approvals_path.exists() else []
    r = runs.get(p.id, {})  # missing entry => nothing established => fail closed
    fp = test_fingerprint(p)
    return Evidence(
        build_passes=r.get("build_passes"),
        existing_tests_pass=r.get("existing_tests_pass"),
        lockfile_reproducible=r.get("lockfile_reproducible"),
        regression_test_red_to_green=r.get("regression_test_red_to_green"),
        changed_code_covered_by_tests=r.get("changed_code_covered_by_tests"),
        covered_by_existing_tests=r.get("covered_by_existing_tests"),
        agent_test_fingerprint=fp,
        agent_test_approved=is_approved(p, cve, approvals, fp),
        advisory_fixed_versions=tuple(advisories.get(cve, [])),
    )
