"""The decision. Pure function: (finding, proposal, evidence) -> Decision.

Order matters:
  1. REJECT rules  - any hit refuses the proposal outright.
  2. ROUTE rules   - any hit sends it to a human.
  3. ACCEPT        - only if every ACCEPT gate is positively proven.
Anything unproven (None) falls to ROUTE_FOR_REVIEW, never to ACCEPT.
Agent claims are recorded but never read here.
"""
from __future__ import annotations

import re

from .models import Decision, Evidence, Finding, Proposal, State

PROTECTED_PATHS = (".github/", ".gitlab-ci", "Jenkinsfile", "CODEOWNERS", "CONTRIBUTING", "docs/", ".env")
TEST_DISABLERS = re.compile(r"@Disabled|<exclude>|pytest\.mark\.skip|@Ignore|xfail")
TEST_FILE = re.compile(r"(^|/)(test_[^/]+\.py|[^/]+Test\.java|tests?/)")
MANIFESTS = ("pom.xml", "requirements.lock", "pyproject.toml", "package-lock.json", "go.sum")


def _ver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def _is_test(path: str) -> bool:
    return bool(TEST_FILE.search(path))


def _is_manifest(path: str) -> bool:
    return path.endswith(MANIFESTS)


def decide(f: Finding, p: Proposal, e: Evidence) -> Decision:
    reject, route = [], []

    # ---- REJECT: the proposal itself is unsafe or does not fix the CVE ----
    for c in p.changes:
        if _is_test(c.path) and c.op == "delete":
            reject.append(f"R1 deletes a test: {c.path}")
        if any(TEST_DISABLERS.search(l) for l in c.added):
            reject.append(f"R1 disables or excludes tests in {c.path}")
        if any(c.path.startswith(x) or f"/{x}" in c.path for x in PROTECTED_PATHS):
            reject.append(f"R2 touches protected path: {c.path}")
    if e.build_passes is False or e.existing_tests_pass is False:
        reject.append("R3 build or existing tests fail in sandbox")
    if e.lockfile_reproducible is False:
        reject.append("R4 manifest/lockfile not reproducible from declared command (hand edit)")
    if p.dependency and e.advisory_fixed_versions and \
            _ver(p.dependency.to_version) < min(_ver(v) for v in e.advisory_fixed_versions):
        reject.append(f"R5 target {p.dependency.to_version} is below advisory fix {e.advisory_fixed_versions}")
    prod_code = [c for c in p.changes if not _is_test(c.path) and not _is_manifest(c.path)]
    if prod_code and e.changed_code_covered_by_tests is False and e.regression_test_red_to_green is not True:
        reject.append("R6 rewrites production code that no test covers, with no characterization test")

    if reject:
        return Decision(p.id, f.id, State.REJECT, reject)

    # ---- ROUTE: possibly fine, but a human must own the risk ----
    if prod_code:
        route.append("Q1 changes production code (behavior change possible): "
                     + ", ".join(c.path.rsplit("/", 1)[-1] for c in prod_code))
    if p.dependency:
        d = p.dependency
        if _ver(d.to_version)[:1] != _ver(d.from_version)[:1]:
            route.append(f"Q2 major version change {d.from_version} -> {d.to_version}")
        if not d.direct:
            route.append("Q3 overrides a transitive/parent-managed version")
    if (f.fixed_version or None) is None and e.advisory_fixed_versions:
        route.append(f"Q4 scanner says no fix, advisory says {list(e.advisory_fixed_versions)}: source data disagree")
    if not e.advisory_fixed_versions:
        route.append("Q4 no advisory confirms a fixed version")
    if e.changed_code_covered_by_tests is not True:
        route.append("Q5 code using the dependency is not covered by tests")
    if e.regression_test_red_to_green is not True:
        route.append("Q6 no regression test proven red-before/green-after")
    if e.covered_by_existing_tests is not True and e.agent_test_fingerprint and not e.agent_test_approved:
        route.append("Q9 only coverage is an agent-written test no human has approved yet "
                     f"(fingerprint {e.agent_test_fingerprint[:12]}); approve once, repeats can auto-accept")
    if p.dependency is None and not prod_code:
        route.append("Q7 proposal has no dependency change and no code change")
    for name, val in (("build", e.build_passes), ("tests", e.existing_tests_pass),
                      ("lockfile", e.lockfile_reproducible)):
        if val is None:
            route.append(f"Q8 {name} result not established (fail closed)")

    if route:
        return Decision(p.id, f.id, State.ROUTE_FOR_REVIEW, route)

    return Decision(p.id, f.id, State.ACCEPT, [
        "A all gates proven: direct same-major bump, manifest/tests only, lockfile reproducible, "
        "build+tests green, regression test red->green, advisory confirms fix, "
        + ("covered by pre-existing tests" if e.covered_by_existing_tests
           else "agent test matches a human-approved fingerprint")])


def finding_outcome(decisions: list[Decision]) -> State:
    """Best proposal wins: one ACCEPT is enough; else any ROUTE; else REJECT
    (= no safe automated fix; the owner must remediate or risk-accept)."""
    states = {d.state for d in decisions}
    for s in (State.ACCEPT, State.ROUTE_FOR_REVIEW):
        if s in states:
            return s
    return State.REJECT
