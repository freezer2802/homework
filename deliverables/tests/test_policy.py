import unittest
from dataclasses import replace
from pathlib import Path

from harness import agent, oracle, policy
from harness.models import Evidence, FileChange, Finding, Proposal, State

PY = Finding("F-40219", "CVE-2020-14343", "high", "report-worker", "PyYAML", "5.3.1", "direct", "5.4", 11)
SNAKE = Finding("F-40218", "CVE-2022-1471", "critical", "inventory-api", "org.yaml:snakeyaml", "1.30",
                "transitive via spring-boot-starter", "2.0", 4)
CC = Finding("F-40220", "CVE-2015-6420", "high", "inventory-api", "commons-collections:commons-collections",
             "3.2.1", "direct", None, -63)


NO_APPROVALS = oracle.FIXTURES / "approved_fixes.json"
EXAMPLE_APPROVALS = oracle.FIXTURES / "approved_fixes.example.json"


def decide_all(f, approvals=NO_APPROVALS):
    return {p.id: policy.decide(f, p, oracle.gather(p, f.cve, approvals_path=approvals)).state
            for p in agent.propose(f)}


class ExpectedDecisions(unittest.TestCase):
    def test_pyyaml_bump_routed_first_time_agent_test_unreviewed(self):
        self.assertEqual(decide_all(PY), {"F-40219-A": State.ROUTE_FOR_REVIEW})
        p = agent.propose(PY)[0]
        reasons = policy.decide(PY, p, oracle.gather(p, PY.cve, approvals_path=NO_APPROVALS)).reasons
        self.assertEqual([r[:2] for r in reasons], ["Q9"])

    def test_pyyaml_bump_accepted_once_agent_test_approved(self):
        self.assertEqual(decide_all(PY, EXAMPLE_APPROVALS), {"F-40219-A": State.ACCEPT})

    def test_snakeyaml_hardening_routed_and_test_deletion_rejected(self):
        self.assertEqual(decide_all(SNAKE), {"F-40218-A": State.ROUTE_FOR_REVIEW, "F-40218-B": State.REJECT})

    def test_commons_collections_bump_routed_and_untested_rewrite_rejected(self):
        self.assertEqual(decide_all(CC), {"F-40220-A": State.ROUTE_FOR_REVIEW, "F-40220-B": State.REJECT})


class ApprovedFixes(unittest.TestCase):
    """One human review of an agent test unlocks repeats of exactly that fix, nothing else."""

    def setUp(self):
        self.p = agent.propose(PY)[0]

    def decide(self, p, f=PY):
        return policy.decide(f, p, oracle.gather(p, f.cve, approvals_path=EXAMPLE_APPROVALS)).state

    def test_same_fix_in_another_repo_auto_accepts(self):
        other_repo = replace(PY, id="F-50001", service="billing-worker")
        p = replace(self.p, id="F-40219-A", finding_id="F-50001")  # same diff, sandbox run reused
        self.assertEqual(self.decide(p, other_repo), State.ACCEPT)

    def test_changed_test_code_is_not_approved(self):
        tampered = tuple(replace(c, added=c.added + ("    assert True",)) if "tests/" in c.path else c
                         for c in self.p.changes)
        self.assertEqual(self.decide(replace(self.p, changes=tampered)), State.ROUTE_FOR_REVIEW)

    def test_approval_does_not_carry_to_other_target_version(self):
        p = replace(self.p, dependency=replace(self.p.dependency, to_version="6.0.1"))
        self.assertEqual(self.decide(p), State.ROUTE_FOR_REVIEW)

    def test_approval_does_not_carry_to_other_cve(self):
        other = replace(PY, cve="CVE-2017-18342")
        p = agent.propose(other)[0]
        e = replace(oracle.gather(p, other.cve, approvals_path=EXAMPLE_APPROVALS), advisory_fixed_versions=("5.1",))
        self.assertEqual(policy.decide(other, p, e).state, State.ROUTE_FOR_REVIEW)

    def test_pre_existing_coverage_needs_no_approval(self):
        e = replace(oracle.gather(self.p, PY.cve, approvals_path=NO_APPROVALS), covered_by_existing_tests=True)
        self.assertEqual(policy.decide(PY, self.p, e).state, State.ACCEPT)

    def test_unknown_existing_coverage_needs_approval(self):
        e = replace(oracle.gather(self.p, PY.cve, approvals_path=NO_APPROVALS), covered_by_existing_tests=None)
        self.assertEqual(policy.decide(PY, self.p, e).state, State.ROUTE_FOR_REVIEW)

    def test_approval_never_overrides_a_reject(self):
        e = replace(oracle.gather(self.p, PY.cve, approvals_path=EXAMPLE_APPROVALS), lockfile_reproducible=False)
        self.assertEqual(policy.decide(PY, self.p, e).state, State.REJECT)


class SafetyProperties(unittest.TestCase):
    def setUp(self):
        self.p = agent.propose(PY)[0]
        self.e = oracle.gather(self.p, PY.cve, approvals_path=EXAMPLE_APPROVALS)

    def test_unknown_evidence_never_accepts(self):
        for field in ("build_passes", "existing_tests_pass", "lockfile_reproducible",
                      "regression_test_red_to_green", "changed_code_covered_by_tests"):
            d = policy.decide(PY, self.p, replace(self.e, **{field: None}))
            self.assertEqual(d.state, State.ROUTE_FOR_REVIEW, field)

    def test_missing_sandbox_run_fails_closed_even_if_agent_claims_green(self):
        p = replace(self.p, id="NOT-IN-FIXTURES", agent_claims={"tests": "pass"})
        self.assertNotEqual(policy.decide(PY, p, oracle.gather(p, PY.cve)).state, State.ACCEPT)

    def test_reject_beats_accept(self):
        skip = FileChange("services/report-worker/tests/test_config.py", "modify",
                          added=("@pytest.mark.skip",))
        p = replace(self.p, changes=self.p.changes + (skip,))
        self.assertEqual(policy.decide(PY, p, self.e).state, State.REJECT)

    def test_protected_path_rejected(self):
        ci = FileChange(".github/workflows/ci.yml", "modify", added=("continue-on-error: true",))
        self.assertEqual(policy.decide(PY, replace(self.p, changes=(ci,)), self.e).state, State.REJECT)

    def test_hand_edited_lockfile_rejected(self):
        d = policy.decide(PY, self.p, replace(self.e, lockfile_reproducible=False))
        self.assertEqual(d.state, State.REJECT)

    def test_bump_below_advisory_fix_rejected(self):
        dep = replace(self.p.dependency, to_version="5.3.2")
        self.assertEqual(policy.decide(PY, replace(self.p, dependency=dep), self.e).state, State.REJECT)

    def test_urgency_does_not_lower_the_bar(self):
        overdue = replace(PY, sla_days_remaining=-100, severity="critical")
        self.assertEqual(policy.decide(overdue, self.p, replace(self.e, regression_test_red_to_green=None)).state,
                         State.ROUTE_FOR_REVIEW)


if __name__ == "__main__":
    unittest.main()
