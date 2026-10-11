"""Entry point: findings -> agent -> evidence -> decision -> outputs."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from . import agent, oracle, policy
from .models import Finding

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FINDINGS = ROOT.parent / "findings" / "findings.json"


def load_findings(path: Path) -> list[Finding]:
    raw = json.loads(path.read_text())
    return [Finding(**f) for f in raw["findings"]]


def run(findings_path: Path, out_dir: Path, approvals: Path = oracle.DEFAULT_APPROVALS) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    report, audit, prev = {}, [], "0" * 64
    for f in load_findings(findings_path):
        decisions = []
        for p in agent.propose(f):
            ev = oracle.gather(p, f.cve, approvals_path=approvals)
            d = policy.decide(f, p, ev)
            decisions.append(d)
            entry = {"finding": f.id, "cve": f.cve, "proposal": p.id, "summary": p.summary,
                     "state": d.state.value, "reasons": d.reasons,
                     "evidence": asdict(ev), "agent_claims_ignored": p.agent_claims, "prev": prev}
            prev = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            entry["hash"] = prev
            audit.append(entry)
        report[f.id] = {
            "cve": f.cve, "severity": f.severity, "service": f.service,
            "outcome": policy.finding_outcome(decisions).value if decisions else "ROUTE_FOR_REVIEW",
            "proposals": [d.to_dict() for d in decisions] or
                         [{"state": "ROUTE_FOR_REVIEW", "reasons": ["agent produced no proposal"]}],
        }
    (out_dir / "decisions.json").write_text(json.dumps(report, indent=2))
    (out_dir / "audit.jsonl").write_text("".join(json.dumps(a) + "\n" for a in audit))
    return report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", type=Path, default=DEFAULT_FINDINGS)
    ap.add_argument("--out", type=Path, default=ROOT / "out")
    ap.add_argument("--approvals", type=Path, default=oracle.DEFAULT_APPROVALS,
                    help="human-approved agent tests (default: fixtures/approved_fixes.json)")
    a = ap.parse_args()
    report = run(a.findings, a.out, a.approvals)
    for fid, r in report.items():
        print(f"{fid}  {r['cve']:<15} {r['outcome']}")
        for p in r["proposals"]:
            print(f"   {p.get('proposal_id', '-'):<10} {p['state']:<17} {p['reasons'][0]}")
            for reason in p["reasons"][1:]:
                print(f"   {'':<10} {'':<17} {reason}")
    print(f"\nwrote {a.out / 'decisions.json'} and {a.out / 'audit.jsonl'}")


if __name__ == "__main__":
    main()
