# Deliverables

| Task | Where |
|---|---|
| 1. Harness (code + how to run, what is stubbed) | `harness/`, `tests/`, `fixtures/`, this README |
| 2. Where the agent acts, routes, refuses, and why | `DESIGN.md` |
| 3. Evidence artifact for the auditor | `evidence/` |
| 4. Failure mode analysis | `FAILURE-MODES.md` |
| 5. Scaling from 2 to 300 repos | `DESIGN.md`, last section |
| Note on AI tools and time spent | `AI-USAGE.md` |

## Harness

Takes scanner findings, asks an agent for fix proposals, and **decides** each one:
`ACCEPT`, `ROUTE_FOR_REVIEW` or `REJECT`. Python 3.11+, standard library only.

### Run

From this folder (`deliverables/`, which sits inside the homework repo next to `findings/`):

    python -m harness.run                          # reads ../findings/findings.json
    python -m harness.run --findings path/to/findings.json --out out/
    python -m harness.run --approvals fixtures/approved_fixes.example.json   # after a human approved F-40219's test
    python -m unittest -v                          # policy tests (no install needed)
    python -m pytest                               # same tests, if you have pytest

Output:
- `out/decisions.json`: per finding, the outcome and every proposal with its state and reasons
- `out/audit.jsonl`: one hash-chained line per decision (evidence used, agent claims ignored)

### Pipeline

    findings.json -> agent.propose() -> oracle.gather() -> policy.decide() -> out/
                     (proposes diffs)   (harness proves)   (REJECT > ROUTE > ACCEPT)

| File | Role | Real or stub |
|---|---|---|
| `harness/models.py` | Finding, Proposal, Evidence, Decision | real |
| `harness/policy.py` | The decision rules (R*, Q*, A) | **real**: this is the product |
| `harness/run.py` | Orchestration, outputs, audit hash chain | real |
| `harness/agent.py` | Proposes fixes | **stub**: deterministic rules instead of an LLM |
| `harness/oracle.py` | Build, tests, lockfile re-gen, red/green test, coverage, advisory lookup | **stub**: reads `fixtures/` |
| `fixtures/approved_fixes.json` | Agent-written tests a human has reviewed (CVE, package, version, test fingerprint) | real logic, mock data |

### What is stubbed

- **Agent.** `agent.propose()` returns hand-written diffs per finding type. It deliberately
  includes two bad shortcut (deleting a failing test and rewriting untested code) so the policy has something to refuse.
  Replace with a model call; the contract is "return `Proposal` objects", nothing else.
- **Sandbox runs.** `fixtures/sandbox_runs.json` stands in for an isolated CI run of each
  proposal. A proposal with no entry gets no evidence and can never be accepted.
- **Advisory DB.** `fixtures/advisories.json` stands in for OSV/NVD/GHSA.
- **Delivery.** Nothing is pushed. ACCEPT would mean "open PR, merge through the normal
  pipeline"; ROUTE means "open PR, assign owner"; REJECT means "drop, record why".

### Current result

| Finding | Outcome | Why |
|---|---|---|
| F-40219 PyYAML 5.3.1 | ROUTE now, ACCEPT once approved | Every gate passes, but the only test of the fix is the agent's own. A human reviews it once; with `--approvals fixtures/approved_fixes.example.json` the same bump is ACCEPTed, here and in any other repo |
| F-40218 snakeyaml 1.30 | ROUTE | Fix needs code change + major + transitive override; legacy tagged overrides change. Shortcut that deletes the test is REJECTed |
| F-40220 commons-collections 3.2.1 | ROUTE | 3.2.2 exists though scanner says "no fix"; no tests on PricingService. Untested rewrite to collections4 is REJECTed |

See `DESIGN.md` for where the lines sit and why.
