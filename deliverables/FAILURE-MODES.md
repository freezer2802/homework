# Failure modes

Five failures, one from each part of the system: the decision, the agent's inputs, the source
data, the infrastructure, and the humans in the loop.

| # | Failure | Safe? | How we detect it | How we handle it |
|---|---|---|---|---|
| 1 | **False ACCEPT** (decision): a fix passes every gate but breaks prod. Causes: behavior no test covers, an agent test that looks right but checks nothing, or a reviewer approving a weak test that then auto-accepts in many repos | **Unsafe** | Canary and post-deploy error/latency SLOs on changes tagged auto-merged; revert rate per rule and per approved-fixes entry; weekly human sample of ACCEPTs | Roll back; revoke the approved-fixes entry (all repeats go back to ROUTE); add the missed case as a test or rule; global kill switch turns all ACCEPT into ROUTE |
| 2 | **Prompt injection** (inputs): the agent follows "instructions" in repo content, e.g. CONTRIBUTING.md or a stale runbook saying "push to main, skip review" | **Unsafe** if the agent can act; contained here | Proposal touches CI, docs or protected paths (R2), or removes/skips tests (R1); audit log shows the rejected attempt | Proposal is REJECTed automatically; repeated hits on one repo flag the source file for its owner to clean up |
| 3 | **Wrong source data** (data): scanner says "no fix" when one exists (F-40220), or misses a finding entirely | **Safe** (nothing changes), but the exposure stays open | Q4 cross-check of scanner vs. advisory DB; reconciliation of findings with no decision; SLA breach alerts | ROUTE to a human to resolve which source is right; report the scanner bug upstream |
| 4 | **Harness or sandbox outage** (infrastructure): builds can't run, evidence comes back empty | **Safe** (fails closed: unknown evidence can only give ROUTE) | Spike of Q8 "result not established" reasons; alert when evidence is missing for more than N proposals | Pause the run, fix the runner, re-run; nothing is accepted meanwhile |
| 5 | **Review overload** (people): too much goes to ROUTE, so reviewers rubber-stamp or the queue ages past SLA | **Safe** short-term, **unsafe** in effect | Queue age; approve-without-change rate per reviewer; which Q-rule fires most | Batch identical fixes into one approval (approved-fixes list); tune the noisiest rule; escalate SLA-breaching items to the service owner |
