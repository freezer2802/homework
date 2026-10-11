# Design: where the agent's authority ends

**One rule:** the agent proposes, the harness proves, the policy decides.
Agent claims ("tests pass", "no behavior change") are logged and never used.
Unknown is treated as no. Urgency (SLA, severity) changes priority, never the bar.

## The three tiers

| Tier | When | Example here |
|---|---|---|
| **ACCEPT** (autonomous) | *Every* gate proven: direct dependency, same major, only manifest/lockfile/tests change, lockfile reproduces from the declared tool command, build + existing tests green, a new regression test fails before and passes after, advisory confirms the target fixes the CVE, and the fix is covered by tests that existed before **or** by an agent test a human already approved | PyYAML 5.3.1 to 5.4.1, after its test was approved once |
| **ROUTE_FOR_REVIEW** (human owns risk) | Fix may be right, but the evidence can't prove it's harmless: production code changes, major version, override of a transitive/parent-managed version, scanner and advisory disagree, code using the package has no tests, no red/green test, any evidence missing, the only test of the fix is an unreviewed agent-written one | PyYAML on first sight; snakeyaml 2.0 + tag allow-list; commons-collections 3.2.2 |
| **REJECT** (refuse) | The proposal weakens a control or can't be trusted at all: deletes/skips/excludes tests, touches CI/CODEOWNERS/docs/contributing or other protected paths, hand-edits a generated lockfile, build or tests fail, target below the fixed version, rewrites untested production code without a characterization test | Delete `ConfigLoaderIntegrationTest`; rewrite `PricingService` onto collections4 |

Order: REJECT rules run first, then ROUTE, ACCEPT is what is left when nothing fired.

## Why the line sits there

1. **Reversibility and blast radius.** A same-major pin bump is one-line, revertable, and
   doesn't change our code. Anything that changes our code or a major API can change behavior
   nobody asked for (e.g. snakeyaml 2.0 stops loading legacy tagged operator overrides).
2. **Can a machine verify it?** ACCEPT needs evidence the harness produced itself: a
   reproducible lockfile and a test that goes red to green. If the only proof is "the agent
   says so", a human decides.
3. **Does it lower our defences?** Removing a test, editing CI or following instructions found
   in repo files (CONTRIBUTING.md, stale runbooks) would let one bad proposal disable the checks
   for every later one. That is never a judgment call, so it's a hard REJECT, not a review.
4. **The agent can't grade its own work.** A test that goes red to green proves it notices the
   version change, not that it checks the right thing. When the agent's test is the only
   coverage, a human reviews it once. The approval is pinned to CVE, package, target version and
   a hash of the test code, so the same fix in the next repo auto-accepts, but a changed test or
   a different version goes back to review. Approval never overrides a REJECT.
5. **Trustworthy inputs.** When scanner and advisory disagree (F-40220 "no fix" vs. 3.2.2),
   the system's own data is wrong; a human resolves which is true.

REJECT is per proposal, not per finding. A finding whose proposals are all rejected is
escalated to the service owner as "no safe automated fix" (remediate or risk-accept), so it
never silently disappears.

## Untrusted input

Everything the agent reads is **data, never instructions**: repo files (including
CONTRIBUTING.md and runbooks), issues, PR comments, CI logs, docs and scanner output.

- **No authority to misuse.** The agent has no credentials and cannot push, merge or comment.
  It can only return a diff, so an injected "push to main" has nothing to act with.
- **Output is checked, not trusted.** The policy reads the diff itself (paths, deleted or
  skipped tests) and the harness's own sandbox results. The agent's claims are logged and
  ignored.
- **Controls are out of reach.** CI config, CODEOWNERS, docs, CONTRIBUTING and test exclusions
  are protected paths. Touching them is a REJECT, whatever reason the agent gives.
- **Inputs are cross-checked.** Scanner data is compared with the advisory DB, and a
  disagreement goes to a human.

## Scaling from 2 repos to 300

At 300 repos the policy stays the same but everything around it changes. Per-repo facts
the harness now assumes (which files are generated, protected paths, how to build and test,
who owns the service) must come from a declared per-repo manifest, and a repo without one
can only get ROUTE. Review becomes the bottleneck: the same CVE across 300 repos must be
batched into one decision (the approved-fixes list: "PyYAML 5.4.1 with this test is approved")
that each repo still has to pass its own gates against, and routing must go to CODEOWNERS, not one security queue. Sandboxed
builds need a queue with priority by severity and reachability, and flaky tests must be
quarantined by the platform, never by the agent. The policy itself becomes versioned
config with its own review, auto-ACCEPT is switched on per repo tier (start in shadow mode,
then low-risk services), and we monitor ACCEPT rate, revert rate and time-to-remediate per
repo, alerting when an agent model or policy change moves them. Shared failure modes (one bad
upgrade auto-merged 300 times) need a global kill switch and a per-day cap on auto-merges.
