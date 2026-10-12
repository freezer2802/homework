# AI usage and time spent

## Where AI was used

All work was done with **Claude (Anthropic), through Claude Code in a Claude project**,
directed and reviewed by me.

| Area | AI did | I did |
|---|---|---|
| Understanding the repo | Read the services and findings; explained Java, Maven, CVE, CI and the three findings | Asked the questions, read the explanations |
| Harness code (`harness/`, `tests/`, `fixtures/`) | Wrote the code, stub agent, fixtures and tests; ran them | Set requirements; reviewed decisions and asked for changes |
| `DESIGN.md`, `FAILURE-MODES.md`, `evidence/` | Drafted the text and the mock attestation | Reviewed and reshaped them |

## How the harness evolved

The harness went through several iterations:

1. **First version**: an initial harness design, used mainly to explore where the
   automation line should sit. It was set aside and rebuilt from scratch.
2. **Second version**: rebuilt from the findings and services only, with a clearer pipeline
   (agent proposes, harness verifies, policy decides). In this version F-40219 was ACCEPTed
   automatically.
3. **Third version**: after review, agent-written tests now need one human approval before a
   fix can auto-accept. F-40219 moved to ROUTE_FOR_REVIEW, and an approved-fixes list lets
   identical fixes in other repos auto-accept later. Tests were extended to cover this.
4. **Final pass**: docs tightened (untrusted input section, failure modes reduced to five with
   handling), folder reorganised as `deliverables`, and a final check against the brief.

## Approximate time

About **3 hours** of active work on 2026-10-11, excluding breaks.

| Phase | Approx. time |
|---|---|
| Exploring the repo and getting explanations | 30 min |
| First harness version | 45 min |
| Second version and the other deliverables | 30 min |
| Review, third version and final pass | 1 h 15 min |
