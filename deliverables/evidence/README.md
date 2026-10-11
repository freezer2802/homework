# Evidence for the auditor

`remediation-attestation.example.json` is a mock signed attestation. It answers the three
questions with pointers to systems of record (deploy log, runtime inventory, scanner, CI),
never with the agent's word:

| Auditor question | Section | Proof |
|---|---|---|
| CVE remediated in prod on date X? | `1_remediated_in_production` | deployment id + timestamp, deployed image digest, SBOM of that digest |
| Vulnerable artifact no longer running? | `2_vulnerable_artifact_not_running` | runtime inventory of digests (old one = 0), clean rescan, admission policy blocking regression |
| Fix went through the right gates? | `3_gates_passed` | harness decision + audit hash, each CI gate with run id, human approvals for ROUTE items |

`integrity` signs the document and links to the hash-chained harness audit log.
