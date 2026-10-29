# Judge Demo Script — Ghost Data Audit

Use this as a guide, not a memorized claim. Be transparent that the current implementation is deterministic and does not call an LLM or perform live deletion.

## 60-second project explanation

“Ghost Data Audit checks whether a customer deletion request is actually complete across the supplied systems evidence. It resolves current and historical identifiers, checks records at the case’s audit-time cutoff, applies the supplied deletion policy, and looks for active sync or restore paths. It returns COMPLETE, INCOMPLETE, or NOT_APPLICABLE with evidence references and ordered recommendations. This demo is local and read-only: it recommends remediation but does not change a live system. The current engine is deterministic rather than LLM-powered, which makes the decisions reproducible. On the public sample, status matched 32 out of 32, while exact ordered action arrays matched 10 out of 32; improving resource attribution and exact step plans is the main next step.”

## Live demo commands (Windows Git Bash)

From the project root:

```bash
py code/agent.py --list --limit 5
py code/agent.py --case case_33
py code/agent.py --validate-output
```

The selected-case audit parses the evidence bundle and can take about a minute. In the tested `case_33` example, the workflow claimed `COMPLETE`, but the evidence showed an export resource still present; the agent reported it and proposed delete and verification steps. The report labels the workflow status as a claim and clearly says remediation was not executed.

To generate the challenge CSV:

```bash
py code/main.py
```

## Likely judge questions and concise answers

**How do you resolve old identifiers?**

“I combine the current identity snapshot with historical audit changes. The email supplied with the request may be historical, so I use its stable user link to search old and current aliases. Ambiguous links should be sent for human review.”

**How do you decide deletion is complete?**

“I don't treat a workflow’s COMPLETE label as proof. I check relevant evidence available at `audit_at`, apply the category’s required action, check active data flows and restore permission, and verify required retained records. If evidence is incomplete or ambiguous, the implementation needs stronger review rather than claiming certainty.”

**What happens to tombstones and legally retained records?**

“The policy may permit a stable `user_id` in a tombstone or retained record, but direct identifiers must be removed. Required security or legal records are preserved and verified as present instead of being deleted.”

**Does the agent actually delete data?**

“No. This challenge implementation audits supplied files and outputs proposed remediation/verification steps. It does not connect to or mutate real Northstar systems. A production deployment would require authenticated connectors, least privilege, approvals, immutable logs, and post-action verification.”

**Why no LLM?**

“The audit decision needs to be reproducible and evidence-linked, so the current engine uses deterministic parsing and policy rules. An LLM could help summarize evidence or ask follow-up questions, but it should not replace the deterministic policy checks or human approval.”

**What is the main limitation?**

“Status decisions matched all 32 public examples, but exact ordered step arrays matched only 10. Resource attribution, per-replica state, and evidence references need improvement. I report this limitation rather than claiming perfect accuracy.”
