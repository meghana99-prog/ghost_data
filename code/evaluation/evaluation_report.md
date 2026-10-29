# Evaluation Report — Ghost Data Audit

## Evaluation scope and method

Predictions were generated from participant-facing data only. The program reads `deletion_requests.csv`, identity/audit history, the policy file, activity data, and the evidence manifest/files. It does not read `sample_output.csv` while generating predictions. The public sample file was used only in the separate evaluation script to score the implementation.

The public set has 32 cases. The complete evaluation run processed 518 requests and 3,224 extracted evidence items.

## Public-sample metrics

| Metric | Result | Definition |
|---|---:|---|
| Status field accuracy | 32/32 (100.00%) | `deletion_status` exactly matches the public sample. |
| Exact row / case accuracy | 10/32 (31.25%) | Status and the entire ordered `steps_json` value match. |
| Exact ordered sequence accuracy | 10/32 (31.25%) | All phase/operation/system/resource tuples match in order. |
| Step signature precision | 155 TP / 170 predicted = 91.18% | Signature is `(phase, operation, system_id, resource_id)`. |
| Step signature recall | 155 TP / 193 expected = 80.31% | Same signature definition. |
| Step signature F1 | 85.40% | Micro-averaged over the sample. |

Status decisions are strong on this small public set, but exact step-array agreement remains incomplete. The main cause is resource attribution and exact evidence/verification planning when records are represented across more than one source. These results are a prototype evaluation, not a production certification claim.

## Full-dataset output checks

The final run produced 518 rows with the exact header `case_id,deletion_status,steps_json`, sorted by `case_id`. Every `steps_json` value parsed as a JSON list, and all step numbers were consecutive from 1. Status totals were:

- `INCOMPLETE`: 344
- `COMPLETE`: 127
- `NOT_APPLICABLE`: 47

These totals are output distribution checks, not accuracy metrics; hidden canonical labels are not available.

## Additional regression cases created

`test_custom_cases.py` contains five cases beyond the public sample. All five pass.

1. **Access/export is not deletion:** “Send me a copy” plus an explicit no-delete statement must be `NOT_APPLICABLE`.
2. **Tombstone retains a stable reference:** `user_id` can remain, while a tombstone containing direct identifiers requires redaction.
3. **Clean tombstone:** null direct identifiers with a stable `subject_reference` are treated as compliant and preserved.
4. **Support attachment:** a subject-owned attachment remains subject to `DELETE`, even if an earlier operation claimed it was merely redacted.
5. **Restore and sync risks:** eligible/unblocked backup evidence yields `REPORT_RESTORE_RISK`/`BLOCK_RESTORE`; an enabled connector yields `REPORT_ACTIVE_DATA_FLOW`/`DISABLE_DATA_FLOW`.

Run the tests with:

```bash
python3 code/evaluation/test_custom_cases.py
```

## Failures found and improvements made

- A broad substring match on names linked unrelated people with similar names. Name matching was changed to exact normalized values from name fields; exact current and historical emails, hashes, phones, and stable IDs remain the primary links.
- A generic filename containing “export” caused support records to be categorized incorrectly. Category detection now emphasizes the observed service and collection, with attachment classification before delivery-log classification.
- Deletion wording varies (`deletion`, `deleting`, `removed`, `gone`, non-English verbs). The intent classifier was expanded while keeping access, correction, and explicit non-deletion phrases negative.
- A support attachment has a different rule from a shared support conversation. The implementation now treats subject-owned attachments as delete-required and shared conversations as redact-required.
- Operation-result logs and record snapshots are not interchangeable. Activity events may help link resources but are not emitted as proof of current state; audit-time cutoffs are enforced using capture and observation timestamps.

## Known limitations / next improvements

1. Exact resource ownership is still ambiguous in some noisy cross-system cases. Improve the evidence graph with trace/request IDs and explicit one-to-many identity links rather than relying on time proximity.
2. Track each replica/archive as a separate copy and avoid collapsing multiple physical locations into a single `(system_id, resource_id)` status.
3. Verify each policy condition explicitly (for example, whether a legal hold is active and whether an attachment is exclusive to the subject) and emit a manual-review state where evidence is ambiguous.
4. Add property-based tests for multilingual intent and identifier normalization, plus regression fixtures for every hidden edge case discovered after submission.
5. Keep a human privacy reviewer in the loop. This deterministic challenge prototype should not certify real deletion requests without stronger provenance and operational controls.


## Judge-demo CLI check

Added `code/agent.py` as a local presentation layer over the same audit engine. Tested it end to end with `case_33`: the workflow claimed `COMPLETE`, while the demo reported an evidence-linked export still present, gave delete/verify steps, and clearly stated that no remediation was executed. `--list` and `--validate-output` also passed. This improves explainability and demo usability; it does not change the audit engine's accuracy metrics above.
