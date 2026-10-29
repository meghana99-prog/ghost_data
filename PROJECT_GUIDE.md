# Ghost Data Still Exists — Project Guide

## 1. What the problem is asking

Northstar Shop believes a customer's deletion request is complete because the main account dashboard says “Complete.” But a customer cannot sign up again because a secondary system still has the email. The challenge is to build an audit agent that independently checks whether data is actually gone across all the systems in the evidence package.

For every request, the program must answer three questions:

1. **Was deletion actually requested?** If not, return `NOT_APPLICABLE` and `[]`.
2. **What is still present or able to come back?** Resolve current and historical identifiers, inspect records and systems at the request's `audit_at` cutoff, and find active sync/import/restore paths.
3. **What should happen next?** Apply the action in `deletion_rules.csv`, preserve required records, and return ordered findings, remediation actions, and verification checks.

The three outcomes are:

- `COMPLETE`: evidence available at `audit_at` shows every in-scope copy received its required treatment, no active recreation path remains, and required retained records are present.
- `INCOMPLETE`: a prohibited identifier or copy remains, or a data-flow/restore path can recreate data. The output must say what remains and provide ordered fixes and follow-up checks.
- `NOT_APPLICABLE`: the text does not authorize deletion (for example, a data-access/export request or a correction-only request).

A tombstone is a special case: the stable internal `user_id` may remain so retained business/security records preserve referential integrity, but direct identifiers such as name, email, phone, and email hash must be removed. A security or legal record required by policy must be retained rather than deleted.

## 2. How this implementation works

The solution is a **deterministic-first evidence audit** in `code/main.py`. It does not call an LLM. For a privacy audit, explicit rule-based classification is easier to reproduce and review than a model making untraceable deletion decisions; a language model could be added later for triage or summarization, but it should not replace evidence checks.

The pipeline is:

1. **Intent classification** — identify positive deletion language and exclude access, correction, or other non-deletion requests.
2. **Identity graph construction** — combine the current identity table and historical email/name/phone/hash changes. An input can use an old email.
3. **Evidence extraction** — read JSON, SQL snapshots, logs, text, PDFs (via `pdftotext`), and screenshots (via Tesseract when installed). Evidence is represented as records with a `file_id`, system, resource ID, capture time, and observed time.
4. **Time filtering** — exclude evidence captured or observed after the request's `audit_at`; future evidence must not change the historical answer.
5. **Resource linking** — join evidence to a subject through stable user IDs and exact identity values. For otherwise unlabeled workflow resources, a bounded time correlation is allowed only when the request mentions the relevant category. Reported operation outcomes are not treated as proof of current state.
6. **Policy evaluation** — categorize records and apply the required treatment from `deletion_rules.csv`: delete, redact, anonymize, or retain. Check active data flows and restore permissions separately.
7. **Output generation** — build ordered `FINDING`, `REMEDIATION`, and `VERIFICATION` arrays and write one sorted output row per evaluation request.

## 3. Step-by-step: run and understand the project

### Step 1 — Set up the workspace

Unzip the starter repository and open a terminal in its root. Python 3 is required. The core code uses the standard library. Optional extractors improve coverage:

```bash
sudo apt-get install poppler-utils tesseract-ocr
```

`poppler-utils` supplies `pdftotext`; `tesseract-ocr` supplies screenshot OCR. The program skips those extraction paths if the relevant binary is absent.

### Step 2 — Learn the input files

Start with these files:

- `dataset/deletion_requests.csv`: 518 requests and the `audit_at` cutoff.
- `dataset/user_identities.csv` and `dataset/user_audit_log.csv`: current and historical identifiers.
- `dataset/deletion_rules.csv`: the required action for each data category.
- `dataset/system_activity.csv`: process events that can help link resources or reveal recreation risk; a success result is only a claim.
- `dataset/evidence_files.csv`: evidence paths and capture times.
- `dataset/evidence/`: the actual database, log, JSON, PDF, text, and image evidence.

A good mental model is a graph: the user and all their identifiers point to resources, and resources are supported by evidence records. Do not assume that every row in a global activity file belongs to the current user.

### Step 3 — Run the public sample checks

The code can be imported for sample evaluation. For a basic run, compare `code.main.audit_case` outputs for `sample_deletion_requests.csv` against `sample_output.csv`. Keep status accuracy separate from exact step-array accuracy: the latter also depends on resource linkage, evidence references, and required ordering.

### Step 3a — Demonstrate the agent to a judge

The CLI demo in `code/agent.py` presents a human-readable report for one case. On Windows, use `py`; on Linux/macOS, use `python3`:

```bash
py code/agent.py --list --limit 10
py code/agent.py --case case_33
py code/agent.py --validate-output
```

Use an actual case ID printed by `--list` (the supplied dataset begins with `case_33`). The case audit loads the evidence bundle and may take about a minute if PDF/OCR extraction runs. The report separates evidence-backed findings from proposed remediation and future verification, and explicitly states that it does not change live systems. This is an explainable local agent demo, not a live-system deletion executor or an LLM-powered system.

### Step 4 — Generate all predictions

From the repository root:

```bash
python3 code/main.py
```

This writes `output.csv` at the root. Validate the output contract:

```bash
python3 - <<'PY'
import csv, json
with open('output.csv', newline='', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))
assert len(rows) == 518
assert list(rows[0]) == ['case_id', 'deletion_status', 'steps_json']
assert [r['case_id'] for r in rows] == sorted(r['case_id'] for r in rows)
for row in rows:
    steps = json.loads(row['steps_json'])
    assert isinstance(steps, list)
    assert [s['step_no'] for s in steps] == list(range(1, len(steps) + 1))
print('Output contract passed')
PY
```

### Step 5 — Read a row

Each `steps_json` value is a JSON array. In an incomplete case, the array should be in this phase order:

1. `FINDING`: cite the evidence that a record or process is still a problem.
2. `REMEDIATION`: propose the policy-compliant change; future actions use an empty `evidence_id`.
3. `VERIFICATION`: specify the post-fix check; future checks also use an empty `evidence_id`.

For a complete case, the array contains evidence-backed verification steps. Required security/legal records should be verified as present. For a tombstone, verify the stable user reference remains while direct identifiers are redacted.

### Step 6 — Package the submission

The challenge contract expects `code/evaluation/evaluation_report.md` and `code/evaluation/usage_report.md`, plus a runnable `code.zip` and the root `output.csv`. Example packaging command from the root:

```bash
zip -r code.zip README.md code -x '*/__pycache__/*' '*/.venv/*' '*/venv/*' '*/node_modules/*' '*/.git/*' '*/.DS_Store'
```

Do not add `dataset/`, credentials, or nested archives to `code.zip`.

## 4. What to improve next

The main remaining weakness is **resource attribution** in a deliberately noisy evidence set: step-level matching is stricter than status matching, and ambiguous activity/evidence relationships can omit or misattribute a resource. Before using this for a real deletion request, add stronger provenance-aware links (trace IDs, request IDs, immutable subject references), per-replica state tracking, and manual-review escalation for ambiguous matches. The generated predictions are challenge output, not a production privacy certification.
