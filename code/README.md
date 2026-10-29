# Ghost Data Audit — Runnable Solution

This package contains two pieces:

- `main.py`: deterministic audit engine that produces the required `output.csv`.
- `agent.py`: local, explainable CLI demo that lets a judge select a case and see the decision, evidence references, ordered recommendations, and safety boundary.

Both read the supplied `dataset/` folder at the repository root. Neither sends data to an AI provider or performs actions in live systems.

## Requirements

- Python 3.10 or newer (standard library only for the solution).
- Optional: `pdftotext` from Poppler for PDF extraction and `tesseract` for screenshot OCR. If absent, other evidence formats are still processed.

On Windows with the Python launcher, use `py`; on Linux/macOS, use `python3`.

## Generate challenge output

From the project root:

```bash
py code/main.py        # Windows
python3 code/main.py   # Linux/macOS
```

This writes `output.csv` with `case_id,deletion_status,steps_json`, one row per request, sorted by `case_id`.

## Demonstrate the agent to a judge

List some request IDs without parsing the evidence:

```bash
py code/agent.py --list --limit 10
```

Audit one case and show the evidence, policy-based next steps, and explanation:

```bash
py code/agent.py --case case_33
```

Replace `case_33` with an ID printed by `--list` if needed. Without `--case`, the program prompts for a case ID. It then loads evidence (PDF/OCR may take about a minute) and produces a human-readable report. The demo explicitly says that it does not modify any live customer or system data.

Validate the generated output:

```bash
py code/agent.py --validate-output
```

## Design

1. Load current and historical identity values.
2. Parse JSON, SQLite-compatible SQL, log/text, PDF, and image evidence into resource observations.
3. Enforce both manifest capture time and resource observation time against `audit_at`.
4. Connect evidence to a subject using stable IDs and exact historical identifiers; time-based activity links are bounded and category-aware.
5. Apply categories/actions from `deletion_rules.csv`; treat activity results as claims, not proof.
6. Emit evidence-cited findings and ordered remediation/verification steps.

The audit engine is deterministic rather than LLM-powered. This is intentional for reproducibility in policy checks. A production deployment would need stronger provenance, human review for ambiguous matches, and additional tests before certifying deletion.

## Evaluation

Run the custom tests:

```bash
py code/evaluation/test_custom_cases.py
```

See `code/evaluation/evaluation_report.md` for public-sample metrics and custom test cases, and `code/evaluation/usage_report.md` for full-run resource accounting. See the root `PROJECT_GUIDE.md` for a plain-language step-by-step walkthrough.
