# Usage Report — Full Dataset Run

## Run summary

- Command: `python3 code/main.py`
- Run date: 2026-10-25 (UTC+05:30 session date)
- Requests processed: 518
- Evidence items parsed: 3,224
- Output: root-level `output.csv`
- Observed wall time: 65.57 seconds for the final full-dataset generation run
- Runtime: Python 3 and local evidence extractors; no remote model/API request

## Model and token accounting

| Provider/model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---:|---:|---:|---:|---:|
| None — deterministic rules and local evidence parsing | 0 | 0 | 0 | 0 | $0.00 |
| **Overall** | **0** | **0** | **0** | **0** | **$0.00** |

Average tokens per request: 0.00. Estimated model cost per request: $0.00. There are no per-model totals beyond the “None” row because no model was invoked.

The implementation deliberately uses a deterministic-first pipeline for auditable classifications and policy actions. It parses local CSV, JSON, SQL, text/log, PDF, and image evidence; it does not use an LLM provider. Local CPU time and OCR work are not token usage and do not incur model/API cost.

## Output distribution (not accuracy)

- `INCOMPLETE`: 344
- `COMPLETE`: 127
- `NOT_APPLICABLE`: 47

The code verifies all 518 rows, sorted case IDs, exact output columns, valid JSON arrays, and consecutive step numbers. Hidden labels were not available, so full-dataset accuracy and cost-weighted quality cannot be reported.
