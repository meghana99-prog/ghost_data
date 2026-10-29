#!/usr/bin/env python3
"""Explainable local demo agent for the Ghost Data Still Exists challenge.

This is a presentation layer over main.py's deterministic audit engine. It reads
only the supplied dataset; it does not call an LLM or modify external systems.
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

import main as audit

PHASE_TITLES = {
    'FINDING': 'What the evidence found',
    'REMEDIATION': 'Recommended remediation (not executed)',
    'VERIFICATION': 'Verification checks',
}
OPERATION_TEXT = {
    'REPORT_REMAINING_RECORD': 'A record that should have been deleted still appears in the evidence.',
    'REPORT_EXPOSED_PII': 'A retained record still appears to contain direct or linkable identifiers.',
    'REPORT_ACTIVE_DATA_FLOW': 'An active data flow may copy or recreate this person’s data.',
    'REPORT_RESTORE_RISK': 'A backup or restore path may bring this person’s data back.',
    'DELETE_RECORD': 'Delete this record according to the applicable policy.',
    'REDACT_RECORD': 'Remove prohibited identifiers while preserving the permitted record/reference.',
    'ANONYMIZE_RECORD': 'Irreversibly unlink this record from the person.',
    'DISABLE_DATA_FLOW': 'Disable the data flow before completing deletion.',
    'BLOCK_RESTORE': 'Block restoration of this person’s deleted data from the archive.',
    'VERIFY_RECORD_ABSENT': 'After remediation, verify that this record is absent.',
    'VERIFY_RECORD_PRESENT': 'Verify that this policy-required retained record remains available.',
    'VERIFY_RECORD_REDCTED': 'Verify the record is retained without prohibited direct identifiers.',
    'VERIFY_RECORD_REDACTED': 'Verify the record is retained without prohibited direct identifiers.',
    'VERIFY_RECORD_ANONYMIZED': 'Verify the record is no longer attributable to the person.',
    'VERIFY_DATA_FLOW_DISABLED': 'Verify that the data flow is disabled.',
    'VERIFY_RESTORE_BLOCKED': 'Verify that restore access is blocked for the affected data.',
}


def load_context():
    requests = audit.readcsv(audit.DATA / 'deletion_requests.csv')
    people, email_user = audit.identity_index(
        audit.readcsv(audit.DATA / 'user_identities.csv'),
        audit.readcsv(audit.DATA / 'user_audit_log.csv'),
    )
    items = audit.load_items(audit.readcsv(audit.DATA / 'evidence_files.csv'))
    activities = audit.correlate_activity(
        requests, email_user, audit.readcsv(audit.DATA / 'system_activity.csv')
    )
    return requests, people, email_user, items, activities


def render_case(row, status, steps):
    print('\n' + '=' * 76)
    print('GHOST DATA AUDIT AGENT — CASE REPORT')
    print('=' * 76)
    print(f"Case: {row.get('case_id', '(unknown)')}")
    print(f"Audit cutoff: {row.get('audit_at') or '(not supplied)'}")
    print(f"Workflow-reported status: {row.get('reported_status') or '(not supplied)'} (claim only)")
    print(f"Agent decision: {status}")
    print('')

    if status == 'NOT_APPLICABLE':
        print('Reason: the request text did not authorize deletion.')
        print('No deletion remediation is proposed for this request.')
    elif not steps:
        print('No audit steps were returned. Treat this case as requiring manual review.')
    else:
        phases = ('FINDING', 'REMEDIATION', 'VERIFICATION')
        for phase in phases:
            section = [step for step in steps if step.get('phase') == phase]
            if not section:
                continue
            print(f'{PHASE_TITLES[phase]}:')
            for item in section:
                op = item.get('operation', '')
                explanation = OPERATION_TEXT.get(op, op.replace('_', ' ').capitalize() + '.')
                resource = item.get('resource_id') or '(scope)'
                evidence = item.get('evidence_id') or 'future check/action; no current evidence citation'
                print(f"  {item.get('step_no')}. {explanation}")
                print(f"     System/resource: {item.get('system_id')} / {resource}")
                print(f"     State: {item.get('state')} | Evidence: {evidence}")
            print('')

    if status == 'COMPLETE':
        print('Interpretation: the supplied evidence supports completion as of the audit cutoff.')
    elif status == 'INCOMPLETE':
        print('Interpretation: do not treat deletion as complete until the listed fixes and checks pass.')
    print('\nSafety boundary: this demo reads the supplied challenge files only. It does not')
    print('delete, redact, anonymize, disable, or restore data in any live system.')
    print('=' * 76)


def validate_output(path: Path):
    if not path.exists():
        raise FileNotFoundError(f'Output file not found: {path}')
    with path.open(encoding='utf-8-sig', newline='') as handle:
        rows = list(csv.DictReader(handle))
    expected = ['case_id', 'deletion_status', 'steps_json']
    if not rows or list(rows[0]) != expected:
        raise ValueError(f'Expected CSV columns {expected}')
    if len(rows) != 518:
        raise ValueError(f'Expected 518 rows; found {len(rows)}')
    if [r['case_id'] for r in rows] != sorted(r['case_id'] for r in rows):
        raise ValueError('Rows are not sorted by case_id')
    for row in rows:
        steps = json.loads(row['steps_json'])
        if not isinstance(steps, list):
            raise ValueError(f"steps_json is not an array for {row['case_id']}")
        if [s.get('step_no') for s in steps] != list(range(1, len(steps) + 1)):
            raise ValueError(f"Non-consecutive step numbers for {row['case_id']}")
    print(f'PASS: {len(rows)} rows, correct columns, sorted case IDs, valid JSON arrays, consecutive steps.')
    print('Status totals:', dict(Counter(r['deletion_status'] for r in rows)))


def main():
    parser = argparse.ArgumentParser(
        description='Explain an evidence-based deletion audit for one supplied challenge case.'
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--case', metavar='CASE_ID', help='Audit and explain one case, e.g. case_001')
    mode.add_argument('--list', action='store_true', help='List case IDs and request summaries; no evidence parsing')
    mode.add_argument('--validate-output', action='store_true', help='Validate the generated root output.csv')
    parser.add_argument('--limit', type=int, default=20, help='Maximum cases shown with --list (default: 20)')
    args = parser.parse_args()

    if not audit.DATA.exists():
        parser.error(f'Dataset folder not found: {audit.DATA}. Run this from the extracted project.')
    if args.validate_output:
        validate_output(audit.ROOT / 'output.csv')
        return

    requests = audit.readcsv(audit.DATA / 'deletion_requests.csv')
    if args.list:
        print(f'{len(requests)} requests available. Showing up to {max(0, args.limit)}:')
        for row in requests[:max(0, args.limit)]:
            text = (row.get('request_text') or '').replace('\n', ' ').strip()
            if len(text) > 100:
                text = text[:97] + '...'
            print(f"{row.get('case_id')} | audit_at={row.get('audit_at')} | {text}")
        return

    chosen = args.case
    if not chosen:
        print('Enter a case ID from the list (for example, case_001). Type q to quit.')
        chosen = input('Case ID: ').strip()
        if chosen.casefold() in {'q', 'quit', 'exit'}:
            print('No audit run.')
            return
    row = next((r for r in requests if r.get('case_id', '').casefold() == chosen.casefold()), None)
    if row is None:
        parser.error(f'Unknown case ID {chosen!r}. Use --list to view available IDs.')

    print('Loading identity history and supplied evidence. PDF/OCR extraction may take about a minute...', flush=True)
    requests, people, email_user, items, activities = load_context()
    status, steps = audit.audit_case(row, people, email_user, items, activities)
    render_case(row, status, steps)


if __name__ == '__main__':
    main()
