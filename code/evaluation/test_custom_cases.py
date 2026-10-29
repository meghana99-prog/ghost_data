#!/usr/bin/env python3
"""Small policy/intent regression cases beyond the supplied 32-case sample."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main

A = {'name': {'A Person'}, 'email': {'a.person@example.test'}, 'phone': {'+1 202 555 0111'}, 'email_hash': set()}
T = main.dt('2026-09-15T12:00:00Z')

# 1. A copy/access request must not be misclassified as deletion.
assert not main.request_is_deletion('Please send me a copy of my data; I am not asking you to delete anything.')

# 2. A tombstone that retains only the stable reference is compliant; exposed
# direct identifiers require redaction while the record itself remains.
tombstone_exposed = main.Item('test', T, 'identity_service', 'deleted_customer_references', 'tombstone_900', {
    'resource_id': 'tombstone_900', 'subject_reference': 'user_900', 'name': 'A Person',
    'email': 'a.person@example.test', 'phone': '+1 202 555 0111', 'email_hash': 'abc'
})
assert main.category(tombstone_exposed, tombstone_exposed.data) == 'ACCOUNT_TOMBSTONE'
assert main.decide(tombstone_exposed, 'user_900', A, T) == ('EXPOSED', 'REPORT_EXPOSED_PII', 'REDACT_RECORD')
tombstone_clean = main.Item('test', T, 'identity_service', 'deleted_customer_references', 'tombstone_901', {
    'resource_id': 'tombstone_901', 'subject_reference': 'user_900', 'name': None,
    'email': None, 'phone': None, 'email_hash': None
})
assert main.decide(tombstone_clean, 'user_900', A, T) == ('REDACTED', '', 'REDACT_RECORD')

# 3. An attachment belonging to the subject must be deleted, even if a prior
# operator claimed it was redacted; this policy requires deletion of the file.
attachment = main.Item('test', T, 'support_platform', 'support_attachment', 'support_attachment_900', {
    'resource_id': 'support_attachment_900', 'result': 'REDACTED', 'owner_user_id': 'user_900'
})
assert main.decide(attachment, 'user_900', A, T) == ('PRESENT', 'REPORT_REMAINING_RECORD', 'DELETE_RECORD')

# 4. A restore candidate that is eligible and not blocked is a live restore risk.
backup = main.Item('test', T, 'backup_service', 'backup_archive', 'backup_900', {
    'resource_id': 'backup_900', 'eligible': 'true', 'deletion_block': 'false'
}, raw='eligible=true deletion_block=false')
assert main.decide(backup, 'user_900', A, T) == ('ACTIVE', 'REPORT_RESTORE_RISK', 'BLOCK_RESTORE')

# 5. An enabled connector is an active recreation path, not proof that data is gone.
flow = main.Item('test', T, 'integration_service', 'connector_configuration', 'data_flow_900', {
    'resource_id': 'data_flow_900', 'enabled': True
})
assert main.decide(flow, 'user_900', A, T) == ('ACTIVE', 'REPORT_ACTIVE_DATA_FLOW', 'DISABLE_DATA_FLOW')

print('PASS: 5 custom regression cases')
