HackerRank Orchestrate - October 2026

Ghost Data Still Exists

Build an AI agent that audits whether a user's personal data was actually deleted.

A deletion workflow may report Complete while data still exists in databases, logs, support attachments, exports, search indexes, archives, or backups. Sync and restore processes may also bring deleted data back.

For each request, the agent must first determine whether deletion was actually requested. It then returns "COMPLETE", "INCOMPLETE", or "NOT_APPLICABLE", reports any remaining data or recreation risk, and produces the ordered remediation and verification steps required to finish an authorized deletion safely.

Read ""problem_statement.md"" (./problem_statement.md) for the complete challenge contract.