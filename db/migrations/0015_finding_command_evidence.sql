-- The idempotent schema supplies the DDL; this migration records the feature version
-- and creates the table on existing databases (ADR-0004, #8: non-HTTP finding proof).
CREATE TABLE IF NOT EXISTS finding_command_evidence (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'supporting',
    command TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL,
    truncated BOOLEAN NOT NULL DEFAULT FALSE,
    position INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_command_evidence_finding ON finding_command_evidence(finding_id, position, id);
