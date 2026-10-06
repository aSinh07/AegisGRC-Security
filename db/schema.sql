CREATE TABLE IF NOT EXISTS assessments (
 id uuid PRIMARY KEY, target text NOT NULL, authorized_at timestamptz NOT NULL, status text NOT NULL, payload jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
 id uuid PRIMARY KEY, assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE, source text NOT NULL, sha256 text NOT NULL, created_at timestamptz NOT NULL, payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_assessment_idx ON evidence(assessment_id);
CREATE TABLE IF NOT EXISTS findings (
 id uuid PRIMARY KEY, assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE, severity text NOT NULL, source text NOT NULL, created_at timestamptz NOT NULL, payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_assessment_idx ON findings(assessment_id);
CREATE TABLE IF NOT EXISTS audit_events (
 id uuid PRIMARY KEY, assessment_id uuid, action text NOT NULL, created_at timestamptz NOT NULL, payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_assessment_idx ON audit_events(assessment_id);
