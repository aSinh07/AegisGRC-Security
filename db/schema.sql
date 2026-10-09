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

CREATE TABLE IF NOT EXISTS documents (
 id uuid PRIMARY KEY,
 assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
 filename text NOT NULL,
 mime_type text NOT NULL,
 size_bytes integer NOT NULL,
 sha256 text NOT NULL,
 created_at timestamptz NOT NULL,
 content bytea NOT NULL
);
CREATE INDEX IF NOT EXISTS documents_assessment_idx ON documents(assessment_id);

-- Assessment tenancy is additive for legacy compatibility. Existing rows remain NULL until explicitly assigned.
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES grc_organizations(id) ON DELETE RESTRICT;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES app_users(id) ON DELETE SET NULL;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS assessments_organization_idx ON assessments(organization_id,authorized_at DESC);

-- Evidence integrity metadata. Existing evidence is retained; integrity_verified_at is NULL until server verification.
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS byte_length bigint;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS integrity_verified_at timestamptz;
DO $
BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM pg_constraint
  WHERE conname='evidence_sha256_format_chk'
    AND conrelid='evidence'::regclass
 ) THEN
  ALTER TABLE evidence ADD CONSTRAINT evidence_sha256_format_chk
   CHECK (sha256 ~ '^[0-9a-f]{64}
) NOT VALID;
 END IF;
END $;
