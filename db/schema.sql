-- Bootstrap identity and tenancy parents before assessment foreign keys.
-- Runtime initializers may add compatible columns/indexes, but a clean database must
-- be valid before the HTTP server starts.
CREATE TABLE IF NOT EXISTS app_users (
 id uuid PRIMARY KEY,
 email text UNIQUE NOT NULL,
 password_hash text NOT NULL,
 password_salt text NOT NULL,
 totp_secret text NOT NULL, -- plaintext legacy rows remain readable; new rows are AES-256-GCM encrypted when TOTP_ENCRYPTION_KEY is configured
 totp_verified boolean NOT NULL DEFAULT false,
 full_name text,
 designation text,
 company_name text,
 role text NOT NULL DEFAULT 'analyst',
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app_auth_attempts (
 attempt_key text PRIMARY KEY,
 failures int NOT NULL DEFAULT 0,
 window_started_at timestamptz NOT NULL DEFAULT now(),
 blocked_until timestamptz,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS app_auth_attempts_blocked_idx ON app_auth_attempts(blocked_until);

CREATE TABLE IF NOT EXISTS grc_organizations (
 id uuid PRIMARY KEY,
 name text NOT NULL,
 industry text,
 status text NOT NULL DEFAULT 'ACTIVE',
 created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);

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
-- SHA-256 format is enforced by application writes. The named database constraint may
-- already exist from an earlier migration; do not recreate or drop it during startup.

