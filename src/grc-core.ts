import crypto from 'node:crypto';
import pg from 'pg';

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false },
  max: Number(process.env.DB_POOL_MAX || 30)
});

export type Applicability = 'APPLICABLE'|'NOT_APPLICABLE'|'PENDING';
export type Implementation = 'NOT_IMPLEMENTED'|'PARTIAL'|'IMPLEMENTED';
export type EvidenceStatus = 'MISSING'|'PENDING'|'VALID'|'STALE'|'EXPIRED';
export type Effectiveness = 'EFFECTIVE'|'INEFFECTIVE'|'NOT_TESTED';
export type OverallControlStatus = 'EFFECTIVE'|'PARTIALLY_EFFECTIVE'|'INEFFECTIVE'|'NOT_ASSESSED'|'NOT_APPLICABLE';

export function calculateControlStatus(x:{
  applicability:Applicability;
  implementation:Implementation;
  evidenceStatus:EvidenceStatus;
  designEffectiveness:Effectiveness;
  operatingEffectiveness:Effectiveness;
}):OverallControlStatus {
  if(x.applicability==='NOT_APPLICABLE') return 'NOT_APPLICABLE';
  if(x.applicability!=='APPLICABLE') return 'NOT_ASSESSED';
  if(!['VALID'].includes(x.evidenceStatus)) return 'NOT_ASSESSED';
  if(x.designEffectiveness==='INEFFECTIVE'||x.operatingEffectiveness==='INEFFECTIVE') return 'INEFFECTIVE';
  if(x.implementation==='PARTIAL') return 'PARTIALLY_EFFECTIVE';
  if(x.implementation==='IMPLEMENTED'&&x.designEffectiveness==='EFFECTIVE'&&x.operatingEffectiveness==='EFFECTIVE') return 'EFFECTIVE';
  return 'NOT_ASSESSED';
}

export function riskScore(likelihood:number,impact:number){
  if(!Number.isInteger(likelihood)||!Number.isInteger(impact)||likelihood<1||likelihood>5||impact<1||impact>5)
    throw new Error('Likelihood and impact must be integers from 1 to 5');
  const score=likelihood*impact;
  return {score,rating:score>=20?'CRITICAL':score>=15?'HIGH':score>=8?'MEDIUM':score>=4?'LOW':'VERY_LOW'};
}

export async function initGrcCore(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS grc_organizations(
      id uuid PRIMARY KEY, name text NOT NULL, industry text, created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS grc_scopes(
      id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
      name text NOT NULL, description text, status text NOT NULL DEFAULT 'DRAFT',
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS grc_controls(
      id uuid PRIMARY KEY, control_key text UNIQUE NOT NULL, title text NOT NULL, description text,
      owner_user_id uuid, created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS grc_control_mappings(
      id uuid PRIMARY KEY, control_id uuid NOT NULL REFERENCES grc_controls(id) ON DELETE CASCADE,
      framework text NOT NULL, framework_control text NOT NULL, mapping_version text NOT NULL DEFAULT '1',
      UNIQUE(control_id,framework,framework_control,mapping_version)
    );
    CREATE TABLE IF NOT EXISTS grc_evidence(
      id uuid PRIMARY KEY, organization_id uuid REFERENCES grc_organizations(id) ON DELETE CASCADE,
      source text NOT NULL, collection_method text NOT NULL DEFAULT 'MANUAL',
      status text NOT NULL DEFAULT 'PENDING', sha256 text, collected_at timestamptz,
      valid_until timestamptz, owner_user_id uuid, metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS grc_evidence_controls(
      evidence_id uuid NOT NULL REFERENCES grc_evidence(id) ON DELETE CASCADE,
      control_id uuid NOT NULL REFERENCES grc_controls(id) ON DELETE CASCADE,
      PRIMARY KEY(evidence_id,control_id)
    );
    CREATE TABLE IF NOT EXISTS grc_control_assessments(
      id uuid PRIMARY KEY, scope_id uuid NOT NULL REFERENCES grc_scopes(id) ON DELETE CASCADE,
      control_id uuid NOT NULL REFERENCES grc_controls(id) ON DELETE CASCADE,
      applicability text NOT NULL DEFAULT 'PENDING',
      applicability_justification text,
      implementation text NOT NULL DEFAULT 'NOT_IMPLEMENTED',
      evidence_status text NOT NULL DEFAULT 'MISSING',
      design_effectiveness text NOT NULL DEFAULT 'NOT_TESTED',
      operating_effectiveness text NOT NULL DEFAULT 'NOT_TESTED',
      automation text NOT NULL DEFAULT 'MANUAL',
      overall_status text NOT NULL DEFAULT 'NOT_ASSESSED',
      owner_user_id uuid, reviewer_user_id uuid,
      last_tested_at timestamptz, next_test_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(scope_id,control_id)
    );
    CREATE TABLE IF NOT EXISTS grc_risks(
      id uuid PRIMARY KEY, organization_id uuid REFERENCES grc_organizations(id) ON DELETE CASCADE,
      risk_key text UNIQUE NOT NULL, title text NOT NULL, description text, category text,
      likelihood integer NOT NULL CHECK(likelihood BETWEEN 1 AND 5),
      impact integer NOT NULL CHECK(impact BETWEEN 1 AND 5),
      inherent_score integer NOT NULL, inherent_rating text NOT NULL,
      treatment text NOT NULL DEFAULT 'MITIGATE',
      residual_likelihood integer CHECK(residual_likelihood BETWEEN 1 AND 5),
      residual_impact integer CHECK(residual_impact BETWEEN 1 AND 5),
      residual_score integer, residual_rating text,
      owner_user_id uuid, status text NOT NULL DEFAULT 'OPEN', review_date date,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS grc_risk_controls(
      risk_id uuid NOT NULL REFERENCES grc_risks(id) ON DELETE CASCADE,
      control_id uuid NOT NULL REFERENCES grc_controls(id) ON DELETE CASCADE,
      PRIMARY KEY(risk_id,control_id)
    );
    CREATE TABLE IF NOT EXISTS grc_issues(
      id uuid PRIMARY KEY, organization_id uuid REFERENCES grc_organizations(id) ON DELETE CASCADE,
      issue_key text UNIQUE NOT NULL, title text NOT NULL, description text,
      source_type text NOT NULL, source_id text, control_id uuid REFERENCES grc_controls(id),
      risk_id uuid REFERENCES grc_risks(id), priority text NOT NULL DEFAULT 'P3',
      status text NOT NULL DEFAULT 'OPEN', owner_user_id uuid, due_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS grc_remediation_tasks(
      id uuid PRIMARY KEY, issue_id uuid NOT NULL REFERENCES grc_issues(id) ON DELETE CASCADE,
      title text NOT NULL, corrective_action text, preventive_action text,
      owner_user_id uuid, status text NOT NULL DEFAULT 'OPEN', due_at timestamptz,
      retest_required boolean NOT NULL DEFAULT true, retest_status text NOT NULL DEFAULT 'NOT_TESTED',
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS grc_workflow_transitions(
      id uuid PRIMARY KEY, record_type text NOT NULL, record_id uuid NOT NULL,
      from_state text, to_state text NOT NULL, actor_user_id uuid, reason text,
      snapshot jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS grc_assessments_scope_idx ON grc_control_assessments(scope_id);
    CREATE INDEX IF NOT EXISTS grc_risks_org_idx ON grc_risks(organization_id);
    CREATE INDEX IF NOT EXISTS grc_issues_org_status_idx ON grc_issues(organization_id,status);
    CREATE INDEX IF NOT EXISTS grc_evidence_validity_idx ON grc_evidence(valid_until);
  `);
}

export async function createRisk(input:{
  organizationId?:string; title:string; description?:string; category?:string;
  likelihood:number; impact:number; treatment?:'MITIGATE'|'ACCEPT'|'TRANSFER'|'AVOID'; ownerUserId?:string; reviewDate?:string;
}){
  const inherent=riskScore(input.likelihood,input.impact);
  const id=crypto.randomUUID(), key='RISK-'+new Date().getUTCFullYear()+'-'+crypto.randomBytes(3).toString('hex').toUpperCase();
  const r=await pool.query(`INSERT INTO grc_risks
    (id,organization_id,risk_key,title,description,category,likelihood,impact,inherent_score,inherent_rating,treatment,owner_user_id,review_date)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
    [id,input.organizationId||null,key,input.title,input.description||null,input.category||null,input.likelihood,input.impact,inherent.score,inherent.rating,input.treatment||'MITIGATE',input.ownerUserId||null,input.reviewDate||null]);
  return r.rows[0];
}

export async function listRisks(organizationId?:string){
  const r=organizationId
    ? await pool.query('SELECT * FROM grc_risks WHERE organization_id=$1 ORDER BY inherent_score DESC,created_at DESC',[organizationId])
    : await pool.query('SELECT * FROM grc_risks ORDER BY inherent_score DESC,created_at DESC LIMIT 250');
  return r.rows;
}

export async function createControlAssessment(input:{scopeId:string;controlId:string;ownerUserId?:string}){
  const id=crypto.randomUUID();
  const r=await pool.query(`INSERT INTO grc_control_assessments(id,scope_id,control_id,owner_user_id)
    VALUES($1,$2,$3,$4) ON CONFLICT(scope_id,control_id) DO UPDATE SET updated_at=now() RETURNING *`,
    [id,input.scopeId,input.controlId,input.ownerUserId||null]);
  return r.rows[0];
}

export async function updateControlAssessment(id:string,patch:any){
  const current=(await pool.query('SELECT * FROM grc_control_assessments WHERE id=$1',[id])).rows[0];
  if(!current) throw new Error('Control assessment not found');
  const x={
    applicability:patch.applicability||current.applicability,
    implementation:patch.implementation||current.implementation,
    evidenceStatus:patch.evidenceStatus||current.evidence_status,
    designEffectiveness:patch.designEffectiveness||current.design_effectiveness,
    operatingEffectiveness:patch.operatingEffectiveness||current.operating_effectiveness
  };
  const overall=calculateControlStatus(x);
  const r=await pool.query(`UPDATE grc_control_assessments SET
    applicability=$2,implementation=$3,evidence_status=$4,design_effectiveness=$5,
    operating_effectiveness=$6,overall_status=$7,applicability_justification=COALESCE($8,applicability_justification),
    last_tested_at=CASE WHEN $5<>'NOT_TESTED' OR $6<>'NOT_TESTED' THEN now() ELSE last_tested_at END,
    updated_at=now() WHERE id=$1 RETURNING *`,
    [id,x.applicability,x.implementation,x.evidenceStatus,x.designEffectiveness,x.operatingEffectiveness,overall,patch.applicabilityJustification||null]);
  return r.rows[0];
}

export async function recordWorkflowTransition(input:{recordType:string;recordId:string;fromState?:string;toState:string;actorUserId?:string;reason?:string;snapshot?:any}){
  const id=crypto.randomUUID();
  const r=await pool.query(`INSERT INTO grc_workflow_transitions(id,record_type,record_id,from_state,to_state,actor_user_id,reason,snapshot)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [id,input.recordType,input.recordId,input.fromState||null,input.toState,input.actorUserId||null,input.reason||null,input.snapshot||{}]);
  return r.rows[0];
}

export async function grcDashboard(){
  const [controls,risks,issues,evidence]=await Promise.all([
    pool.query(`SELECT count(*)::int total,
      count(*) FILTER(WHERE overall_status='EFFECTIVE')::int effective,
      count(*) FILTER(WHERE overall_status='INEFFECTIVE')::int ineffective,
      count(*) FILTER(WHERE overall_status='PARTIALLY_EFFECTIVE')::int partial,
      count(*) FILTER(WHERE overall_status='NOT_ASSESSED')::int not_assessed FROM grc_control_assessments`),
    pool.query(`SELECT count(*)::int total,count(*) FILTER(WHERE status='OPEN')::int open,
      count(*) FILTER(WHERE inherent_rating='CRITICAL' AND status='OPEN')::int critical FROM grc_risks`),
    pool.query(`SELECT count(*) FILTER(WHERE status<>'CLOSED')::int open,
      count(*) FILTER(WHERE status<>'CLOSED' AND due_at<now())::int overdue FROM grc_issues`),
    pool.query(`SELECT count(*) FILTER(WHERE status='VALID')::int valid,
      count(*) FILTER(WHERE valid_until IS NOT NULL AND valid_until<now())::int expired,
      count(*) FILTER(WHERE valid_until BETWEEN now() AND now()+interval '7 days')::int expiring FROM grc_evidence`)
  ]);
  return {controls:controls.rows[0],risks:risks.rows[0],issues:issues.rows[0],evidence:evidence.rows[0]};
}
