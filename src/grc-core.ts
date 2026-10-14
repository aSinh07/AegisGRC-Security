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
export type EvidenceSufficiency = 'INSUFFICIENT'|'PARTIAL'|'SUFFICIENT';
export type ReviewResult = 'NOT_REVIEWED'|'PASS'|'PARTIAL'|'FAIL'|'NOT_APPLICABLE';
export type ApprovalStatus = 'PENDING'|'APPROVED'|'REJECTED';
export type RiskTreatment = 'MITIGATE'|'ACCEPT'|'TRANSFER'|'AVOID';
export type SoAApplicability = 'APPLICABLE'|'NOT_APPLICABLE'|'PENDING';
export type SoAImplementation = 'NOT_IMPLEMENTED'|'PARTIAL'|'IMPLEMENTED';
export type AiRiskClass = 'PROHIBITED'|'HIGH'|'TRANSPARENCY'|'MINIMAL'|'UNDETERMINED';

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
      evidence_sufficiency text NOT NULL DEFAULT 'INSUFFICIENT',
      automated_result text NOT NULL DEFAULT 'NOT_REVIEWED',
      manual_result text NOT NULL DEFAULT 'NOT_REVIEWED',
      approval_status text NOT NULL DEFAULT 'PENDING',
      approved_by uuid, approved_at timestamptz, review_notes text,
      last_tested_at timestamptz, next_test_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(scope_id,control_id)
    );
    ALTER TABLE grc_control_assessments ADD COLUMN IF NOT EXISTS evidence_sufficiency text NOT NULL DEFAULT 'INSUFFICIENT';
    ALTER TABLE grc_control_assessments ADD COLUMN IF NOT EXISTS automated_result text NOT NULL DEFAULT 'NOT_REVIEWED';
    ALTER TABLE grc_control_assessments ADD COLUMN IF NOT EXISTS manual_result text NOT NULL DEFAULT 'NOT_REVIEWED';
    ALTER TABLE grc_control_assessments ADD COLUMN IF NOT EXISTS approval_status text NOT NULL DEFAULT 'PENDING';
    ALTER TABLE grc_control_assessments ADD COLUMN IF NOT EXISTS approved_by uuid;
    ALTER TABLE grc_control_assessments ADD COLUMN IF NOT EXISTS approved_at timestamptz;
    ALTER TABLE grc_control_assessments ADD COLUMN IF NOT EXISTS review_notes text;
    CREATE TABLE IF NOT EXISTS grc_control_assessment_events(
      id uuid PRIMARY KEY, assessment_id uuid NOT NULL REFERENCES grc_control_assessments(id) ON DELETE CASCADE,
      event text NOT NULL, actor_user_id uuid, snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS grc_risk_methodologies(
      id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
      name text NOT NULL, likelihood_max integer NOT NULL DEFAULT 5 CHECK(likelihood_max BETWEEN 3 AND 10),
      impact_max integer NOT NULL DEFAULT 5 CHECK(impact_max BETWEEN 3 AND 10),
      thresholds jsonb NOT NULL DEFAULT '{"critical":20,"high":15,"medium":8,"low":4}'::jsonb,
      is_default boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS grc_statements_of_applicability(
      id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
      scope_id uuid NOT NULL REFERENCES grc_scopes(id) ON DELETE CASCADE,
      control_id uuid NOT NULL REFERENCES grc_controls(id) ON DELETE CASCADE,
      applicability text NOT NULL DEFAULT 'PENDING', justification text,
      implementation_state text NOT NULL DEFAULT 'NOT_IMPLEMENTED', related_risk_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
      evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb, owner_user_id uuid, reviewer_user_id uuid,
      approval_status text NOT NULL DEFAULT 'PENDING', approved_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(scope_id,control_id)
    );
    CREATE TABLE IF NOT EXISTS grc_ai_impact_assessments(
      id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
      scope_id uuid REFERENCES grc_scopes(id) ON DELETE CASCADE, system_name text NOT NULL,
      intended_use text NOT NULL, affected_parties text, data_categories text, human_oversight text,
      potential_impacts text, mitigations text, evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
      eu_risk_class text NOT NULL DEFAULT 'UNDETERMINED', status text NOT NULL DEFAULT 'DRAFT',
      reviewer_user_id uuid, approval_status text NOT NULL DEFAULT 'PENDING', approved_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS grc_privacy_assessments(
      id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
      scope_id uuid REFERENCES grc_scopes(id) ON DELETE CASCADE, processing_activity text NOT NULL,
      pii_categories text, purposes text, data_subjects text, retention text, recipients text,
      safeguards text, evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb, status text NOT NULL DEFAULT 'DRAFT',
      reviewer_user_id uuid, approval_status text NOT NULL DEFAULT 'PENDING',
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
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
      methodology_id uuid REFERENCES grc_risk_methodologies(id), acceptance_rationale text,
      accepted_by uuid, accepted_at timestamptz, acceptance_expires_at timestamptz,
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
    ALTER TABLE grc_risks ADD COLUMN IF NOT EXISTS methodology_id uuid REFERENCES grc_risk_methodologies(id);
    ALTER TABLE grc_risks ADD COLUMN IF NOT EXISTS acceptance_rationale text;
    ALTER TABLE grc_risks ADD COLUMN IF NOT EXISTS accepted_by uuid;
    ALTER TABLE grc_risks ADD COLUMN IF NOT EXISTS accepted_at timestamptz;
    ALTER TABLE grc_risks ADD COLUMN IF NOT EXISTS acceptance_expires_at timestamptz;
    CREATE INDEX IF NOT EXISTS grc_risks_org_idx ON grc_risks(organization_id);
    CREATE INDEX IF NOT EXISTS grc_issues_org_status_idx ON grc_issues(organization_id,status);
    CREATE INDEX IF NOT EXISTS grc_evidence_validity_idx ON grc_evidence(valid_until);
  `);
}

export async function createRiskMethodology(input:{organizationId:string;name:string;likelihoodMax?:number;impactMax?:number;thresholds?:any;isDefault?:boolean}){
 if(!input.organizationId||!input.name?.trim())throw new Error('Organization and methodology name are required');
 const l=input.likelihoodMax||5,i=input.impactMax||5;if(l<3||l>10||i<3||i>10)throw new Error('Risk scales must be between 3 and 10');
 const thresholds=input.thresholds||{critical:20,high:15,medium:8,low:4};
 const critical=Number(thresholds.critical),high=Number(thresholds.high),medium=Number(thresholds.medium),low=Number(thresholds.low),maxScore=l*i;
 if(![critical,high,medium,low].every(Number.isFinite)||!(critical>high&&high>medium&&medium>low&&low>=1)||critical>maxScore)throw new Error('Risk thresholds must be ordered critical > high > medium > low >= 1 and fit the selected scale');
 if(input.isDefault)await pool.query('UPDATE grc_risk_methodologies SET is_default=false WHERE organization_id=$1',[input.organizationId]);
 return (await pool.query(`INSERT INTO grc_risk_methodologies(id,organization_id,name,likelihood_max,impact_max,thresholds,is_default)
 VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[crypto.randomUUID(),input.organizationId,input.name.trim(),l,i,thresholds,Boolean(input.isDefault)])).rows[0];
}
export async function listRiskMethodologies(organizationId:string){return (await pool.query('SELECT * FROM grc_risk_methodologies WHERE organization_id=$1 ORDER BY is_default DESC,created_at',[organizationId])).rows}

export async function upsertStatementOfApplicability(input:{organizationId:string;scopeId:string;controlId:string;applicability:SoAApplicability;justification:string;implementationState:SoAImplementation;relatedRiskIds?:string[];evidenceRefs?:string[];ownerUserId?:string;reviewerUserId?:string;actorUserId?:string;approvalStatus?:ApprovalStatus}){
 if(!input.justification||input.justification.trim().length<10)throw new Error('SoA justification is required');
 const scope=(await pool.query('SELECT id FROM grc_scopes WHERE id=$1 AND organization_id=$2',[input.scopeId,input.organizationId])).rows[0];if(!scope)throw new Error('Scope not found in organization');
 if(input.approvalStatus==='APPROVED'&&!input.reviewerUserId)throw new Error('SoA approval requires accountable reviewer');
 if(input.approvalStatus==='APPROVED'&&input.actorUserId&&input.ownerUserId===input.actorUserId)throw new Error('SoA owner cannot approve their own applicability decision');
 if(input.approvalStatus==='APPROVED'&&input.applicability==='PENDING')throw new Error('Pending applicability cannot be approved');
 return (await pool.query(`INSERT INTO grc_statements_of_applicability(id,organization_id,scope_id,control_id,applicability,justification,implementation_state,related_risk_ids,evidence_refs,owner_user_id,reviewer_user_id,approval_status,approved_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CASE WHEN $12='APPROVED' THEN now() ELSE NULL END)
 ON CONFLICT(scope_id,control_id) DO UPDATE SET applicability=EXCLUDED.applicability,justification=EXCLUDED.justification,implementation_state=EXCLUDED.implementation_state,related_risk_ids=EXCLUDED.related_risk_ids,evidence_refs=EXCLUDED.evidence_refs,owner_user_id=EXCLUDED.owner_user_id,reviewer_user_id=EXCLUDED.reviewer_user_id,approval_status=EXCLUDED.approval_status,approved_at=EXCLUDED.approved_at,updated_at=now() RETURNING *`,
 [crypto.randomUUID(),input.organizationId,input.scopeId,input.controlId,input.applicability,input.justification.trim(),input.implementationState,input.relatedRiskIds||[],input.evidenceRefs||[],input.ownerUserId||null,input.reviewerUserId||null,input.approvalStatus||'PENDING'])).rows[0];
}
export async function listStatementsOfApplicability(organizationId:string,scopeId?:string){const v:any[]=[organizationId];let f='';if(scopeId){v.push(scopeId);f=' AND s.scope_id=$2'}return (await pool.query(`SELECT s.*,c.control_key,c.title AS control_title FROM grc_statements_of_applicability s JOIN grc_controls c ON c.id=s.control_id WHERE s.organization_id=$1${f} ORDER BY c.control_key`,v)).rows}

export async function createAiImpactAssessment(input:{organizationId:string;scopeId?:string;systemName:string;intendedUse:string;affectedParties?:string;dataCategories?:string;humanOversight?:string;potentialImpacts?:string;mitigations?:string;evidenceRefs?:string[];euRiskClass?:AiRiskClass}){
 if(!input.organizationId||!input.systemName?.trim()||!input.intendedUse?.trim())throw new Error('Organization, AI system name and intended use are required');
 if(input.scopeId){const x=(await pool.query('SELECT id FROM grc_scopes WHERE id=$1 AND organization_id=$2',[input.scopeId,input.organizationId])).rows[0];if(!x)throw new Error('Scope not found in organization')}
 return (await pool.query(`INSERT INTO grc_ai_impact_assessments(id,organization_id,scope_id,system_name,intended_use,affected_parties,data_categories,human_oversight,potential_impacts,mitigations,evidence_refs,eu_risk_class)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,[crypto.randomUUID(),input.organizationId,input.scopeId||null,input.systemName.trim(),input.intendedUse.trim(),input.affectedParties||null,input.dataCategories||null,input.humanOversight||null,input.potentialImpacts||null,input.mitigations||null,input.evidenceRefs||[],input.euRiskClass||'UNDETERMINED'])).rows[0];
}
export async function listAiImpactAssessments(organizationId:string){return (await pool.query('SELECT * FROM grc_ai_impact_assessments WHERE organization_id=$1 ORDER BY created_at DESC',[organizationId])).rows}
export async function listPrivacyAssessments(organizationId:string){return (await pool.query('SELECT * FROM grc_privacy_assessments WHERE organization_id=$1 ORDER BY created_at DESC',[organizationId])).rows}

export async function createPrivacyAssessment(input:{organizationId:string;scopeId?:string;processingActivity:string;piiCategories?:string;purposes?:string;dataSubjects?:string;retention?:string;recipients?:string;safeguards?:string;evidenceRefs?:string[]}){
 if(!input.organizationId||!input.processingActivity?.trim())throw new Error('Organization and processing activity are required');
 if(input.scopeId){const x=(await pool.query('SELECT id FROM grc_scopes WHERE id=$1 AND organization_id=$2',[input.scopeId,input.organizationId])).rows[0];if(!x)throw new Error('Scope not found in organization')}
 return (await pool.query(`INSERT INTO grc_privacy_assessments(id,organization_id,scope_id,processing_activity,pii_categories,purposes,data_subjects,retention,recipients,safeguards,evidence_refs)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,[crypto.randomUUID(),input.organizationId,input.scopeId||null,input.processingActivity.trim(),input.piiCategories||null,input.purposes||null,input.dataSubjects||null,input.retention||null,input.recipients||null,input.safeguards||null,input.evidenceRefs||[]])).rows[0];
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

export async function listRisks(organizationId:string){
  if(!organizationId)throw new Error('Organization scope is required');
  const r=await pool.query('SELECT * FROM grc_risks WHERE organization_id=$1 ORDER BY inherent_score DESC,created_at DESC',[organizationId]);
  return r.rows;
}

export async function createControlAssessment(input:{scopeId:string;controlId:string;ownerUserId?:string;organizationId?:string}){
  if(!input.organizationId)throw new Error('Organization scope is required');
  const scope=(await pool.query('SELECT id FROM grc_scopes WHERE id=$1 AND organization_id=$2',[input.scopeId,input.organizationId])).rows[0];
  if(!scope)throw new Error('Scope not found in organization');
  const id=crypto.randomUUID();
  const r=await pool.query(`INSERT INTO grc_control_assessments(id,scope_id,control_id,owner_user_id)
    VALUES($1,$2,$3,$4) ON CONFLICT(scope_id,control_id) DO UPDATE SET updated_at=now() RETURNING *`,
    [id,input.scopeId,input.controlId,input.ownerUserId||null]);
  return r.rows[0];
}

export async function updateControlAssessment(id:string,patch:any,organizationId?:string){
  if(!organizationId)throw new Error('Organization scope is required');
  const current=(await pool.query(`SELECT ca.* FROM grc_control_assessments ca JOIN grc_scopes s ON s.id=ca.scope_id WHERE ca.id=$1 AND s.organization_id=$2`,[id,organizationId])).rows[0];
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

export async function reviewControlAssessment(id:string,input:{
  actorUserId:string; evidenceSufficiency:EvidenceSufficiency; automatedResult?:ReviewResult;
  manualResult:ReviewResult; designEffectiveness:Effectiveness; operatingEffectiveness:Effectiveness;
  notes:string; approvalStatus?:ApprovalStatus; organizationId?:string;
}){
  if(!input.organizationId)throw new Error('Organization scope is required');
  if(!input.actorUserId)throw new Error('Accountable reviewer is required');
  if(!input.notes||input.notes.trim().length<10)throw new Error('Review rationale is required');
  if(input.approvalStatus==='APPROVED'&&input.evidenceSufficiency!=='SUFFICIENT')throw new Error('Approval requires sufficient evidence');
  if(input.approvalStatus==='APPROVED'&&(input.designEffectiveness==='NOT_TESTED'||input.operatingEffectiveness==='NOT_TESTED'))throw new Error('Approval requires design and operating effectiveness tests');
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const current=(await client.query(`SELECT ca.* FROM grc_control_assessments ca JOIN grc_scopes s ON s.id=ca.scope_id WHERE ca.id=$1 AND s.organization_id=$2 FOR UPDATE OF ca`,[id,input.organizationId])).rows[0];
    if(!current)throw new Error('Control assessment not found');
    const automated=input.automatedResult||current.automated_result||'NOT_REVIEWED';
    const approval=input.approvalStatus||'PENDING';
    const overall=calculateControlStatus({
      applicability:current.applicability,implementation:current.implementation,
      evidenceStatus:input.evidenceSufficiency==='SUFFICIENT'?'VALID':'PENDING',
      designEffectiveness:input.designEffectiveness,operatingEffectiveness:input.operatingEffectiveness
    });
    const finalStatus=approval==='APPROVED'?overall:'NOT_ASSESSED';
    const row=(await client.query(`UPDATE grc_control_assessments SET evidence_sufficiency=$2,automated_result=$3,
      manual_result=$4,design_effectiveness=$5,operating_effectiveness=$6,approval_status=$7,
      reviewer_user_id=$8,approved_by=CASE WHEN $7='APPROVED' THEN $8 ELSE NULL END,
      approved_at=CASE WHEN $7='APPROVED' THEN now() ELSE NULL END,review_notes=$9,
      evidence_status=CASE WHEN $2='SUFFICIENT' THEN 'VALID' ELSE 'PENDING' END,
      overall_status=$10,last_tested_at=now(),updated_at=now() WHERE id=$1 RETURNING *`,
      [id,input.evidenceSufficiency,automated,input.manualResult,input.designEffectiveness,input.operatingEffectiveness,approval,input.actorUserId,input.notes.trim(),finalStatus])).rows[0];
    await client.query(`INSERT INTO grc_control_assessment_events(id,assessment_id,event,actor_user_id,snapshot)
      VALUES($1,$2,$3,$4,$5)`,[crypto.randomUUID(),id,approval==='APPROVED'?'CONTROL_APPROVED':'CONTROL_REVIEWED',input.actorUserId,{
        evidenceSufficiency:input.evidenceSufficiency,automatedResult:automated,manualResult:input.manualResult,
        designEffectiveness:input.designEffectiveness,operatingEffectiveness:input.operatingEffectiveness,
        approvalStatus:approval,overallStatus:finalStatus,notes:input.notes.trim()
      }]);
    await client.query('COMMIT');return row;
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}

export async function listControlAssessments(organizationId:string,scopeId?:string){
  if(!organizationId)throw new Error('Organization scope is required');
  const values:any[]=[organizationId];let scopeFilter='';
  if(scopeId){values.push(scopeId);scopeFilter=' AND ca.scope_id=$2'}
  return (await pool.query(`SELECT ca.*,c.control_key,c.title AS control_title,s.name AS scope_name
    FROM grc_control_assessments ca JOIN grc_scopes s ON s.id=ca.scope_id
    JOIN grc_controls c ON c.id=ca.control_id
    WHERE s.organization_id=$1${scopeFilter} ORDER BY c.control_key`,values)).rows;
}

export async function controlAssessmentHistory(id:string,organizationId?:string){
  if(!organizationId)throw new Error('Organization scope is required');
  return (await pool.query(`SELECT e.* FROM grc_control_assessment_events e JOIN grc_control_assessments ca ON ca.id=e.assessment_id JOIN grc_scopes s ON s.id=ca.scope_id WHERE e.assessment_id=$1 AND s.organization_id=$2 ORDER BY e.created_at DESC`,[id,organizationId])).rows;
}

export async function recordWorkflowTransition(input:{recordType:string;recordId:string;fromState?:string;toState:string;actorUserId?:string;reason?:string;snapshot?:any}){
  const id=crypto.randomUUID();
  const r=await pool.query(`INSERT INTO grc_workflow_transitions(id,record_type,record_id,from_state,to_state,actor_user_id,reason,snapshot)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [id,input.recordType,input.recordId,input.fromState||null,input.toState,input.actorUserId||null,input.reason||null,input.snapshot||{}]);
  return r.rows[0];
}

export async function grcDashboard(organizationId:string){
  if(!organizationId)throw new Error('Organization scope is required');
  const [controls,risks,issues,evidence]=await Promise.all([
    pool.query(`SELECT count(*)::int total,
      count(*) FILTER(WHERE ca.overall_status='EFFECTIVE')::int effective,
      count(*) FILTER(WHERE ca.overall_status='INEFFECTIVE')::int ineffective,
      count(*) FILTER(WHERE ca.overall_status='PARTIALLY_EFFECTIVE')::int partial,
      count(*) FILTER(WHERE ca.overall_status='NOT_ASSESSED')::int not_assessed
      FROM grc_control_assessments ca JOIN grc_scopes s ON s.id=ca.scope_id WHERE s.organization_id=$1`,[organizationId]),
    pool.query(`SELECT count(*)::int total,count(*) FILTER(WHERE status='OPEN')::int open,
      count(*) FILTER(WHERE inherent_rating='CRITICAL' AND status='OPEN')::int critical
      FROM grc_risks WHERE organization_id=$1`,[organizationId]),
    pool.query(`SELECT count(*) FILTER(WHERE status<>'CLOSED')::int open,
      count(*) FILTER(WHERE status<>'CLOSED' AND due_at<now())::int overdue
      FROM grc_issues WHERE organization_id=$1`,[organizationId]),
    pool.query(`SELECT count(*) FILTER(WHERE status='VALID')::int valid,
      count(*) FILTER(WHERE valid_until IS NOT NULL AND valid_until<now())::int expired,
      count(*) FILTER(WHERE valid_until BETWEEN now() AND now()+interval '7 days')::int expiring
      FROM grc_evidence WHERE organization_id=$1`,[organizationId])
  ]);
  return {organizationId,controls:controls.rows[0],risks:risks.rows[0],issues:issues.rows[0],evidence:evidence.rows[0]};
}
