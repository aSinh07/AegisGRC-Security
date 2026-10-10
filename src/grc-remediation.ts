import crypto from 'node:crypto';import pg from 'pg';import {requireOrgPermission} from './grc-organizations.js';
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
const key=(p:string)=>p+'-'+new Date().getUTCFullYear()+'-'+crypto.randomBytes(3).toString('hex').toUpperCase();
export function riskBand(score:number){return score>=20?'CRITICAL':score>=15?'HIGH':score>=8?'MEDIUM':score>=4?'LOW':'VERY_LOW'}
export async function initIssueRiskCapa(){await pool.query(`
ALTER TABLE grc_issues ADD COLUMN IF NOT EXISTS scope_control_id uuid REFERENCES grc_scope_controls(id) ON DELETE SET NULL;
ALTER TABLE grc_issues ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES app_users(id) ON DELETE SET NULL;
ALTER TABLE grc_issues ADD COLUMN IF NOT EXISTS closed_by uuid REFERENCES app_users(id) ON DELETE SET NULL;
ALTER TABLE grc_issues ADD COLUMN IF NOT EXISTS closed_at timestamptz;
ALTER TABLE grc_capa ADD COLUMN IF NOT EXISTS finding_retest_id uuid REFERENCES finding_retests(id) ON DELETE SET NULL;
CREATE TABLE IF NOT EXISTS grc_enterprise_risks(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,risk_key text UNIQUE NOT NULL,
 title text NOT NULL,description text NOT NULL DEFAULT '',likelihood int NOT NULL CHECK(likelihood BETWEEN 1 AND 5),impact int NOT NULL CHECK(impact BETWEEN 1 AND 5),
 inherent_score int NOT NULL,inherent_rating text NOT NULL,treatment text NOT NULL CHECK(treatment IN ('MITIGATE','ACCEPT','TRANSFER','AVOID')),
 residual_likelihood int CHECK(residual_likelihood BETWEEN 1 AND 5),residual_impact int CHECK(residual_impact BETWEEN 1 AND 5),residual_score int,residual_rating text,
 owner_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,status text NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','TREATMENT','ACCEPTANCE_PENDING','ACCEPTED','CLOSED')),
 acceptance_expires_at timestamptz,accepted_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS grc_issue_risks(issue_id uuid NOT NULL REFERENCES grc_issues(id) ON DELETE CASCADE,risk_id uuid NOT NULL REFERENCES grc_enterprise_risks(id) ON DELETE CASCADE,PRIMARY KEY(issue_id,risk_id));
CREATE TABLE IF NOT EXISTS grc_capa(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,capa_key text UNIQUE NOT NULL,
 issue_id uuid NOT NULL REFERENCES grc_issues(id) ON DELETE CASCADE,root_cause text NOT NULL,corrective_action text NOT NULL,preventive_action text NOT NULL DEFAULT '',
 owner_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,priority text NOT NULL DEFAULT 'P2',status text NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','IN_PROGRESS','EVIDENCE_SUBMITTED','RETEST_PENDING','VALIDATION','CHANGES_REQUESTED','CLOSED','OVERDUE')),
 due_at timestamptz NOT NULL,retest_run_id uuid REFERENCES grc_control_test_runs(id) ON DELETE SET NULL,submitted_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 approved_by uuid REFERENCES app_users(id) ON DELETE SET NULL,closed_at timestamptz,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS grc_capa_evidence(capa_id uuid NOT NULL REFERENCES grc_capa(id) ON DELETE CASCADE,evidence_version_id uuid NOT NULL REFERENCES grc_evidence_versions(id) ON DELETE RESTRICT,linked_by uuid REFERENCES app_users(id) ON DELETE SET NULL,linked_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(capa_id,evidence_version_id));
CREATE TABLE IF NOT EXISTS grc_record_events(id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,record_type text NOT NULL,record_id uuid NOT NULL,event text NOT NULL,actor_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,reason text,snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS grc_capa_org_status_idx ON grc_capa(organization_id,status,due_at);CREATE INDEX IF NOT EXISTS grc_erisk_org_idx ON grc_enterprise_risks(organization_id,status,inherent_score DESC);
`)}
type Queryable={query:(text:string,values?:any[])=>Promise<any>};
async function event(org:string,type:string,id:string,eventName:string,actor:string,reason?:string,snapshot:any={},db:Queryable=pool){await db.query('INSERT INTO grc_record_events(id,organization_id,record_type,record_id,event,actor_user_id,reason,snapshot) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[crypto.randomUUID(),org,type,id,eventName,actor,reason||null,snapshot])}
export async function listIssues(user:string,org:string){await requireOrgPermission(user,org,'read');return (await pool.query('SELECT * FROM grc_issues WHERE organization_id=$1 ORDER BY created_at DESC',[org])).rows}
export async function createRiskFromIssue(user:string,org:string,issueId:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');
 const l=Number(input.likelihood),i=Number(input.impact);if(!Number.isInteger(l)||!Number.isInteger(i)||l<1||l>5||i<1||i>5)throw new Error('Likelihood and impact must be 1-5');
 const score=l*i,t=String(input.treatment||'MITIGATE').toUpperCase();if(!['MITIGATE','ACCEPT','TRANSFER','AVOID'].includes(t))throw new Error('Invalid treatment');
 if(input.ownerUserId)await requireOrgPermission(input.ownerUserId,org,'read');
 const id=crypto.randomUUID(),client=await pool.connect();
 try{
  await client.query('BEGIN');
  const issue=(await client.query('SELECT * FROM grc_issues WHERE id=$1 AND organization_id=$2 FOR UPDATE',[issueId,org])).rows[0];
  if(!issue)throw Object.assign(new Error('Issue not found'),{statusCode:404});
  if(issue.status==='CLOSED')throw Object.assign(new Error('Closed issue cannot create a new risk'),{statusCode:409});
  const risk=(await client.query(`INSERT INTO grc_enterprise_risks(id,organization_id,risk_key,title,description,likelihood,impact,inherent_score,inherent_rating,treatment,owner_user_id,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,[id,org,key('RISK'),String(input.title||issue.title),String(input.description||issue.description||''),l,i,score,riskBand(score),t,input.ownerUserId||null,t==='ACCEPT'?'ACCEPTANCE_PENDING':'TREATMENT',user])).rows[0];
  await client.query('INSERT INTO grc_issue_risks(issue_id,risk_id) VALUES($1,$2)',[issueId,id]);
  await event(org,'RISK',id,'CREATED',user,undefined,{issueId,score,treatment:t},client);
  await client.query('COMMIT');return risk;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function approveRiskAcceptance(user:string,org:string,riskId:string,input:any){
 await requireOrgPermission(user,org,'review');
 const expiry=new Date(String(input.expiresAt||''));if(!Number.isFinite(expiry.getTime())||expiry<=new Date())throw new Error('Future acceptance expiry required');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const r=(await client.query('SELECT * FROM grc_enterprise_risks WHERE id=$1 AND organization_id=$2 FOR UPDATE',[riskId,org])).rows[0];
  if(!r)throw Object.assign(new Error('Risk not found'),{statusCode:404});
  if(r.treatment!=='ACCEPT'||r.status!=='ACCEPTANCE_PENDING')throw Object.assign(new Error('Risk is not awaiting acceptance'),{statusCode:409});
  if(r.created_by===user||r.owner_user_id===user)throw Object.assign(new Error('Risk creator/owner cannot approve own acceptance'),{statusCode:409});
  const out=(await client.query(`UPDATE grc_enterprise_risks SET status='ACCEPTED',acceptance_expires_at=$2,accepted_by=$3,updated_at=now() WHERE id=$1 AND organization_id=$4 AND status='ACCEPTANCE_PENDING' RETURNING *`,[riskId,expiry,user,org])).rows[0];
  if(!out)throw Object.assign(new Error('Risk state changed before acceptance'),{statusCode:409});
  await event(org,'RISK',riskId,'RISK_ACCEPTED',user,String(input.reason||''),{expiresAt:expiry.toISOString()},client);
  await client.query('COMMIT');return out;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function createCapa(user:string,org:string,issueId:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');
 const root=String(input.rootCause||'').trim(),action=String(input.correctiveAction||'').trim();if(root.length<5||action.length<5)throw new Error('Root cause and corrective action are required');
 const due=new Date(String(input.dueAt||''));if(!Number.isFinite(due.getTime())||due<=new Date())throw new Error('Future CAPA due date required');
 if(input.ownerUserId)await requireOrgPermission(input.ownerUserId,org,'read');
 const id=crypto.randomUUID(),client=await pool.connect();
 try{
  await client.query('BEGIN');
  const issue=(await client.query('SELECT * FROM grc_issues WHERE id=$1 AND organization_id=$2 FOR UPDATE',[issueId,org])).rows[0];
  if(!issue)throw Object.assign(new Error('Issue not found'),{statusCode:404});
  if(issue.status==='CLOSED')throw Object.assign(new Error('Closed issue cannot create CAPA'),{statusCode:409});
  const row=(await client.query(`INSERT INTO grc_capa(id,organization_id,capa_key,issue_id,root_cause,corrective_action,preventive_action,owner_user_id,priority,due_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,[id,org,key('CAPA'),issueId,root,action,String(input.preventiveAction||''),input.ownerUserId||null,String(input.priority||issue.priority||'P2'),due,user])).rows[0];
  await event(org,'CAPA',id,'CREATED',user,undefined,{issueId},client);
  await client.query('COMMIT');return row;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function submitCapaEvidence(user:string,org:string,capaId:string,evidenceVersionId:string){
 const m=await requireOrgPermission(user,org,'manageControl');const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const c=(await client.query('SELECT * FROM grc_capa WHERE id=$1 AND organization_id=$2 FOR UPDATE',[capaId,org])).rows[0];
  if(!c)throw Object.assign(new Error('CAPA not found'),{statusCode:404});
  if(!['OPEN','IN_PROGRESS','EVIDENCE_SUBMITTED','CHANGES_REQUESTED'].includes(c.status))throw Object.assign(new Error('CAPA is not accepting evidence in its current state'),{statusCode:409});
  if(c.owner_user_id&&c.owner_user_id!==user&&!['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST'].includes(m.role))throw Object.assign(new Error('CAPA owner required'),{statusCode:403});
  const issue=(await client.query('SELECT scope_control_id FROM grc_issues WHERE id=$1 AND organization_id=$2 FOR UPDATE',[c.issue_id,org])).rows[0];
  const ev=(await client.query(`SELECT v.id,r.scope_control_id FROM grc_evidence_versions v JOIN grc_evidence_requests r ON r.id=v.evidence_request_id WHERE v.id=$1 AND r.organization_id=$2 AND r.status='VALID' AND v.validated_at IS NOT NULL AND v.valid_until>now() FOR UPDATE OF v,r`,[evidenceVersionId,org])).rows[0];
  if(!ev)throw new Error('Current validated evidence version required');
  if(issue?.scope_control_id&&ev.scope_control_id!==issue.scope_control_id)throw Object.assign(new Error('CAPA evidence must belong to the affected control'),{statusCode:409});
  await client.query('INSERT INTO grc_capa_evidence(capa_id,evidence_version_id,linked_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[capaId,evidenceVersionId,user]);
  const out=(await client.query(`UPDATE grc_capa SET status='RETEST_PENDING',submitted_by=$2,updated_at=now() WHERE id=$1 AND status = ANY($3::text[]) RETURNING *`,[capaId,user,['OPEN','IN_PROGRESS','EVIDENCE_SUBMITTED','CHANGES_REQUESTED']])).rows[0];
  if(!out)throw Object.assign(new Error('CAPA state changed before evidence submission'),{statusCode:409});
  await event(org,'CAPA',capaId,'EVIDENCE_SUBMITTED',user,undefined,{evidenceVersionId},client);
  await client.query('COMMIT');return out;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function attachRetest(user:string,org:string,capaId:string,testRunId:string){
 await requireOrgPermission(user,org,'review');const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const c=(await client.query('SELECT * FROM grc_capa WHERE id=$1 AND organization_id=$2 FOR UPDATE',[capaId,org])).rows[0];
  if(!c)throw Object.assign(new Error('CAPA not found'),{statusCode:404});
  if(c.status!=='RETEST_PENDING'&&c.status!=='CHANGES_REQUESTED')throw Object.assign(new Error('CAPA is not ready for retest'),{statusCode:409});
  const run=(await client.query(`SELECT r.*,d.scope_control_id FROM grc_control_test_runs r JOIN grc_control_test_definitions d ON d.id=r.test_definition_id WHERE r.id=$1 AND r.organization_id=$2 FOR UPDATE OF r,d`,[testRunId,org])).rows[0];
  if(!run)throw new Error('Retest run not found');
  const issue=(await client.query('SELECT scope_control_id FROM grc_issues WHERE id=$1 AND organization_id=$2 FOR UPDATE',[c.issue_id,org])).rows[0];
  if(issue?.scope_control_id&&run.scope_control_id!==issue.scope_control_id)throw Object.assign(new Error('CAPA retest must test the affected control'),{statusCode:409});
  if(run.result!=='PASS'&&run.result!=='FAIL')throw Object.assign(new Error('Retest must have a deterministic PASS or FAIL result'),{statusCode:409});
  const status=run.result==='PASS'?'VALIDATION':'CHANGES_REQUESTED';
  const out=(await client.query(`UPDATE grc_capa SET retest_run_id=$2,status=$3,updated_at=now() WHERE id=$1 AND status = ANY($4::text[]) RETURNING *`,[capaId,testRunId,status,['RETEST_PENDING','CHANGES_REQUESTED']])).rows[0];
  if(!out)throw Object.assign(new Error('CAPA state changed before retest attachment'),{statusCode:409});
  await event(org,'CAPA',capaId,'RETEST_'+run.result,user,run.rationale,{testRunId},client);
  await client.query('COMMIT');return out;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function closeCapa(user:string,org:string,capaId:string,input:any){
 await requireOrgPermission(user,org,'review');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const c=(await client.query(`SELECT c.*,r.result retest_result,fr.id finding_retest_proof FROM grc_capa c LEFT JOIN grc_control_test_runs r ON r.id=c.retest_run_id LEFT JOIN finding_retests fr ON fr.id=c.finding_retest_id WHERE c.id=$1 AND c.organization_id=$2 FOR UPDATE OF c`,[capaId,org])).rows[0];
  if(!c)throw Object.assign(new Error('CAPA not found'),{statusCode:404});
  const validatedByControlTest=c.retest_result==='PASS',validatedByFindingRetest=Boolean(c.finding_retest_proof);
  if(c.status!=='VALIDATION'||(!validatedByControlTest&&!validatedByFindingRetest))throw Object.assign(new Error('Validated control-test or targeted finding-retest proof required'),{statusCode:409});
  if(c.created_by===user||c.owner_user_id===user||c.submitted_by===user)throw Object.assign(new Error('Independent reviewer required for CAPA closure'),{statusCode:409});
  const out=(await client.query(`UPDATE grc_capa SET status='CLOSED',approved_by=$2,closed_at=now(),updated_at=now() WHERE id=$1 AND status='VALIDATION' RETURNING *`,[capaId,user])).rows[0];
  if(!out)throw Object.assign(new Error('CAPA state changed before closure'),{statusCode:409});
  await client.query(`UPDATE grc_issues SET status='CLOSED',closed_by=$2,closed_at=now(),updated_at=now() WHERE id=$1`,[c.issue_id,user]);
  await event(org,'CAPA',capaId,'CLOSED',user,String(input.reason||''),{retestRunId:c.retest_run_id,findingRetestId:c.finding_retest_id,validationSource:c.finding_retest_id?'TARGETED_FINDING_RETEST':'CONTROL_TEST'},client);
  await client.query('COMMIT');return out;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function listCapa(user:string,org:string){await requireOrgPermission(user,org,'read');return (await pool.query(`SELECT c.*,CASE WHEN c.status<>'CLOSED' AND c.due_at<now() THEN true ELSE false END AS overdue FROM grc_capa c WHERE organization_id=$1 ORDER BY due_at ASC`,[org])).rows}
export async function listEnterpriseRisks(user:string,org:string){await requireOrgPermission(user,org,'read');return (await pool.query('SELECT * FROM grc_enterprise_risks WHERE organization_id=$1 ORDER BY inherent_score DESC,created_at DESC',[org])).rows}
