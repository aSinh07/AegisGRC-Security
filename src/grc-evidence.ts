import crypto from 'node:crypto';import pg from 'pg';import {requireOrgPermission} from './grc-organizations.js';
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
export async function initEvidenceEngine(){await pool.query(`
CREATE TABLE IF NOT EXISTS grc_evidence_requests(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 scope_control_id uuid NOT NULL REFERENCES grc_scope_controls(id) ON DELETE CASCADE,
 title text NOT NULL,description text NOT NULL DEFAULT '',owner_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,
 status text NOT NULL DEFAULT 'REQUESTED' CHECK(status IN ('REQUESTED','SUBMITTED','VALIDATION','VALID','CHANGES_REQUESTED','STALE','EXPIRED')),
 due_at timestamptz,validity_days integer NOT NULL DEFAULT 90 CHECK(validity_days BETWEEN 1 AND 730),
 created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS grc_evidence_versions(
 id uuid PRIMARY KEY,evidence_request_id uuid NOT NULL REFERENCES grc_evidence_requests(id) ON DELETE CASCADE,
 version integer NOT NULL,source_type text NOT NULL CHECK(source_type IN ('UPLOAD','API','SCANNER','MANUAL')),
 source_ref text,sha256 text NOT NULL,content_type text,byte_size bigint,
 metadata jsonb NOT NULL DEFAULT '{}'::jsonb,submitted_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 submitted_at timestamptz NOT NULL DEFAULT now(),validated_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 validated_at timestamptz,valid_until timestamptz,validation_note text,
 UNIQUE(evidence_request_id,version)
);
CREATE TABLE IF NOT EXISTS grc_control_test_definitions(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 scope_control_id uuid NOT NULL REFERENCES grc_scope_controls(id) ON DELETE CASCADE,
 name text NOT NULL,test_type text NOT NULL CHECK(test_type IN ('EVIDENCE_PRESENT','MANUAL_ASSERTION','BOOLEAN_FIELD')),
 expected jsonb NOT NULL DEFAULT '{}'::jsonb,active boolean NOT NULL DEFAULT true,
 created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS grc_control_test_runs(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 test_definition_id uuid NOT NULL REFERENCES grc_control_test_definitions(id) ON DELETE CASCADE,
 result text NOT NULL CHECK(result IN ('PASS','FAIL','NOT_TESTED','ERROR')),
 rationale text NOT NULL,evidence_version_id uuid REFERENCES grc_evidence_versions(id) ON DELETE SET NULL,
 executed_by uuid REFERENCES app_users(id) ON DELETE SET NULL,executed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS grc_evidence_request_org_idx ON grc_evidence_requests(organization_id,status);
CREATE INDEX IF NOT EXISTS grc_test_run_org_idx ON grc_control_test_runs(organization_id,executed_at DESC);
`)}
async function scopeControl(orgId:string,id:string){return (await pool.query('SELECT * FROM grc_scope_controls WHERE id=$1 AND organization_id=$2',[id,orgId])).rows[0]||null}
export async function createEvidenceRequest(userId:string,orgId:string,input:any){
 await requireOrgPermission(userId,orgId,'manageControl');const sc=await scopeControl(orgId,String(input.scopeControlId||''));if(!sc)throw Object.assign(new Error('Scope control not found'),{statusCode:404});
 const title=String(input.title||'').trim();if(title.length<3)throw new Error('Evidence request title required');
 if(input.ownerUserId)await requireOrgPermission(input.ownerUserId,orgId,'read');
 return (await pool.query(`INSERT INTO grc_evidence_requests(id,organization_id,scope_control_id,title,description,owner_user_id,due_at,validity_days,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,[crypto.randomUUID(),orgId,sc.id,title,String(input.description||''),input.ownerUserId||null,input.dueAt||null,Number(input.validityDays||90),userId])).rows[0]
}
export async function submitEvidence(userId:string,orgId:string,requestId:string,input:any){
 await requireOrgPermission(userId,orgId,'manageControl');
 const sha=String(input.sha256||'').toLowerCase();if(!/^[a-f0-9]{64}$/.test(sha))throw new Error('Valid SHA-256 is required');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const req=(await client.query('SELECT * FROM grc_evidence_requests WHERE id=$1 AND organization_id=$2 FOR UPDATE',[requestId,orgId])).rows[0];
  if(!req)throw Object.assign(new Error('Evidence request not found'),{statusCode:404});
  if(req.owner_user_id&&req.owner_user_id!==userId){
   const m=await requireOrgPermission(userId,orgId,'manageControl');
   if(!['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST'].includes(m.role))throw Object.assign(new Error('Evidence owner or GRC manager required'),{statusCode:403});
  }
  const v=Number((await client.query('SELECT COALESCE(max(version),0)+1 v FROM grc_evidence_versions WHERE evidence_request_id=$1',[requestId])).rows[0].v);
  const row=(await client.query(`INSERT INTO grc_evidence_versions(id,evidence_request_id,version,source_type,source_ref,sha256,content_type,byte_size,metadata,submitted_by)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,[crypto.randomUUID(),requestId,v,String(input.sourceType||'MANUAL').toUpperCase(),input.sourceRef||null,sha,input.contentType||null,input.byteSize||null,input.metadata||{},userId])).rows[0];
  await client.query(`UPDATE grc_evidence_requests SET status='SUBMITTED',updated_at=now() WHERE id=$1`,[requestId]);
  await client.query('COMMIT');return row;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function validateEvidence(userId:string,orgId:string,requestId:string,versionId:string,input:any){
 await requireOrgPermission(userId,orgId,'review');
 const approved=Boolean(input.approved),note=String(input.note||'').trim();if(!approved&&note.length<5)throw new Error('Change request requires a reason');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const q=(await client.query(`SELECT r.*,v.submitted_by FROM grc_evidence_requests r JOIN grc_evidence_versions v ON v.evidence_request_id=r.id WHERE r.id=$1 AND r.organization_id=$2 AND v.id=$3 FOR UPDATE OF r,v`,[requestId,orgId,versionId])).rows[0];
  if(!q)throw Object.assign(new Error('Evidence version not found'),{statusCode:404});
  if(q.submitted_by===userId)throw Object.assign(new Error('Evidence submitter cannot validate own evidence'),{statusCode:409});
  if(approved){
   await client.query(`UPDATE grc_evidence_versions SET validated_by=$2,validated_at=now(),valid_until=now()+($3::text||' days')::interval,validation_note=$4 WHERE id=$1`,[versionId,userId,q.validity_days,note||null]);
   await client.query(`UPDATE grc_evidence_requests SET status='VALID',updated_at=now() WHERE id=$1`,[requestId]);
  }else{
   await client.query(`UPDATE grc_evidence_requests SET status='CHANGES_REQUESTED',updated_at=now() WHERE id=$1`,[requestId]);
  }
  await client.query('COMMIT');return {requestId,versionId,status:approved?'VALID':'CHANGES_REQUESTED'};
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function createTestDefinition(userId:string,orgId:string,input:any){
 await requireOrgPermission(userId,orgId,'manageControl');const sc=await scopeControl(orgId,String(input.scopeControlId||''));if(!sc)throw Object.assign(new Error('Scope control not found'),{statusCode:404});
 const type=String(input.testType||'EVIDENCE_PRESENT').toUpperCase();if(!['EVIDENCE_PRESENT','MANUAL_ASSERTION','BOOLEAN_FIELD'].includes(type))throw new Error('Unsupported deterministic test type');
 return (await pool.query(`INSERT INTO grc_control_test_definitions(id,organization_id,scope_control_id,name,test_type,expected,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[crypto.randomUUID(),orgId,sc.id,String(input.name||'Evidence test'),type,input.expected||{},userId])).rows[0]
}
export async function runControlTest(userId:string,orgId:string,testId:string){
 await requireOrgPermission(userId,orgId,'manageControl');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const t=(await client.query('SELECT * FROM grc_control_test_definitions WHERE id=$1 AND organization_id=$2 AND active=true FOR UPDATE',[testId,orgId])).rows[0];
  if(!t)throw Object.assign(new Error('Control test not found'),{statusCode:404});
  let result:'PASS'|'FAIL'|'NOT_TESTED'='NOT_TESTED',rationale='No deterministic result';
  let ev:any=null;
  if(t.test_type==='EVIDENCE_PRESENT'){
   ev=(await client.query(`SELECT v.* FROM grc_evidence_requests r JOIN grc_evidence_versions v ON v.evidence_request_id=r.id WHERE r.organization_id=$1 AND r.scope_control_id=$2 AND r.status='VALID' AND v.validated_at IS NOT NULL AND v.valid_until>now() ORDER BY v.validated_at DESC LIMIT 1 FOR UPDATE OF v`,[orgId,t.scope_control_id])).rows[0];
   result=ev?'PASS':'FAIL';rationale=ev?'Current independently validated evidence is present':'No current independently validated evidence is present';
  }
  const run=(await client.query(`INSERT INTO grc_control_test_runs(id,organization_id,test_definition_id,result,rationale,evidence_version_id,executed_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[crypto.randomUUID(),orgId,testId,result,rationale,ev?.id||null,userId])).rows[0];
  if(result==='FAIL'){
   const issueId=crypto.randomUUID(),issueKey='ISS-'+new Date().getUTCFullYear()+'-'+crypto.randomBytes(3).toString('hex').toUpperCase();
   await client.query(`INSERT INTO grc_issues(id,organization_id,issue_key,title,description,source_type,source_id,priority,status,created_by)
    SELECT $1,$2,$3,$4,$5,'CONTROL_TEST',$6,'P2','OPEN',$7
    WHERE NOT EXISTS(SELECT 1 FROM grc_issues WHERE organization_id=$2 AND source_type='CONTROL_TEST' AND source_id=$6 AND status<>'CLOSED')`,
    [issueId,orgId,issueKey,'Failed control test: '+t.name,rationale,testId,userId]);
  }
  await client.query('COMMIT');
  return run;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function listEvidence(userId:string,orgId:string){await requireOrgPermission(userId,orgId,'read');return (await pool.query(`SELECT r.*,v.id latest_version_id,v.version,v.sha256,v.validated_at,v.valid_until FROM grc_evidence_requests r LEFT JOIN LATERAL(SELECT * FROM grc_evidence_versions WHERE evidence_request_id=r.id ORDER BY version DESC LIMIT 1)v ON true WHERE r.organization_id=$1 ORDER BY r.created_at DESC`,[orgId])).rows}

export async function listControlTests(userId:string,orgId:string){
 await requireOrgPermission(userId,orgId,'read');
 return (await pool.query(`SELECT t.id,t.scope_control_id,t.name,t.test_type,t.active,t.created_at,
 r.id latest_run_id,r.result latest_result,r.rationale latest_rationale,r.executed_at latest_executed_at
 FROM grc_control_test_definitions t
 LEFT JOIN LATERAL(SELECT * FROM grc_control_test_runs WHERE test_definition_id=t.id ORDER BY executed_at DESC LIMIT 1) r ON true
 WHERE t.organization_id=$1 ORDER BY t.created_at DESC`,[orgId])).rows;
}
