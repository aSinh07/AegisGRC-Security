import crypto from 'node:crypto';
import pg from 'pg';
import {requireOrgPermission,requireAssessmentAccess} from './grc-organizations.js';
import type {Severity} from './models.js';
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});

export const defaultSlaDays:Record<Severity,number>={CRITICAL:7,HIGH:30,MEDIUM:90,LOW:180,INFO:365};
export function remediationDueAt(severity:Severity,policy:Partial<Record<Severity,number>>={},from=new Date()){
 const days=Number(policy[severity]??defaultSlaDays[severity]);
 if(!Number.isFinite(days)||days<1||days>3650)throw new Error('SLA days must be between 1 and 3650');
 return new Date(from.getTime()+days*86400000);
}
export async function initFindingRisk(){
 await pool.query(`
 CREATE TABLE IF NOT EXISTS grc_sla_policies(
  organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
  severity text NOT NULL CHECK(severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
  days int NOT NULL CHECK(days BETWEEN 1 AND 3650),updated_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(organization_id,severity)
 );
 ALTER TABLE grc_issues ADD COLUMN IF NOT EXISTS assessment_id uuid REFERENCES assessments(id) ON DELETE SET NULL;
 ALTER TABLE grc_issues ADD COLUMN IF NOT EXISTS finding_id uuid REFERENCES findings(id) ON DELETE SET NULL;
 CREATE UNIQUE INDEX IF NOT EXISTS grc_issue_finding_unique ON grc_issues(organization_id,finding_id) WHERE finding_id IS NOT NULL;
 `);
}
export async function slaPolicy(user:string,org:string){
 await requireOrgPermission(user,org,'read');const rows=(await pool.query('SELECT severity,days FROM grc_sla_policies WHERE organization_id=$1',[org])).rows;
 return {...defaultSlaDays,...Object.fromEntries(rows.map((x:any)=>[x.severity,Number(x.days)]))};
}
export async function setSlaPolicy(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');const values=input||{},updates:Array<[Severity,number]>=[];
 for(const s of Object.keys(defaultSlaDays) as Severity[]){if(values[s]===undefined)continue;const d=Number(values[s]);if(!Number.isInteger(d)||d<1||d>3650)throw new Error(s+' SLA must be an integer from 1 to 3650 days');updates.push([s,d])}
 const client=await pool.connect();try{await client.query('BEGIN');
  for(const [s,d] of updates)await client.query(`INSERT INTO grc_sla_policies(organization_id,severity,days,updated_by) VALUES($1,$2,$3,$4)
   ON CONFLICT(organization_id,severity) DO UPDATE SET days=EXCLUDED.days,updated_by=EXCLUDED.updated_by,updated_at=now()`,[org,s,d,user]);
  if(updates.length)await client.query(`INSERT INTO grc_record_events(id,organization_id,record_type,record_id,event,actor_user_id,snapshot)
   VALUES($1,$2,'SLA_POLICY',$2,'UPDATED',$3,$4)`,[crypto.randomUUID(),org,user,Object.fromEntries(updates)]);
  await client.query('COMMIT');
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
 return slaPolicy(user,org);
}
export async function promoteFindingToIssue(user:string,org:string,assessmentId:string,findingId:string,input:any={}){
 await requireOrgPermission(user,org,'manageRisk');await requireAssessmentAccess(user,assessmentId);
 const a=(await pool.query('SELECT organization_id FROM assessments WHERE id=$1',[assessmentId])).rows[0];
 if(!a||a.organization_id!==org)throw Object.assign(new Error('Assessment does not belong to organization'),{statusCode:403});
 const f=(await pool.query('SELECT payload FROM findings WHERE id=$1 AND assessment_id=$2',[findingId,assessmentId])).rows[0]?.payload;
 if(!f)throw Object.assign(new Error('Finding not found'),{statusCode:404});
 const latest=(await pool.query('SELECT decision FROM finding_reviews WHERE finding_id=$1 AND assessment_id=$2 ORDER BY created_at DESC LIMIT 1',[findingId,assessmentId])).rows[0];
 if(!latest||latest.decision!=='CONFIRMED')throw Object.assign(new Error('Only analyst-confirmed findings can become GRC issues'),{statusCode:409});
 const existing=(await pool.query('SELECT * FROM grc_issues WHERE organization_id=$1 AND finding_id=$2',[org,findingId])).rows[0];if(existing)return existing;
 if(input.ownerUserId){
  const owner=(await pool.query(`SELECT 1 FROM grc_organization_members m JOIN grc_organizations o ON o.id=m.organization_id
   WHERE m.organization_id=$1 AND m.user_id=$2 AND m.status='ACTIVE' AND o.status='ACTIVE'`,[org,input.ownerUserId])).rows[0];
  if(!owner)throw Object.assign(new Error('Issue owner must be an active organization member'),{statusCode:400});
 }
 const policy=await slaPolicy(user,org),due=remediationDueAt(f.severity,policy),id=crypto.randomUUID();
 const priority=f.severity==='CRITICAL'?'P0':f.severity==='HIGH'?'P1':f.severity==='MEDIUM'?'P2':'P3';
 const issueKey='ISSUE-'+new Date().getUTCFullYear()+'-'+crypto.randomBytes(3).toString('hex').toUpperCase();
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const row=(await client.query(`INSERT INTO grc_issues(id,organization_id,issue_key,title,description,source_type,source_id,priority,status,owner_user_id,due_at,created_by,assessment_id,finding_id)
   VALUES($1,$2,$3,$4,$5,'CONFIRMED_FINDING',$6,$7,'OPEN',$8,$9,$10,$11,$12) RETURNING *`,
   [id,org,issueKey,String(input.title||f.title),String(input.description||f.description||''),findingId,priority,input.ownerUserId||null,due,user,assessmentId,findingId])).rows[0];
  await client.query(`INSERT INTO grc_record_events(id,organization_id,record_type,record_id,event,actor_user_id,snapshot)
   VALUES($1,$2,'ISSUE',$3,'CREATED_FROM_CONFIRMED_FINDING',$4,$5)`,
   [crypto.randomUUID(),org,id,user,{assessmentId,findingId,priority,dueAt:due.toISOString()}]);
  await client.query('COMMIT');return row;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
