import crypto from 'node:crypto';
import pg from 'pg';
import {requireOrgPermission} from './grc-organizations.js';

const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
const kinds=['EVIDENCE_EXPIRY','CONTROL_TEST_DUE','CAPA_SLA','RISK_ACCEPTANCE_EXPIRY'] as const;
type Kind=typeof kinds[number];

export async function initGrcAutomation(){await pool.query(`
CREATE TABLE IF NOT EXISTS grc_automation_rules(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 name text NOT NULL,kind text NOT NULL CHECK(kind IN ('EVIDENCE_EXPIRY','CONTROL_TEST_DUE','CAPA_SLA','RISK_ACCEPTANCE_EXPIRY')),
 enabled boolean NOT NULL DEFAULT true,interval_hours integer NOT NULL DEFAULT 24 CHECK(interval_hours BETWEEN 1 AND 8760),
 config jsonb NOT NULL DEFAULT '{}'::jsonb,last_run_at timestamptz,next_run_at timestamptz NOT NULL DEFAULT now(),
 created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS grc_automation_runs(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 rule_id uuid NOT NULL REFERENCES grc_automation_rules(id) ON DELETE CASCADE,
 status text NOT NULL CHECK(status IN ('RUNNING','SUCCEEDED','FAILED')),started_at timestamptz NOT NULL DEFAULT now(),finished_at timestamptz,
 actions_count integer NOT NULL DEFAULT 0,summary jsonb NOT NULL DEFAULT '{}'::jsonb,error text
);
CREATE INDEX IF NOT EXISTS grc_automation_due_idx ON grc_automation_rules(enabled,next_run_at);
CREATE INDEX IF NOT EXISTS grc_automation_runs_org_idx ON grc_automation_runs(organization_id,started_at DESC);
`)}

export async function createAutomationRule(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageOrg');
 const kind=String(input.kind||'').toUpperCase() as Kind;if(!kinds.includes(kind))throw new Error('Unsupported automation kind');
 const hours=Number(input.intervalHours||24);if(!Number.isInteger(hours)||hours<1||hours>8760)throw new Error('Automation interval must be 1-8760 hours');
 const name=String(input.name||kind.replaceAll('_',' ')).trim();if(name.length<3||name.length>160)throw new Error('Automation name must be 3-160 characters');
 return (await pool.query(`INSERT INTO grc_automation_rules(id,organization_id,name,kind,interval_hours,config,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[crypto.randomUUID(),org,name,kind,hours,input.config||{},user])).rows[0]
}
export async function listAutomation(user:string,org:string){
 await requireOrgPermission(user,org,'read');
 const [rules,runs]=await Promise.all([
  pool.query('SELECT * FROM grc_automation_rules WHERE organization_id=$1 ORDER BY created_at',[org]),
  pool.query('SELECT * FROM grc_automation_runs WHERE organization_id=$1 ORDER BY started_at DESC LIMIT 100',[org])
 ]);
 return {rules:rules.rows,runs:runs.rows}
}

async function execute(client:any,org:string,kind:Kind,config:any){
 const events:any[]=[];
 if(kind==='EVIDENCE_EXPIRY'){
  const staleDays=Math.max(1,Number(config?.staleWarningDays||14));
  const stale=(await client.query(`UPDATE grc_evidence_requests r SET status='STALE',updated_at=now()
   WHERE r.organization_id=$1 AND r.status='VALID' AND EXISTS(
    SELECT 1 FROM grc_evidence_versions v WHERE v.evidence_request_id=r.id AND v.validated_at IS NOT NULL
    AND v.valid_until>now() AND v.valid_until<=now()+($2::text||' days')::interval
    AND v.version=(SELECT max(v2.version) FROM grc_evidence_versions v2 WHERE v2.evidence_request_id=r.id))
   RETURNING id,title`,[org,staleDays])).rows;
  const expired=(await client.query(`UPDATE grc_evidence_requests r SET status='EXPIRED',updated_at=now()
   WHERE r.organization_id=$1 AND r.status IN ('VALID','STALE') AND EXISTS(
    SELECT 1 FROM grc_evidence_versions v WHERE v.evidence_request_id=r.id AND v.validated_at IS NOT NULL AND v.valid_until<=now()
    AND v.version=(SELECT max(v2.version) FROM grc_evidence_versions v2 WHERE v2.evidence_request_id=r.id))
   RETURNING id,title`,[org])).rows;
  events.push({stale:stale.length,expired:expired.length});
 }else if(kind==='CONTROL_TEST_DUE'){
  const maxAge=Math.max(1,Number(config?.maxAgeDays||30));
  const due=(await client.query(`SELECT t.id,t.name,t.scope_control_id FROM grc_control_test_definitions t
   LEFT JOIN LATERAL(SELECT executed_at FROM grc_control_test_runs WHERE test_definition_id=t.id ORDER BY executed_at DESC LIMIT 1) r ON true
   WHERE t.organization_id=$1 AND t.active=true AND (r.executed_at IS NULL OR r.executed_at<now()-($2::text||' days')::interval)`,[org,maxAge])).rows;
  events.push({dueTests:due.length,testIds:due.map((x:any)=>x.id)});
 }else if(kind==='CAPA_SLA'){
  const changed=(await client.query(`UPDATE grc_capa SET status='OVERDUE',updated_at=now()
   WHERE organization_id=$1 AND status NOT IN ('CLOSED','OVERDUE') AND due_at<now() RETURNING id,capa_key`,[org])).rows;
  events.push({overdueCapa:changed.length,capaIds:changed.map((x:any)=>x.id)});
 }else if(kind==='RISK_ACCEPTANCE_EXPIRY'){
  const changed=(await client.query(`UPDATE grc_enterprise_risks SET status='ACCEPTANCE_PENDING',accepted_by=NULL,updated_at=now()
   WHERE organization_id=$1 AND status='ACCEPTED' AND acceptance_expires_at IS NOT NULL AND acceptance_expires_at<=now()
   RETURNING id,risk_key`,[org])).rows;
  events.push({expiredAcceptances:changed.length,riskIds:changed.map((x:any)=>x.id)});
 }
 return events;
}

export async function runAutomationRule(user:string,org:string,ruleId:string){
 await requireOrgPermission(user,org,'manageOrg');const client=await pool.connect();const runId=crypto.randomUUID();
 try{
  await client.query('BEGIN');
  const rule=(await client.query('SELECT * FROM grc_automation_rules WHERE id=$1 AND organization_id=$2 AND enabled=true FOR UPDATE',[ruleId,org])).rows[0];
  if(!rule)throw Object.assign(new Error('Enabled automation rule not found'),{statusCode:404});
  await client.query(`INSERT INTO grc_automation_runs(id,organization_id,rule_id,status) VALUES($1,$2,$3,'RUNNING')`,[runId,org,ruleId]);
  const actions=await execute(client,org,rule.kind as Kind,rule.config||{});
  const count=actions.reduce((n:number,x:any)=>n+Object.entries(x).filter(([k])=>!k.endsWith('Ids')).reduce((a,[,v])=>a+(typeof v==='number'?v:0),0),0);
  await client.query(`UPDATE grc_automation_runs SET status='SUCCEEDED',finished_at=now(),actions_count=$2,summary=$3 WHERE id=$1`,[runId,count,{actions}]);
  await client.query(`UPDATE grc_automation_rules SET last_run_at=now(),next_run_at=now()+(interval_hours::text||' hours')::interval,updated_at=now() WHERE id=$1`,[ruleId]);
  await client.query('COMMIT');return {runId,status:'SUCCEEDED',actionsCount:count,actions};
 }catch(e:any){await client.query('ROLLBACK');throw e}finally{client.release()}
}


export async function runDueAutomations(limit=50){
 const capped=Math.max(1,Math.min(200,Number(limit)||50));
 const due=(await pool.query('SELECT id,organization_id FROM grc_automation_rules WHERE enabled=true AND next_run_at<=now() ORDER BY next_run_at LIMIT $1',[capped])).rows;
 const results:any[]=[];
 for(const item of due){
  const client=await pool.connect();
  try{
   await client.query('BEGIN');
   const rule=(await client.query('SELECT * FROM grc_automation_rules WHERE id=$1 AND organization_id=$2 AND enabled=true AND next_run_at<=now() FOR UPDATE SKIP LOCKED',[item.id,item.organization_id])).rows[0];
   if(!rule){await client.query('ROLLBACK');continue}
   const runId=crypto.randomUUID();
   await client.query("INSERT INTO grc_automation_runs(id,organization_id,rule_id,status) VALUES($1,$2,$3,'RUNNING')",[runId,item.organization_id,item.id]);
   const actions=await execute(client,item.organization_id,rule.kind as Kind,rule.config||{});
   const count=actions.reduce((n:number,x:any)=>n+Object.entries(x).filter(([k])=>!k.endsWith('Ids')).reduce((a,[,v])=>a+(typeof v==='number'?v:0),0),0);
   await client.query("UPDATE grc_automation_runs SET status='SUCCEEDED',finished_at=now(),actions_count=$2,summary=$3 WHERE id=$1",[runId,count,{actions,trigger:'SCHEDULED'}]);
   await client.query("UPDATE grc_automation_rules SET last_run_at=now(),next_run_at=now()+(interval_hours::text||' hours')::interval,updated_at=now() WHERE id=$1",[item.id]);
   await client.query('COMMIT');
   results.push({ruleId:item.id,runId,status:'SUCCEEDED',actionsCount:count});
  }catch(e:any){
   await client.query('ROLLBACK');
   results.push({ruleId:item.id,status:'FAILED',error:String(e?.message||e).slice(0,500)});
  }finally{client.release()}
 }
 return results;
}
