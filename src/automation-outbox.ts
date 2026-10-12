import crypto from 'node:crypto';
import pg from 'pg';
import {requireOrgPermission} from './grc-organizations.js';
import {buildServiceNowWorkItem,type ServiceNowSyncRecord} from './tprm-engine.js';

const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
export type OutboxKind='SERVICENOW_WORK_ITEM'|'SCRIPT_TASK';
export type ScriptTaskName='TPRM_REVIEW_DUE'|'TPRM_REMEDIATION_DUE'|'EVIDENCE_EXPIRY_CHECK';
const scripts:ScriptTaskName[]=['TPRM_REVIEW_DUE','TPRM_REMEDIATION_DUE','EVIDENCE_EXPIRY_CHECK'];

export async function initAutomationOutbox(){await pool.query(`
CREATE TABLE IF NOT EXISTS grc_automation_outbox(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 kind text NOT NULL CHECK(kind IN ('SERVICENOW_WORK_ITEM','SCRIPT_TASK')),idempotency_key text NOT NULL,
 status text NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','PROCESSING','SUCCEEDED','FAILED','DEAD_LETTER')),
 payload jsonb NOT NULL DEFAULT '{}'::jsonb,attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0),max_attempts integer NOT NULL DEFAULT 5 CHECK(max_attempts BETWEEN 1 AND 20),
 next_attempt_at timestamptz NOT NULL DEFAULT now(),last_error text,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),completed_at timestamptz,
 result jsonb,locked_at timestamptz,locked_by text,
 UNIQUE(organization_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS grc_automation_outbox_due_idx ON grc_automation_outbox(status,next_attempt_at);
CREATE INDEX IF NOT EXISTS grc_automation_outbox_org_idx ON grc_automation_outbox(organization_id,created_at DESC);
ALTER TABLE grc_automation_outbox ADD COLUMN IF NOT EXISTS result jsonb;
ALTER TABLE grc_automation_outbox ADD COLUMN IF NOT EXISTS locked_at timestamptz;
ALTER TABLE grc_automation_outbox ADD COLUMN IF NOT EXISTS locked_by text;
`)}

export async function enqueueServiceNowWorkItem(user:string,org:string,input:ServiceNowSyncRecord){
 await requireOrgPermission(user,org,'manageRisk');const item=buildServiceNowWorkItem(input);
 const row=(await pool.query(`INSERT INTO grc_automation_outbox(id,organization_id,kind,idempotency_key,payload,created_by)
 VALUES($1,$2,'SERVICENOW_WORK_ITEM',$3,$4,$5) ON CONFLICT(organization_id,idempotency_key) DO UPDATE SET updated_at=grc_automation_outbox.updated_at RETURNING *`,
 [crypto.randomUUID(),org,item.idempotencyKey,item,user])).rows[0];return {job:row,workItem:item}
}

export async function enqueueScriptTask(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageOrg');const task=String(input.task||'').toUpperCase() as ScriptTaskName;
 if(!scripts.includes(task))throw new Error('Unsupported script task; arbitrary shell execution is prohibited');
 const target=String(input.targetId||'organization').trim();const key=['script',task,target].map(x=>x.toLowerCase()).join(':');
 return (await pool.query(`INSERT INTO grc_automation_outbox(id,organization_id,kind,idempotency_key,payload,created_by)
 VALUES($1,$2,'SCRIPT_TASK',$3,$4,$5) ON CONFLICT(organization_id,idempotency_key) DO UPDATE SET updated_at=grc_automation_outbox.updated_at RETURNING *`,
 [crypto.randomUUID(),org,key,{task,targetId:target,parameters:input.parameters||{}},user])).rows[0]
}

export async function listAutomationOutbox(user:string,org:string){
 await requireOrgPermission(user,org,'read');return (await pool.query('SELECT * FROM grc_automation_outbox WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 200',[org])).rows
}

export function serviceNowConnectorReadiness(){
 const base=String(process.env.SERVICENOW_BASE_URL||'').trim(),token=String(process.env.SERVICENOW_TOKEN||'').trim();
 let valid=false;try{const u=new URL(base);valid=u.protocol==='https:'&&!!u.hostname}catch{}
 return {configured:valid&&token.length>=16,httpsEndpoint:valid,credentialPresent:token.length>=16,externalWriteTested:false,autoCloseRisk:false,
  limitations:['External ServiceNow delivery requires configured credentials and an explicit worker; API enqueue never closes GRC risk automatically.']}
}


type ClaimedJob={id:string;organization_id:string;kind:OutboxKind;payload:any;attempts:number;max_attempts:number};
function connectorConfig(){
 const base=String(process.env.SERVICENOW_BASE_URL||'').trim(),token=String(process.env.SERVICENOW_TOKEN||'').trim(),table=String(process.env.SERVICENOW_TABLE||'incident').trim();
 let url:URL|null=null;try{const u=new URL(base);if(u.protocol==='https:'&&u.username===''&&u.password===''&&u.pathname.replace(/\/$/,'')==='')url=u}catch{}
 if(!url||token.length<16||!/^[A-Za-z0-9_]{2,80}$/.test(table))return null;
 return {base:url.origin,token,table};
}
export async function claimDueAutomation(workerId:string,organizationId?:string):Promise<ClaimedJob|null>{
 const client=await pool.connect();try{await client.query('BEGIN');
  const row=(organizationId
   ?(await client.query(`SELECT * FROM grc_automation_outbox WHERE organization_id=$1 AND status IN ('PENDING','FAILED') AND next_attempt_at<=now() AND attempts<max_attempts ORDER BY next_attempt_at,created_at FOR UPDATE SKIP LOCKED LIMIT 1`,[organizationId])).rows[0]
   :(await client.query(`SELECT * FROM grc_automation_outbox WHERE status IN ('PENDING','FAILED') AND next_attempt_at<=now() AND attempts<max_attempts ORDER BY next_attempt_at,created_at FOR UPDATE SKIP LOCKED LIMIT 1`)).rows[0]);
  if(!row){await client.query('COMMIT');return null}
  const claimed=(await client.query(`UPDATE grc_automation_outbox SET status='PROCESSING',attempts=attempts+1,locked_at=now(),locked_by=$2,updated_at=now() WHERE id=$1 RETURNING *`,[row.id,workerId])).rows[0];
  await client.query('COMMIT');return claimed;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
function safeError(e:any){return String(e?.message||e||'Automation failed').replace(/[\r\n]/g,' ').slice(0,500)}
export async function completeAutomationJob(id:string,result:any){
 return (await pool.query(`UPDATE grc_automation_outbox SET status='SUCCEEDED',result=$2,last_error=NULL,completed_at=now(),locked_at=NULL,locked_by=NULL,updated_at=now() WHERE id=$1 AND status='PROCESSING' RETURNING *`,[id,result||{}])).rows[0];
}
export async function failAutomationJob(id:string,error:any){
 const row=(await pool.query('SELECT attempts,max_attempts FROM grc_automation_outbox WHERE id=$1',[id])).rows[0];if(!row)return null;
 const dead=Number(row.attempts)>=Number(row.max_attempts),delay=Math.min(3600,Math.max(30,30*Math.pow(2,Math.max(0,Number(row.attempts)-1))));
 return (await pool.query(`UPDATE grc_automation_outbox SET status=$2,last_error=$3,next_attempt_at=now()+($4::text||' seconds')::interval,locked_at=NULL,locked_by=NULL,updated_at=now() WHERE id=$1 RETURNING *`,[id,dead?'DEAD_LETTER':'FAILED',safeError(error),String(delay)])).rows[0];
}
export async function recoverStaleAutomationJobs(organizationId?:string){
 const setClause="SET status=CASE WHEN attempts>=max_attempts THEN 'DEAD_LETTER' ELSE 'FAILED' END,last_error='Worker lease expired',next_attempt_at=now(),locked_at=NULL,locked_by=NULL,updated_at=now()";
 if(organizationId)return (await pool.query(`UPDATE grc_automation_outbox ${setClause} WHERE organization_id=$1 AND status='PROCESSING' AND locked_at<now()-interval '10 minutes' RETURNING id,status`,[organizationId])).rows;
 return (await pool.query(`UPDATE grc_automation_outbox ${setClause} WHERE status='PROCESSING' AND locked_at<now()-interval '10 minutes' RETURNING id,status`)).rows;
}
async function deliverServiceNow(job:ClaimedJob){
 const cfg=connectorConfig();if(!cfg)throw new Error('ServiceNow connector is not safely configured');
 const item=job.payload||{};if(item.autoCloseRisk!==false)throw new Error('Unsafe ServiceNow work item: autoCloseRisk must be false');
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),10000);
 try{
  const endpoint=cfg.base+'/api/now/table/'+encodeURIComponent(cfg.table);
  const response=await fetch(endpoint,{method:'POST',headers:{'Authorization':'Bearer '+cfg.token,'Accept':'application/json','Content-Type':'application/json','X-Aegis-Idempotency-Key':String(item.idempotencyKey||job.id)},body:JSON.stringify(item.payload||{}),signal:controller.signal});
  const text=await response.text();if(!response.ok)throw new Error('ServiceNow HTTP '+response.status);
  let body:any={};try{body=JSON.parse(text)}catch{}
  const result=body?.result||{};return {provider:'ServiceNow',delivered:true,httpStatus:response.status,sysId:String(result.sys_id||'').slice(0,80)||null,number:String(result.number||'').slice(0,80)||null,autoCloseRisk:false};
 }finally{clearTimeout(timer)}
}
async function executeScriptTask(job:ClaimedJob){
 const p=job.payload||{},task=String(p.task||'') as ScriptTaskName;if(!scripts.includes(task))throw new Error('Stored script task is not allowlisted');
 const org=job.organization_id;
 if(task==='TPRM_REVIEW_DUE'){const r=await pool.query(`SELECT count(*)::int count FROM grc_third_parties WHERE organization_id=$1 AND next_review_at IS NOT NULL AND next_review_at<=now() AND status NOT IN ('TERMINATED')`,[org]);return {task,checkedAt:new Date().toISOString(),due:Number(r.rows[0]?.count||0),sideEffect:'NONE'};}
 if(task==='TPRM_REMEDIATION_DUE'){const r=await pool.query(`SELECT count(*)::int count FROM grc_tprm_remediations WHERE organization_id=$1 AND due_at IS NOT NULL AND due_at<=now() AND status<>'CLOSED'`,[org]);return {task,checkedAt:new Date().toISOString(),due:Number(r.rows[0]?.count||0),sideEffect:'NONE'};}
 const r=await pool.query(`SELECT count(*)::int count FROM grc_evidence_requests r WHERE r.organization_id=$1 AND r.status='VALID' AND EXISTS (SELECT 1 FROM grc_evidence_versions v WHERE v.evidence_request_id=r.id AND v.valid_until IS NOT NULL AND v.valid_until<=now() AND v.version=(SELECT max(v2.version) FROM grc_evidence_versions v2 WHERE v2.evidence_request_id=r.id))`,[org]);
 return {task,checkedAt:new Date().toISOString(),due:Number(r.rows[0]?.count||0),sideEffect:'NONE',note:'Evidence expiry check is advisory and never changes control status.'};
}
export async function runAutomationOutboxBatch(limit=10,workerId='aegis-worker',organizationId?:string){
 const n=Math.max(1,Math.min(50,Number(limit)||10)),results:any[]=[];await recoverStaleAutomationJobs(organizationId);
 for(let i=0;i<n;i++){const job=await claimDueAutomation(workerId,organizationId);if(!job)break;try{const result=job.kind==='SERVICENOW_WORK_ITEM'?await deliverServiceNow(job):await executeScriptTask(job);await completeAutomationJob(job.id,result);results.push({id:job.id,status:'SUCCEEDED',result})}catch(e){const failed=await failAutomationJob(job.id,e);results.push({id:job.id,status:failed?.status||'FAILED',error:safeError(e)})}}
 return {processed:results.length,results};
}
export function automationWorkerEnabled(){return String(process.env.AUTOMATION_WORKER_ENABLED||'false').toLowerCase()==='true'}
