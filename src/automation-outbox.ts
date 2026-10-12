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
 UNIQUE(organization_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS grc_automation_outbox_due_idx ON grc_automation_outbox(status,next_attempt_at);
CREATE INDEX IF NOT EXISTS grc_automation_outbox_org_idx ON grc_automation_outbox(organization_id,created_at DESC);
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
