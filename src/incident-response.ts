import crypto from 'node:crypto';
import pg from 'pg';
import {requireOrgPermission} from './grc-organizations.js';
import {validateIncidentTransition,normalizeIdentitySignal,type IncidentPhase,type IdentitySignal} from './cyber-operations-handoff.js';

const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
const severity=new Set(['LOW','MEDIUM','HIGH','CRITICAL']);

export async function initIncidentResponse(){await pool.query(`
CREATE TABLE IF NOT EXISTS security_incidents(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 incident_key text NOT NULL,title text NOT NULL,severity text NOT NULL,phase text NOT NULL DEFAULT 'DETECTED',
 owner_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,source text NOT NULL,affected_assets jsonb NOT NULL DEFAULT '[]'::jsonb,
 summary text NOT NULL DEFAULT '',created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),closed_at timestamptz,UNIQUE(organization_id,incident_key)
);
CREATE TABLE IF NOT EXISTS security_incident_events(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 incident_id uuid NOT NULL REFERENCES security_incidents(id) ON DELETE CASCADE,phase text NOT NULL,actor_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,
 reason text NOT NULL,evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,occurred_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS security_identity_signals(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 incident_id uuid REFERENCES security_incidents(id) ON DELETE SET NULL,kind text NOT NULL,principal_id text NOT NULL,source text NOT NULL,
 observed_at timestamptz NOT NULL,evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,status text NOT NULL DEFAULT 'REVIEW_REQUIRED',
 reviewed_by uuid REFERENCES app_users(id) ON DELETE SET NULL,reviewed_at timestamptz,disposition text,created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS security_incident_org_idx ON security_incidents(organization_id,phase,severity,created_at DESC);
CREATE INDEX IF NOT EXISTS security_identity_org_idx ON security_identity_signals(organization_id,status,observed_at DESC);
`)}

export async function createIncident(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');const title=String(input.title||'').trim(),sev=String(input.severity||'').toUpperCase(),source=String(input.source||'').trim();
 if(title.length<3||!severity.has(sev)||source.length<2)throw new Error('Incident title, recognized severity and source required');
 const key=String(input.incidentKey||('INC-'+Date.now())).toUpperCase().replace(/[^A-Z0-9._-]/g,'-').slice(0,80);
 const assets=Array.isArray(input.affectedAssets)?input.affectedAssets.slice(0,200).map((x:any)=>String(x).slice(0,200)):[];
 return (await pool.query(`INSERT INTO security_incidents(id,organization_id,incident_key,title,severity,phase,owner_user_id,source,affected_assets,summary,created_by)
 VALUES($1,$2,$3,$4,$5,'DETECTED',$6,$7,$8,$9,$10) RETURNING *`,[crypto.randomUUID(),org,key,title,sev,input.ownerUserId||user,source,assets,String(input.summary||'').slice(0,5000),user])).rows[0];
}
export async function transitionIncident(user:string,org:string,id:string,next:IncidentPhase,input:any){
 await requireOrgPermission(user,org,'manageRisk');
 const event={phase:next,actorId:user,reason:String(input.reason||''),occurredAt:String(input.occurredAt||new Date().toISOString()),evidenceRefs:Array.isArray(input.evidenceRefs)?input.evidenceRefs:[]};
 const client=await pool.connect();try{await client.query('BEGIN');const row=(await client.query('SELECT * FROM security_incidents WHERE id=$1 AND organization_id=$2 FOR UPDATE',[id,org])).rows[0];if(!row)throw Object.assign(new Error('Incident not found'),{statusCode:404});validateIncidentTransition(row.phase,next,event);await client.query(`INSERT INTO security_incident_events(id,organization_id,incident_id,phase,actor_user_id,reason,evidence_refs,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,[crypto.randomUUID(),org,id,next,user,event.reason,event.evidenceRefs,event.occurredAt]);const updated=(await client.query(`UPDATE security_incidents SET phase=$3,updated_at=now(),closed_at=CASE WHEN $3='CLOSED' THEN now() ELSE closed_at END WHERE id=$1 AND organization_id=$2 RETURNING *`,[id,org,next])).rows[0];await client.query('COMMIT');return updated}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function ingestIdentitySignal(user:string,org:string,input:IdentitySignal&{incidentId?:string}){
 await requireOrgPermission(user,org,'manageRisk');const x=normalizeIdentitySignal(input);
 if(input.incidentId){const ok=(await pool.query('SELECT 1 FROM security_incidents WHERE id=$1 AND organization_id=$2',[input.incidentId,org])).rowCount;if(!ok)throw new Error('Incident does not belong to organization')}
 return (await pool.query(`INSERT INTO security_identity_signals(id,organization_id,incident_id,kind,principal_id,source,observed_at,evidence_refs) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[crypto.randomUUID(),org,input.incidentId||null,x.kind,x.principalId,x.source,x.observedAt,x.evidenceRefs])).rows[0];
}
export async function reviewIdentitySignal(user:string,org:string,id:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');
 const disposition=String(input.disposition||'').toUpperCase(),reason=String(input.reason||'').trim();
 if(!['BENIGN','INVESTIGATED','ESCALATED_TO_INCIDENT'].includes(disposition))throw new Error('Recognized identity signal disposition required');
 if(reason.length<5)throw new Error('Identity signal review reason required');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const row=(await client.query('SELECT * FROM security_identity_signals WHERE id=$1 AND organization_id=$2 FOR UPDATE',[id,org])).rows[0];
  if(!row)throw Object.assign(new Error('Identity signal not found'),{statusCode:404});
  if(row.status!=='REVIEW_REQUIRED')throw Object.assign(new Error('Identity signal already reviewed'),{statusCode:409});
  let incidentId=row.incident_id;
  if(disposition==='ESCALATED_TO_INCIDENT'&&!incidentId){
   incidentId=crypto.randomUUID();const incidentKey='INC-IDR-'+Date.now()+'-'+crypto.randomBytes(2).toString('hex').toUpperCase();
   await client.query(`INSERT INTO security_incidents(id,organization_id,incident_key,title,severity,phase,owner_user_id,source,affected_assets,summary,created_by) VALUES($1,$2,$3,$4,'HIGH','DETECTED',$5,$6,'[]'::jsonb,$7,$5)`,[incidentId,org,incidentKey,'Identity escalation: '+row.kind,user,row.source,reason.slice(0,5000)]);
   await client.query(`INSERT INTO security_incident_events(id,organization_id,incident_id,phase,actor_user_id,reason,evidence_refs,occurred_at) VALUES($1,$2,$3,'DETECTED',$4,$5,$6,now())`,[crypto.randomUUID(),org,incidentId,user,'Escalated from identity signal: '+reason,row.evidence_refs]);
  }
  const out=(await client.query(`UPDATE security_identity_signals SET status='REVIEWED',incident_id=$5,reviewed_by=$3,reviewed_at=now(),disposition=$4 WHERE id=$1 AND organization_id=$2 AND status='REVIEW_REQUIRED' RETURNING *`,[id,org,user,disposition+': '+reason.slice(0,1000),incidentId])).rows[0];
  if(!out)throw Object.assign(new Error('Identity signal state changed before review'),{statusCode:409});
  await client.query('COMMIT');return out;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function incidentDashboard(user:string,org:string){await requireOrgPermission(user,org,'read');const incidents=(await pool.query('SELECT * FROM security_incidents WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 200',[org])).rows,signals=(await pool.query('SELECT * FROM security_identity_signals WHERE organization_id=$1 ORDER BY observed_at DESC LIMIT 200',[org])).rows;return {incidents,identitySignals:signals,summary:{open:incidents.filter(x=>x.phase!=='CLOSED').length,critical:incidents.filter(x=>x.phase!=='CLOSED'&&x.severity==='CRITICAL').length,identityReviewRequired:signals.filter(x=>x.status==='REVIEW_REQUIRED').length}}}
