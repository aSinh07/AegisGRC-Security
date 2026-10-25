import crypto from 'node:crypto';
import {pool} from './db-pool.js';
import {requireOrgPermission} from './grc-organizations.js';
import {createIncident} from './incident-response.js';

type SourceKind='WAZUH'|'ENTRA_ID'|'OPENVAS'|'PROWLER'|'CUSTOM';
const kinds=new Set<SourceKind>(['WAZUH','ENTRA_ID','OPENVAS','PROWLER','CUSTOM']);
const sha=(x:string)=>crypto.createHash('sha256').update(x).digest('hex');
const timing=(a:string,b:string)=>{const aa=Buffer.from(a),bb=Buffer.from(b);return aa.length===bb.length&&crypto.timingSafeEqual(aa,bb)};
const severity=(level:number)=>level>=13?'CRITICAL':level>=10?'HIGH':level>=7?'MEDIUM':level>=4?'LOW':'INFO';

export async function initOperationalSecurity(){await pool.query(`
CREATE TABLE IF NOT EXISTS security_telemetry_sources(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 source_key text NOT NULL,kind text NOT NULL,status text NOT NULL DEFAULT 'DISCONNECTED',
 token_hash text,display_name text NOT NULL,last_seen_at timestamptz,event_count bigint NOT NULL DEFAULT 0,
 detection_count bigint NOT NULL DEFAULT 0,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,source_key)
);
CREATE TABLE IF NOT EXISTS security_telemetry_events(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 source_id uuid NOT NULL REFERENCES security_telemetry_sources(id) ON DELETE CASCADE,
 external_event_id text NOT NULL,event_type text NOT NULL,severity text NOT NULL,asset text NOT NULL,
 principal_id text,observed_at timestamptz NOT NULL,evidence_sha256 text NOT NULL,raw_event jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(organization_id,source_id,external_event_id)
);
CREATE TABLE IF NOT EXISTS security_detections(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 source_id uuid NOT NULL REFERENCES security_telemetry_sources(id) ON DELETE CASCADE,
 event_id uuid NOT NULL REFERENCES security_telemetry_events(id) ON DELETE CASCADE,
 detection_key text NOT NULL,title text NOT NULL,severity text NOT NULL,confidence text NOT NULL DEFAULT 'SOURCE_REPORTED',
 status text NOT NULL DEFAULT 'NEW',asset text NOT NULL,evidence_sha256 text NOT NULL,
 reviewed_by uuid REFERENCES app_users(id) ON DELETE SET NULL,reviewed_at timestamptz,disposition_reason text,
 incident_id uuid REFERENCES security_incidents(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,detection_key)
);
CREATE INDEX IF NOT EXISTS security_telemetry_event_org_idx ON security_telemetry_events(organization_id,observed_at DESC);
CREATE INDEX IF NOT EXISTS security_detection_org_idx ON security_detections(organization_id,status,severity,created_at DESC);
`)}

export async function registerTelemetrySource(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');
 const kind=String(input.kind||'').toUpperCase() as SourceKind;if(!kinds.has(kind))throw new Error('Supported telemetry source kind required');
 const sourceKey=String(input.sourceKey||'').trim().toLowerCase().replace(/[^a-z0-9._-]/g,'-').slice(0,80);
 const name=String(input.displayName||kind).trim().slice(0,120);if(sourceKey.length<3)throw new Error('Source key must be at least 3 characters');
 const token=crypto.randomBytes(32).toString('base64url'),tokenHash=sha(token);
 const row=(await pool.query(`INSERT INTO security_telemetry_sources(id,organization_id,source_key,kind,status,token_hash,display_name,created_by)
 VALUES($1,$2,$3,$4,'DISCONNECTED',$5,$6,$7)
 ON CONFLICT(organization_id,source_key) DO UPDATE SET kind=EXCLUDED.kind,token_hash=EXCLUDED.token_hash,display_name=EXCLUDED.display_name,status='DISCONNECTED',updated_at=now()
 RETURNING id,organization_id,source_key,kind,status,display_name,last_seen_at,event_count,detection_count,created_at,updated_at`,
 [crypto.randomUUID(),org,sourceKey,kind,tokenHash,name,user])).rows[0];
 return {source:row,ingestToken:token,warning:'Store this token securely. It is shown once and cannot be recovered.'};
}
export async function telemetryDashboard(user:string,org:string){
 await requireOrgPermission(user,org,'read');
 const sources=(await pool.query(`SELECT id,source_key,kind,status,display_name,last_seen_at,event_count,detection_count,created_at,updated_at,
 CASE WHEN last_seen_at IS NULL THEN 'NEVER' WHEN last_seen_at < now()-interval '10 minutes' THEN 'STALE' ELSE 'CURRENT' END freshness
 FROM security_telemetry_sources WHERE organization_id=$1 ORDER BY created_at DESC`,[org])).rows;
 const detections=(await pool.query(`SELECT d.*,s.kind source_kind,s.display_name source_name FROM security_detections d JOIN security_telemetry_sources s ON s.id=d.source_id WHERE d.organization_id=$1 ORDER BY d.created_at DESC LIMIT 200`,[org])).rows;
 const events=(await pool.query(`SELECT e.id,e.external_event_id,e.event_type,e.severity,e.asset,e.principal_id,e.observed_at,e.evidence_sha256,e.created_at,s.kind source_kind,s.display_name source_name FROM security_telemetry_events e JOIN security_telemetry_sources s ON s.id=e.source_id WHERE e.organization_id=$1 ORDER BY e.observed_at DESC LIMIT 100`,[org])).rows;
 return {sources,detections,events,summary:{sources:sources.length,connected:sources.filter((x:any)=>x.status==='CONNECTED'&&x.freshness==='CURRENT').length,events:sources.reduce((n:number,x:any)=>n+Number(x.event_count||0),0),detections:sources.reduce((n:number,x:any)=>n+Number(x.detection_count||0),0),open:detections.filter((x:any)=>['NEW','INVESTIGATING','CONFIRMED'].includes(x.status)).length,critical:detections.filter((x:any)=>x.status!=='BENIGN'&&x.severity==='CRITICAL').length},assurance:'CONNECTED requires authenticated telemetry received within the freshness window; registration alone never proves monitoring.'};
}
export async function ingestWazuhTelemetry(org:string,sourceKey:string,bearer:string,payload:any){
 const client=await pool.connect();try{await client.query('BEGIN');
 const src=(await client.query(`SELECT * FROM security_telemetry_sources WHERE organization_id=$1 AND source_key=$2 AND kind='WAZUH' FOR UPDATE`,[org,sourceKey])).rows[0];
 if(!src||!src.token_hash||!bearer||!timing(src.token_hash,sha(bearer)))throw Object.assign(new Error('Telemetry source authentication failed'),{statusCode:401});
 const rows=Array.isArray(payload)?payload:Array.isArray(payload?.alerts)?payload.alerts:Array.isArray(payload?.data?.affected_items)?payload.data.affected_items:Array.isArray(payload?.hits?.hits)?payload.hits.hits.map((x:any)=>x._source):payload?.rule?[payload]:[];
 if(!rows.length)throw Object.assign(new Error('No parseable Wazuh alerts supplied'),{statusCode:422});
 let accepted=0,duplicates=0,created=0;
 for(const x of rows.slice(0,1000)){if(!x?.rule)continue;const raw=JSON.stringify(x),evidence=sha(raw),level=Number(x.rule?.level||0),sev=severity(level),asset=String(x.agent?.name||x.agent?.id||'unknown').slice(0,200),principal=String(x.data?.srcuser||x.data?.dstuser||x.data?.user||'').slice(0,200)||null;
  const external=String(x.id||x._id||[x.rule?.id,x.agent?.id,x.timestamp||x['@timestamp'],evidence.slice(0,16)].filter(Boolean).join(':')).slice(0,300);
  const eventId=crypto.randomUUID();const ins=await client.query(`INSERT INTO security_telemetry_events(id,organization_id,source_id,external_event_id,event_type,severity,asset,principal_id,observed_at,evidence_sha256,raw_event)
  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(organization_id,source_id,external_event_id) DO NOTHING RETURNING id`,
  [eventId,org,src.id,external,String(x.rule?.groups?.[0]||'WAZUH_ALERT').slice(0,120),sev,asset,principal,new Date(x.timestamp||x['@timestamp']||Date.now()).toISOString(),evidence,JSON.stringify(x)]);
  if(!ins.rowCount){duplicates++;continue}accepted++;
  if(level>=7){const key=sha(org+'|'+src.id+'|'+String(x.rule?.id||'wazuh')+'|'+asset+'|'+evidence);const d=await client.query(`INSERT INTO security_detections(id,organization_id,source_id,event_id,detection_key,title,severity,asset,evidence_sha256)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(organization_id,detection_key) DO NOTHING RETURNING id`,
   [crypto.randomUUID(),org,src.id,eventId,key,String(x.rule?.description||'Wazuh security detection').slice(0,500),sev,asset,evidence]);created+=d.rowCount||0}
 }
 await client.query(`UPDATE security_telemetry_sources SET status='CONNECTED',last_seen_at=now(),event_count=event_count+$3,detection_count=detection_count+$4,updated_at=now() WHERE id=$1 AND organization_id=$2`,[src.id,org,accepted,created]);
 await client.query('COMMIT');return {authenticated:true,source:sourceKey,received:rows.length,accepted,duplicates,detectionsCreated:created};
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function reviewDetection(user:string,org:string,id:string,input:any){
 await requireOrgPermission(user,org,'review');const disposition=String(input.disposition||'').toUpperCase(),reason=String(input.reason||'').trim();
 if(!['INVESTIGATING','BENIGN','CONFIRMED','ESCALATED_TO_INCIDENT'].includes(disposition))throw new Error('Recognized detection disposition required');if(reason.length<5)throw new Error('Analyst reason required');
 const row=(await pool.query('SELECT * FROM security_detections WHERE id=$1 AND organization_id=$2',[id,org])).rows[0];if(!row)throw Object.assign(new Error('Detection not found'),{statusCode:404});
 let incidentId=row.incident_id;if(disposition==='ESCALATED_TO_INCIDENT'&&!incidentId){const incident=await createIncident(user,org,{title:'Detection: '+row.title,severity:row.severity,source:'TELEMETRY:'+row.source_id,affectedAssets:[row.asset],summary:'Escalated from detection '+row.id+'. Evidence SHA-256 '+row.evidence_sha256+'. '+reason});incidentId=incident.id}
 const status=disposition==='ESCALATED_TO_INCIDENT'?'ESCALATED':disposition;
 return (await pool.query(`UPDATE security_detections SET status=$3,reviewed_by=$4,reviewed_at=now(),disposition_reason=$5,incident_id=$6 WHERE id=$1 AND organization_id=$2 RETURNING *`,[id,org,status,user,reason.slice(0,2000),incidentId])).rows[0];
}
