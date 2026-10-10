import pg from 'pg';import {requireOrgPermission} from './grc-organizations.js';
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
export async function initGrcOperations(){await pool.query(`
CREATE INDEX IF NOT EXISTS grc_record_events_lookup_idx ON grc_record_events(organization_id,record_type,record_id,created_at DESC);
CREATE TABLE IF NOT EXISTS grc_notifications(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
 severity text NOT NULL CHECK(severity IN ('INFO','WARNING','HIGH','CRITICAL')),
 title text NOT NULL,message text NOT NULL,record_type text,record_id uuid,dedupe_key text NOT NULL,
 status text NOT NULL DEFAULT 'UNREAD' CHECK(status IN ('UNREAD','READ','DISMISSED')),
 created_at timestamptz NOT NULL DEFAULT now(),read_at timestamptz,
 UNIQUE(organization_id,user_id,dedupe_key)
);
CREATE INDEX IF NOT EXISTS grc_notifications_user_idx ON grc_notifications(organization_id,user_id,status,created_at DESC);
`)}
export async function myWork(user:string,org:string){
 await requireOrgPermission(user,org,'read');
 const [e,c,r,i]=await Promise.all([
  pool.query(`SELECT 'EVIDENCE' kind,id,title,status,due_at due_at,scope_control_id related_id FROM grc_evidence_requests WHERE organization_id=$1 AND owner_user_id=$2 AND status NOT IN ('VALID','EXPIRED')`,[org,user]),
  pool.query(`SELECT 'CAPA' kind,id,capa_key title,status,due_at,issue_id related_id FROM grc_capa WHERE organization_id=$1 AND owner_user_id=$2 AND status<>'CLOSED'`,[org,user]),
  pool.query(`SELECT 'RISK' kind,id,risk_key title,status,acceptance_expires_at due_at,NULL::uuid related_id FROM grc_enterprise_risks WHERE organization_id=$1 AND owner_user_id=$2 AND status<>'CLOSED'`,[org,user]),
  pool.query(`SELECT 'ISSUE' kind,id,issue_key title,status,NULL::timestamptz due_at,scope_control_id related_id FROM grc_issues WHERE organization_id=$1 AND status<>'CLOSED' AND created_by=$2`,[org,user])
 ]);
 const now=Date.now(),items=[...e.rows,...c.rows,...r.rows,...i.rows].map((x:any)=>({...x,overdue:Boolean(x.due_at&&new Date(x.due_at).getTime()<now)}));
 items.sort((a:any,b:any)=>(Number(b.overdue)-Number(a.overdue))||(new Date(a.due_at||'2999-01-01').getTime()-new Date(b.due_at||'2999-01-01').getTime()));
 return {organizationId:org,userId:user,generatedAt:new Date().toISOString(),items,summary:{total:items.length,overdue:items.filter((x:any)=>x.overdue).length,evidence:items.filter((x:any)=>x.kind==='EVIDENCE').length,capa:items.filter((x:any)=>x.kind==='CAPA').length,risks:items.filter((x:any)=>x.kind==='RISK').length}};
}
export async function timeline(user:string,org:string,type:string,id:string){
 await requireOrgPermission(user,org,'read');const t=String(type||'').toUpperCase();if(!['RISK','CAPA','ISSUE','EVIDENCE','CONTROL'].includes(t))throw new Error('Unsupported record type');
 return (await pool.query(`SELECT id,record_type,record_id,event,actor_user_id,reason,snapshot,created_at FROM grc_record_events WHERE organization_id=$1 AND record_type=$2 AND record_id=$3 ORDER BY created_at DESC LIMIT 250`,[org,t,id])).rows;
}
export async function operationsDashboard(user:string,org:string){
 await requireOrgPermission(user,org,'read');
 const q=await pool.query(`
 SELECT
 (SELECT count(*) FROM grc_scope_controls WHERE organization_id=$1) controls,
 (SELECT count(*) FROM grc_scope_controls WHERE organization_id=$1 AND applicability='APPLICABLE') applicable_controls,
 (SELECT count(*) FROM grc_scope_controls WHERE organization_id=$1 AND applicability='PENDING') pending_applicability,
 (SELECT count(*) FROM grc_evidence_requests WHERE organization_id=$1 AND status='VALID') valid_evidence,
 (SELECT count(*) FROM grc_evidence_requests WHERE organization_id=$1 AND status IN ('REQUESTED','SUBMITTED','VALIDATION','CHANGES_REQUESTED')) evidence_attention,
 (SELECT count(*) FROM grc_issues WHERE organization_id=$1 AND status<>'CLOSED') open_issues,
 (SELECT count(*) FROM grc_enterprise_risks WHERE organization_id=$1 AND status<>'CLOSED') open_risks,
 (SELECT count(*) FROM grc_enterprise_risks WHERE organization_id=$1 AND inherent_rating IN ('HIGH','CRITICAL') AND status<>'CLOSED') high_critical_risks,
 (SELECT count(*) FROM grc_capa WHERE organization_id=$1 AND status<>'CLOSED') open_capa,
 (SELECT count(*) FROM grc_capa WHERE organization_id=$1 AND status<>'CLOSED' AND due_at<now()) overdue_capa,
 (SELECT count(*) FROM grc_control_test_runs WHERE organization_id=$1 AND result='FAIL' AND executed_at>now()-interval '30 days') failed_tests_30d,
 (SELECT count(*) FROM grc_control_test_runs WHERE organization_id=$1 AND result='PASS' AND executed_at>now()-interval '30 days') passed_tests_30d
 `,[org]);
 const x=q.rows[0],num=(v:any)=>Number(v||0);
 return {organizationId:org,generatedAt:new Date().toISOString(),metrics:Object.fromEntries(Object.entries(x).map(([k,v])=>[k,num(v)])),note:'Operational metrics only. They are not a certification or compliance score.'};
}
export async function sla(user:string,org:string){
 await requireOrgPermission(user,org,'read');const rows=(await pool.query(`
 SELECT 'CAPA' type,id,capa_key key,status,due_at,owner_user_id,
 CASE WHEN status<>'CLOSED' AND due_at<now() THEN 'BREACHED' WHEN status<>'CLOSED' AND due_at<now()+interval '24 hours' THEN 'AT_RISK' ELSE 'ON_TRACK' END sla
 FROM grc_capa WHERE organization_id=$1 AND status<>'CLOSED'
 UNION ALL
 SELECT 'EVIDENCE',id,title,status,due_at,owner_user_id,
 CASE WHEN due_at IS NULL THEN 'NO_DUE_DATE' WHEN due_at<now() THEN 'BREACHED' WHEN due_at<now()+interval '24 hours' THEN 'AT_RISK' ELSE 'ON_TRACK' END
 FROM grc_evidence_requests WHERE organization_id=$1 AND status NOT IN ('VALID','EXPIRED')
 ORDER BY due_at NULLS LAST`,[org])).rows;
 return {items:rows,summary:{breached:rows.filter((x:any)=>x.sla==='BREACHED').length,atRisk:rows.filter((x:any)=>x.sla==='AT_RISK').length,onTrack:rows.filter((x:any)=>x.sla==='ON_TRACK').length}};
}

export async function notifications(user:string,org:string){
 await requireOrgPermission(user,org,'read');
 const rows=(await pool.query('SELECT * FROM grc_notifications WHERE organization_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 200',[org,user])).rows;
 return {items:rows,unread:rows.filter((x:any)=>x.status==='UNREAD').length};
}
export async function markNotification(user:string,org:string,id:string,status:string){
 await requireOrgPermission(user,org,'read');if(!['READ','DISMISSED'].includes(status))throw new Error('Invalid notification status');
 const row=(await pool.query("UPDATE grc_notifications SET status=$4,read_at=CASE WHEN $4='READ' THEN now() ELSE read_at END WHERE id=$1 AND organization_id=$2 AND user_id=$3 RETURNING *",[id,org,user,status])).rows[0];
 if(!row)throw Object.assign(new Error('Notification not found'),{statusCode:404});return row;
}
