import crypto from 'node:crypto';import pg from 'pg';import {requireOrgPermission} from './grc-organizations.js';
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
const criticality=new Set(['LOW','MEDIUM','HIGH','CRITICAL']);
const tier=new Set(['TIER_1','TIER_2','TIER_3','TIER_4']);
const status=new Set(['PROSPECT','DUE_DILIGENCE','APPROVED','ACTIVE','RESTRICTED','SUSPENDED','TERMINATED']);
export async function initThirdPartyRisk(){await pool.query(`
CREATE TABLE IF NOT EXISTS grc_third_parties(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 vendor_key text NOT NULL,name text NOT NULL,service text NOT NULL DEFAULT '',tier text NOT NULL DEFAULT 'TIER_3',
 criticality text NOT NULL DEFAULT 'MEDIUM',status text NOT NULL DEFAULT 'DUE_DILIGENCE',
 owner_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,data_access text NOT NULL DEFAULT 'NONE',
 processes_pii boolean NOT NULL DEFAULT false,network_access boolean NOT NULL DEFAULT false,subprocessors boolean NOT NULL DEFAULT false,
 country text,contract_start date,contract_end date,next_review_at timestamptz,
 metadata jsonb NOT NULL DEFAULT '{}'::jsonb,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),UNIQUE(organization_id,vendor_key)
);
CREATE TABLE IF NOT EXISTS grc_third_party_assessments(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 third_party_id uuid NOT NULL REFERENCES grc_third_parties(id) ON DELETE CASCADE,
 assessment_type text NOT NULL DEFAULT 'DUE_DILIGENCE',status text NOT NULL DEFAULT 'OPEN',
 inherent_risk int NOT NULL CHECK(inherent_risk BETWEEN 1 AND 25),residual_risk int CHECK(residual_risk BETWEEN 1 AND 25),
 security_rating text,findings jsonb NOT NULL DEFAULT '[]'::jsonb,evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
 decision text CHECK(decision IS NULL OR decision IN ('APPROVE','CONDITIONAL','REJECT','REVIEW_REQUIRED')),
 rationale text NOT NULL DEFAULT '',assessor_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,
 reviewer_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,reviewed_at timestamptz,next_review_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS grc_third_party_incidents(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 third_party_id uuid NOT NULL REFERENCES grc_third_parties(id) ON DELETE CASCADE,title text NOT NULL,severity text NOT NULL,
 status text NOT NULL DEFAULT 'OPEN',occurred_at timestamptz,detected_at timestamptz NOT NULL DEFAULT now(),
 data_impact text NOT NULL DEFAULT '',business_impact text NOT NULL DEFAULT '',source_ref text,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS grc_third_party_org_idx ON grc_third_parties(organization_id,status,tier);
CREATE INDEX IF NOT EXISTS grc_third_party_assessment_idx ON grc_third_party_assessments(organization_id,third_party_id,created_at DESC);
CREATE INDEX IF NOT EXISTS grc_third_party_incident_idx ON grc_third_party_incidents(organization_id,third_party_id,status);
`)}
export async function createThirdParty(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');const name=String(input.name||'').trim(),key=String(input.vendorKey||'').trim().toUpperCase();
 const t=String(input.tier||'TIER_3').toUpperCase(),c=String(input.criticality||'MEDIUM').toUpperCase(),st=String(input.status||'DUE_DILIGENCE').toUpperCase();
 if(name.length<2||!/^[A-Z0-9._-]{2,60}$/.test(key)||!tier.has(t)||!criticality.has(c)||!status.has(st))throw new Error('Invalid third-party profile');
 if(input.ownerUserId)await requireOrgPermission(input.ownerUserId,org,'read');
 return (await pool.query(`INSERT INTO grc_third_parties(id,organization_id,vendor_key,name,service,tier,criticality,status,owner_user_id,data_access,processes_pii,network_access,subprocessors,country,contract_start,contract_end,next_review_at,metadata,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING *`,
 [crypto.randomUUID(),org,key,name,String(input.service||''),t,c,st,input.ownerUserId||null,String(input.dataAccess||'NONE').toUpperCase(),Boolean(input.processesPii),Boolean(input.networkAccess),Boolean(input.subprocessors),input.country||null,input.contractStart||null,input.contractEnd||null,input.nextReviewAt||null,input.metadata||{},user])).rows[0]
}
export async function listThirdParties(user:string,org:string){await requireOrgPermission(user,org,'read');return (await pool.query(`
SELECT v.*,COALESCE(a.inherent_risk,0) latest_inherent_risk,a.residual_risk latest_residual_risk,a.decision latest_decision,a.reviewed_at,
 (SELECT count(*) FROM grc_third_party_incidents i WHERE i.third_party_id=v.id AND i.status<>'CLOSED') open_incidents
FROM grc_third_parties v LEFT JOIN LATERAL(SELECT * FROM grc_third_party_assessments x WHERE x.third_party_id=v.id ORDER BY x.created_at DESC LIMIT 1)a ON true
WHERE v.organization_id=$1 ORDER BY CASE v.tier WHEN 'TIER_1' THEN 1 WHEN 'TIER_2' THEN 2 WHEN 'TIER_3' THEN 3 ELSE 4 END,v.name`,[org])).rows}
export async function assessThirdParty(user:string,org:string,vendorId:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');const vendor=(await pool.query('SELECT * FROM grc_third_parties WHERE id=$1 AND organization_id=$2',[vendorId,org])).rows[0];if(!vendor)throw Object.assign(new Error('Third party not found'),{statusCode:404});
 const inherent=Number(input.inherentRisk);if(!Number.isInteger(inherent)||inherent<1||inherent>25)throw new Error('Inherent risk must be 1-25');
 return (await pool.query(`INSERT INTO grc_third_party_assessments(id,organization_id,third_party_id,assessment_type,status,inherent_risk,security_rating,findings,evidence,rationale,assessor_user_id,next_review_at)
 VALUES($1,$2,$3,$4,'OPEN',$5,$6,$7,$8,$9,$10,$11) RETURNING *`,[crypto.randomUUID(),org,vendorId,String(input.assessmentType||'DUE_DILIGENCE').toUpperCase(),inherent,input.securityRating||null,input.findings||[],input.evidence||[],String(input.rationale||''),user,input.nextReviewAt||null])).rows[0]
}
export async function reviewThirdParty(user:string,org:string,assessmentId:string,input:any){
 await requireOrgPermission(user,org,'review');const decision=String(input.decision||'').toUpperCase();if(!['APPROVE','CONDITIONAL','REJECT','REVIEW_REQUIRED'].includes(decision))throw new Error('Invalid vendor decision');
 const residual=input.residualRisk===null||input.residualRisk===undefined?null:Number(input.residualRisk);if(residual!==null&&(!Number.isInteger(residual)||residual<1||residual>25))throw new Error('Residual risk must be 1-25');
 const row=(await pool.query('SELECT * FROM grc_third_party_assessments WHERE id=$1 AND organization_id=$2',[assessmentId,org])).rows[0];if(!row)throw Object.assign(new Error('Third-party assessment not found'),{statusCode:404});if(row.assessor_user_id===user)throw Object.assign(new Error('Independent reviewer required for third-party approval'),{statusCode:409});
 return (await pool.query(`UPDATE grc_third_party_assessments SET status='REVIEWED',decision=$3,residual_risk=$4,rationale=$5,reviewer_user_id=$6,reviewed_at=now(),updated_at=now() WHERE id=$1 AND organization_id=$2 RETURNING *`,[assessmentId,org,decision,residual,String(input.rationale||row.rationale||''),user])).rows[0]
}
export async function recordThirdPartyIncident(user:string,org:string,vendorId:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');const v=(await pool.query('SELECT id FROM grc_third_parties WHERE id=$1 AND organization_id=$2',[vendorId,org])).rows[0];if(!v)throw Object.assign(new Error('Third party not found'),{statusCode:404});
 const sev=String(input.severity||'MEDIUM').toUpperCase();if(!criticality.has(sev))throw new Error('Invalid incident severity');
 return (await pool.query(`INSERT INTO grc_third_party_incidents(id,organization_id,third_party_id,title,severity,status,occurred_at,data_impact,business_impact,source_ref,created_by)
 VALUES($1,$2,$3,$4,$5,'OPEN',$6,$7,$8,$9,$10) RETURNING *`,[crypto.randomUUID(),org,vendorId,String(input.title||'Third-party incident').trim(),sev,input.occurredAt||null,String(input.dataImpact||''),String(input.businessImpact||''),input.sourceRef||null,user])).rows[0]
}
export async function thirdPartyDashboard(user:string,org:string){const vendors=await listThirdParties(user,org);const incidents=(await pool.query("SELECT * FROM grc_third_party_incidents WHERE organization_id=$1 AND status<>'CLOSED' ORDER BY detected_at DESC",[org])).rows;return {vendors,incidents,summary:{vendors:vendors.length,tier1:vendors.filter((x:any)=>x.tier==='TIER_1').length,dueReview:vendors.filter((x:any)=>x.next_review_at&&new Date(x.next_review_at)<=new Date()).length,openIncidents:incidents.length,criticalIncidents:incidents.filter((x:any)=>x.severity==='CRITICAL').length}}}
