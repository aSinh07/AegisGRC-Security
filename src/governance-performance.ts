import crypto from 'node:crypto';
import pg from 'pg';
import {requireOrgPermission} from './grc-organizations.js';

const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
const err=(m:string,code=400)=>Object.assign(new Error(m),{statusCode:code});
const rating=(v:any)=>{const x=String(v||'MEDIUM').toUpperCase();if(!['LOW','MEDIUM','HIGH','CRITICAL'].includes(x))throw err('Invalid risk rating');return x};
const direction=(v:any)=>{const x=String(v||'MAX').toUpperCase();if(!['MAX','MIN','RANGE'].includes(x))throw err('Metric direction must be MAX, MIN or RANGE');return x};

export async function initGovernancePerformance(){await pool.query(`
CREATE TABLE IF NOT EXISTS grc_risk_appetite_statements(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 appetite_key text NOT NULL,title text NOT NULL,category text NOT NULL DEFAULT 'ENTERPRISE',statement text NOT NULL,
 tolerance_rating text NOT NULL DEFAULT 'MEDIUM' CHECK(tolerance_rating IN ('LOW','MEDIUM','HIGH','CRITICAL')),
 quantitative_limit numeric,unit text,owner_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,
 status text NOT NULL DEFAULT 'DRAFT' CHECK(status IN ('DRAFT','APPROVED','RETIRED')),
 created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,approved_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 approved_at timestamptz,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,appetite_key)
);
CREATE TABLE IF NOT EXISTS grc_performance_metrics(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 scope_id uuid REFERENCES grc_scopes(id) ON DELETE CASCADE,metric_key text NOT NULL,title text NOT NULL,
 metric_type text NOT NULL CHECK(metric_type IN ('KPI','KRI','KCI')),direction text NOT NULL DEFAULT 'MAX' CHECK(direction IN ('MAX','MIN','RANGE')),
 target_value numeric,warning_value numeric,critical_value numeric,unit text NOT NULL DEFAULT 'count',
 owner_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,active boolean NOT NULL DEFAULT true,
 created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,metric_key)
);
CREATE TABLE IF NOT EXISTS grc_metric_measurements(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 metric_id uuid NOT NULL REFERENCES grc_performance_metrics(id) ON DELETE CASCADE,value numeric NOT NULL,
 measured_at timestamptz NOT NULL DEFAULT now(),evidence_ref text NOT NULL,notes text NOT NULL DEFAULT '',
 recorded_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS grc_management_reviews(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 scope_id uuid REFERENCES grc_scopes(id) ON DELETE CASCADE,review_key text NOT NULL,title text NOT NULL,
 review_period text NOT NULL,inputs jsonb NOT NULL DEFAULT '{}'::jsonb,decisions jsonb NOT NULL DEFAULT '[]'::jsonb,
 actions jsonb NOT NULL DEFAULT '[]'::jsonb,status text NOT NULL DEFAULT 'DRAFT' CHECK(status IN ('DRAFT','SUBMITTED','APPROVED')),
 created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,approved_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 approved_at timestamptz,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,review_key)
);
CREATE INDEX IF NOT EXISTS grc_metric_measurements_metric_idx ON grc_metric_measurements(metric_id,measured_at DESC);
`)}

async function validateActor(org:string,userId?:string){if(userId)await requireOrgPermission(userId,org,'read')}
async function validateScope(org:string,scopeId?:string){if(scopeId&&!((await pool.query('SELECT 1 FROM grc_scopes WHERE id=$1 AND organization_id=$2',[scopeId,org])).rows[0]))throw err('Scope not found in organization',404)}

export async function createRiskAppetite(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');await validateActor(org,input.ownerUserId);
 const key=String(input.appetiteKey||'').trim().toUpperCase(),title=String(input.title||'').trim(),statement=String(input.statement||'').trim();
 if(!key||title.length<3||statement.length<15)throw err('Appetite key, title and meaningful statement are required');
 const limit=input.quantitativeLimit===null||input.quantitativeLimit===undefined||input.quantitativeLimit===''?null:Number(input.quantitativeLimit);
 if(limit!==null&&!Number.isFinite(limit))throw err('Quantitative limit must be numeric');
 return (await pool.query(`INSERT INTO grc_risk_appetite_statements(id,organization_id,appetite_key,title,category,statement,tolerance_rating,quantitative_limit,unit,owner_user_id,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
 ON CONFLICT(organization_id,appetite_key) DO UPDATE SET title=EXCLUDED.title,category=EXCLUDED.category,statement=EXCLUDED.statement,tolerance_rating=EXCLUDED.tolerance_rating,quantitative_limit=EXCLUDED.quantitative_limit,unit=EXCLUDED.unit,owner_user_id=EXCLUDED.owner_user_id,status='DRAFT',approved_by=NULL,approved_at=NULL,updated_at=now()
 RETURNING *`,[crypto.randomUUID(),org,key,title,String(input.category||'ENTERPRISE').toUpperCase(),statement,rating(input.toleranceRating),limit,String(input.unit||'').trim()||null,input.ownerUserId||null,user])).rows[0]
}
export async function approveRiskAppetite(user:string,org:string,id:string){
 await requireOrgPermission(user,org,'review');const row=(await pool.query('SELECT * FROM grc_risk_appetite_statements WHERE id=$1 AND organization_id=$2',[id,org])).rows[0];
 if(!row)throw err('Risk appetite statement not found',404);if(row.created_by===user||row.owner_user_id===user)throw err('Independent approver required for risk appetite',409);
 return (await pool.query("UPDATE grc_risk_appetite_statements SET status='APPROVED',approved_by=$3,approved_at=now(),updated_at=now() WHERE id=$1 AND organization_id=$2 RETURNING *",[id,org,user])).rows[0]
}
export async function createMetric(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageControl');await validateScope(org,input.scopeId);await validateActor(org,input.ownerUserId);
 const key=String(input.metricKey||'').trim().toUpperCase(),title=String(input.title||'').trim(),type=String(input.metricType||'KRI').toUpperCase();
 if(!key||title.length<3||!['KPI','KRI','KCI'].includes(type))throw err('Valid metric key, title and KPI/KRI/KCI type required');
 const num=(x:any)=>x===null||x===undefined||x===''?null:Number(x),target=num(input.targetValue),warning=num(input.warningValue),critical=num(input.criticalValue);
 if([target,warning,critical].some(x=>x!==null&&!Number.isFinite(x)))throw err('Metric thresholds must be numeric');
 return (await pool.query(`INSERT INTO grc_performance_metrics(id,organization_id,scope_id,metric_key,title,metric_type,direction,target_value,warning_value,critical_value,unit,owner_user_id,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
 ON CONFLICT(organization_id,metric_key) DO UPDATE SET title=EXCLUDED.title,metric_type=EXCLUDED.metric_type,direction=EXCLUDED.direction,target_value=EXCLUDED.target_value,warning_value=EXCLUDED.warning_value,critical_value=EXCLUDED.critical_value,unit=EXCLUDED.unit,owner_user_id=EXCLUDED.owner_user_id,active=true,updated_at=now() RETURNING *`,
 [crypto.randomUUID(),org,input.scopeId||null,key,title,type,direction(input.direction),target,warning,critical,String(input.unit||'count').trim(),input.ownerUserId||null,user])).rows[0]
}
export async function recordMetricMeasurement(user:string,org:string,id:string,input:any){
 await requireOrgPermission(user,org,'manageControl');const metric=(await pool.query('SELECT * FROM grc_performance_metrics WHERE id=$1 AND organization_id=$2 AND active=true',[id,org])).rows[0];if(!metric)throw err('Active metric not found',404);
 const value=Number(input.value),evidence=String(input.evidenceRef||'').trim();if(!Number.isFinite(value)||!evidence)throw err('Numeric value and evidence reference required');
 return (await pool.query('INSERT INTO grc_metric_measurements(id,organization_id,metric_id,value,measured_at,evidence_ref,notes,recorded_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[crypto.randomUUID(),org,id,value,input.measuredAt||new Date(),evidence,String(input.notes||''),user])).rows[0]
}
export const ISO42001_AI_IMPACT_PROFILE='ISO42001_AI_IMPACT';
const meaningful=(v:any,min=10)=>String(v||'').trim().length>=min;
export function validateIso42001AiImpact(input:any){
 const x=input&&typeof input==='object'?input:{};
 const required:[string,any][]=[
  ['aiSystem',x.aiSystem],['intendedUse',x.intendedUse],['foreseeableMisuse',x.foreseeableMisuse],
  ['affectedParties',x.affectedParties],['dataExposureImpact',x.dataExposureImpact],
  ['erroneousOutputImpact',x.erroneousOutputImpact],['downstreamImpact',x.downstreamImpact],
  ['humanOversight',x.humanOversight],['reviewTriggers',x.reviewTriggers]
 ];
 const missing=required.filter(([,v])=>!meaningful(v)).map(([k])=>k);
 const risk=String(x.riskRating||'').toUpperCase();if(!['LOW','MEDIUM','HIGH','CRITICAL'].includes(risk))missing.push('riskRating');
 const evidence=Array.isArray(x.evidenceRefs)?x.evidenceRefs.map((v:any)=>String(v||'').trim()).filter(Boolean):[];if(evidence.length===0)missing.push('evidenceRefs');
 if(missing.length)throw err('ISO 42001 AI impact assessment incomplete: '+[...new Set(missing)].join(', '),409);
 return {...x,profile:ISO42001_AI_IMPACT_PROFILE,riskRating:risk,evidenceRefs:evidence};
}
async function requireCurrentEvidence(org:string,refs:string[]){if(refs.some(x=>!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(x)))throw err('Evidence references must be Evidence Vault version UUIDs',409);const q=(await pool.query(`SELECT count(*)::int n FROM grc_evidence_versions v JOIN grc_evidence_requests r ON r.id=v.evidence_request_id WHERE r.organization_id=$1 AND v.id=ANY($2::uuid[]) AND r.status='VALID' AND v.integrity_status='SERVER_VERIFIED' AND v.validated_at IS NOT NULL AND v.valid_until>now()`,[org,refs])).rows[0];if(Number(q?.n)!==new Set(refs).size)throw err('Current independently validated Evidence Vault versions required',409)}
export async function createIso42001AiImpactReview(user:string,org:string,input:any){
 const impact=validateIso42001AiImpact(input?.impact);await requireCurrentEvidence(org,impact.evidenceRefs);
 const decisions=Array.isArray(input?.decisions)?input.decisions:[];
 const actions=Array.isArray(input?.actions)?input.actions:[];
 const rawKey=String(input?.reviewKey||'').trim().toUpperCase();if(!rawKey)throw err('AI impact assessment review key required');const reviewKey=rawKey.startsWith('AI-IMPACT-')?rawKey:'AI-IMPACT-'+rawKey;
 return createManagementReview(user,org,{...input,reviewKey,title:String(input?.title||'ISO 42001 AI Impact Assessment').trim(),inputs:{profile:ISO42001_AI_IMPACT_PROFILE,impact},decisions,actions});
}

export async function createManagementReview(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');await validateScope(org,input.scopeId);
 const key=String(input.reviewKey||'').trim().toUpperCase(),title=String(input.title||'').trim(),period=String(input.reviewPeriod||'').trim();
 if(!key||title.length<3||!period)throw err('Review key, title and review period required');
 const inputs=input.inputs&&typeof input.inputs==='object'?input.inputs:{},decisions=Array.isArray(input.decisions)?input.decisions:[],actions=Array.isArray(input.actions)?input.actions:[];
 return (await pool.query('INSERT INTO grc_management_reviews(id,organization_id,scope_id,review_key,title,review_period,inputs,decisions,actions,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,\'SUBMITTED\',$10) ON CONFLICT(organization_id,review_key) DO UPDATE SET title=EXCLUDED.title,review_period=EXCLUDED.review_period,inputs=EXCLUDED.inputs,decisions=EXCLUDED.decisions,actions=EXCLUDED.actions,status=\'SUBMITTED\',approved_by=NULL,approved_at=NULL,updated_at=now() RETURNING *',[crypto.randomUUID(),org,input.scopeId||null,key,title,period,JSON.stringify(inputs),JSON.stringify(decisions),JSON.stringify(actions),user])).rows[0]
}
export async function approveManagementReview(user:string,org:string,id:string){
 await requireOrgPermission(user,org,'review');const row=(await pool.query('SELECT * FROM grc_management_reviews WHERE id=$1 AND organization_id=$2',[id,org])).rows[0];if(!row)throw err('Management review not found',404);if(row.created_by===user)throw err('Independent approver required for management review',409);if(row.status!=='SUBMITTED')throw err('Management review must be submitted',409);
 return (await pool.query("UPDATE grc_management_reviews SET status='APPROVED',approved_by=$3,approved_at=now(),updated_at=now() WHERE id=$1 AND organization_id=$2 RETURNING *",[id,org,user])).rows[0]
}
function metricState(m:any,value:any){if(value===null||value===undefined)return 'NO_DATA';const v=Number(value),w=m.warning_value===null?null:Number(m.warning_value),c=m.critical_value===null?null:Number(m.critical_value),d=m.direction;
 if(d==='MAX'){if(c!==null&&v>=c)return 'CRITICAL';if(w!==null&&v>=w)return 'WARNING';return 'WITHIN_TOLERANCE'}
 if(d==='MIN'){if(c!==null&&v<=c)return 'CRITICAL';if(w!==null&&v<=w)return 'WARNING';return 'WITHIN_TOLERANCE'}
 return 'OBSERVED'
}
export async function governancePerformanceDashboard(user:string,org:string,scopeId?:string){
 await requireOrgPermission(user,org,'read');await validateScope(org,scopeId);
 const appetites=(await pool.query('SELECT * FROM grc_risk_appetite_statements WHERE organization_id=$1 ORDER BY appetite_key',[org])).rows;
 const args=scopeId?[org,scopeId]:[org],clause=scopeId?' AND (m.scope_id=$2 OR m.scope_id IS NULL)':'';
 const metrics=(await pool.query(`SELECT m.*,x.value latest_value,x.measured_at latest_measured_at,x.evidence_ref latest_evidence_ref FROM grc_performance_metrics m LEFT JOIN LATERAL(SELECT value,measured_at,evidence_ref FROM grc_metric_measurements mm WHERE mm.metric_id=m.id ORDER BY measured_at DESC LIMIT 1)x ON true WHERE m.organization_id=$1 AND m.active=true${clause} ORDER BY m.metric_type,m.metric_key`,args)).rows.map((m:any)=>({...m,state:metricState(m,m.latest_value)}));
 const reviews=(await pool.query('SELECT * FROM grc_management_reviews WHERE organization_id=$1'+(scopeId?' AND (scope_id=$2 OR scope_id IS NULL)':'')+' ORDER BY created_at DESC LIMIT 50',args)).rows;
 return {appetites,metrics,reviews,summary:{approvedAppetites:appetites.filter((x:any)=>x.status==='APPROVED').length,draftAppetites:appetites.filter((x:any)=>x.status==='DRAFT').length,metrics:metrics.length,metricsCritical:metrics.filter((x:any)=>x.state==='CRITICAL').length,metricsWarning:metrics.filter((x:any)=>x.state==='WARNING').length,metricsNoData:metrics.filter((x:any)=>x.state==='NO_DATA').length,managementReviews:reviews.length,approvedManagementReviews:reviews.filter((x:any)=>x.status==='APPROVED').length}}
}
