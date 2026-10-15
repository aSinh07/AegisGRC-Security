import {pool} from './db-pool.js';
import crypto from 'node:crypto';
import pg from 'pg';
import {requireAssessmentAccess,requireOrgPermission} from './grc-organizations.js';
import {assessBreachImpact,type BreachSignal} from './breach-impact.js';


export async function initBreachAssessment(){await pool.query(`
CREATE TABLE IF NOT EXISTS breach_assessments(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,asset_id uuid NOT NULL REFERENCES assessment_assets(id) ON DELETE CASCADE,
 status text NOT NULL,impact_score integer NOT NULL,impact_band text NOT NULL,requires_human_review boolean NOT NULL,
 fingerprint text NOT NULL,evidence jsonb NOT NULL DEFAULT '[]'::jsonb,result jsonb NOT NULL,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(assessment_id,asset_id,fingerprint));
CREATE INDEX IF NOT EXISTS breach_assessments_org_idx ON breach_assessments(organization_id,assessment_id,asset_id,created_at DESC);
`)}

function category(text:string):BreachSignal['category']|null{
 const x=text.toLowerCase();
 if(/exfiltrat|data transfer|data sent|upload(ed)? to|egress anomaly/.test(x))return 'EXFILTRATION';
 if(/unauthori[sz]ed|authentication fail|credential abuse|account compromise|privilege escalation|impossible travel/.test(x))return 'UNAUTHORIZED_ACCESS';
 if(/public bucket|publicly accessible|internet exposed|anonymous access|public exposure/.test(x))return 'PUBLIC_EXPOSURE';
 if(/secret|credential|api key|access key|password|token leak/.test(x))return 'CREDENTIAL_LEAK';
 if(/pii|personal data|sensitive data|restricted data/.test(x))return 'SENSITIVE_DATA';
 if(/disabled logging|audit log disabled|security control|control failure/.test(x))return 'CONTROL_FAILURE';
 return null;
}
export async function deriveBreachAssessment(userId:string,organizationId:string,assessmentId:string,assetId:string){
 await requireOrgPermission(userId,organizationId,'manageAssessment');const access=await requireAssessmentAccess(userId,assessmentId);
 if(access.organization_id!==organizationId)throw Object.assign(new Error('Assessment does not belong to this organization'),{statusCode:403});
 const asset=(await pool.query('SELECT id,asset_key,criticality,data_classification,contains_pii FROM assessment_assets WHERE id=$1 AND organization_id=$2 AND status=\'ACTIVE\'',[assetId,organizationId])).rows[0];
 if(!asset)throw Object.assign(new Error('Active assessment asset not found'),{statusCode:404});
 const rows=(await pool.query(`SELECT f.id,f.source,f.created_at,f.payload,e.sha256,e.integrity_verified_at
 FROM findings f JOIN evidence e ON e.assessment_id=f.assessment_id AND e.sha256=f.payload->>'evidenceHash'
 WHERE f.assessment_id=$1 AND e.integrity_verified_at IS NOT NULL AND f.source=ANY($2::text[])
 ORDER BY f.created_at`,[assessmentId,['wazuh','prowler','gitleaks','trivy','openvas','nuclei']])).rows;
 const signals:BreachSignal[]=[];
 for(const r of rows){const p=r.payload||{};if(String(p.asset||'')!==String(asset.asset_key))continue;const c=category([p.title,p.description,p.remediation].filter(Boolean).join(' '));if(!c)continue;signals.push({source:String(r.source),evidenceSha256:String(r.sha256),observedAt:new Date(r.created_at).toISOString(),category:c,verified:true,assetId,details:String(p.title||'').slice(0,300)})}
 const classification=String(asset.data_classification||'INTERNAL').toUpperCase();const allowedClass=['PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED'];const criticality=String(asset.criticality||'MEDIUM').toUpperCase();const allowedCritical=['LOW','MEDIUM','HIGH','CRITICAL'];
 const result=assessBreachImpact({organizationId,assessmentId,assetId,classification:(allowedClass.includes(classification)?classification:'INTERNAL') as any,containsPii:Boolean(asset.contains_pii),criticality:(allowedCritical.includes(criticality)?criticality:'MEDIUM') as any,signals});
 const id=crypto.randomUUID();const inserted=(await pool.query(`INSERT INTO breach_assessments(id,organization_id,assessment_id,asset_id,status,impact_score,impact_band,requires_human_review,fingerprint,evidence,result,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(assessment_id,asset_id,fingerprint) DO UPDATE SET result=EXCLUDED.result RETURNING *`,
 [id,organizationId,assessmentId,assetId,result.status,result.impactScore,result.impactBand,result.requiresHumanReview,result.fingerprint,result.evidence,result,userId])).rows[0];
 return {...result,id:inserted.id,asset:{id:asset.id,key:asset.asset_key},derivedFromPersistedEvidence:true}
}
export async function listBreachAssessments(userId:string,organizationId:string,assessmentId:string){
 await requireOrgPermission(userId,organizationId,'read');const access=await requireAssessmentAccess(userId,assessmentId);if(access.organization_id!==organizationId)throw Object.assign(new Error('Assessment does not belong to this organization'),{statusCode:403});
 return (await pool.query('SELECT id,asset_id,status,impact_score,impact_band,requires_human_review,fingerprint,evidence,result,created_at FROM breach_assessments WHERE organization_id=$1 AND assessment_id=$2 ORDER BY created_at DESC',[organizationId,assessmentId])).rows
}
