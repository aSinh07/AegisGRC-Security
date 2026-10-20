import {pool} from './db-pool.js';
import crypto from 'node:crypto';
import pg from 'pg';
import {requireOrgPermission,membership,roleAllows} from './grc-organizations.js';
import {prepareEvidenceHandoff,type SecuritySource} from './cyber-operations-handoff.js';
import {materializeAcceptedSecurityFindings} from './security-report-findings.js';


export async function initSecurityReportHandoffs(){await pool.query(`
CREATE TABLE IF NOT EXISTS grc_security_report_handoffs(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,report_id uuid NOT NULL,source text NOT NULL,
 sha256 text NOT NULL,recorded_at timestamptz NOT NULL,evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
 frameworks_requested jsonb NOT NULL DEFAULT '[]'::jsonb,status text NOT NULL DEFAULT 'REVIEW_REQUIRED',
 created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,reviewed_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 review_note text,source_context jsonb NOT NULL DEFAULT '{}'::jsonb,created_at timestamptz NOT NULL DEFAULT now(),reviewed_at timestamptz,
 UNIQUE(organization_id,report_id)
);
ALTER TABLE grc_security_report_handoffs ADD COLUMN IF NOT EXISTS source_context jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS grc_security_handoff_org_idx ON grc_security_report_handoffs(organization_id,status,created_at DESC);
`);
 // Backfill Offensive/Defensive documents uploaded before automatic GRC handoff existed.
 await pool.query(`
 INSERT INTO grc_security_report_handoffs(id,organization_id,assessment_id,report_id,source,sha256,recorded_at,evidence_refs,frameworks_requested,status,created_by,created_at)
 SELECT gen_random_uuid(),a.organization_id,d.assessment_id,d.id,
   CASE WHEN COALESCE(ev.payload->'metadata'->>'description','') ILIKE '%offensive%' OR COALESCE(ev.payload->'metadata'->>'documentType','') IN ('PENTEST_REPORT','VULNERABILITY_REPORT') THEN 'OFFENSIVE' ELSE 'DEFENSIVE' END,
   d.sha256,d.created_at,jsonb_build_array(d.id::text),'[]'::jsonb,'REVIEW_REQUIRED',a.created_by,d.created_at
 FROM documents d JOIN assessments a ON a.id=d.assessment_id
 JOIN LATERAL (SELECT e.payload FROM audit_events e WHERE e.assessment_id=d.assessment_id AND e.action='DOCUMENT_UPLOADED' AND e.payload->'metadata'->>'documentId'=d.id::text ORDER BY e.created_at DESC LIMIT 1) ev ON true
 WHERE a.organization_id IS NOT NULL AND (COALESCE(ev.payload->'metadata'->>'description','') ILIKE '%offensive%' OR COALESCE(ev.payload->'metadata'->>'description','') ILIKE '%defensive%' OR COALESCE(ev.payload->'metadata'->>'documentType','') IN ('PENTEST_REPORT','VULNERABILITY_REPORT'))
 ON CONFLICT(organization_id,report_id) DO NOTHING;
 `)
}

async function requireSecurityHandoffOperator(user:string,org:string){
 const m=await membership(user,org);
 if(!m||(!roleAllows(m.role as any,'manageAssessment')&&!roleAllows(m.role as any,'manageRisk')))throw Object.assign(new Error('Assessment or risk management permission required for security evidence handoff'),{statusCode:403});
}
export async function createSecurityReportHandoff(user:string,org:string,input:any){
 await requireSecurityHandoffOperator(user,org);
 const assessment=(await pool.query('SELECT id FROM assessments WHERE id=$1 AND organization_id=$2',[input.assessmentId,org])).rows[0];
 if(!assessment)throw Object.assign(new Error('Assessment not found in organization'),{statusCode:404});
 const document=(await pool.query('SELECT id,assessment_id,sha256,created_at FROM documents WHERE id=$1 AND assessment_id=$2',[String(input.reportId||''),assessment.id])).rows[0];
 if(!document)throw Object.assign(new Error('Security report document is not part of the assessment'),{statusCode:404});
 if(String(input.sha256||'').toLowerCase()!==String(document.sha256||'').toLowerCase())throw Object.assign(new Error('Security report evidence hash does not match stored document'),{statusCode:409});
 const evidenceRefs=Array.isArray(input.evidenceRefs)&&input.evidenceRefs.length?input.evidenceRefs.map(String):[String(input.reportId)];
 if(!evidenceRefs.includes(String(input.reportId)))throw Object.assign(new Error('Primary security report must be included in evidence references'),{statusCode:409});
 const linked=(await pool.query('SELECT id FROM documents WHERE assessment_id=$1 AND id::text=ANY($2::text[])',[assessment.id,evidenceRefs])).rows.map((x:any)=>String(x.id));
 if(linked.length!==new Set(evidenceRefs).size)throw Object.assign(new Error('Every security handoff evidence reference must resolve to a stored document in the same assessment'),{statusCode:409});
 const normalized=prepareEvidenceHandoff({organizationId:org,assessmentId:String(input.assessmentId),reportId:String(input.reportId),source:String(input.source||'').toUpperCase() as SecuritySource,sha256:String(input.sha256||''),recordedAt:String(input.recordedAt||''),status:'EVIDENCE_RECORDED',evidenceRefs,frameworksRequested:input.frameworksRequested||[]});
 const sourceContext=input.sourceContext&&typeof input.sourceContext==='object'&&!Array.isArray(input.sourceContext)?input.sourceContext:{};
 const inserted=(await pool.query(`INSERT INTO grc_security_report_handoffs(id,organization_id,assessment_id,report_id,source,sha256,recorded_at,evidence_refs,frameworks_requested,status,created_by,source_context)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'REVIEW_REQUIRED',$10,$11::jsonb) ON CONFLICT(organization_id,report_id) DO NOTHING RETURNING *`,[crypto.randomUUID(),org,normalized.assessmentId,normalized.reportId,normalized.source,normalized.sha256,normalized.recordedAt,JSON.stringify(normalized.evidenceRefs),JSON.stringify(normalized.frameworksRequested),user,JSON.stringify(sourceContext)])).rows[0];
 if(inserted)return inserted;
 const existing=(await pool.query('SELECT * FROM grc_security_report_handoffs WHERE organization_id=$1 AND report_id=$2',[org,normalized.reportId])).rows[0];
 if(existing&&String(existing.assessment_id)===normalized.assessmentId&&String(existing.sha256).toLowerCase()===normalized.sha256.toLowerCase()&&String(existing.source)===normalized.source)return {...existing,reused:true};
 throw Object.assign(new Error('Conflicting security report handoff already exists'),{statusCode:409})
}
export async function reviewSecurityReportHandoff(user:string,org:string,id:string,input:any){
 await requireOrgPermission(user,org,'review');const decision=String(input.decision||'').toUpperCase();if(!['ACCEPT_EVIDENCE','REJECT'].includes(decision))throw new Error('Invalid handoff review decision');
 const client=await pool.connect();try{await client.query('BEGIN');const row=(await client.query('SELECT * FROM grc_security_report_handoffs WHERE id=$1 AND organization_id=$2 FOR UPDATE',[id,org])).rows[0];if(!row)throw Object.assign(new Error('Report handoff not found'),{statusCode:404});if(row.created_by===user)throw Object.assign(new Error('Independent reviewer required'),{statusCode:409});if(row.reviewed_at){await client.query('COMMIT');if(row.status==='EVIDENCE_ACCEPTED'){const intelligence=await materializeAcceptedSecurityFindings(org,id);return {...row,alreadyReviewed:true,intelligence:{extractedFindings:intelligence.findings.length,createdFindings:intelligence.created,governanceState:'PROPOSED',automaticComplianceDecision:false,recovered:true}}}return {...row,alreadyReviewed:true}}
 const reviewed=(await client.query(`UPDATE grc_security_report_handoffs SET status=$4,reviewed_by=$3,reviewed_at=now(),review_note=$5 WHERE id=$1 AND organization_id=$2 AND reviewed_at IS NULL RETURNING *`,[id,org,user,decision==='ACCEPT_EVIDENCE'?'EVIDENCE_ACCEPTED':'REJECTED',String(input.note||'').slice(0,3000)])).rows[0];await client.query('COMMIT');if(decision==='ACCEPT_EVIDENCE'){const intelligence=await materializeAcceptedSecurityFindings(org,id);return {...reviewed,intelligence:{extractedFindings:intelligence.findings.length,createdFindings:intelligence.created,governanceState:'PROPOSED',automaticComplianceDecision:false}}}return reviewed;}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function listSecurityReportHandoffs(user:string,org:string){await requireOrgPermission(user,org,'read');return (await pool.query('SELECT * FROM grc_security_report_handoffs WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 300',[org])).rows}
