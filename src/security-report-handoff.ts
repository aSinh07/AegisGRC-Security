import {pool} from './db-pool.js';
import crypto from 'node:crypto';
import pg from 'pg';
import {requireOrgPermission} from './grc-organizations.js';
import {prepareEvidenceHandoff,type SecuritySource} from './cyber-operations-handoff.js';


export async function initSecurityReportHandoffs(){await pool.query(`
CREATE TABLE IF NOT EXISTS grc_security_report_handoffs(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,report_id uuid NOT NULL,source text NOT NULL,
 sha256 text NOT NULL,recorded_at timestamptz NOT NULL,evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
 frameworks_requested jsonb NOT NULL DEFAULT '[]'::jsonb,status text NOT NULL DEFAULT 'REVIEW_REQUIRED',
 created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,reviewed_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 review_note text,created_at timestamptz NOT NULL DEFAULT now(),reviewed_at timestamptz,
 UNIQUE(organization_id,report_id)
);
CREATE INDEX IF NOT EXISTS grc_security_handoff_org_idx ON grc_security_report_handoffs(organization_id,status,created_at DESC);
`)}

export async function createSecurityReportHandoff(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');
 const assessment=(await pool.query('SELECT id FROM assessments WHERE id=$1 AND organization_id=$2',[input.assessmentId,org])).rows[0];
 if(!assessment)throw Object.assign(new Error('Assessment not found in organization'),{statusCode:404});
 const normalized=prepareEvidenceHandoff({organizationId:org,assessmentId:String(input.assessmentId),reportId:String(input.reportId),source:String(input.source||'').toUpperCase() as SecuritySource,sha256:String(input.sha256||''),recordedAt:String(input.recordedAt||''),status:'EVIDENCE_RECORDED',evidenceRefs:input.evidenceRefs,frameworksRequested:input.frameworksRequested||[]});
 return (await pool.query(`INSERT INTO grc_security_report_handoffs(id,organization_id,assessment_id,report_id,source,sha256,recorded_at,evidence_refs,frameworks_requested,status,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'REVIEW_REQUIRED',$10) ON CONFLICT(organization_id,report_id) DO NOTHING RETURNING *`,[crypto.randomUUID(),org,normalized.assessmentId,normalized.reportId,normalized.source,normalized.sha256,normalized.recordedAt,normalized.evidenceRefs,normalized.frameworksRequested,user])).rows[0]||(()=>{throw Object.assign(new Error('Report already handed off'),{statusCode:409})})()
}
export async function reviewSecurityReportHandoff(user:string,org:string,id:string,input:any){
 await requireOrgPermission(user,org,'review');const decision=String(input.decision||'').toUpperCase();if(!['ACCEPT_EVIDENCE','REJECT'].includes(decision))throw new Error('Invalid handoff review decision');
 const row=(await pool.query('SELECT * FROM grc_security_report_handoffs WHERE id=$1 AND organization_id=$2',[id,org])).rows[0];if(!row)throw Object.assign(new Error('Report handoff not found'),{statusCode:404});if(row.created_by===user)throw Object.assign(new Error('Independent reviewer required'),{statusCode:409});if(row.reviewed_at)throw Object.assign(new Error('Report handoff already reviewed'),{statusCode:409});
 return (await pool.query(`UPDATE grc_security_report_handoffs SET status=$4,reviewed_by=$3,reviewed_at=now(),review_note=$5 WHERE id=$1 AND organization_id=$2 RETURNING *`,[id,org,user,decision==='ACCEPT_EVIDENCE'?'EVIDENCE_ACCEPTED':'REJECTED',String(input.note||'').slice(0,3000)])).rows[0];
}
export async function listSecurityReportHandoffs(user:string,org:string){await requireOrgPermission(user,org,'read');return (await pool.query('SELECT * FROM grc_security_report_handoffs WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 300',[org])).rows}
