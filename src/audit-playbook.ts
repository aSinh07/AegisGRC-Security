import crypto from 'node:crypto';import pg from 'pg';import {requireOrgPermission} from './grc-organizations.js';import {createAudit} from './audit-management.js';
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
export const ISO42001_AUDIT_EVIDENCE_REQUESTS=[
 {key:'AIMS-GOV',title:'Approved AIMS scope, AI policy and objectives',procedure:'Verify approved AIMS scope, policy, objectives and accountable approval records.'},
 {key:'AIMS-RACI',title:'AIMS RACI and role descriptions',procedure:'Verify named AIMS accountability, role descriptions, ownership and escalation responsibilities.'},
 {key:'AI-ASSETS',title:'AI asset and dependency inventory',procedure:'Verify inventory covers AI systems, models, prompts, agents, tools, data stores, suppliers and infrastructure.'},
 {key:'AI-RISK',title:'AI risk methodology, register and treatment',procedure:'Verify current AI risk method, risk register, treatments and residual-risk approvals.'},
 {key:'AI-IMPACT',title:'AI system impact assessment and review history',procedure:'Verify intended use, foreseeable misuse, affected parties, data/output/downstream impacts, human oversight, evidence and independent approval.'},
 {key:'AI-LIFECYCLE',title:'AI lifecycle, V&V, change, release and rollback evidence',procedure:'Verify lifecycle procedure, verification/validation criteria, controlled changes, releases, rollback and retirement evidence.'},
 {key:'AI-DATA',title:'AI data provenance, quality, access, retention and deletion',procedure:'Verify governed provenance, quality, access, retention and deletion for applicable RAG, document, SQL, graph and other AI data sources.'},
 {key:'AI-ACCESS',title:'Least-privilege data/tool authorization evidence',procedure:'Verify least-privilege database/tool roles and deterministic authorization tests for AI tool actions.'},
 {key:'SEC-RETEST',title:'Security scans, remediation and retest evidence',procedure:'Verify attributable technical findings, remediation, retest and closure evidence without treating scanner output as automatic conformity.'},
 {key:'MONITORING',title:'Monitoring, KPI/KRI, AI incident and response records',procedure:'Verify governed performance indicators, monitoring records, AI incidents, response and follow-up.'},
 {key:'AI-SUPPLIER',title:'AI supplier due diligence and shared-responsibility evidence',procedure:'Verify current supplier due diligence, contractual/shared responsibilities, change notification and exit arrangements.'},
 {key:'TRAINING',title:'Training and competence records',procedure:'Verify role-based AI governance/security training and competence evidence for in-scope personnel.'},
 {key:'AIMS-AUDIT',title:'Internal AIMS audit, findings and CAPA records',procedure:'Verify independent internal AIMS audit workpapers, findings, corrective actions, retest and closure state.'},
 {key:'MGMT-REVIEW',title:'Management review minutes, decisions and actions',procedure:'Verify approved management review records include inputs, decisions, actions and accountable follow-up.'}
] as const;
const q=async(sql:string,args:any[])=>Number((await pool.query(sql,args)).rows[0]?.n||0);
export async function iso42001AuditEvidenceReadiness(user:string,org:string,scopeId?:string){
 await requireOrgPermission(user,org,'read');if(scopeId){const s=(await pool.query('SELECT 1 FROM grc_scopes WHERE id=$1 AND organization_id=$2',[scopeId,org])).rows[0];if(!s)throw Object.assign(new Error('Scope not found in organization'),{statusCode:404})}
 const scope=scopeId?[org,scopeId]:[org];
 const evidence=async(words:string[])=>{const pattern='%('+words.join('|')+')%';return q("SELECT count(*) n FROM grc_evidence_requests r JOIN grc_evidence_versions v ON v.evidence_request_id=r.id WHERE r.organization_id=$1 "+(scopeId?'AND (r.scope_id=$2 OR r.scope_id IS NULL) ':'')+"AND r.status='VALID' AND v.integrity_status='SERVER_VERIFIED' AND v.validated_at IS NOT NULL AND v.valid_until>now() AND lower(r.title) SIMILAR TO $"+(scope.length+1),[...scope,pattern])};
 const checks:any[]=[
  ['AIMS-GOV',await evidence(['%aims%','%ai policy%','%scope%','%objective%'])],['AIMS-RACI',await evidence(['%raci%','%role%','%accountab%'])],
  ['AI-ASSETS',await q("SELECT count(*) n FROM assessment_assets WHERE organization_id=$1 "+(scopeId?'AND (scope_id=$2 OR scope_id IS NULL) ':'')+"AND status='ACTIVE'",scope)],
  ['AI-RISK',await q("SELECT count(*) n FROM grc_enterprise_risks WHERE organization_id=$1 AND status<>'CLOSED'",[org])],
  ['AI-IMPACT',await q("SELECT count(*) n FROM grc_management_reviews WHERE organization_id=$1 "+(scopeId?'AND (scope_id=$2 OR scope_id IS NULL) ':'')+"AND status='APPROVED' AND inputs->>'profile'='ISO42001_AI_IMPACT'",scope)],
  ['AI-LIFECYCLE',await evidence(['%lifecycle%','%validation%','%release%','%rollback%'])],['AI-DATA',await evidence(['%provenance%','%data quality%','%retention%','%deletion%'])],['AI-ACCESS',await evidence(['%least privilege%','%authorization%','%access%'])],
  ['SEC-RETEST',await q("SELECT count(*) n FROM grc_control_test_runs WHERE organization_id=$1 AND result='PASS'",[org])],
  ['MONITORING',await q("SELECT count(*) n FROM grc_performance_metrics WHERE organization_id=$1",[org])],
  ['AI-SUPPLIER',await q("SELECT count(*) n FROM grc_third_party_assessments WHERE organization_id=$1 AND assessment_type='ISO42001_AI_SUPPLIER' AND reviewed_at IS NOT NULL",[org])],
  ['TRAINING',await evidence(['%training%','%competence%','%awareness%'])],
  ['AIMS-AUDIT',await q("SELECT count(*) n FROM grc_audits WHERE organization_id=$1 "+(scopeId?'AND (scope_id=$2 OR scope_id IS NULL) ':'')+"AND status='COMPLETE'",scope)],
  ['MGMT-REVIEW',await q("SELECT count(*) n FROM grc_management_reviews WHERE organization_id=$1 "+(scopeId?'AND (scope_id=$2 OR scope_id IS NULL) ':'')+"AND status='APPROVED'",scope)]
 ];
 const by=new Map(checks);const confirmed=await pool.query("SELECT w.title FROM grc_audit_workpapers w JOIN grc_audits a ON a.id=w.audit_id AND a.organization_id=w.organization_id WHERE w.organization_id=$1 "+(scopeId?'AND (a.scope_id=$2 OR a.scope_id IS NULL) ':'')+"AND a.status='COMPLETE' AND w.result='PASS' AND w.reviewed_at IS NOT NULL AND jsonb_array_length(w.evidence_refs)>0",scope);const passed=new Set(confirmed.rows.map((r:any)=>String(r.title).split(' · ')[0]));const requests=ISO42001_AUDIT_EVIDENCE_REQUESTS.map(x=>({...x,status:passed.has(x.key)?'EVIDENCED':Number(by.get(x.key)||0)>0?'REVIEW_REQUIRED':'ACTION_REQUIRED',supportingRecords:Number(by.get(x.key)||0)}));const evidenced=requests.filter(x=>x.status==='EVIDENCED').length;
 return {profile:'ISO42001_AUDIT_EVIDENCE_REQUEST_LIST',source:'Supplied ISO 42001 GRC Master Pack section 18',organizationId:org,scopeId:scopeId||null,requests,summary:{total:requests.length,evidenced,actionRequired:requests.length-evidenced,percent:Math.round(evidenced*100/requests.length)},boundary:'Deterministic evidence-request readiness only. Only completed, independently reviewed PASS workpapers count as EVIDENCED; candidate records require audit sampling. This is not an ISO/IEC 42001 certification or external audit opinion.'}
}
export async function createIso42001AuditPlaybook(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'review');const audit=await createAudit(user,org,{...input,auditKey:String(input?.auditKey||'').trim(),title:String(input?.title||'ISO 42001 Internal AIMS Audit').trim(),auditType:'INTERNAL',objective:String(input?.objective||'Evaluate evidence-backed operation of the scoped AI management system.').trim(),criteria:String(input?.criteria||'ISO/IEC 42001:2023 scoped internal AIMS criteria and approved organizational controls.').trim()});
 for(const item of ISO42001_AUDIT_EVIDENCE_REQUESTS)await pool.query("INSERT INTO grc_audit_workpapers(id,organization_id,audit_id,title,procedure,sample_description,conclusion,evidence_refs,result,prepared_by) VALUES($1,$2,$3,$4,$5,'','','[]'::jsonb,'NOT_TESTED',$6)",[crypto.randomUUID(),org,audit.id,item.key+' · '+item.title,item.procedure,user]);
 return {...audit,playbook:'ISO42001_AUDIT_EVIDENCE_REQUEST_LIST',workpapersCreated:ISO42001_AUDIT_EVIDENCE_REQUESTS.length}
}
