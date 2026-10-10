import pg from 'pg';
import {requireOrgPermission} from './grc-organizations.js';

const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});

export function evaluateReadiness(rows:any[]){
 const controls=rows.map(x=>{
  const reasons:string[]=[];
  if(x.applicability==='PENDING')reasons.push('Applicability decision is pending.');
  if(!x.approved_at)reasons.push('Independent applicability approval is missing.');
  if(x.applicability==='NOT_APPLICABLE'&&!String(x.applicability_justification||'').trim())reasons.push('Exclusion justification is missing.');
  if(x.applicability==='APPLICABLE'){
   if(x.implementation!=='IMPLEMENTED')reasons.push('Control implementation is not complete.');
   if(Number(x.valid_evidence||0)===0)reasons.push('No current independently validated evidence is linked.');
   if(Number(x.passed_tests||0)===0)reasons.push('No passing deterministic control test is recorded.');
   if(Number(x.open_issues||0)>0)reasons.push('Open issues require treatment or closure.');
  }
  if(!(x.mappings||[]).length)reasons.push('No framework requirement/clauses mapped.');
  return {...x,readiness:reasons.length?'ACTION_REQUIRED':'EVIDENCE_READY',gaps:reasons,
   explanation:reasons.length?'Additional evidence, remediation, mapping or approval is required before this control is audit-ready.':'Available records satisfy this automated readiness checklist; an auditor must still verify scope and operating effectiveness.'};
 });
 const total=controls.length,ready=controls.filter(x=>x.readiness==='EVIDENCE_READY').length;
 return {controls,summary:{total,ready,actionRequired:total-ready,readinessPercent:total?Math.round(100*ready/total):0,unassessed:total===0},
  assuranceBoundary:'Internal automated evidence-readiness assessment, not a conformity opinion, external certification, or guarantee of compliance. A missing mapped control is not evidence that a framework is fully covered.'};
}

export async function organizationAuditReadiness(userId:string,orgId:string,scopeId:string){
 await requireOrgPermission(userId,orgId,'read');
 const scope=(await pool.query('SELECT id,name,status,description FROM grc_scopes WHERE id=$1 AND organization_id=$2',[scopeId,orgId])).rows[0];
 if(!scope)throw Object.assign(new Error('Scope not found in organization'),{statusCode:404});
 const rows=(await pool.query(`
 SELECT sc.id,sc.scope_id,sc.control_id,sc.applicability,sc.applicability_justification,sc.implementation,sc.owner_user_id,sc.approved_by,sc.approved_at,
 c.control_key,c.title,c.description,c.domain,
 COALESCE((SELECT json_agg(DISTINCT jsonb_build_object('framework',fr.framework,'version',fr.framework_version,'clause',fr.requirement_key,'title',fr.title,'summary',fr.summary))
 FROM grc_control_framework_mappings m JOIN grc_framework_requirements fr ON fr.id=m.requirement_id WHERE m.control_id=sc.control_id AND fr.active=true),'[]'::json) mappings,
 (SELECT count(*)::int FROM grc_evidence_requests er JOIN grc_evidence_versions ev ON ev.evidence_request_id=er.id
  WHERE er.organization_id=sc.organization_id AND er.scope_control_id=sc.id AND er.status='VALID' AND ev.validated_at IS NOT NULL AND ev.valid_until>now()) valid_evidence,
 (SELECT count(*)::int FROM grc_control_test_definitions td JOIN grc_control_test_runs tr ON tr.test_definition_id=td.id
  WHERE td.organization_id=sc.organization_id AND td.scope_control_id=sc.id AND tr.organization_id=sc.organization_id AND tr.result='PASS') passed_tests,
 (SELECT count(*)::int FROM grc_issues i WHERE i.organization_id=sc.organization_id AND i.scope_control_id=sc.id AND i.status<>'CLOSED') open_issues
 FROM grc_scope_controls sc JOIN grc_canonical_controls c ON c.id=sc.control_id
 WHERE sc.organization_id=$1 AND sc.scope_id=$2 ORDER BY c.control_key`,[orgId,scopeId])).rows;
 const result=evaluateReadiness(rows);
 return {organizationId:orgId,scope,generatedAt:new Date().toISOString(),...result,
  auditChecklist:['Confirm scope and framework inventory completeness.','Review every applicability decision and justification.','Verify evidence provenance, integrity, freshness and independent approval.','Review unresolved findings, risks, accepted exceptions and CAPA.','Confirm operating effectiveness through representative audit sampling.','Obtain authorized management sign-off before external submission.']};
}


export function auditReadinessReportModel(r:any){
 const controls=Array.isArray(r?.controls)?r.controls:[];
 const frameworks=[...new Set(controls.flatMap((c:any)=>(c.mappings||[]).map((m:any)=>String(m.framework||'').trim())).filter(Boolean))];
 const clauses=controls.flatMap((c:any)=>(c.mappings||[]).map((m:any)=>({
  framework:m.framework,version:m.version,clause:m.clause,title:m.title,summary:m.summary,
  controlKey:c.control_key,controlTitle:c.title,readiness:c.readiness,gaps:(c.gaps||[]).join(' | ')
 })));
 return {
  reportType:'AEGIS_GRC_AUDIT_READINESS_REPORT',generatedAt:r.generatedAt,organizationId:r.organizationId,scope:r.scope,
  assuranceBoundary:r.assuranceBoundary,frameworks,
  executiveSummary:{...r.summary,frameworksAssessed:frameworks.length,clausesMapped:clauses.length},
  controls,clauses,auditChecklist:r.auditChecklist||[],
  methodology:[
   'Scope controls are evaluated only from records stored for the selected organization and scope.',
   'Applicable controls require completed implementation, independent applicability approval, current independently validated evidence, a passing deterministic test, no unresolved linked issue, and at least one framework mapping.',
   'Not-applicable controls require a documented justification and independent approval.',
   'A readiness percentage measures completion of this internal evidence checklist; it is not a compliance percentage or certification score.'
  ],
  limitations:[
   'The report cannot prove that every applicable framework requirement has been loaded into the registry; framework inventory completeness requires authorized review.',
   'Automated tests and vulnerability observations are evidence inputs and do not replace auditor sampling or professional judgment.',
   'External certification, regulatory approval and formal audit opinions can only be issued by appropriately authorized independent parties.',
   'Risk acceptance, scope decisions and management sign-off remain accountable human decisions.'
  ]
 };
}
