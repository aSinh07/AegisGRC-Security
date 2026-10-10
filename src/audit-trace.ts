import pg from 'pg';
import { requireAssessmentAccess } from './grc-organizations.js';

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false }
});

export async function assessmentTrace(userId:string, assessmentId:string) {
  const access = await requireAssessmentAccess(userId, assessmentId);
  const evidence = (await pool.query(
    'SELECT id,source,sha256,created_at,byte_length,integrity_verified_at FROM evidence WHERE assessment_id=$1 ORDER BY created_at',
    [assessmentId]
  )).rows;
  const findings = (await pool.query(
    'SELECT id,severity,source,payload FROM findings WHERE assessment_id=$1 ORDER BY created_at',
    [assessmentId]
  )).rows;
  const layerCoverage = (await pool.query('SELECT layer,status,required,engines,evidence_count,failure_reasons,completed_at FROM assessment_layer_runs WHERE assessment_id=$1 ORDER BY layer',[assessmentId])).rows;
  const reviews = (await pool.query(
    'SELECT finding_id,decision,rationale,created_at FROM finding_reviews WHERE assessment_id=$1 ORDER BY created_at',
    [assessmentId]
  )).rows;
  const issues = (await pool.query(
    'SELECT id,issue_key,finding_id,status,priority,due_at FROM grc_issues WHERE assessment_id=$1 ORDER BY created_at',
    [assessmentId]
  )).rows;
  const risks = (await pool.query(
    'SELECT r.id,r.risk_key,r.inherent_score,r.inherent_rating,r.treatment,r.status,ir.issue_id FROM grc_enterprise_risks r JOIN grc_issue_risks ir ON ir.risk_id=r.id JOIN grc_issues i ON i.id=ir.issue_id WHERE i.assessment_id=$1 ORDER BY r.created_at',
    [assessmentId]
  )).rows;
  const capas = (await pool.query(
    'SELECT c.id,c.capa_key,c.issue_id,c.status,c.priority,c.due_at,c.retest_run_id,c.closed_at FROM grc_capa c JOIN grc_issues i ON i.id=c.issue_id WHERE i.assessment_id=$1 ORDER BY c.created_at',
    [assessmentId]
  )).rows;
  const capaEvidence = (await pool.query(
    'SELECT ce.capa_id,ce.evidence_version_id,ce.linked_at FROM grc_capa_evidence ce JOIN grc_capa c ON c.id=ce.capa_id JOIN grc_issues i ON i.id=c.issue_id WHERE i.assessment_id=$1 ORDER BY ce.linked_at',
    [assessmentId]
  )).rows;
  const controlAssurance = (await pool.query(`
    SELECT DISTINCT i.id issue_id,sc.id scope_control_id,c.control_key,c.title control_title,
      sc.applicability,sc.implementation,sc.approved_at applicability_approved_at,
      lr.id test_run_id,lr.result test_result,lr.rationale test_rationale,lr.executed_at test_executed_at,
      COALESCE(json_agg(DISTINCT jsonb_build_object('framework',fr.framework,'version',fr.framework_version,'requirementKey',fr.requirement_key,'title',fr.title,'mappingType',m.mapping_type))
        FILTER(WHERE fr.id IS NOT NULL),'[]'::json) framework_mappings
    FROM grc_issues i
    JOIN grc_scope_controls sc ON sc.id=i.scope_control_id
    JOIN grc_canonical_controls c ON c.id=sc.control_id
    LEFT JOIN grc_control_framework_mappings m ON m.control_id=c.id
    LEFT JOIN grc_framework_requirements fr ON fr.id=m.requirement_id
    LEFT JOIN LATERAL(
      SELECT tr.id,tr.result,tr.rationale,tr.executed_at FROM grc_control_test_definitions td
      JOIN grc_control_test_runs tr ON tr.test_definition_id=td.id
      WHERE td.scope_control_id=sc.id AND td.organization_id=sc.organization_id AND td.active=true
      ORDER BY tr.executed_at DESC LIMIT 1
    ) lr ON true
    WHERE i.assessment_id=$1
    GROUP BY i.id,sc.id,c.id,lr.id,lr.result,lr.rationale,lr.executed_at
    ORDER BY c.control_key`,[assessmentId])).rows;

  const chains = findings.map((row:any) => {
    const f = row.payload || {};
    const history = reviews.filter((x:any) => x.finding_id === row.id);
    const issue = issues.find((x:any) => x.finding_id === row.id) || null;
    return {
      findingId: row.id,
      title: f.title,
      severity: row.severity,
      source: row.source,
      evidenceHash: f.evidenceHash || null,
      status: f.status || 'UNREVIEWED',
      reviews: history,
      issue,
      controlAssurance: issue ? controlAssurance.find((x:any)=>x.issue_id===issue.id)||null : null,
      risks: issue ? risks.filter((x:any) => x.issue_id === issue.id) : [],
      capa: issue ? capas.filter((x:any) => x.issue_id === issue.id).map((x:any) => ({
        ...x,
        evidence: capaEvidence.filter((e:any) => e.capa_id === x.id)
      })) : []
    };
  });

  return {
    assessmentId,
    organizationId: access.organization_id,
    generatedAt: new Date().toISOString(),
    assuranceBoundary: 'Traceability records provenance and workflow state. It is not certification or proof of control effectiveness.',
    summary: {
      evidence: evidence.length,
      findings: findings.length,
      reviewed: chains.filter((x:any) => x.reviews.length > 0).length,
      confirmed: chains.filter((x:any) => x.reviews.length > 0 && x.reviews[x.reviews.length-1].decision === 'CONFIRMED').length,
      issues: issues.length,
      risks: risks.length,
      capa: capas.length,
      closedCapa: capas.filter((x:any) => x.status === 'CLOSED').length,
      controlsWithDeterministicTests: controlAssurance.filter((x:any)=>['PASS','FAIL'].includes(x.test_result)).length,
      controlsNotTested: controlAssurance.filter((x:any)=>!['PASS','FAIL'].includes(x.test_result)).length
    },
    dataSecurityAssurance:(()=>{const x=layerCoverage.find((r:any)=>r.layer==='DATA_SECURITY');return x?{status:x.status,required:x.required,engines:x.engines||[],evidenceCount:Number(x.evidence_count||0),failureReasons:x.failure_reasons||[],completedAt:x.completed_at}:{status:'NOT_STARTED',required:true,engines:['PROWLER'],evidenceCount:0,failureReasons:['Data-security coverage has not been reconciled'],completedAt:null}})(),
    identityAssurance:(()=>{const x=layerCoverage.find((r:any)=>r.layer==='IDENTITY');return x?{status:x.status,required:x.required,engines:x.engines||[],evidenceCount:Number(x.evidence_count||0),failureReasons:x.failure_reasons||[],completedAt:x.completed_at}:{status:'NOT_STARTED',required:true,engines:['PROWLER','WAZUH'],evidenceCount:0,failureReasons:['Identity coverage has not been reconciled'],completedAt:null}})(),
    cloudAssurance:(()=>{const x=layerCoverage.find((r:any)=>r.layer==='CLOUD');return x?{status:x.status,required:x.required,engines:x.engines||[],evidenceCount:Number(x.evidence_count||0),failureReasons:x.failure_reasons||[],completedAt:x.completed_at}:{status:'NOT_STARTED',required:true,engines:['PROWLER'],evidenceCount:0,failureReasons:['Cloud coverage has not been reconciled'],completedAt:null}})(),
    containerAssurance:(()=>{const x=layerCoverage.find((r:any)=>r.layer==='CONTAINER');return x?{status:x.status,required:x.required,engines:x.engines||[],evidenceCount:Number(x.evidence_count||0),failureReasons:x.failure_reasons||[],completedAt:x.completed_at}:{status:'NOT_STARTED',required:true,engines:['TRIVY'],evidenceCount:0,failureReasons:['Container coverage has not been reconciled'],completedAt:null}})(),
    dependencyAssurance:(()=>{const x=layerCoverage.find((r:any)=>r.layer==='DEPENDENCIES');return x?{status:x.status,required:x.required,engines:x.engines||[],evidenceCount:Number(x.evidence_count||0),failureReasons:x.failure_reasons||[],completedAt:x.completed_at}:{status:'NOT_STARTED',required:true,engines:['TRIVY'],evidenceCount:0,failureReasons:['Dependency coverage has not been reconciled'],completedAt:null}})(),
    sourceCodeAssurance:(()=>{const x=layerCoverage.find((r:any)=>r.layer==='SOURCE_CODE');return x?{status:x.status,required:x.required,engines:x.engines||[],evidenceCount:Number(x.evidence_count||0),failureReasons:x.failure_reasons||[],completedAt:x.completed_at}:{status:'NOT_STARTED',required:true,engines:['SEMGREP'],evidenceCount:0,failureReasons:['Source-code coverage has not been reconciled'],completedAt:null}})(),
    apiAssurance:(()=>{const x=layerCoverage.find((r:any)=>r.layer==='API');return x?{status:x.status,required:x.required,engines:x.engines||[],evidenceCount:Number(x.evidence_count||0),failureReasons:x.failure_reasons||[],completedAt:x.completed_at}:{status:'NOT_STARTED',required:true,engines:['ZAP','NUCLEI'],evidenceCount:0,failureReasons:['API coverage has not been reconciled'],completedAt:null}})(),
    webAssurance:(()=>{const x=layerCoverage.find((r:any)=>r.layer==='WEB');return x?{status:x.status,required:x.required,engines:x.engines||[],evidenceCount:Number(x.evidence_count||0),failureReasons:x.failure_reasons||[],completedAt:x.completed_at}:{status:'NOT_STARTED',required:true,engines:['ZAP','NUCLEI'],evidenceCount:0,failureReasons:['Web coverage has not been reconciled'],completedAt:null}})(),
    endpointAssurance:(()=>{const x=layerCoverage.find((r:any)=>r.layer==='ENDPOINT');return x?{status:x.status,required:x.required,engines:x.engines||[],evidenceCount:Number(x.evidence_count||0),failureReasons:x.failure_reasons||[],completedAt:x.completed_at}:{status:'NOT_STARTED',required:true,engines:['WAZUH'],evidenceCount:0,failureReasons:['Endpoint coverage has not been reconciled'],completedAt:null}})(),
    infrastructureAssurance:(()=>{const x=layerCoverage.find((r:any)=>r.layer==='INFRASTRUCTURE');return x?{status:x.status,required:x.required,engines:x.engines||[],evidenceCount:Number(x.evidence_count||0),failureReasons:x.failure_reasons||[],completedAt:x.completed_at}: {status:'NOT_STARTED',required:true,engines:['NMAP','OPENVAS'],evidenceCount:0,failureReasons:['Infrastructure coverage has not been reconciled'],completedAt:null}})(),
    evidence,
    chains
  };
}

export function auditPackageModel(trace:any){
 const chains=Array.isArray(trace?.chains)?trace.chains:[];
 const generatedAt=trace?.generatedAt||new Date().toISOString();
 const assessmentId=trace?.assessmentId||'';
 return {
  documentControl:{documentId:'AEGIS-AUDIT-'+assessmentId,version:'1.0',classification:'CONFIDENTIAL',generatedAt,assessmentId,status:'UNAPPROVED_SNAPSHOT'},
  reportType:'AEGIS_GRC_AUDIT_PACKAGE',
  generatedAt,
  assessmentId,
  organizationId:trace?.organizationId||'',
  assuranceBoundary:trace?.assuranceBoundary||'Traceability is not certification.',
  executiveSummary:{...trace?.summary,
   openIssues:chains.filter((x:any)=>x.issue&&x.issue.status!=='CLOSED').length,
   overdueIssues:chains.filter((x:any)=>x.issue&&x.issue.status!=='CLOSED'&&x.issue.due_at&&new Date(x.issue.due_at)<new Date()).length
  },
  dataSecurityAssurance:trace?.dataSecurityAssurance||{status:'NOT_STARTED',required:true,engines:['PROWLER'],evidenceCount:0,failureReasons:['Data-security coverage unavailable']},
  identityAssurance:trace?.identityAssurance||{status:'NOT_STARTED',required:true,engines:['PROWLER','WAZUH'],evidenceCount:0,failureReasons:['Identity coverage unavailable']},
  cloudAssurance:trace?.cloudAssurance||{status:'NOT_STARTED',required:true,engines:['PROWLER'],evidenceCount:0,failureReasons:['Cloud coverage unavailable']},
  containerAssurance:trace?.containerAssurance||{status:'NOT_STARTED',required:true,engines:['TRIVY'],evidenceCount:0,failureReasons:['Container coverage unavailable']},
  dependencyAssurance:trace?.dependencyAssurance||{status:'NOT_STARTED',required:true,engines:['TRIVY'],evidenceCount:0,failureReasons:['Dependency coverage unavailable']},
  sourceCodeAssurance:trace?.sourceCodeAssurance||{status:'NOT_STARTED',required:true,engines:['SEMGREP'],evidenceCount:0,failureReasons:['Source-code coverage unavailable']},
  apiAssurance:trace?.apiAssurance||{status:'NOT_STARTED',required:true,engines:['ZAP','NUCLEI'],evidenceCount:0,failureReasons:['API coverage unavailable']},
  webAssurance:trace?.webAssurance||{status:'NOT_STARTED',required:true,engines:['ZAP','NUCLEI'],evidenceCount:0,failureReasons:['Web coverage unavailable']},
  endpointAssurance:trace?.endpointAssurance||{status:'NOT_STARTED',required:true,engines:['WAZUH'],evidenceCount:0,failureReasons:['Endpoint coverage unavailable']},
  infrastructureAssurance:trace?.infrastructureAssurance||{status:'NOT_STARTED',required:true,engines:['NMAP','OPENVAS'],evidenceCount:0,failureReasons:['Infrastructure coverage unavailable']},
  evidenceRegister:(trace?.evidence||[]).map((e:any)=>({...e,hash_recorded_at:e.integrity_verified_at||e.created_at,integrity_status:'HASH_RECORDED_AT_INGEST'})),
  findingLifecycle:chains.map((x:any)=>({
   findingId:x.findingId,title:x.title,severity:x.severity,source:x.source,evidenceHash:x.evidenceHash,
   findingStatus:x.status,analystDecisions:x.reviews||[],issue:x.issue||null,controlAssurance:x.controlAssurance||null,risks:x.risks||[],capa:x.capa||[]
  })),
  limitations:[
   'Scanner or imported observations require analyst validation before escalation.',
   'Framework mappings are CONTROL_RELEVANCE cross-references only. They do not establish a control failure, pass, conformity or certification.',
   'Control effectiveness is reported only from the latest separately executed deterministic control test. Missing tests remain NOT_TESTED.',
   'Risk treatment and acceptance remain accountable human decisions.',
   'Closure requires the applicable remediation, evidence and retest workflow.',
   'A stored SHA-256 records evidence identity at ingest. Unless retained bytes are re-read and compared later, it is not a subsequent integrity re-verification.'
  ]
 };
}
