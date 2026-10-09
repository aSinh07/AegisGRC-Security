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
      closedCapa: capas.filter((x:any) => x.status === 'CLOSED').length
    },
    evidence,
    chains
  };
}

export function auditPackageModel(trace:any){
 const chains=Array.isArray(trace?.chains)?trace.chains:[];
 return {
  reportType:'AEGIS_GRC_AUDIT_PACKAGE',
  generatedAt:trace?.generatedAt||new Date().toISOString(),
  assessmentId:trace?.assessmentId||'',
  organizationId:trace?.organizationId||'',
  assuranceBoundary:trace?.assuranceBoundary||'Traceability is not certification.',
  executiveSummary:{...trace?.summary,
   openIssues:chains.filter((x:any)=>x.issue&&x.issue.status!=='CLOSED').length,
   overdueIssues:chains.filter((x:any)=>x.issue&&x.issue.status!=='CLOSED'&&x.issue.due_at&&new Date(x.issue.due_at)<new Date()).length
  },
  evidenceRegister:(trace?.evidence||[]).map((e:any)=>({...e,hash_recorded_at:e.integrity_verified_at||e.created_at,integrity_status:'HASH_RECORDED_AT_INGEST'})),
  findingLifecycle:chains.map((x:any)=>({
   findingId:x.findingId,title:x.title,severity:x.severity,source:x.source,evidenceHash:x.evidenceHash,
   findingStatus:x.status,analystDecisions:x.reviews||[],issue:x.issue||null,risks:x.risks||[],capa:x.capa||[]
  })),
  limitations:[
   'Scanner or imported observations require analyst validation before escalation.',
   'Framework mappings are cross-references and do not constitute certification.',
   'Risk treatment and acceptance remain accountable human decisions.',
   'Closure requires the applicable remediation, evidence and retest workflow.',
   'A stored SHA-256 records evidence identity at ingest. Unless retained bytes are re-read and compared later, it is not a subsequent integrity re-verification.'
  ]
 };
}
