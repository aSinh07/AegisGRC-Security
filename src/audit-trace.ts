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
      issue
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
      issues: issues.length
    },
    evidence,
    chains
  };
}
