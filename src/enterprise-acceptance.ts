import {pool} from './db-pool.js';
import pg from 'pg';import {requireOrgPermission} from './grc-organizations.js';import {organizationAuditReadiness} from './grc-readiness.js';import {thirdPartyDashboard} from './third-party-risk.js';import {architectureAssurance} from './architecture-assurance.js';import {continuousComplianceDashboard} from './continuous-compliance.js';import {resilienceDashboard} from './business-continuity.js';import {policyDashboard} from './policy-governance.js';import {auditDashboard} from './audit-management.js';import {iso42001AuditEvidenceReadiness} from './audit-playbook.js';

export async function enterpriseAcceptance(user:string,org:string,scopeId:string){
 await requireOrgPermission(user,org,'read');
 const [readiness,vendors,architecture,continuous,resilience,policies,audits,auditEvidence]=await Promise.all([organizationAuditReadiness(user,org,scopeId),thirdPartyDashboard(user,org),architectureAssurance(user,org,scopeId),continuousComplianceDashboard(user,org,scopeId),resilienceDashboard(user,org,scopeId),policyDashboard(user,org,scopeId),auditDashboard(user,org,scopeId),iso42001AuditEvidenceReadiness(user,org,scopeId)]);
 const q=async(sql:string,args:any[]=[org])=>Number((await pool.query(sql,args)).rows[0]?.c||0);
 const [openCriticalRisks,openP0Issues,overdueCapa,pendingEvidence,failedTests,activeAssessments,pendingSecurityEvidence,pendingSecurityIntelligence,duplicateIssueRiskLinks,duplicateIssueCapas,assessmentCoverageRows]=await Promise.all([
  q("SELECT count(*) c FROM grc_enterprise_risks WHERE organization_id=$1 AND status<>'CLOSED' AND inherent_rating='CRITICAL'"),
  q("SELECT count(*) c FROM grc_issues WHERE organization_id=$1 AND status<>'CLOSED' AND priority='P0'"),
  q("SELECT count(*) c FROM grc_capa WHERE organization_id=$1 AND status<>'CLOSED' AND due_at<now()"),
  q("SELECT count(*) c FROM grc_evidence_requests WHERE organization_id=$1 AND status NOT IN ('VALID')"),
  q("SELECT count(*) c FROM grc_control_test_runs r JOIN grc_control_test_definitions d ON d.id=r.test_definition_id WHERE r.organization_id=$1 AND r.id=(SELECT r2.id FROM grc_control_test_runs r2 WHERE r2.test_definition_id=d.id ORDER BY r2.executed_at DESC LIMIT 1) AND r.result IN ('FAIL','ERROR','NOT_TESTED')"),
  q("SELECT count(*) c FROM assessments WHERE organization_id=$1"),
  q("SELECT count(*) c FROM grc_security_report_handoffs WHERE organization_id=$1 AND status='REVIEW_REQUIRED'"),
  q("SELECT count(*) c FROM grc_security_finding_proposals WHERE organization_id=$1 AND status='PROPOSED'"),
  q("SELECT count(*) c FROM (SELECT ir.issue_id FROM grc_issue_risks ir JOIN grc_issues i ON i.id=ir.issue_id LEFT JOIN grc_remediation_reconciliations rr ON rr.issue_id=i.id AND rr.organization_id=i.organization_id WHERE i.organization_id=$1 AND rr.id IS NULL GROUP BY ir.issue_id HAVING count(*)>1) d"),
  q("SELECT count(*) c FROM (SELECT c.issue_id FROM grc_capa c LEFT JOIN grc_remediation_reconciliations rr ON rr.issue_id=c.issue_id AND rr.organization_id=c.organization_id WHERE c.organization_id=$1 AND rr.id IS NULL GROUP BY c.issue_id HAVING count(*)>1) d"),
  pool.query("SELECT lr.status,count(*)::int c FROM assessment_layer_runs lr JOIN assessments a ON a.id=lr.assessment_id WHERE a.organization_id=$1 GROUP BY lr.status",[org])
 ]);
 const checks=[
  {id:'CONTROL_READINESS',pass:readiness.summary.total>0&&readiness.summary.actionRequired===0,detail:readiness.summary},
  {id:'CRITICAL_RISK',pass:openCriticalRisks===0,detail:{openCriticalRisks}},
  {id:'P0_ISSUES',pass:openP0Issues===0,detail:{openP0Issues}},
  {id:'CAPA_SLA',pass:overdueCapa===0,detail:{overdueCapa}},
  {id:'EVIDENCE_WORKFLOW',pass:pendingEvidence===0,detail:{pendingEvidence}},
  {id:'CONTROL_TESTS',pass:failedTests===0,detail:{failedTests}},
  {id:'SECURITY_EVIDENCE_GOVERNANCE',pass:pendingSecurityEvidence===0,detail:{pendingSecurityEvidence}},
  {id:'SECURITY_INTELLIGENCE_GOVERNANCE',pass:pendingSecurityIntelligence===0,detail:{pendingSecurityIntelligence}},
  {id:'REMEDIATION_DATA_INTEGRITY',pass:duplicateIssueRiskLinks===0&&duplicateIssueCapas===0,detail:{duplicateIssueRiskLinks,duplicateIssueCapas,action:duplicateIssueRiskLinks||duplicateIssueCapas?'Reconcile historical duplicate remediation records through the governed reconciliation workflow; Aegis preserves governance history.':'NONE'}},
  {id:'THIRD_PARTY_RISK',pass:(vendors.summary.criticalIncidents||0)===0&&(vendors.summary.dueReview||0)===0,detail:vendors.summary},
  {id:'ARCHITECTURE_FIREWALL',pass:(architecture.summary.gaps||0)===0,detail:architecture.summary},
  {id:'CONTINUOUS_COMPLIANCE',pass:(continuous.summary.overdueObligations||0)===0&&(continuous.summary.expiredExceptions||0)===0,detail:continuous.summary},
  {id:'BUSINESS_CONTINUITY',pass:resilience.summary.services>0&&resilience.summary.gaps===0,detail:resilience.summary},
  {id:'POLICY_GOVERNANCE',pass:policies.summary.approved>0&&policies.summary.overdueReview===0&&policies.summary.unmapped===0,detail:policies.summary},
  {id:'AUDIT_ASSURANCE',pass:audits.summary.complete>0&&audits.summary.unreviewed===0&&audits.summary.active===0,detail:audits.summary},
  {id:'ASSESSMENT_INVENTORY',pass:activeAssessments>0&&(assessmentCoverageRows as any).rows.length>0&&!(assessmentCoverageRows as any).rows.some((x:any)=>['NOT_STARTED','RUNNING','PARTIAL','FAILED'].includes(x.status)),detail:{assessments:activeAssessments,layerStatuses:(assessmentCoverageRows as any).rows}}
 ];
 const passed=checks.filter(x=>x.pass).length;
 return {organizationId:org,scopeId,generatedAt:new Date().toISOString(),status:passed===checks.length?'ACCEPTANCE_READY':'ACTION_REQUIRED',score:Math.round(passed/checks.length*100),passed,total:checks.length,checks,iso42001AuditEvidenceReadiness:auditEvidence.summary,
  boundary:'This acceptance gate measures completion of configured AegisGRC enterprise workflows. It is not a certification, legal opinion, penetration-test guarantee, or proof that no vulnerability exists.'};
}
