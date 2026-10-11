import pg from 'pg';import {requireOrgPermission} from './grc-organizations.js';import {organizationAuditReadiness} from './grc-readiness.js';import {thirdPartyDashboard} from './third-party-risk.js';import {architectureAssurance} from './architecture-assurance.js';import {continuousComplianceDashboard} from './continuous-compliance.js';import {resilienceDashboard} from './business-continuity.js';
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
export async function enterpriseAcceptance(user:string,org:string,scopeId:string){
 await requireOrgPermission(user,org,'read');
 const [readiness,vendors,architecture,continuous,resilience]=await Promise.all([organizationAuditReadiness(user,org,scopeId),thirdPartyDashboard(user,org),architectureAssurance(user,org,scopeId),continuousComplianceDashboard(user,org,scopeId),resilienceDashboard(user,org,scopeId)]);
 const q=async(sql:string,args:any[]=[org])=>Number((await pool.query(sql,args)).rows[0]?.c||0);
 const [openCriticalRisks,openP0Issues,overdueCapa,pendingEvidence,failedTests,activeAssessments,assessmentCoverageRows]=await Promise.all([
  q("SELECT count(*) c FROM grc_enterprise_risks WHERE organization_id=$1 AND status<>'CLOSED' AND inherent_rating='CRITICAL'"),
  q("SELECT count(*) c FROM grc_issues WHERE organization_id=$1 AND status<>'CLOSED' AND priority='P0'"),
  q("SELECT count(*) c FROM grc_capa WHERE organization_id=$1 AND status<>'CLOSED' AND due_at<now()"),
  q("SELECT count(*) c FROM grc_evidence_requests WHERE organization_id=$1 AND status NOT IN ('VALID')"),
  q("SELECT count(*) c FROM grc_control_test_runs r JOIN grc_control_test_definitions d ON d.id=r.test_definition_id WHERE r.organization_id=$1 AND r.id=(SELECT r2.id FROM grc_control_test_runs r2 WHERE r2.test_definition_id=d.id ORDER BY r2.executed_at DESC LIMIT 1) AND r.result IN ('FAIL','ERROR','NOT_TESTED')"),
  q("SELECT count(*) c FROM assessments WHERE organization_id=$1"),
  pool.query("SELECT status,count(*)::int c FROM assessment_layer_coverage lc JOIN assessments a ON a.id=lc.assessment_id WHERE a.organization_id=$1 GROUP BY status",[org]).catch(()=>({rows:[]}))
 ]);
 const checks=[
  {id:'CONTROL_READINESS',pass:readiness.summary.total>0&&readiness.summary.actionRequired===0,detail:readiness.summary},
  {id:'CRITICAL_RISK',pass:openCriticalRisks===0,detail:{openCriticalRisks}},
  {id:'P0_ISSUES',pass:openP0Issues===0,detail:{openP0Issues}},
  {id:'CAPA_SLA',pass:overdueCapa===0,detail:{overdueCapa}},
  {id:'EVIDENCE_WORKFLOW',pass:pendingEvidence===0,detail:{pendingEvidence}},
  {id:'CONTROL_TESTS',pass:failedTests===0,detail:{failedTests}},
  {id:'THIRD_PARTY_RISK',pass:(vendors.summary.criticalIncidents||0)===0&&(vendors.summary.dueReview||0)===0,detail:vendors.summary},
  {id:'ARCHITECTURE_FIREWALL',pass:(architecture.summary.gaps||0)===0,detail:architecture.summary},
  {id:'CONTINUOUS_COMPLIANCE',pass:(continuous.summary.overdueObligations||0)===0&&(continuous.summary.expiredExceptions||0)===0,detail:continuous.summary},
  {id:'BUSINESS_CONTINUITY',pass:resilience.summary.services>0&&resilience.summary.gaps===0,detail:resilience.summary},
  {id:'ASSESSMENT_INVENTORY',pass:activeAssessments>0,detail:{assessments:activeAssessments,layerStatuses:(assessmentCoverageRows as any).rows}}
 ];
 const passed=checks.filter(x=>x.pass).length;
 return {organizationId:org,scopeId,generatedAt:new Date().toISOString(),status:passed===checks.length?'ACCEPTANCE_READY':'ACTION_REQUIRED',score:Math.round(passed/checks.length*100),passed,total:checks.length,checks,
  boundary:'This acceptance gate measures completion of configured AegisGRC enterprise workflows. It is not a certification, legal opinion, penetration-test guarantee, or proof that no vulnerability exists.'};
}
