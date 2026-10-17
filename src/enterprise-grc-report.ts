/**
 * Enterprise GRC consultant/auditor report composition.
 * Pure model logic: it never invents evidence or converts scanner observations into audit conclusions.
 */
export type ConsultantOpinion='AUDIT_READY'|'CONDITIONAL'|'SIGNIFICANT_GAPS'|'INSUFFICIENT_EVIDENCE';

const n=(v:any)=>Number(v||0);
const s=(v:any)=>v===null||v===undefined?'':String(v);
const rows=(v:any)=>Array.isArray(v)?v:[];

export function buildEnterpriseGrcReport(input:{
 organization:any;scope:any;readiness:any;soa:any;risks:any[];issues:any[];capa:any[];
 dashboard?:any;sla?:any;assessmentTraces?:any[];securityHandoffs?:any[];automationRuns?:any[];incidents?:any[];identitySignals?:any[];thirdParty?:any;architecture?:any;continuousCompliance?:any;resilience?:any;policy?:any;audit?:any;auditEvidenceReadiness?:any;governancePerformance?:any;selectedFramework?:string;generatedAt?:string;
}){
 const generatedAt=input.generatedAt||new Date().toISOString();
 const selectedFramework=s(input.selectedFramework).trim().toUpperCase();
 const allControls=rows(input.readiness?.controls);
 const frameworkMatchedControls=selectedFramework?allControls.filter((c:any)=>rows(c.mappings).some((m:any)=>s(m.framework).trim().toUpperCase()===selectedFramework)):allControls;
 // Never erase persisted scope records merely because framework mapping metadata is incomplete.
 // The selected framework narrows mapped controls when mappings exist; otherwise the report
 // preserves the selected scope's real controls/SoA and marks the mapping gap explicitly.
 const frameworkFilterFallback=Boolean(selectedFramework&&allControls.length&&frameworkMatchedControls.length===0);
 const controls=frameworkFilterFallback?allControls:frameworkMatchedControls;
 const controlKeys=new Set(controls.map((c:any)=>s(c.control_key||c.controlKey)));
 const allSoaControls=rows(input.soa?.controls);
 const matchedSoaControls=allSoaControls.filter((c:any)=>!selectedFramework||controlKeys.has(s(c.control_key||c.controlKey)));
 const soaControls=frameworkFilterFallback?allSoaControls:matchedSoaControls;
 const risks=rows(input.risks),issues=rows(input.issues),capa=rows(input.capa),traces=rows(input.assessmentTraces),securityHandoffs=rows(input.securityHandoffs),automationRuns=rows(input.automationRuns),incidents=rows(input.incidents),identitySignals=rows(input.identitySignals);
 const applicable=controls.filter((x:any)=>x.applicability==='APPLICABLE');
 const ready=controls.filter((x:any)=>x.readiness==='EVIDENCE_READY');
 const actionRequired=controls.filter((x:any)=>x.readiness!=='EVIDENCE_READY');
 const openIssues=issues.filter((x:any)=>x.status!=='CLOSED');
 const overdueIssues=openIssues.filter((x:any)=>x.due_at&&new Date(x.due_at).getTime()<Date.now());
 const openRisks=risks.filter((x:any)=>x.status!=='CLOSED');
 const highRisks=openRisks.filter((x:any)=>['HIGH','CRITICAL'].includes(String(x.inherent_rating||'').toUpperCase()));
 const acceptedRisks=openRisks.filter((x:any)=>x.status==='ACCEPTED');
 const expiredAcceptance=acceptedRisks.filter((x:any)=>!x.acceptance_expires_at||new Date(x.acceptance_expires_at).getTime()<=Date.now());
 const openCapa=capa.filter((x:any)=>x.status!=='CLOSED');
 const overdueCapa=openCapa.filter((x:any)=>x.due_at&&new Date(x.due_at).getTime()<Date.now());
 const frameworkSet=new Set<string>();
 for(const c of controls)for(const m of rows(c.mappings))if(m.framework&&(!selectedFramework||s(m.framework).trim().toUpperCase()===selectedFramework))frameworkSet.add((s(m.framework)+' '+s(m.version||'').trim()).trim());
 const total=controls.length,coverage=total?Math.round(ready.length*100/total):0;
 const acceptedSecurityHandoffs=securityHandoffs.filter((x:any)=>x.status==='EVIDENCE_ACCEPTED');
 const pendingSecurityHandoffs=securityHandoffs.filter((x:any)=>x.status==='REVIEW_REQUIRED');
 const failedAutomationRuns=automationRuns.filter((x:any)=>x.status==='FAILED');
 const openIncidents=incidents.filter((x:any)=>x.phase!=='CLOSED');
 const criticalOpenIncidents=openIncidents.filter((x:any)=>x.severity==='CRITICAL');
 const identityReviewRequired=identitySignals.filter((x:any)=>x.status==='REVIEW_REQUIRED');
 const enterpriseGaps=Number(input.architecture?.summary?.gaps||0)+Number(input.resilience?.summary?.gaps||0)+Number(input.continuousCompliance?.summary?.overdueObligations||0)+Number(input.continuousCompliance?.summary?.expiredExceptions||0)+Number(input.policy?.summary?.overdueReview||0)+Number(input.policy?.summary?.unmapped||0)+Number(input.audit?.summary?.unreviewed||0)+Number(input.thirdParty?.summary?.criticalIncidents||0)+Number(input.thirdParty?.summary?.dueReview||0);
 let opinion:ConsultantOpinion='AUDIT_READY';
 if(!total||!soaControls.length)opinion='INSUFFICIENT_EVIDENCE';
 else if(highRisks.length||overdueIssues.length||overdueCapa.length||enterpriseGaps>0||criticalOpenIncidents.length||actionRequired.length>Math.max(3,Math.ceil(total*.2)))opinion='SIGNIFICANT_GAPS';
 else if(actionRequired.length||openIssues.length||openCapa.length||expiredAcceptance.length||openIncidents.length||identityReviewRequired.length||failedAutomationRuns.length||pendingSecurityHandoffs.length)opinion='CONDITIONAL';
 const sourceRegister=traces.flatMap((t:any)=>rows(t.evidenceProvenance||t.evidence).map((e:any)=>({
  assessmentId:t.assessmentId,id:e.id,source:e.source,sha256:e.sha256,createdAt:e.createdAt||e.created_at,
  integrityVerifiedAt:e.integrityVerifiedAt||e.integrity_verified_at,trust:e.trust||e.payload?.metadata?.evidenceTrust||'UNVERIFIED'
 })));
 const technicalCoverage=traces.map((t:any)=>({
  assessmentId:t.assessmentId,
  infrastructure:t.infrastructureAssurance?.status||'NOT_STARTED',web:t.webAssurance?.status||'NOT_STARTED',
  api:t.apiAssurance?.status||'NOT_STARTED',cloud:t.cloudAssurance?.status||'NOT_STARTED',
  endpoint:t.endpointAssurance?.status||'NOT_STARTED',identity:t.identityAssurance?.status||'NOT_STARTED',
  dataSecurity:t.dataSecurityAssurance?.status||'NOT_STARTED',privacy:t.privacyAssurance?.status||'NOT_STARTED',
  sourceCode:t.sourceCodeAssurance?.status||'NOT_STARTED',dependencies:t.dependencyAssurance?.status||'NOT_STARTED',
  container:t.containerAssurance?.status||'NOT_STARTED',attackSurface:t.attackSurfaceAssurance?.status||'NOT_STARTED',
  breachTelemetry:t.breachTelemetryAssurance?.status||'NOT_STARTED'
 }));
 return {
  documentControl:{
   documentId:'AEGIS-ENTERPRISE-GRC-'+s(input.scope?.id||'SCOPE').toUpperCase(),
   title:'Enterprise Governance, Risk & Compliance Assurance Report',version:'1.0',
   classification:'CONFIDENTIAL',status:'INTERNAL_ASSESSMENT',generatedAt
  },
  organization:{id:input.organization?.id,name:input.organization?.name,industry:input.organization?.industry},
  scope:input.scope,
  frameworks:[...frameworkSet].sort(),
  reportContext:{selectedFramework:selectedFramework||null,scopeMode:selectedFramework?'FRAMEWORK_FILTERED':'MULTI_FRAMEWORK',frameworkFilterFallback,frameworkMappingWarning:frameworkFilterFallback?'No controls in this populated scope are mapped to the selected framework. Persisted scope controls and SoA decisions are retained in this report so entered governance data is not silently hidden. Add governed framework mappings to obtain framework-specific filtering.':null},
  managementOpinion:{
   conclusion:opinion,
   statement:opinion==='AUDIT_READY'
    ?'The recorded scope satisfies the platform evidence-readiness criteria. Independent auditors must still perform professional sampling and issue any formal opinion.'
    :opinion==='INSUFFICIENT_EVIDENCE'
     ?'The available scope, applicability, evidence or control inventory is insufficient for a supportable assurance conclusion.'
     :'Material actions remain before this scope should be represented as audit-ready.',
   evidenceReadinessPercent:coverage
  },
  executiveSummary:{
   controlsTotal:total,controlsApplicable:applicable.length,controlsEvidenceReady:ready.length,controlsActionRequired:actionRequired.length,
   openIssues:openIssues.length,overdueIssues:overdueIssues.length,openRisks:openRisks.length,highCriticalRisks:highRisks.length,
   acceptedRisks:acceptedRisks.length,expiredRiskAcceptances:expiredAcceptance.length,openCapa:openCapa.length,overdueCapa:overdueCapa.length,
   evidenceSources:sourceRegister.length,enterpriseWorkflowGaps:enterpriseGaps,acceptedSecurityEvidence:acceptedSecurityHandoffs.length,pendingSecurityEvidenceReview:pendingSecurityHandoffs.length,recentAutomationFailures:failedAutomationRuns.length,openSecurityIncidents:openIncidents.length,criticalOpenSecurityIncidents:criticalOpenIncidents.length,identitySignalsReviewRequired:identityReviewRequired.length
  },
  methodology:[
   'Assess scope and applicability before control effectiveness.',
   'Require independently approved applicability decisions, current validated evidence and the latest deterministic control-test result.',
   'Treat scanner, firewall, endpoint, cloud, source-code and imported technical reports as evidence sources; they do not independently establish conformity.',
   'Trace confirmed findings through issue, risk, treatment/CAPA, retest and independent closure.',
   'Keep NOT_TESTED, missing, stale and expired evidence distinct from PASS.',
   'Preserve separation of duties for evidence validation, risk acceptance and remediation closure.'
  ],
  statementOfApplicability:soaControls,
  controlAssurance:controls.map((c:any)=>({
   controlKey:c.control_key,title:c.title,domain:c.domain,applicability:c.applicability,
   justification:c.applicability_justification,implementation:c.implementation,approvedAt:c.approved_at,
   validEvidence:n(c.valid_evidence),passedLatestTests:n(c.passed_tests),openIssues:n(c.open_issues),
   readiness:c.readiness,gaps:rows(c.gaps),frameworkMappings:[...new Map(rows(c.mappings).filter((m:any)=>!selectedFramework||s(m.framework).trim().toUpperCase()===selectedFramework).map((m:any)=>[s(m.framework).trim().toUpperCase()+'|'+s(m.requirementKey||m.requirement_key).trim().toUpperCase(),m])).values()]
  })),
  riskRegister:risks,
  issueRegister:issues,
  correctivePreventiveActions:capa,
  evidenceRegister:sourceRegister,
  technicalAssuranceCoverage:technicalCoverage,
  securityReportEvidence:{accepted:acceptedSecurityHandoffs,pendingReview:pendingSecurityHandoffs,total:securityHandoffs.length,assuranceNote:'Accepted technical reports are governed evidence inputs, not automatic proof of control conformity.'},
  automationAssurance:{recentRuns:automationRuns,failedRuns:failedAutomationRuns,assuranceNote:'Automation execution health is disclosed because failed or missing automation cannot be treated as successful control testing.'},
  incidentAndIdentityAssurance:{openIncidents,criticalOpenIncidents,identitySignalsReviewRequired:identityReviewRequired,assuranceNote:'Incident and identity signals are operational risk indicators requiring investigation; they are not automatic declarations of breach, compromise, or control failure.'},
  thirdPartyRisk:input.thirdParty||{vendors:[],incidents:[],summary:{}},
  architectureAssurance:input.architecture||{components:[],edges:[],firewallReviews:[],gaps:[],summary:{}},
  continuousCompliance:input.continuousCompliance||{obligations:[],exceptions:[],summary:{}},
  operationalResilience:input.resilience||{services:[],latestExercises:[],gaps:[],summary:{}},
  policyGovernance:input.policy||{policies:[],summary:{}},
  governancePerformance:input.governancePerformance||{appetites:[],metrics:[],reviews:[],summary:{}},
  auditManagement:input.audit||{audits:[],summary:{}},
  iso42001AuditEvidenceReadiness:input.auditEvidenceReadiness||{requests:[],summary:{total:0,evidenced:0,actionRequired:0,percent:0}},
  sla:input.sla||null,
  operationalMetrics:input.dashboard?.metrics||input.dashboard||null,
  priorityActions:[
   ...actionRequired.slice(0,25).map((x:any)=>({type:'CONTROL',key:x.control_key,priority:'HIGH',action:rows(x.gaps).join(' ')})),
   ...highRisks.slice(0,25).map((x:any)=>({type:'RISK',key:x.risk_key,priority:x.inherent_rating,action:'Complete accountable treatment, residual-risk review and approval.'})),
   ...overdueIssues.slice(0,25).map((x:any)=>({type:'ISSUE',key:x.issue_key,priority:x.priority||'HIGH',action:'Overdue issue requires owner escalation and documented disposition.'})),
   ...overdueCapa.slice(0,25).map((x:any)=>({type:'CAPA',key:x.capa_key,priority:x.priority||'HIGH',action:'Overdue corrective/preventive action requires escalation, evidence and retest.'}))
  ],
  assuranceBoundary:[
   'This is an internal GRC assurance package, not an ISO certificate, accreditation, legal opinion or external audit opinion.',
   'Framework requirement wording must be sourced from appropriately licensed/authoritative material; mappings in this report are traceability records.',
   'A vulnerability or firewall observation is technical evidence. Control effectiveness requires scoped evidence, testing and accountable review.',
   'No absence-of-findings condition is converted to PASS. Untested controls remain NOT_TESTED/ACTION_REQUIRED.',
   'Risk acceptance and management-system conclusions remain accountable human decisions.'
  ]
 };
}
