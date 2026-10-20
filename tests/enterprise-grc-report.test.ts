import test from 'node:test';
import assert from 'node:assert/strict';
import {buildEnterpriseGrcReport} from '../src/enterprise-grc-report.js';

const complete={control_key:'AC-1',title:'Access control',domain:'ACCESS',applicability:'APPLICABLE',implementation:'IMPLEMENTED',approved_at:'2026-10-10',valid_evidence:1,passed_tests:1,open_issues:0,readiness:'EVIDENCE_READY',gaps:[],mappings:[{framework:'ISO27001',version:'2022',clause:'A.5.15'}]};

test('enterprise report produces supportable audit-ready conclusion only from complete records',()=>{
 const r=buildEnterpriseGrcReport({organization:{id:'o',name:'Acme'},scope:{id:'s',name:'Production'},readiness:{controls:[complete]},soa:{controls:[complete]},risks:[],issues:[],capa:[],assessmentTraces:[],generatedAt:'2026-10-12T00:00:00Z'});
 assert.equal(r.managementOpinion.conclusion,'AUDIT_READY');
 assert.equal(r.managementOpinion.evidenceReadinessPercent,100);
 assert.match(r.managementOpinion.statement,/Independent auditors/);
 assert.ok(r.assuranceBoundary.some((x:string)=>/not an ISO certificate/i.test(x)));
});

test('empty inventory is insufficient evidence rather than compliant',()=>{
 const r=buildEnterpriseGrcReport({organization:{id:'o',name:'Acme'},scope:{id:'s',name:'Production'},readiness:{controls:[]},soa:{controls:[]},risks:[],issues:[],capa:[],assessmentTraces:[]});
 assert.equal(r.managementOpinion.conclusion,'INSUFFICIENT_EVIDENCE');
 assert.equal(r.managementOpinion.evidenceReadinessPercent,0);
});

test('high risk and overdue remediation drive significant gaps',()=>{
 const r=buildEnterpriseGrcReport({organization:{id:'o',name:'Acme'},scope:{id:'s',name:'Production'},readiness:{controls:[complete]},soa:{controls:[complete]},
  risks:[{risk_key:'R-1',title:'Critical exposure',inherent_rating:'CRITICAL',status:'OPEN',treatment:'MITIGATE'}],
  issues:[],capa:[{capa_key:'C-1',status:'OPEN',due_at:'2020-01-01T00:00:00Z',priority:'P1'}],assessmentTraces:[]});
 assert.equal(r.managementOpinion.conclusion,'SIGNIFICANT_GAPS');
 assert.ok(r.priorityActions.some((x:any)=>x.type==='RISK'));
 assert.ok(r.priorityActions.some((x:any)=>x.type==='CAPA'));
});

test('technical scanner and firewall-style evidence remains evidence, not conformity',()=>{
 const r=buildEnterpriseGrcReport({organization:{id:'o',name:'Acme'},scope:{id:'s',name:'Production'},readiness:{controls:[complete]},soa:{controls:[complete]},risks:[],issues:[],capa:[],
  assessmentTraces:[{assessmentId:'a1',evidenceProvenance:[{id:'e1',source:'wazuh',sha256:'a'.repeat(64),trust:'VERIFIED'}],infrastructureAssurance:{status:'COMPLETE'},endpointAssurance:{status:'COMPLETE'}}]});
 assert.equal(r.evidenceRegister[0].source,'wazuh');
 assert.equal(r.technicalAssuranceCoverage[0].endpoint,'COMPLETE');
 assert.ok(r.assuranceBoundary.some((x:string)=>/firewall observation is technical evidence/i.test(x)));
});

test('enterprise workflow gaps prevent an audit-ready management opinion',()=>{
 const r=buildEnterpriseGrcReport({organization:{id:'o',name:'Acme'},scope:{id:'s',name:'Production'},readiness:{controls:[complete]},soa:{controls:[complete]},risks:[],issues:[],capa:[],assessmentTraces:[],architecture:{summary:{gaps:1}},resilience:{summary:{gaps:0}},policy:{summary:{overdueReview:0,unmapped:0}},audit:{summary:{unreviewed:0}},continuousCompliance:{summary:{overdueObligations:0,expiredExceptions:0}},thirdParty:{summary:{criticalIncidents:0,dueReview:0}}});
 assert.equal(r.managementOpinion.conclusion,'SIGNIFICANT_GAPS');
 assert.equal(r.executiveSummary.enterpriseWorkflowGaps,1);
});


test('enterprise report carries governed GRC evidence provenance into control assurance and evidence register',()=>{const evidence={requestId:'er1',title:'Access review',status:'VALID',version:2,sha256:'a'.repeat(64),verifiedAt:'2026-10-10T00:00:00Z',validatedAt:'2026-10-11T00:00:00Z',validUntil:'2027-01-01T00:00:00Z'};const control={control_key:'IAM-01',title:'Access',domain:'IAM',applicability:'APPLICABLE',implementation:'IMPLEMENTED',approved_at:'2026-10-01T00:00:00Z',valid_evidence:1,passed_tests:1,open_issues:0,readiness:'EVIDENCE_READY',gaps:[],mappings:[{framework:'ISO27001',version:'2022',requirementKey:'A.5.15'}],evidence_records:[evidence]};const r=buildEnterpriseGrcReport({organization:{id:'o',name:'Acme'},scope:{id:'s',name:'Production'},readiness:{controls:[control]},soa:{controls:[control]},risks:[],issues:[],capa:[],assessmentTraces:[],selectedFramework:'ISO27001',generatedAt:'2026-10-17T00:00:00Z'});assert.equal(r.controlAssurance[0].evidenceRecords.length,1);const x=r.evidenceRegister.find((e:any)=>e.evidenceClass==='GOVERNED_GRC');assert.ok(x);assert.equal(x.controlKey,'IAM-01');assert.equal(x.sha256,'a'.repeat(64));assert.equal(x.trust,'INDEPENDENTLY_VALIDATED');});


test('combined assurance model separates offensive and defensive governed handoffs',()=>{const m=buildEnterpriseGrcReport({organization:{id:'o',name:'Acme'},scope:{id:'s',name:'Production'},readiness:{controls:[complete]},soa:{controls:[complete]},risks:[],issues:[],capa:[],assessmentTraces:[],securityHandoffs:[{report_id:'o1',source:'OFFENSIVE',status:'EVIDENCE_ACCEPTED',sha256:'a'},{report_id:'d1',source:'DEFENSIVE',status:'REVIEW_REQUIRED',sha256:'b'}]});assert.equal(m.combinedAssurance.grcIncluded,true);assert.equal(m.combinedAssurance.offensive.total,1);assert.equal(m.combinedAssurance.offensive.accepted,1);assert.equal(m.combinedAssurance.defensive.total,1);assert.equal(m.combinedAssurance.defensive.accepted,0);assert.equal(m.securityReportEvidence.total,2);});

test('ISO 42001 AI impact records are retained in report model',()=>{
 const ai={review_key:'AI-IMPACT-001',status:'APPROVED',approved_at:'2026-10-20T00:00:00Z',inputs:{impact:{aiSystem:'Fraud model',riskRating:'HIGH'}}};
 const r=buildEnterpriseGrcReport({organization:{id:'o',name:'Acme'},scope:{id:'s',name:'AI'},readiness:{controls:[]},soa:{controls:[]},risks:[],issues:[],capa:[],aiImpactAssessments:[ai],generatedAt:'2026-10-20T00:00:00Z'});
 assert.equal(r.iso42001AiImpactAssessments.length,1);
 assert.equal(r.iso42001AiImpactAssessments[0].review_key,'AI-IMPACT-001');
});


test('enterprise report separates staged security audit facts from governed records',()=>{const m=buildEnterpriseGrcReport({organization:{id:'o',name:'Northbridge'},scope:{id:'s',name:'AIMS'},readiness:{controls:[]},soa:{controls:[]},risks:[],issues:[],capa:[],documentIntake:{intakes:[],pendingIntakes:[{id:'i',filename:'audit.pdf',status:'APPROVED'}],stagedProposals:[{kind:'AUDIT',field:'auditStartAt',value:'2026-10-20',status:'ACCEPTED'},{kind:'AUDIT',field:'nextAuditAt',value:'2027-04-20',status:'ACCEPTED'}],governanceNotice:'provenance only'}});assert.equal(m.auditManagement?.audits?.length||0,0);assert.equal(m.stagedSecurityAuditIntake.intakes.length,1);assert.equal(m.stagedSecurityAuditIntake.proposals[1].value,'2027-04-20');});
