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
