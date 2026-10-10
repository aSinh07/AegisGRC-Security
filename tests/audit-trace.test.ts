import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {auditPackageModel} from '../src/audit-trace.js';

test('traceability endpoint requires authenticated assessment access',async()=>{
 const src=await readFile(new URL('../src/audit-trace.ts',import.meta.url),'utf8');
 assert.match(src,/requireAssessmentAccess\(userId, assessmentId\)/);
 assert.match(src,/WHERE assessment_id=\$1/);
});
test('traceability preserves evidence hash and review state',async()=>{
 const src=await readFile(new URL('../src/audit-trace.ts',import.meta.url),'utf8');
 assert.match(src,/evidenceHash: f\.evidenceHash/);
 assert.match(src,/reviews: history/);
 assert.match(src,/assuranceBoundary/);
});

test('traceability continues through enterprise risk CAPA and retest evidence',async()=>{
 const src=await readFile(new URL('../src/audit-trace.ts',import.meta.url),'utf8');
 assert.match(src,/grc_enterprise_risks/);
 assert.match(src,/grc_issue_risks/);
 assert.match(src,/grc_capa/);
 assert.match(src,/grc_capa_evidence/);
 assert.match(src,/retest_run_id/);
 assert.match(src,/closedCapa/);
});

test('audit package separates evidence workflow from assurance claims',()=>{
 const m=auditPackageModel({assessmentId:'a1',organizationId:'o1',generatedAt:'2026-01-01T00:00:00Z',assuranceBoundary:'Not certification',summary:{findings:1},evidence:[{sha256:'a'.repeat(64)}],chains:[{findingId:'f1',title:'Test',severity:'HIGH',source:'document',evidenceHash:'a'.repeat(64),status:'OPEN',reviews:[{decision:'CONFIRMED'}],issue:null,risks:[],capa:[]}]});
 assert.equal(m.reportType,'AEGIS_GRC_AUDIT_PACKAGE');
 assert.equal(m.findingLifecycle[0].analystDecisions[0].decision,'CONFIRMED');
 assert.match(m.limitations.join(' '),/do not constitute certification/i);
});

test('audit package reports control relevance separately from deterministic control test',()=>{
 const m=auditPackageModel({assessmentId:'a1',organizationId:'o1',generatedAt:'2026-10-10T00:00:00Z',summary:{},evidence:[],chains:[{
  findingId:'f1',title:'TLS issue',severity:'HIGH',source:'zap',status:'CONFIRMED',reviews:[{decision:'CONFIRMED'}],
  issue:{issue_key:'ISS-1'},controlAssurance:{control_key:'VULN-01',framework_mappings:[{framework:'ISO27001',requirementKey:'A.8.8'}],test_result:null},risks:[],capa:[]
 }]});
 assert.equal(m.findingLifecycle[0].controlAssurance.control_key,'VULN-01');
 assert.match(m.limitations.join(' '),/CONTROL_RELEVANCE/);
 assert.match(m.limitations.join(' '),/NOT_TESTED/);
 assert.equal(m.documentControl.documentId,'AEGIS-AUDIT-a1');
});
