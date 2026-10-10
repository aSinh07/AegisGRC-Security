import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluateReadiness,auditReadinessReportModel} from '../src/grc-readiness.js';

const complete={id:'1',control_key:'AC-1',title:'Access control',applicability:'APPLICABLE',approved_at:'2026-10-10',implementation:'IMPLEMENTED',valid_evidence:1,passed_tests:1,open_issues:0,mappings:[{framework:'ISO27001',clause:'A.5.15'}]};

test('readiness requires approvals, current evidence, passing tests and mapped clauses',()=>{
 const r=evaluateReadiness([complete]);
 assert.equal(r.summary.ready,1);
 assert.equal(r.summary.readinessPercent,100);
 assert.equal(r.controls[0].readiness,'EVIDENCE_READY');
 assert.match(r.assuranceBoundary,/not a conformity opinion/);
});

test('missing evidence, testing, approval, mapping and unresolved issue become explicit gaps',()=>{
 const r=evaluateReadiness([{...complete,approved_at:null,valid_evidence:0,passed_tests:0,open_issues:2,mappings:[]}]);
 assert.equal(r.summary.ready,0);
 assert.equal(r.controls[0].gaps.length,5);
 assert.equal(r.controls[0].readiness,'ACTION_REQUIRED');
});

test('no scoped controls is unassessed rather than compliant',()=>{
 const r=evaluateReadiness([]);
 assert.equal(r.summary.readinessPercent,0);
 assert.equal(r.summary.unassessed,true);
});

test('not-applicable control requires approved decision and justification',()=>{
 const r=evaluateReadiness([{...complete,applicability:'NOT_APPLICABLE',applicability_justification:'Not used by scoped infrastructure',implementation:'NOT_IMPLEMENTED',valid_evidence:0,passed_tests:0}]);
 assert.equal(r.summary.ready,1);
 const invalid=evaluateReadiness([{...complete,applicability:'NOT_APPLICABLE',applicability_justification:'',approved_at:null}]);
 assert.equal(invalid.summary.ready,0);
});


test('audit readiness report model preserves clause traceability and assurance boundary',()=>{
 const base=evaluateReadiness([complete]);
 const model=auditReadinessReportModel({organizationId:'org',scope:{id:'scope',name:'Production'},generatedAt:'2026-10-10T00:00:00Z',auditChecklist:['review'],...base});
 assert.equal(model.executiveSummary.frameworksAssessed,1);
 assert.equal(model.executiveSummary.clausesMapped,1);
 assert.equal(model.clauses[0].clause,'A.5.15');
 assert.match(model.methodology.join(' '),/not a compliance percentage/);
 assert.match(model.limitations.join(' '),/External certification/);
});


test('readiness query only accepts the latest active control test result',async()=>{
 const src=await readFile(new URL('../src/grc-readiness.ts',import.meta.url),'utf8');
 const start=src.indexOf('export async function organizationAuditReadiness');
 const end=src.indexOf('export function auditReadinessReportModel',start);
 const fn=src.slice(start,end);
 assert.match(fn,/td\.active=true/);
 assert.match(fn,/tr\.result='PASS'/);
 assert.match(fn,/tr\.id=\(SELECT tr2\.id FROM grc_control_test_runs tr2 WHERE tr2\.test_definition_id=td\.id ORDER BY tr2\.executed_at DESC LIMIT 1\)/);
});
