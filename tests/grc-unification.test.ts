import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('enterprise risk workflow consumes configurable methodology without creating a third risk workflow',async()=>{
 const s=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 for(const x of ['grc_enterprise_risks','grc_risk_methodologies','methodology_id','acceptance_rationale','accepted_at'])assert.match(s,new RegExp(x));
 assert.match(s,/Risk methodology not found in organization/);
 assert.match(s,/Risk acceptance requires a meaningful rationale/);
 assert.match(s,/Risk creator\/owner cannot approve own acceptance/);
});

test('authoritative SoA is canonical scope control with risk and evidence provenance',async()=>{
 const s=await readFile(new URL('../src/grc-controls.ts',import.meta.url),'utf8');
 for(const x of ['grc_scope_controls','related_risk_ids','evidence_refs','grc_enterprise_risks'])assert.match(s,new RegExp(x));
 assert.match(s,/SoA risk references must belong to the organization/);
 assert.match(s,/Control owner cannot approve own applicability decision/);
 assert.match(s,/Pending applicability cannot be approved/);
});

test('public SoA API routes through canonical governed control registry',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(s,/statementOfApplicability\(u\.userId,req\.params\.orgId,scopeId\)/);
 assert.match(s,/setScopeControl\(u\.userId,req\.params\.orgId,scopeId/);
 assert.match(s,/approveScopeControl\(u\.userId,req\.params\.orgId,scopeId,row\.id\)/);
 assert.doesNotMatch(s,/upsertStatementOfApplicability/);
 assert.doesNotMatch(s,/listStatementsOfApplicability/);
});
