import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('enterprise GRC has configurable risk methodology and governed SoA foundation',async()=>{
 const s=await readFile(new URL('../src/grc-core.ts',import.meta.url),'utf8');
 for(const x of ['grc_risk_methodologies','likelihood_max','impact_max','thresholds','grc_statements_of_applicability','related_risk_ids','evidence_refs','approval_status'])assert.match(s,new RegExp(x));
 assert.match(s,/SoA justification is required/);
 assert.match(s,/SoA approval requires accountable reviewer/);
});
test('AI impact and privacy assessments are evidence-bearing organization records',async()=>{
 const s=await readFile(new URL('../src/grc-core.ts',import.meta.url),'utf8');
 for(const x of ['grc_ai_impact_assessments','intended_use','affected_parties','human_oversight','potential_impacts','eu_risk_class','grc_privacy_assessments','processing_activity','pii_categories','retention','safeguards'])assert.match(s,new RegExp(x));
 assert.match(s,/Scope not found in organization/);
});
test('enterprise GRC phase 3 APIs are permission gated',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 for(const p of ['/risk-methodologies','/soa','/ai-impact','/privacy-assessments'])assert.ok(s.includes(p));
 assert.match(s,/requireOrgPermission\(u\.userId,req\.params\.orgId,'findingReview'\)/);
 assert.match(s,/requireOrgPermission\(u\.userId,req\.params\.orgId,'read'\)/);
});

test('phase 3 enterprise workspace exposes risk SoA AI impact and privacy records',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 for(const label of ['Risk · SoA · AI Impact · ISO 27701 Privacy','Configurable scoring','EU AI risk context','ISO 27701 evidence'])assert.ok(html.includes(label));
 for(const fn of ['loadEnterprisePhase3','createEnterpriseRiskMethod','saveEnterpriseSoa','createEnterpriseAiImpact','createEnterprisePrivacyAssessment'])assert.match(js,new RegExp(fn));
});

test('SoA approval enforces accountable segregation and resolved applicability',async()=>{
 const core=await readFile(new URL('../src/grc-core.ts',import.meta.url),'utf8');
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(core,/SoA owner cannot approve their own applicability decision/);
 assert.match(core,/Pending applicability cannot be approved/);
 assert.match(server,/actorUserId:u\.userId/);
});
