import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('unified control assurance preserves automation and accountable manual review',async()=>{
 const s=await readFile(new URL('../src/grc-core.ts',import.meta.url),'utf8');
 for(const field of ['evidence_sufficiency','automated_result','manual_result','design_effectiveness','operating_effectiveness','approval_status','approved_by','approved_at'])
  assert.match(s,new RegExp(field));
 assert.match(s,/reviewControlAssessment/);
 assert.match(s,/Accountable reviewer is required/);
 assert.match(s,/Approval requires sufficient evidence/);
 assert.match(s,/Approval requires design and operating effectiveness tests/);
});

test('control assurance approval is transactional and append-only auditable',async()=>{
 const s=await readFile(new URL('../src/grc-core.ts',import.meta.url),'utf8');
 assert.match(s,/grc_control_assessment_events/);
 assert.match(s,/SELECT ca\.\* FROM grc_control_assessments ca JOIN grc_scopes s/);
 assert.match(s,/client\.query\('BEGIN'\)/);
 assert.match(s,/client\.query\('COMMIT'\)/);
 assert.match(s,/client\.query\('ROLLBACK'\)/);
 assert.match(s,/CONTROL_APPROVED/);
 assert.match(s,/controlAssessmentHistory/);
});

test('unapproved review cannot become an effective final control status',async()=>{
 const s=await readFile(new URL('../src/grc-core.ts',import.meta.url),'utf8');
 assert.match(s,/approval==='APPROVED'\?overall:'NOT_ASSESSED'/);
});

test('governed control assurance API requires organization permissions and server-bound reviewer identity',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.ok(s.includes("/control-assessments'"));
 assert.match(s,/\/control-assessments\/:id\/review/);
 assert.match(s,/\/control-assessments\/:id\/history/);
 assert.match(s,/requireOrgPermission\(u\.userId,req\.params\.orgId,'findingReview'\)/);
 assert.match(s,/actorUserId:u\.userId/);
});

test('control assurance records are tenant-bound through their scope',async()=>{
 const core=await readFile(new URL('../src/grc-core.ts',import.meta.url),'utf8');
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(core,/JOIN grc_scopes s ON s\.id=ca\.scope_id WHERE ca\.id=\$1 AND s\.organization_id=\$2/);
 assert.match(core,/Scope not found in organization/);
 assert.match(core,/FOR UPDATE OF ca/);
 assert.match(core,/JOIN grc_control_assessments ca ON ca\.id=e\.assessment_id JOIN grc_scopes s/);
 assert.match(server,/organizationId:req\.params\.orgId/);
});

test('enterprise workspace exposes unified automation and human control assurance',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 for(const label of ['Unified Control Assurance','AUTOMATION RESULT','MANUAL REVIEW','Design + Operating','Human approval gated'])assert.match(html,new RegExp(label.replace(/[+]/g,'\\+')));
 for(const id of ['assuranceControl','assuranceEvidence','assuranceManual','assuranceDesign','assuranceOperating','assuranceApproval','assuranceNotes','assuranceHistory'])assert.match(html,new RegExp('id="'+id+'"'));
 assert.match(js,/loadControlAssurance/);assert.match(js,/submitControlAssuranceReview/);assert.match(js,/loadControlAssuranceHistory/);
 assert.match(js,/\/control-assessments/);
});


test('empty assurance workspace can initialize governed assessments from scoped canonical controls',async()=>{const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');const controls=await readFile(new URL('../src/grc-controls.ts',import.meta.url),'utf8');assert.match(html,/id="initializeAssuranceBtn"/);assert.match(html,/Initialize Scope Assessments/);assert.match(js,/async function initializeScopeAssurance/);assert.match(js,/controlId:x\.control_id/);assert.match(js,/\/control-assessments/);assert.match(controls,/SELECT sc\.id,sc\.control_id,sc\.applicability/);assert.match(js,/No assessments yet\. Click Initialize Scope Assessments/);});


test('governed evidence review is actionable and preserves separation of duties',async()=>{const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(html,/id="validateGrcEvidenceBtn"/);assert.match(html,/id="rejectGrcEvidenceBtn"/);assert.match(html,/submitter cannot validate their own evidence/);assert.match(js,/async function reviewGrcEvidence\(approved\)/);assert.match(js,/data-version-id/);assert.match(js,/\/validate/);assert.match(js,/Only SUBMITTED evidence awaiting review/);});
test('GRC refresh preserves selected scope and phase3 does not call scoped SoA without a scope',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(js,/const previousScope=activeGrcScope/);assert.match(js,/const preserved=scopes\.find\(x=>x\.id===previousScope\)/);assert.match(js,/activeGrcScope\?jf\('\/api\/grc\/organizations\/'\+activeGrcOrg\+'\/soa\?scopeId='/);assert.match(js,/Promise\.resolve\(\{controls:\[\]\}\)/);});


test('changing Enterprise GRC scope refreshes every scope-dependent governed workspace',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');const start=js.indexOf('async function loadSoa()');const end=js.indexOf('function toggleMobileNav',start);const fn=js.slice(start,end);for(const dep of ['loadGovernancePerformance()','loadControlAssurance()','loadAimsAudits()','loadEnterprisePhase3()','loadIso42001AuditEvidence()'])assert.ok(fn.includes(dep),dep);assert.match(fn,/Promise\.allSettled/);});
