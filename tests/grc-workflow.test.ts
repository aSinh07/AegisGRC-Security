import test from 'node:test';
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {authorizeGrcTransition,allowedTransitions} from '../src/grc-workflow.js';
const base={type:'EVIDENCE' as const,from:'SUBMITTED',to:'APPROVED',role:'REVIEWER' as const,actorId:'reviewer',ownerId:'owner',submitterId:'owner',evidenceValidated:true};
test('independent reviewer may approve validated evidence',()=>assert.equal(authorizeGrcTransition(base).ok,true));
test('self approval denied',()=>assert.equal(authorizeGrcTransition({...base,actorId:'owner'}).ok,false));
test('unvalidated evidence denied',()=>assert.equal(authorizeGrcTransition({...base,evidenceValidated:false}).ok,false));
test('invalid transition denied',()=>assert.equal(authorizeGrcTransition({...base,to:'CLOSED'}).ok,false));
test('risk acceptance requires expiry',()=>assert.equal(authorizeGrcTransition({type:'RISK_ACCEPTANCE',from:'IN_REVIEW',to:'APPROVED',role:'GRC_MANAGER',actorId:'manager',submitterId:'owner'}).ok,false));
test('remediation closure requires passing retest',()=>assert.equal(authorizeGrcTransition({type:'REMEDIATION',from:'VALIDATION',to:'CLOSED',role:'REVIEWER',actorId:'reviewer',submitterId:'owner'}).ok,false));
test('policy exposes valid next states',()=>assert.deepEqual(allowedTransitions('EVIDENCE','DRAFT'),['SUBMITTED']));

test('core remediation state changes commit audit events atomically',async()=>{
 const src=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 assert.match(src,/db:Queryable=pool/);
 assert.match(src,/CREATED',user,undefined,\{issueId,score,treatment:t\},client/);
 assert.match(src,/RISK_ACCEPTED'.*client/);
 assert.match(src,/CREATED',user,undefined,\{issueId\},client/);
 assert.match(src,/CLOSED'.*client/);
});

test('CAPA evidence retest and finding review audit writes are atomic',async()=>{
 const rem=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 assert.match(rem,/EVIDENCE_SUBMITTED'.*client/);
 assert.match(rem,/RETEST_'.*client/);
 const review=await readFile(new URL('../src/finding-review.ts',import.meta.url),'utf8');
 assert.match(review,/action:'FINDING_REVIEWED'/);
 assert.match(review,/INSERT INTO audit_events/);
 const reviewInsert=review.indexOf("INSERT INTO audit_events");
 const commit=review.indexOf("await client.query('COMMIT')",reviewInsert);
 assert.ok(reviewInsert>=0&&commit>reviewInsert);
});


test('CAPA evidence and retest preconditions are locked inside their transactions',async()=>{
 const remediation=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 const evidenceStart=remediation.indexOf('export async function submitCapaEvidence');
 const retestStart=remediation.indexOf('export async function attachRetest',evidenceStart);
 const closeStart=remediation.indexOf('export async function closeCapa',retestStart);
 const evidence=remediation.slice(evidenceStart,retestStart),retest=remediation.slice(retestStart,closeStart);
 assert.ok(evidence.indexOf("client.query('BEGIN')")<evidence.indexOf('FOR UPDATE'));
 assert.match(evidence,/FOR UPDATE OF v,r/);
 assert.match(evidence,/client\.query\('ROLLBACK'\)/);
 assert.ok(retest.indexOf("client.query('BEGIN')")<retest.indexOf('FOR UPDATE'));
 assert.match(retest,/CAPA is not ready for retest/);
 assert.match(retest,/grc_control_test_runs WHERE id=\$1 AND organization_id=\$2 FOR UPDATE/);
 assert.match(retest,/client\.query\('ROLLBACK'\)/);
});


test('finding promotion is concurrency safe and idempotent',async()=>{
 const risk=await readFile(new URL('../src/finding-risk.ts',import.meta.url),'utf8');
 const start=risk.indexOf('export async function promoteFindingToIssue');
 const fn=risk.slice(start);
 assert.ok(fn.indexOf("client.query('BEGIN')")<fn.indexOf('SELECT organization_id FROM assessments'));
 assert.match(fn,/findings WHERE id=\$1 AND assessment_id=\$2 FOR UPDATE/);
 assert.match(fn,/finding_reviews[\s\S]*LIMIT 1 FOR UPDATE/);
 assert.match(fn,/ON CONFLICT \(organization_id,finding_id\) WHERE finding_id IS NOT NULL DO NOTHING RETURNING \*/);
 assert.match(fn,/const winner=.*SELECT \* FROM grc_issues/s);
 assert.match(fn,/client\.query\('ROLLBACK'\)/);
});


test('finding review route relies on the transactional audit event only',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const start=server.indexOf("app.post('/api/grc/assessments/:assessmentId/findings/:findingId/review'");
 const end=server.indexOf("app.get('/api/grc/assessments/:assessmentId/findings/:findingId/reviews'",start);
 const route=server.slice(start,end);
 assert.match(route,/reviewFinding\(u\.userId,req\.params\.assessmentId,req\.params\.findingId/);
 assert.doesNotMatch(route,/db\.saveAudit/);
 const review=await readFile(new URL('../src/finding-review.ts',import.meta.url),'utf8');
 const fn=review.slice(review.indexOf('export async function reviewFinding'),review.indexOf('export async function findingReviewHistory'));
 assert.match(fn,/INSERT INTO audit_events/);
 assert.match(fn,/client\.query\('COMMIT'\)/);
 assert.match(fn,/client\.query\('ROLLBACK'\)/);
});
