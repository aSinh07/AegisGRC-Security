import test from 'node:test';
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
