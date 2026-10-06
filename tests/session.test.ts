import test from 'node:test';import assert from 'node:assert/strict';import { issueSession,verifySession } from '../src/session.js';
test('assessment session round trip',()=>{process.env.ASSESSMENT_SESSION_SECRET='test-secret';const t=issueSession('a1','https://example.com',60000);const p=verifySession(t);assert.equal(p.assessmentId,'a1');assert.equal(p.targetOrigin,'https://example.com')});
test('tampered assessment session fails',()=>{process.env.ASSESSMENT_SESSION_SECRET='test-secret';const t=issueSession('a1','https://example.com',60000);assert.throws(()=>verifySession(t+'x'))});
