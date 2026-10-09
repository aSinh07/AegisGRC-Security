import test from 'node:test';import assert from 'node:assert/strict';import { issueSession,verifySession } from '../src/session.js';
test('assessment session round trip',()=>{process.env.ASSESSMENT_SESSION_SECRET='test-secret';const t=issueSession('a1','https://example.com',60000);const p=verifySession(t);assert.equal(p.assessmentId,'a1');assert.equal(p.targetOrigin,'https://example.com')});
test('tampered assessment session fails',()=>{process.env.ASSESSMENT_SESSION_SECRET='test-secret';const t=issueSession('a1','https://example.com',60000);assert.throws(()=>verifySession(t+'x'))});

test('user authentication hardening is present',async()=>{
 const {readFile}=await import('node:fs/promises');
 const auth=await readFile(new URL('../src/user-auth.ts',import.meta.url),'utf8');
 assert.match(auth,/\[-1,0,1\]\.some/);
 assert.doesNotMatch(auth,/\[-2,-1,0,1,2\]\.some/);
 assert.match(auth,/Account already exists or registration is already pending/);
 assert.doesNotMatch(auth,/UPDATE app_users SET password_hash=\$2,password_salt=\$3,totp_secret=\$4,totp_verified=false/);
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(server,/authAttemptAllowed\(attemptKey\)/);
 assert.match(server,/recordAuthFailure\(attemptKey\)/);
 assert.match(server,/clearAuthFailures\(attemptKey\)/);
 assert.match(server,/status\(429\)/);
});

test('authentication throttling persists in PostgreSQL',async()=>{
 const {readFile}=await import('node:fs/promises');
 const auth=await readFile(new URL('../src/user-auth.ts',import.meta.url),'utf8');
 const schema=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 assert.match(auth,/CREATE TABLE IF NOT EXISTS app_auth_attempts/);
 assert.match(auth,/export async function authAttemptAllowed/);
 assert.match(auth,/export async function recordAuthFailure/);
 assert.match(auth,/blocked_until/);
 assert.match(schema,/CREATE TABLE IF NOT EXISTS app_auth_attempts/);
});
