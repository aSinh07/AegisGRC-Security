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

test('legacy admin cookie cannot authorize tenant APIs or report step-up',async()=>{
 const {readFile}=await import('node:fs/promises');
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const middleware=server.slice(server.indexOf("app.use('/api'"),server.indexOf("app.get('/api/grc/organizations'"));
 assert.doesNotMatch(middleware,/valid\(token\)/);
 assert.match(middleware,/User login required/);
 const step=server.slice(server.indexOf('async function reportAuthorized'),server.indexOf("app.get('/api/assessments'",server.indexOf('async function reportAuthorized')));
 assert.doesNotMatch(step,/verifyCredentials/);
 assert.match(step,/verifyUserStepUp/);
});


test('registration abuse controls and legacy login retirement are enforced',async()=>{
 const {readFile}=await import('node:fs/promises');
 const auth=await readFile(new URL('../src/user-auth.ts',import.meta.url),'utf8');
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(server,/authAttemptKey\(req,'register',email\)/);
 assert.match(server,/authAttemptKey\(req,'register-confirm',userId\)/);
 assert.match(server,/Legacy administrator login is disabled/);
 assert.match(server,/status\(410\)/);
 assert.match(auth,/totp_verified=false AND created_at < now\(\)-interval '24 hours'/);
 assert.match(auth,/app_auth_attempts WHERE updated_at < now\(\)-interval '2 days'/);
});


test('report step-up authentication is PostgreSQL rate limited',async()=>{
 const {readFile}=await import('node:fs/promises');
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const step=server.slice(server.indexOf('async function reportAuthorized'),server.indexOf("type Tool=",server.indexOf('async function reportAuthorized')));
 assert.match(step,/authAttemptKey\(req,'report-step-up',u\.userId\)/);
 assert.match(step,/authAttemptAllowed\(attemptKey,6,15\)/);
 assert.match(step,/recordAuthFailure\(attemptKey,6,15\)/);
 assert.match(step,/clearAuthFailures\(attemptKey\)/);
 assert.match(step,/STEP_UP_RATE_LIMITED/);
});


test('scan targets are revalidated against DNS rebinding and unsafe ports',async()=>{
 const {readFile}=await import('node:fs/promises');
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(server,/Only standard HTTP\(S\) target ports are allowed/);
 assert.match(server,/async function revalidateTarget/);
 assert.match(server,/Target DNS changed to a blocked address/);
 assert.match(server,/Target DNS changed after authorization; scan refused/);
 const quick=server.slice(server.indexOf('async function quickPosture'),server.indexOf('function documentSecurityScan'));
 assert.match(quick,/t=await revalidateTarget\(t\)/);
 const real=server.slice(server.indexOf('async function executeRealTool'),server.indexOf("app.post('/api/scans/run'"));
 assert.match(real,/t=await revalidateTarget\(t\)/);
});


test('TOTP secrets support authenticated encryption at rest with legacy compatibility',async()=>{
 const {readFile}=await import('node:fs/promises');
 const auth=await readFile(new URL('../src/user-auth.ts',import.meta.url),'utf8');
 assert.match(auth,/createCipheriv\('aes-256-gcm'/);
 assert.match(auth,/createDecipheriv\('aes-256-gcm'/);
 assert.match(auth,/TOTP_ENCRYPTION_KEY/);
 assert.match(auth,/const secret=b32enc\(crypto\.randomBytes\(20\)\),storedSecret=protectTotp\(secret\)/);
 assert.match(auth,/verify\(revealTotp\(u\.totp_secret\),code\)/);
 assert.match(auth,/if\(!value\.startsWith\('enc:v1:'\)\)return value/);
});


test('authentication throttle state updates are atomic PostgreSQL upserts',async()=>{
 const {readFile}=await import('node:fs/promises');
 const auth=await readFile(new URL('../src/user-auth.ts',import.meta.url),'utf8');
 const start=auth.indexOf('export async function authAttemptAllowed');
 const limiter=auth.slice(start);
 assert.match(limiter,/INSERT INTO app_auth_attempts/);
 assert.match(limiter,/ON CONFLICT\(attempt_key\) DO UPDATE SET/);
 assert.match(limiter,/RETURNING failures,blocked_until/);
 assert.doesNotMatch(limiter,/SELECT failures,window_started_at,blocked_until FROM app_auth_attempts/);
 assert.match(limiter,/blocked_until=CASE WHEN app_auth_attempts\.blocked_until<=now\(\) THEN NULL/);
});
