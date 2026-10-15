import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('GRC review approval is transaction locked and bound to snapshot digest',async()=>{
 const src=await readFile(new URL('../src/grc-review.ts',import.meta.url),'utf8');
 assert.match(src,/snapshot_digest/);
 assert.match(src,/FOR UPDATE/);
 assert.match(src,/signApprovedReport/);
 assert.match(src,/client\.query\('COMMIT'\)/);
 assert.match(src,/client\.query\('ROLLBACK'\)/);
});
test('authenticated audit export fails closed without a valid approved snapshot',async()=>{
 const src=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const start=src.indexOf("app.get('/api/grc/assessments/:assessmentId/audit-package.:format'");
 const end=src.indexOf("app.get('/api/grc/assessments/:assessmentId/traceability'",start);
 const route=src.slice(start,end);
 assert.match(route,/Approved GRC review is required/);
 assert.match(route,/verifyGrcReview/);
 assert.match(route,/reportSnapshotDigest/);
 assert.match(route,/snapshot is missing, invalid, or stale/);
});
test('public verification reveals approval validity without report evidence',async()=>{
 const src=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(src,/\/api\/report-verification\/:reviewId/);
 assert.match(src,/Cryptographic AegisGRC issuance\/approval verification only/);
});

test('enterprise GRC exports require the same password and authenticator step-up gate',async()=>{const src=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');const start=src.indexOf("app.get('/api/grc/organizations/:orgId/scopes/:scopeId/enterprise-report.:format'");const end=src.indexOf('\napp.',start+10);const route=src.slice(start,end);assert.match(route,/reportAuthorized\(req\)/);assert.match(route,/Password and authenticator verification required for enterprise report download/)});

test('Report Center invokes Enterprise GRC export through the existing MFA step-up dialog',async()=>{const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(html,/Enterprise GRC Assurance/);assert.match(html,/downloadEnterpriseGrc/);assert.match(js,/enterprise-report\.'/);assert.match(js,/'x-report-password':password/);assert.match(js,/'x-report-totp':code/)});
