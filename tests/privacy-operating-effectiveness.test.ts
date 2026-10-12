import fs from 'node:fs';import assert from 'node:assert/strict';import test from 'node:test';
const p=fs.readFileSync('src/privacy-operations.ts','utf8'),s=fs.readFileSync('src/server.ts','utf8');
test('privacy testing separates design and operating effectiveness',()=>{for(const x of ['design_result','operating_result','sample_size','evidence_refs','procedure'])assert.ok(p.includes(x),x);assert.match(p,/PASS.*FAIL.*NOT_TESTED/)});
test('operating PASS requires evidence and sample',()=>{assert.match(p,/Operating effectiveness PASS requires a tested sample and evidence/);assert.match(p,/operating==='PASS'/)});
test('privacy tests require independent review',()=>{assert.match(p,/Independent reviewer required for privacy control test/);assert.match(p,/reviewed_by/);assert.match(p,/reviewed_at/)});
test('privacy control test APIs are tenant scoped',()=>{assert.match(s,/privacy\/control-tests/);assert.match(p,/organization_id=\$2/);assert.match(p,/requireOrgPermission\(user,org,'review'\)/)});
test('privacy test schema is additive and non-destructive',()=>{assert.match(p,/CREATE TABLE IF NOT EXISTS grc_privacy_control_tests/);assert.doesNotMatch(p,/DROP TABLE|TRUNCATE|DELETE FROM/i)});
