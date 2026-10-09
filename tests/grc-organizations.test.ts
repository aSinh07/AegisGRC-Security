import test from 'node:test';import {readFile} from 'node:fs/promises';import assert from 'node:assert/strict';import {roleAllows} from '../src/grc-organizations.js';
test('viewer is read only',()=>{assert.equal(roleAllows('VIEWER','read'),true);assert.equal(roleAllows('VIEWER','manageRisk'),false)});
test('control owner cannot approve reviews',()=>assert.equal(roleAllows('CONTROL_OWNER','review'),false));
test('reviewer cannot manage organization',()=>assert.equal(roleAllows('REVIEWER','manageOrg'),false));
test('org admin can manage scopes',()=>assert.equal(roleAllows('ORG_ADMIN','manageScope'),true));

test('finding decisions require an explicit analyst or reviewer role',()=>{assert.equal(roleAllows('GRC_ANALYST','findingReview'),true);assert.equal(roleAllows('REVIEWER','findingReview'),true);assert.equal(roleAllows('VIEWER','findingReview'),false);assert.equal(roleAllows('AUDITOR','findingReview'),false)});

test('account profile and MFA reset hardening are wired',async()=>{
 const src=await readFile(new URL('../src/user-auth.ts',import.meta.url),'utf8');
 assert.match(src,/full_name text/);assert.match(src,/designation text/);assert.match(src,/company_name text/);
 assert.match(src,/resetPasswordWithTotp/);assert.match(src,/DELETE FROM app_sessions WHERE user_id/);
});
