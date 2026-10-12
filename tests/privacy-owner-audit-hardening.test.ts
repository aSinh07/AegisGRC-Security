import fs from 'node:fs';import assert from 'node:assert/strict';import test from 'node:test';
const p=fs.readFileSync('src/privacy-operations.ts','utf8');
test('privacy request and breach owners must belong to tenant',()=>{const matches=[...p.matchAll(/if\(input\.ownerUserId\)await requireOrgPermission\(input\.ownerUserId,org,'read'\)/g)];assert.ok(matches.length>=3)});
test('privacy lifecycle has tenant-scoped audit events',()=>{assert.match(p,/CREATE TABLE IF NOT EXISTS grc_privacy_events/);assert.match(p,/organization_id uuid NOT NULL REFERENCES grc_organizations/);for(const e of ['IDENTITY_VERIFIED','FULFILLED','WITHDRAWN','STATUS_'])assert.ok(p.includes(e),e)});
test('privacy event details avoid storing request outcome or principal identifier',()=>{assert.match(p,/evidenceCount:evidence\.length/);assert.match(p,/evidenceRefPresent:Boolean/);assert.doesNotMatch(p,/privacyEvent\([^\n]+principal_ref/);assert.doesNotMatch(p,/privacyEvent\([^\n]+String\(input\.outcome/)});
test('privacy audit migration is additive',()=>{assert.doesNotMatch(p,/DROP TABLE|TRUNCATE/i)});
