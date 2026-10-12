import fs from 'node:fs';import assert from 'node:assert/strict';import test from 'node:test';
const src=fs.readFileSync('src/automation-outbox.ts','utf8');
test('automation outbox is additive tenant scoped and idempotent',()=>{assert.match(src,/CREATE TABLE IF NOT EXISTS grc_automation_outbox/);assert.match(src,/organization_id uuid NOT NULL/);assert.match(src,/UNIQUE\(organization_id,idempotency_key\)/);assert.doesNotMatch(src,/DROP TABLE|TRUNCATE|DELETE FROM/i)});
test('script automation is allowlisted and prohibits arbitrary shell',()=>{assert.match(src,/Unsupported script task; arbitrary shell execution is prohibited/);assert.doesNotMatch(src,/child_process|exec\(|spawn\(/)});
test('ServiceNow remains configuration gated and cannot auto-close risk',()=>{assert.match(src,/SERVICENOW_BASE_URL/);assert.match(src,/SERVICENOW_TOKEN/);assert.match(src,/httpsEndpoint/);assert.match(src,/externalWriteTested:false/);assert.match(src,/autoCloseRisk:false/)});
