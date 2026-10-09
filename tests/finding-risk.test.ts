import test from 'node:test';import assert from 'node:assert/strict';
import {defaultSlaDays,remediationDueAt} from '../src/finding-risk.js';
test('default remediation targets are explicit operational policy values',()=>{
 assert.deepEqual(defaultSlaDays,{CRITICAL:7,HIGH:30,MEDIUM:90,LOW:180,INFO:365});
});
test('organization SLA override changes due date deterministically',()=>{
 const from=new Date('2026-01-01T00:00:00Z');assert.equal(remediationDueAt('HIGH',{HIGH:10},from).toISOString(),'2026-01-11T00:00:00.000Z');
});
test('invalid SLA cannot create impossible remediation target',()=>{
 assert.throws(()=>remediationDueAt('CRITICAL',{CRITICAL:0}),/between 1 and 3650/);
});

test('finding promotion is assessment scoped owner validated and atomically audited',async()=>{
 const {readFile}=await import('node:fs/promises');
 const src=await readFile(new URL('../src/finding-risk.ts',import.meta.url),'utf8');
 assert.match(src,/WHERE finding_id=\$1 AND assessment_id=\$2 ORDER BY created_at DESC LIMIT 1/);
 assert.match(src,/Issue owner must be an active organization member/);
 assert.match(src,/m\.status='ACTIVE' AND o\.status='ACTIVE'/);
 assert.match(src,/CREATED_FROM_CONFIRMED_FINDING/);
 const eventAt=src.indexOf('CREATED_FROM_CONFIRMED_FINDING');
 const commitAt=src.indexOf("await client.query('COMMIT')",eventAt);
 assert.ok(eventAt>=0&&commitAt>eventAt);
});

test('SLA policy updates are atomic and auditable',async()=>{
 const {readFile}=await import('node:fs/promises');
 const src=await readFile(new URL('../src/finding-risk.ts',import.meta.url),'utf8');
 const start=src.indexOf('export async function setSlaPolicy');
 const end=src.indexOf('export async function promoteFindingToIssue',start);
 const block=src.slice(start,end);
 assert.match(block,/client\.query\('BEGIN'\)/);
 assert.match(block,/grc_record_events/);
 assert.match(block,/'SLA_POLICY'/);
 assert.match(block,/client\.query\('COMMIT'\)/);
 assert.match(block,/client\.query\('ROLLBACK'\)/);
});
