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
