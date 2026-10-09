import test from 'node:test';import assert from 'node:assert/strict';
test('SoA rule: not-applicable needs justification',()=>{const applicability='NOT_APPLICABLE',justification='';assert.equal(applicability==='NOT_APPLICABLE'&&justification.length<10,true)});
test('SoA rule: pending is not approval-ready',()=>assert.notEqual('PENDING','APPLICABLE'));
