import test from 'node:test';
import assert from 'node:assert/strict';
import {scanCoverage,assessmentStatusForCoverage,scannerRunStatus} from '../src/scan-coverage.js';

test('complete only when every required scanner succeeds',()=>{
 const c=scanCoverage(['nmap','zap'],[{tool:'nmap',status:'SUCCEEDED'},{tool:'zap',status:'SUCCEEDED'}]);
 assert.equal(c.complete,true);assert.equal(assessmentStatusForCoverage(c),'COMPLETED');
});
test('scanner failure produces PARTIAL when other coverage succeeded',()=>{
 const c=scanCoverage(['nmap','zap'],[{tool:'nmap',status:'SUCCEEDED'},{tool:'zap',status:'FAILED'}]);
 assert.equal(c.complete,false);assert.deepEqual(c.failed,['zap']);assert.equal(assessmentStatusForCoverage(c),'PARTIAL');
});
test('missing scanner can never produce completed assessment',()=>{
 const c=scanCoverage(['nmap','zap'],[{tool:'nmap',status:'SUCCEEDED'}]);
 assert.deepEqual(c.notRun,['zap']);assert.equal(assessmentStatusForCoverage(c),'PARTIAL');
});
test('all failed or absent is FAILED',()=>{
 const c=scanCoverage(['nmap'],[{tool:'nmap',status:'FAILED'}]);assert.equal(assessmentStatusForCoverage(c),'FAILED');
});
test('nonzero or missing exit is failed',()=>{
 assert.equal(scannerRunStatus(0),'SUCCEEDED');assert.equal(scannerRunStatus(2),'FAILED');assert.equal(scannerRunStatus(null),'FAILED');
});
