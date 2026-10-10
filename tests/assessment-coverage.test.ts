import test from 'node:test';import assert from 'node:assert/strict';
import {ASSESSMENT_LAYERS,assessmentCoverage,dataExposureState} from '../src/assessment-coverage.js';
test('enterprise assessment declares full security data and privacy surface',()=>{
 for(const x of ['ATTACK_SURFACE','INFRASTRUCTURE','ENDPOINT','WEB','API','SOURCE_CODE','DEPENDENCIES','CONTAINER','CLOUD','IDENTITY','DATA_SECURITY','PRIVACY','BREACH_TELEMETRY'])assert.ok(ASSESSMENT_LAYERS.includes(x as any));
});
test('incomplete required layer makes overall assessment partial',()=>{
 const r=assessmentCoverage([
  {layer:'INFRASTRUCTURE',status:'COMPLETE',required:true,engines:['nmap'],evidenceCount:1,failureReasons:[]},
  {layer:'ENDPOINT',status:'FAILED',required:true,engines:['wazuh'],evidenceCount:0,failureReasons:['agent unavailable']}
 ]);assert.equal(r.status,'PARTIAL');assert.equal(r.coveragePercent,50);assert.equal(r.incompleteLayers[0].layer,'ENDPOINT');
});
test('breach is never inferred from vulnerability alone',()=>{
 assert.equal(dataExposureState({vulnerability:true,dataExposed:false,telemetryIndicators:false,confirmedExfiltration:false}),'VULNERABILITY');
 assert.equal(dataExposureState({vulnerability:true,dataExposed:true,telemetryIndicators:false,confirmedExfiltration:false}),'EXPOSURE');
 assert.equal(dataExposureState({vulnerability:true,dataExposed:true,telemetryIndicators:true,confirmedExfiltration:false}),'SUSPECTED_BREACH');
 assert.equal(dataExposureState({vulnerability:true,dataExposed:true,telemetryIndicators:true,confirmedExfiltration:true}),'CONFIRMED_BREACH');
});
