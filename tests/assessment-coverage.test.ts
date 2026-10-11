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

test('coverage fails closed when layer declarations are incomplete',()=>{const r=assessmentCoverage([]);assert.equal(r.status,'PARTIAL');assert.equal(r.coveragePercent,0);assert.equal(r.missingLayers.length,13)});
test('required not-applicable layer needs explicit justification',()=>{const rows:any[]=ASSESSMENT_LAYERS.map(layer=>({layer,status:'COMPLETE',required:true,engines:['X'],evidenceCount:1,failureReasons:[]}));rows[0]={...rows[0],status:'NOT_APPLICABLE',failureReasons:[]};assert.equal(assessmentCoverage(rows).status,'PARTIAL')});
