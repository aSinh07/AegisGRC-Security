import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluateEvidenceAutomation} from '../src/evidence-automation-assurance.js';
const hash='a'.repeat(64),now='2026-10-12T10:00:00.000Z';
const requirement={id:'ENC',systems:['prod','staging'],supportedProviders:['AWS'],maxAgeHours:24};
const source={id:'aws-test',provider:'AWS',kind:'TEST' as const,state:'PASS' as const,collectedAt:now,hash,systems:['prod','staging']};
const connected=[{provider:'AWS',state:'CONNECTED' as const}];
test('no configured integration cannot claim automation',()=>{
 const x=evaluateEvidenceAutomation({requirement,connections:[],sources:[source],now});
 assert.equal(x.status,'AUTOMATION_READY');assert.equal(x.approved,false);
});
test('partial system coverage cannot claim fully automated',()=>{
 const x=evaluateEvidenceAutomation({requirement,connections:connected,sources:[{...source,systems:['prod']}],now});
 assert.equal(x.status,'PARTIALLY_AUTOMATED');assert.deepEqual(x.uncoveredSystems,['staging']);
});
test('fresh hashed passing sources are eligible but still need reviewer',()=>{
 const x=evaluateEvidenceAutomation({requirement,connections:connected,sources:[source],now});
 assert.equal(x.status,'FULLY_AUTOMATED');assert.equal(x.evidenceReady,true);assert.equal(x.approved,false);
});
test('explicit reviewer decision gates readiness',()=>{
 const x=evaluateEvidenceAutomation({requirement,connections:connected,sources:[source],review:{decision:'APPROVED',reviewerId:'reviewer',reviewedAt:now},now});
 assert.equal(x.approved,true);
});
test('stale, failed, future and unverifiable evidence never passes',()=>{
 for(const bad of [{...source,collectedAt:'2026-10-01T00:00:00Z'},{...source,state:'FAIL' as const},{...source,collectedAt:'2026-10-13T00:00:00Z'},{...source,hash:null}]){
 const x=evaluateEvidenceAutomation({requirement,connections:connected,sources:[bad],review:{decision:'APPROVED',reviewerId:'reviewer',reviewedAt:now},now});
 assert.equal(x.approved,false);assert.equal(x.evidenceReady,false);
 }
});
test('manual requirements cannot be silently considered fully automated',()=>{
 const x=evaluateEvidenceAutomation({requirement:{...requirement,requiresManualProof:true},connections:connected,sources:[source],now});
 assert.equal(x.status,'PARTIALLY_AUTOMATED');assert.equal(x.approved,false);
});
