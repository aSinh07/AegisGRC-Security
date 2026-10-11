import test from 'node:test';
import assert from 'node:assert/strict';
import {assessBreachImpact} from '../src/breach-impact.js';
const base={organizationId:'org1',assessmentId:'a1',assetId:'asset1',classification:'RESTRICTED' as const,containsPii:true,criticality:'HIGH' as const};
const sig=(category:'EXFILTRATION'|'UNAUTHORIZED_ACCESS',hash='a'.repeat(64))=>({source:'wazuh',evidenceSha256:hash,observedAt:'2026-10-11T00:00:00Z',category,verified:true,assetId:'asset1'});
test('invalid evidence hashes are rejected from correlation',()=>{const r=assessBreachImpact({...base,signals:[sig('EXFILTRATION','bad')]});assert.equal(r.verifiedSignalCount,0);assert.equal(r.status,'INSUFFICIENT_EVIDENCE');});
test('restricted PII criticality raises impact without asserting breach',()=>{const r=assessBreachImpact({...base,signals:[]});assert.equal(r.impactScore,80);assert.equal(r.impactBand,'CRITICAL');assert.equal(r.breachConfirmed,false);});
