import test from 'node:test';
import assert from 'node:assert/strict';
import {assessBreachImpact} from '../src/breach-impact.js';
const base={organizationId:'org1',assessmentId:'a1',assetId:'asset1',classification:'RESTRICTED' as const,containsPii:true,criticality:'HIGH' as const};
const signal=(category:'EXFILTRATION'|'UNAUTHORIZED_ACCESS',verified=true)=>({source:'wazuh',evidenceSha256:'a'.repeat(64),observedAt:'2026-10-11T00:00:00Z',category,verified,assetId:'asset1'});
test('unverified signals cannot establish exposure',()=>{const r=assessBreachImpact({...base,signals:[signal('EXFILTRATION',false)]});assert.equal(r.status,'INSUFFICIENT_EVIDENCE');assert.equal(r.verifiedSignalCount,0);});
test('correlated signals require human review and never auto-confirm breach',()=>{const r=assessBreachImpact({...base,signals:[signal('EXFILTRATION'),signal('UNAUTHORIZED_ACCESS')]});assert.equal(r.status,'SUSPECTED_BREACH_REQUIRES_REVIEW');assert.equal(r.breachConfirmed,false);assert.equal(r.requiresHumanReview,true);});
test('foreign asset signals are excluded',()=>{const r=assessBreachImpact({...base,signals:[{...signal('EXFILTRATION'),assetId:'other'}]});assert.equal(r.verifiedSignalCount,0);});
test('fingerprint is deterministic regardless of signal order',()=>{const a=signal('EXFILTRATION'),b=signal('UNAUTHORIZED_ACCESS');assert.equal(assessBreachImpact({...base,signals:[a,b]}).fingerprint,assessBreachImpact({...base,signals:[b,a]}).fingerprint);});
