import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {prepareEvidenceHandoff,validateIncidentTransition,normalizeIdentitySignal} from '../src/cyber-operations-handoff.js';
const org='11111111-1111-4111-8111-111111111111',assessment='22222222-2222-4222-8222-222222222222',report='33333333-3333-4333-8333-333333333333';
const input={organizationId:org,assessmentId:assessment,reportId:report,source:'OFFENSIVE' as const,sha256:'a'.repeat(64),recordedAt:'2026-10-14T00:00:00Z',status:'EVIDENCE_RECORDED' as const,evidenceRefs:['evidence-1'],frameworksRequested:['ISO 27001']};
test('offensive evidence handoff never auto-certifies or closes risk',()=>{const x=prepareEvidenceHandoff(input);assert.equal(x.status,'REVIEW_REQUIRED');assert.equal(x.canAutoCertify,false);assert.equal(x.canAutoCloseRisk,false);assert.ok(x.gates.includes('TENANT_OWNERSHIP'))});
test('defensive and incident sources share the same provenance gate',()=>{for(const source of ['DEFENSIVE','INCIDENT_RESPONSE','IDENTITY_DETECTION_RESPONSE','TPRM'] as const)assert.equal(prepareEvidenceHandoff({...input,source}).status,'REVIEW_REQUIRED')});
test('handoff rejects invalid digest and missing evidence',()=>{assert.throws(()=>prepareEvidenceHandoff({...input,sha256:'invalid'}));assert.throws(()=>prepareEvidenceHandoff({...input,evidenceRefs:[]}))});
test('incident transitions must be sequential and evidence backed',()=>{const evt={phase:'TRIAGED' as const,actorId:'analyst',reason:'Validated alert',occurredAt:'2026-10-14T00:00:00Z',evidenceRefs:['alert-1']};assert.equal(validateIncidentTransition('DETECTED','TRIAGED',evt).accepted,true);assert.throws(()=>validateIncidentTransition('DETECTED','CLOSED',{...evt,phase:'CLOSED'}));assert.throws(()=>validateIncidentTransition('DETECTED','TRIAGED',{...evt,evidenceRefs:[]}))});
test('identity signals cannot automatically assert compromise',()=>{const x=normalizeIdentitySignal({kind:'MFA_FATIGUE',principalId:'user-1',observedAt:'2026-10-14T00:00:00Z',source:'wazuh',evidenceRefs:['event-1']});assert.equal(x.automaticAccountDisable,false);assert.equal(x.automaticCompromiseAssertion,false)});


test('offensive and defensive workspace uploads explicitly request governed GRC handoff',()=>{
 const ui=fs.readFileSync('public/dashboard.js','utf8');
 const server=fs.readFileSync('src/server.ts','utf8');
 const fn=ui.slice(ui.indexOf('async function uploadSecurityDocs'),ui.indexOf('function defensiveActionCard'));
 assert.match(fn,/fd\.append\('securitySource',source\)/);
 assert.match(fn,/grcHandoff/);
 assert.match(server,/organizationId:access\.organization_id,documents:saved/);
 assert.match(server,/explicitSecuritySource/);
});
