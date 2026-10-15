import fs from 'node:fs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {ISO42001_AI_IMPACT_PROFILE,validateIso42001AiImpact} from '../src/governance-performance.js';

const complete={aiSystem:'Aegis AI governance assistant',intendedUse:'Assist authorized GRC users with evidence-backed governance analysis.',foreseeableMisuse:'Users may over-rely on generated recommendations or attempt unauthorized use.',affectedParties:'Organization users, customers, suppliers and data subjects may be affected.',dataExposureImpact:'Unauthorized retrieval or disclosure could expose governed or personal information.',erroneousOutputImpact:'Incorrect output could cause an inappropriate control or risk decision.',downstreamImpact:'Errors may propagate into reports, remediation priorities or management decisions.',humanOversight:'Material governance decisions require an authorized human reviewer before approval.',reviewTriggers:'Reassess after material model, data, use-case, supplier, incident or control changes.',riskRating:'HIGH',evidenceRefs:['evidence://ai-impact/assessment-1']};

test('ISO 42001 AI impact profile requires the supplied-material impact dimensions',()=>{
 const x=validateIso42001AiImpact(complete);assert.equal(x.profile,ISO42001_AI_IMPACT_PROFILE);assert.equal(x.riskRating,'HIGH');assert.deepEqual(x.evidenceRefs,complete.evidenceRefs);
});

test('ISO 42001 AI impact profile rejects incomplete assessment before persistence',()=>{
 assert.throws(()=>validateIso42001AiImpact({...complete,humanOversight:'',evidenceRefs:[]}),/humanOversight, evidenceRefs/);
});

test('AI impact API uses dedicated authenticated organization-scoped workflow',()=>{
 const server=fs.readFileSync('src/server.ts','utf8');const start=server.indexOf("app.post('/api/grc/organizations/:orgId/ai-impact-assessments'");assert.ok(start>=0);const route=server.slice(start,server.indexOf('\n',start));assert.match(route,/currentUser\(req\)/);assert.match(route,/createIso42001AiImpactReview\(u\.userId,req\.params\.orgId/);
});

test('AI impact review reuses independent management-review approval rather than self-certifying',()=>{
 const source=fs.readFileSync('src/governance-performance.ts','utf8');assert.match(source,/if\(row\.created_by===user\)throw err\('Independent approver required for management review'/);const start=source.indexOf('export async function createIso42001AiImpactReview');const end=source.indexOf('export async function createManagementReview',start);const profileFlow=source.slice(start,end);assert.ok(start>=0&&end>start);assert.doesNotMatch(profileFlow,/APPROVED|approved_by|approved_at/);
});

test('AI impact records use a reserved key namespace to avoid generic review collisions',()=>{const source=fs.readFileSync('src/governance-performance.ts','utf8');assert.match(source,/rawKey\.startsWith\('AI-IMPACT-'\)/);assert.match(source,/AI impact assessment review key required/)});

test('AI impact persistence resolves current independently validated Evidence Vault versions',()=>{const s=fs.readFileSync('src/governance-performance.ts','utf8');assert.match(s,/grc_evidence_versions v JOIN grc_evidence_requests r/);assert.match(s,/integrity_status='SERVER_VERIFIED'/);assert.match(s,/v\.valid_until>now\(\)/)});
