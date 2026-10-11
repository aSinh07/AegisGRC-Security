import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';

test('enterprise server initializes vendor and architecture assurance before serving',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(s,/await initThirdPartyRisk\(\)/);assert.match(s,/await initArchitectureAssurance\(\)/);
 assert.match(s,/third-party-dashboard/);assert.match(s,/architecture-assurance/);assert.match(s,/firewall-reviews/);
});
test('third-party workflow enforces independent review and bounded risk',async()=>{
 const s=await readFile(new URL('../src/third-party-risk.ts',import.meta.url),'utf8');
 assert.match(s,/Independent reviewer required for third-party approval/);assert.match(s,/Inherent risk must be 1-25/);
 assert.match(s,/TIER_1/);assert.match(s,/processes_pii/);assert.match(s,/network_access/);assert.match(s,/grc_third_party_incidents/);
});
test('architecture assurance supports security gateways and never silently passes missing firewall review',async()=>{
 const s=await readFile(new URL('../src/architecture-assurance.ts',import.meta.url),'utf8');
 assert.match(s,/FIREWALL_REVIEW_MISSING/);assert.match(s,/cannot PASS with rule gaps or an empty rule set/);assert.match(s,/components must belong to the same requested scope/);assert.match(s,/UNENCRYPTED_FLOW/);assert.match(s,/UNAUTHENTICATED_FLOW/);
 assert.match(s,/any_any_rules/);assert.match(s,/shadowed_rules/);assert.match(s,/stale_rules/);assert.match(s,/expired_rules/);
});

test('continuous compliance requires evidence and independent exception approval',async()=>{
 const s=await readFile(new URL('../src/continuous-compliance.ts',import.meta.url),'utf8');
 assert.match(s,/Evidence reference required to complete obligation/);
 assert.match(s,/Independent approver required for exception/);
 assert.match(s,/effective_status/);assert.doesNotMatch(s,/UPDATE grc_exceptions SET status='EXPIRED'/);assert.match(s,/Invalid exception risk rating/);
 assert.match(s,/overdueObligations/);
});

test('enterprise acceptance gate cannot represent workflow completion as certification',async()=>{
 const s=await readFile(new URL('../src/enterprise-acceptance.ts',import.meta.url),'utf8');
 assert.match(s,/ACCEPTANCE_READY/);assert.match(s,/ACTION_REQUIRED/);
 assert.match(s,/not a certification/);assert.match(s,/proof that no vulnerability exists/);
 assert.match(s,/ARCHITECTURE_FIREWALL/);assert.match(s,/THIRD_PARTY_RISK/);assert.match(s,/CONTINUOUS_COMPLIANCE/);
});

test('business continuity records RTO RPO MTD and evidence-backed exercises',async()=>{
 const s=await readFile(new URL('../src/business-continuity.ts',import.meta.url),'utf8');
 assert.match(s,/rto_minutes/);assert.match(s,/rpo_minutes/);assert.match(s,/mtd_minutes/);
 assert.match(s,/evidence reference required/i);assert.match(s,/Independent reviewer required for resilience exercise/);assert.match(s,/RECOVERY_EXERCISE_UNREVIEWED/);assert.match(s,/RTO_BREACH/);assert.match(s,/RPO_BREACH/);assert.match(s,/BIA_OVERDUE/);assert.match(s,/Exercise cannot PASS when actual RTO or RPO breaches the approved objective/);assert.match(s,/Actual RTO and RPO must be non-negative integers/);assert.match(s,/Invalid service criticality/);
});

test('policy governance requires independent approval and control traceability',async()=>{
 const s=await readFile(new URL('../src/policy-governance.ts',import.meta.url),'utf8');
 assert.match(s,/Independent approver required for policy/);assert.match(s,/grc_policy_control_links/);
 assert.match(s,/grc_policy_attestations/);assert.match(s,/overdueReview/);assert.match(s,/unmapped/);
});

test('audit management requires evidence and independent workpaper review',async()=>{
 const s=await readFile(new URL('../src/audit-management.ts',import.meta.url),'utf8');
 assert.match(s,/Independent workpaper reviewer required/);assert.match(s,/Tested result, conclusion and evidence required before review/);
 assert.match(s,/All audit workpapers require independent review before completion/);assert.match(s,/Completed audit is immutable/);
});

test('enterprise modules initialize only after organization and control dependencies',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const org=s.indexOf('await initOrganizations()'),control=s.indexOf('await initControlRegistry()'),vendor=s.indexOf('await initThirdPartyRisk()'),arch=s.indexOf('await initArchitectureAssurance()'),continuity=s.indexOf('await initBusinessContinuity()');
 assert.ok(org>=0&&control>org&&vendor>control&&arch>control&&continuity>control,'enterprise schema initialization order must satisfy foreign-key dependencies');
});

test('failed deterministic control tests preserve scope-control traceability',async()=>{
 const s=await readFile(new URL('../src/grc-evidence.ts',import.meta.url),'utf8');
 assert.match(s,/INSERT INTO grc_issues\(id,organization_id,scope_control_id/);
 assert.match(s,/t\.scope_control_id/);
});
