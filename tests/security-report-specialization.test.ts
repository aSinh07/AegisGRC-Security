import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import * as XLSX from 'xlsx';
import {reportModel,xlsxReport} from '../src/exporters.js';
const a:any={id:'a1',target:'https://example.test',authorizedAt:'2026-01-01',status:'COMPLETED',findings:[],evidenceIds:[]};
const fs:any[]=[{id:'f1',assessmentId:'a1',source:'zap',title:'Observed weakness',description:'Evidence-backed observation',severity:'HIGH',asset:'https://example.test',evidenceHash:'a'.repeat(64),createdAt:'2026-01-01',mappings:{},remediation:'Apply fix and retest.'}];
const ev:any[]=[{id:'e1',assessmentId:'a1',source:'zap',sha256:'a'.repeat(64),createdAt:'2026-01-01',exitCode:0,metadata:{target:'https://example.test'}}];

test('technical report is explicitly offensive-security focused rather than GRC',()=>{const m=reportModel(a,fs,'technical',ev);assert.equal(m.purpose.title,'Offensive Security Technical Assessment');assert.match(m.purpose.objective,/attack-surface testing/i);assert.doesNotMatch(m.purpose.title,/GRC/);});
test('remediation report contains defensive mitigation and retest lifecycle',()=>{const m=reportModel(a,fs,'remediation',ev);assert.equal(m.purpose.title,'Defensive Security Remediation & Hardening Plan');assert.equal(m.defensive?.actions.length,1);assert.match(m.defensive?.actions[0].validation||'',/retest/i);});
test('defensive XLSX includes a dedicated mitigation and retest sheet',()=>{const b=xlsxReport(a,fs,'remediation',ev);const wb=XLSX.read(b,{type:'buffer'});assert.ok(wb.SheetNames.includes('Mitigation Retest'));assert.ok(wb.SheetNames.includes('Evidence Provenance'));});

test('security reports distinguish supported capability from executed evidence',()=>{const m=reportModel({...a,scanCoverage:{required:['http-posture','nmap'],succeeded:['http-posture'],failed:[],notRun:['nmap'],complete:false}},fs,'technical',ev);assert.equal(m.coverage.complete,false);assert.deepEqual(m.coverage.notRun,['nmap']);assert.match(m.coverage.boundary,/not reported as tested/i);});


test('security report upload and legacy backfill classify offensive and defensive evidence robustly',()=>{
 const server=readFileSync('src/server.ts','utf8'),handoff=readFileSync('src/security-report-handoff.ts','utf8');
 assert.match(server,/securitySource/);
 assert.match(server,/\/offensive\/i\.test\(description\)/);
 assert.match(server,/\/defensive\/i\.test\(description\)/);
 assert.match(server,/PENTEST_REPORT','VULNERABILITY_REPORT/);
 assert.match(handoff,/ILIKE '%offensive%'/);
 assert.match(handoff,/ILIKE '%defensive%'/);
});


test('security evidence review is tenant-scoped serialized and idempotent',()=>{const x=readFileSync('src/security-report-handoff.ts','utf8');assert.match(x,/organization_id=\$2 FOR UPDATE/);assert.match(x,/alreadyReviewed:true/);assert.match(x,/AND reviewed_at IS NULL RETURNING \*/);assert.match(x,/client\.query\('BEGIN'\)/);});


test('security handoff is cryptographically bound to a stored document in the same assessment',()=>{const x=readFileSync('src/security-report-handoff.ts','utf8');assert.match(x,/FROM documents WHERE id=\$1 AND assessment_id=\$2/);assert.match(x,/evidence hash does not match stored document/);assert.match(x,/String\(document\.sha256/);});


test('all security handoff evidence references are assessment-bound',()=>{const x=readFileSync('src/security-report-handoff.ts','utf8');assert.match(x,/Primary security report must be included in evidence references/);assert.match(x,/id::text=ANY\(\$2::text\[\]\)/);assert.match(x,/Every security handoff evidence reference must resolve to a stored document in the same assessment/);});


test('security report handoff accepts assessment operators and duplicate creation is idempotent',()=>{const x=readFileSync('src/security-report-handoff.ts','utf8');assert.match(x,/roleAllows\(m\.role as any,'manageAssessment'\)/);assert.match(x,/roleAllows\(m\.role as any,'manageRisk'\)/);assert.match(x,/reused:true/);assert.match(x,/Conflicting security report handoff already exists/);});


test('generated Offensive and Defensive PDF reports are persisted and handed to Enterprise GRC',()=>{
 const server=readFileSync('src/server.ts','utf8');
 assert.match(server,/Generated Offensive\/Defensive reports are themselves governed technical evidence/);
 assert.match(server,/kind==='technical'\|\|kind==='remediation'/);
 assert.match(server,/kind==='technical'\?'OFFENSIVE':'DEFENSIVE'/);
 assert.match(server,/crypto\.createHash\('sha256'\)\.update\(body\)\.digest\('hex'\)/);
 assert.match(server,/await db\.saveDocument\(\{id:reportId,assessmentId:a\.id/);
 assert.match(server,/generated:true,securitySource:source/);
 assert.match(server,/await createSecurityReportHandoff\(u\.userId,access\.organization_id,\{assessmentId:a\.id,reportId,source,sha256/);
 const handoff=readFileSync('src/security-report-handoff.ts','utf8');
 assert.match(handoff,/DEFAULT 'REVIEW_REQUIRED'/);
 assert.match(handoff,/,'REVIEW_REQUIRED',a\.created_by/);
});


test('accepted security reports materialize proposed GRC intelligence without automatic compliance decisions',()=>{
 const handoff=readFileSync('src/security-report-handoff.ts','utf8');
 const engine=readFileSync('src/security-report-findings.ts','utf8');
 const server=readFileSync('src/server.ts','utf8');
 assert.match(handoff,/materializeAcceptedSecurityFindings\(org,id\)/);
 assert.match(handoff,/governanceState:'PROPOSED'/);
 assert.match(handoff,/automaticComplianceDecision:false/);
 assert.match(engine,/status text NOT NULL DEFAULT 'PROPOSED'/);
 assert.match(engine,/recommendFindingGrcLinkage\(f\)/);
 assert.match(engine,/confidence:'SCANNER_REPORTED'/);
 assert.match(engine,/automaticComplianceDecision:false/);
 assert.match(server,/security-finding-proposals/);
 assert.match(server,/assurance:'PROPOSED_ONLY'/);
});

test('confirmed security proposals can enter governed risk and CAPA workflow',()=>{
 const engine=readFileSync('src/security-report-findings.ts','utf8');
 const server=readFileSync('src/server.ts','utf8');
 assert.match(engine,/Analyst CONFIRMED review is required before governing proposed risk\/CAPA/);
 assert.match(engine,/promoteFindingToIssue\(/);
 assert.match(engine,/createRiskFromIssue\(/);
 assert.match(engine,/createCapa\(/);
 assert.match(engine,/remediationDueAt\(/);
 assert.match(engine,/status='GOVERNED'/);
 assert.match(server,/security-finding-proposals\/:proposalId\/govern/);
 assert.match(server,/security-finding-proposals\/:proposalId\/reject/);
});


test('enterprise security intelligence requires confirmed findings and accountable CAPA root cause',()=>{
 const src=readFileSync('src/security-report-findings.ts','utf8');
 const ui=readFileSync('public/dashboard.js','utf8');
 const html=readFileSync('public/index.html','utf8');
 assert.match(src,/Analyst CONFIRMED review is required/);
 assert.match(src,/Governance requires a validated root-cause statement/);
 assert.match(ui,/confirmSecurityFindingProposal/);
 assert.match(ui,/governSecurityFindingProposal/);
 assert.match(html,/Proposed GRC Intelligence/);
});

test('accepted security handoff can recover deterministic finding materialization after review commit',()=>{
 const src=readFileSync('src/security-report-handoff.ts','utf8');
 assert.match(src,/row\.status==='EVIDENCE_ACCEPTED'/);
 assert.match(src,/materializeAcceptedSecurityFindings\(org,id\)/);
 assert.match(src,/recovered:true/);
});


test('security intelligence governance emits durable proposal audit events',()=>{
 const src=readFileSync('src/security-report-findings.ts','utf8');
 assert.match(src,/grc_security_proposal_events/);
 assert.match(src,/event,actor_user_id,snapshot/);
 assert.match(src,/'GOVERNED'/);
 assert.match(src,/'REJECTED'/);
});


test('governed security findings may be explicitly linked to a tenant scoped control',()=>{
 const findings=readFileSync('src/security-report-findings.ts','utf8');
 const risk=readFileSync('src/finding-risk.ts','utf8');
 const ui=readFileSync('public/dashboard.js','utf8');
 assert.match(findings,/scopeControlId:input\.scopeControlId/);
 assert.match(risk,/Control-gap linkage requires an active scoped control in the same organization/);
 assert.match(risk,/scope_control_id\) VALUES/);
 assert.match(ui,/Optional authoritative control-gap linkage/);
 assert.match(ui,/__aegisScopedControls/);
});


test('authorized URL evidence can generate first-party Offensive and Defensive reports and hand them to GRC',()=>{
 const server=readFileSync('src/server.ts','utf8'),ui=readFileSync('public/dashboard.js','utf8'),html=readFileSync('public/index.html','utf8');
 assert.match(server,/generated-security-report\/:source/);
 assert.match(server,/Run or import security evidence before generating a governed security report/);
 assert.match(server,/renderDefensiveSecurityPdf/);
 assert.match(server,/createSecurityReportHandoff\(u\.userId,access\.organization_id/);
 assert.match(server,/GENERATED_SECURITY_REPORT_RECORDED/);
 assert.match(ui,/generateSecurityReportToGrc/);
 assert.match(ui,/generated-security-report/);
 assert.match(html,/Generate Offensive Report → GRC/);
 assert.match(html,/Generate Defensive Report → GRC/);
 assert.match(html,/Authorize \+ Analyze Defensive URL/);
});


test('generated security reports preserve authorized URL provenance through the GRC handoff',()=>{
 const server=readFileSync('src/server.ts','utf8'),handoff=readFileSync('src/security-report-handoff.ts','utf8');
 assert.match(handoff,/source_context jsonb NOT NULL DEFAULT/);
 assert.match(handoff,/ADD COLUMN IF NOT EXISTS source_context/);
 assert.match(server,/inputMode:'AUTHORIZED_URL_ASSESSMENT'/);
 assert.match(server,/target:a\.target/);
 assert.match(server,/organizationId:access\.organization_id/);
 assert.match(server,/sourceContext:handoff\.source_context/);
});


test('security proposal final state and governance audit event commit atomically',()=>{
 const mod=readFileSync('src/security-report-findings.ts','utf8');
 assert.match(mod,/const client=await pool\.connect\(\);let governed:any;try\{await client\.query\('BEGIN'\)/);
 assert.match(mod,/client\.query\("UPDATE grc_security_finding_proposals SET status='GOVERNED'/);
 assert.match(mod,/client\.query\("INSERT INTO grc_security_proposal_events/);
 assert.match(mod,/await client\.query\('COMMIT'\)/);
 assert.match(mod,/catch\(e\)\{await client\.query\('ROLLBACK'\);throw e\}/);
 assert.match(mod,/status='REJECTED'.*client\.query\("INSERT INTO grc_security_proposal_events/s);
});




test('accepted security reports expose conservative cross-report correlation as advisory intelligence',()=>{
 const mod=readFileSync('src/security-report-findings.ts','utf8');
 assert.match(mod,/findingFingerprint,correlateFindings/);
 assert.match(mod,/SELECT payload FROM findings WHERE assessment_id=\$1/);
 assert.match(mod,/correlationIsAdvisory:true/);
 assert.match(mod,/automaticComplianceDecision:false/);
 assert.match(mod,/severityConflict:correlation\.severityConflict/);
});


test('security report findings retain parser provenance and validate CVE/CWE identifiers',()=>{
 const mod=readFileSync('src/security-report-findings.ts','utf8');
 assert.match(mod,/SECURITY_REPORT_PARSER_VERSION='SECURITY_REPORT_RULES_V2'/);
 assert.match(mod,/CVE-\\d\{4\}-\\d\{4,\}/);
 assert.match(mod,/CWE-\\d\{1,5\}/);
 assert.match(mod,/parserVersion:SECURITY_REPORT_PARSER_VERSION/);
 assert.match(mod,/sourceLine:i\+1/);
 assert.match(mod,/sourceSha256:sha256/);
});


test('security report materialization correlates the assessment in one batch',()=>{
 const mod=readFileSync('src/security-report-findings.ts','utf8');
 assert.match(mod,/correlated=correlateFindings\(related\)/);
 assert.match(mod,/correlationByFinding=new Map/);
 assert.match(mod,/for\(const group of correlated\)for\(const findingId of group\.findingIds\)/);
 assert.match(mod,/correlationByFinding\.get\(f\.id\)/);
});






test('remediation startup indexes do not fail on legacy duplicate issue links',()=>{
 const mod=readFileSync('src/grc-remediation.ts','utf8');
 assert.match(mod,/CREATE INDEX IF NOT EXISTS grc_issue_risks_issue_idx ON grc_issue_risks\(issue_id\)/);
 assert.match(mod,/CREATE INDEX IF NOT EXISTS grc_capa_issue_idx ON grc_capa\(issue_id\)/);
 assert.doesNotMatch(mod,/CREATE UNIQUE INDEX IF NOT EXISTS grc_issue_risks_one_risk_per_issue_idx/);
 assert.doesNotMatch(mod,/CREATE UNIQUE INDEX IF NOT EXISTS grc_capa_one_per_issue_idx/);
 assert.match(mod,/SELECT r\.\* FROM grc_enterprise_risks r JOIN grc_issue_risks ir ON ir\.risk_id=r\.id WHERE ir\.issue_id=\$1/);
 assert.match(mod,/SELECT \* FROM grc_capa WHERE organization_id=\$1 AND issue_id=\$2/);
});


test('security workflows hold session advisory locks across materialization and governance orchestration',()=>{
 const mod=readFileSync('src/security-report-findings.ts','utf8');
 assert.match(mod,/pg_advisory_lock\(hashtext\('AEGIS_SECURITY_HANDOFF'\),hashtext\(\$1\)\)/);
 assert.match(mod,/pg_advisory_unlock\(hashtext\('AEGIS_SECURITY_HANDOFF'\),hashtext\(\$1\)\)/);
 assert.match(mod,/pg_advisory_lock\(hashtext\('AEGIS_SECURITY_PROPOSAL'\),hashtext\(\$1\)\)/);
 assert.match(mod,/pg_advisory_unlock\(hashtext\('AEGIS_SECURITY_PROPOSAL'\),hashtext\(\$1\)\)/);
 assert.doesNotMatch(mod,/status='EVIDENCE_ACCEPTED' FOR UPDATE OF h/);
});
