import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {parseGrcDocumentDeterministically} from '../src/grc-document-intake.js';

test('deterministic GRC intake extracts labelled governance facts without AI',()=>{
 const p=parseGrcDocumentDeterministically('Control ID: IAM-01\nImplementation Status: Implemented\nControl Owner: Security Team\nRisk ID: RISK-17\nVendor Name: Example Cloud Ltd');
 assert.ok(p.some(x=>x.field==='controlKey'&&x.value==='IAM-01'));
 assert.ok(p.some(x=>x.field==='implementation'&&x.value.toLowerCase()==='implemented'));
 assert.ok(p.some(x=>x.field==='riskKey'&&x.value==='RISK-17'));
 assert.ok(p.some(x=>x.field==='vendorName'&&x.value==='Example Cloud Ltd'));
 assert.ok(p.every(x=>x.rule.startsWith('LABEL_')&&x.source.line>0&&x.confidence<=.95));
});
test('intake engine does not invent facts from unlabelled prose',()=>{assert.deepEqual(parseGrcDocumentDeterministically('This document discusses governance generally without structured labelled records.'),[])});
test('Document-to-GRC UI requires staged human review and discloses no AI',()=>{
 const ui=fs.readFileSync('public/index.html','utf8'),js=fs.readFileSync('public/dashboard.js','utf8'),engine=fs.readFileSync('src/grc-document-intake.ts','utf8');
 assert.match(ui,/Document-to-GRC Intake/);assert.match(ui,/No parsing result declares compliance/);assert.match(ui,/Independent Approval/);
 for(const fn of ['parseGrcIntake','saveGrcIntakeReview','approveGrcIntake','importGrcIntake'])assert.match(js,new RegExp('function '+fn+'\\('));
 assert.match(engine,/automaticComplianceDecision:false/);assert.match(engine,/Independent reviewer required/);assert.doesNotMatch(engine,/gemini|openai|anthropic|llm/i);
});
test('intake persists staging separately and never directly writes compliance state',()=>{
 const s=fs.readFileSync('src/grc-document-intake.ts','utf8');assert.match(s,/grc_document_intakes/);assert.match(s,/grc_document_intake_proposals/);assert.match(s,/status='APPROVED'/);assert.match(s,/grc_scope_controls/);assert.match(s,/automaticComplianceDecision:false/);assert.doesNotMatch(s,/UPDATE grc_control_assessments SET overall_status/);
});

test('governed import targets live enterprise modules and requires an explicit scope',()=>{
 const s=fs.readFileSync('src/grc-document-intake.ts','utf8');
 assert.match(s,/A governed scope is required before importing document proposals/);
 for(const table of ['grc_scope_controls','grc_enterprise_risks','grc_third_parties','grc_policies','grc_audits','grc_document_governed_records'])assert.match(s,new RegExp(table));
 assert.match(s,/automaticComplianceDecision:false/);
});

test('incomplete approved controls enter the governed scope as pending review without inventing compliance',()=>{
 const x=fs.readFileSync('src/grc-document-intake.ts','utf8');
 assert.match(x,/suppliedApplicability\|\|'PENDING'/);
 assert.match(x,/suppliedImplementation\|\|'NOT_IMPLEMENTED'/);
 assert.match(x,/accountable human review required/);
 assert.match(x,/automaticComplianceDecision:false/);
});

test('intake validates upload trust boundaries and reviewer separation',()=>{
 const x=fs.readFileSync('src/grc-document-intake.ts','utf8');
 assert.match(x,/between 1 byte and 10 MB/);
 assert.match(x,/content signature do not match an allowed deterministic intake format/);
 assert.match(x,/Proposal not found in this intake/);
 assert.match(x,/Approver must be independent from proposal reviewer/);
 assert.match(x,/Approved or imported intake cannot be modified/);
});
test('import fails closed and preserves incomplete document facts for review',()=>{
 const x=fs.readFileSync('src/grc-document-intake.ts','utf8');
 assert.match(x,/nothing was imported/);
 assert.match(x,/remains staged because likelihood and impact 1-5 are required/);
 assert.match(x,/remains staged because title, objective and criteria are required/);
});

test('Enterprise GRC presents intake before scope operations and report export as final step',()=>{
 const ui=fs.readFileSync('public/index.html','utf8');
 const intake=ui.indexOf('STEP 1 · INGEST & STAGE');
 const scopes=ui.indexOf('<h3>Scopes</h3>');
 const report=ui.indexOf('FINAL STEP · REPORTING');
 assert.ok(intake>0&&scopes>intake&&report>scopes);
 assert.ok(ui.indexOf('INTAKE</span>')<ui.indexOf('REVIEW</span>')&&ui.indexOf('REVIEW</span>')<ui.indexOf('IMPORT</span>')&&ui.indexOf('IMPORT</span>')<ui.indexOf('SCOPE & CONTROLS</span>')&&ui.indexOf('SCOPE & CONTROLS</span>')<ui.indexOf('EVIDENCE</span>')&&ui.indexOf('EVIDENCE</span>')<ui.indexOf('REPORT</span>'));
 assert.match(ui,/Generate & Export Enterprise GRC Report/);
});

test('intake can stage before scope but governed import binds an explicit organization scope',()=>{
 const js=fs.readFileSync('public/dashboard.js','utf8'),server=fs.readFileSync('src/server.ts','utf8'),engine=fs.readFileSync('src/grc-document-intake.ts','utf8');
 assert.match(js,/if\(activeGrcScope\)form\.append\('scopeId',activeGrcScope\)/);
 assert.match(js,/Select or create the governed target scope before import/);
 assert.match(js,/document-intakes\/.*\/scope/);
 assert.match(server,/document-intakes\/:id\/scope/);
 assert.match(engine,/export async function bindGrcIntakeScope/);
 assert.match(engine,/Imported intake scope cannot be changed/);
 assert.match(engine,/Scope not found in organization/);
});

test('Document-to-GRC supports multi-file staging and responsive async review actions',()=>{
 const ui=fs.readFileSync('public/index.html','utf8'),js=fs.readFileSync('public/dashboard.js','utf8');
 assert.match(ui,/id="grcIntakeFile" type="file" multiple/);
 assert.match(ui,/Upload & Autofill Documents/);
 assert.match(js,/async function parseGrcIntake\(\)/);
 assert.match(js,/files=\[\.\.\.\(input\?\.files\|\|\[\]\)\]/);
 assert.match(js,/for\(let i=0;i<files\.length;i\+\+\)/);
 assert.match(js,/results\.push\(\{ok:true,file:file\.name,id:created\.id/);
 assert.match(js,/Existing GRC fields were populated where deterministic document facts were available/);
 assert.match(js,/async function saveGrcIntakeReview\(\)/);
 assert.match(js,/Saving '\+decisions\.length\+' review decision\(s\)/);
 assert.match(js,/This intake is REVIEWED; an independent reviewer may now approve it/);
});


test('Document intake reuses duplicates and supports direct scope autofill',()=>{
 const source=fs.readFileSync('src/grc-document-intake.ts','utf8');
 const server=fs.readFileSync('src/server.ts','utf8');
 const ui=fs.readFileSync('public/dashboard.js','utf8');
 const html=fs.readFileSync('public/index.html','utf8');
 assert.match(source,/reused:true/);
 assert.match(source,/applyGrcIntakeAutofill/);
 assert.match(source,/scopeDescription/);
 assert.match(server,/document-intakes\/:id\/autofill/);
 assert.match(ui,/document-intakes\/'\+encodeURIComponent\(created\.id\)\+'\/autofill/);
 assert.match(ui,/if\(btn\)btn\.disabled=false/);
 assert.match(html,/Upload & Autofill Documents/);
});

test('document parser covers enterprise GRC report domains without inventing approvals',()=>{
 const p=parseGrcDocumentDeterministically('Scope: Banking AI\nControl ID: CFG-02\nControl Title: Secure AI gateway\nApplicability: Applicable\nImplementation Status: Partial\nRisk Title: Prompt injection\nLikelihood: 4\nImpact: 5\nRisk Treatment: Mitigate\nVendor Name: Model Cloud\nVendor Service: Hosted model\nPolicy Title: AI Security Policy\nPolicy Version: 2.0\nAudit Title: AIMS Internal Audit\nAudit Objective: Evaluate AIMS controls\nAudit Criteria: ISO 42001\nAudit Finding: Evidence review is incomplete');
 for(const f of ['scopeName','controlTitle','riskTitle','likelihood','impact','vendorName','policyTitle','auditTitle','auditFinding'])assert.ok(p.some(x=>x.field===f),f+' missing');
});

test('multi-document autofill exposes provenance and flags conflicts instead of overwriting',()=>{
 const js=fs.readFileSync('public/dashboard.js','utf8'),html=fs.readFileSync('public/index.html','utf8'),engine=fs.readFileSync('src/grc-document-intake.ts','utf8');
 assert.match(js,/mergeDocumentAutofill/);assert.match(js,/CONFLICT — REVIEW/);assert.match(js,/sourceLine/);
 assert.match(html,/grcIntakeAutofill/);assert.match(engine,/sourceProvenancePreserved:true/);assert.match(engine,/governedRecords:true/);
});

test('enterprise exporters disclose populated vendor policy audit and finding detail',()=>{
 const e=fs.readFileSync('src/enterprise-grc-exporters.ts','utf8'),a=fs.readFileSync('src/audit-management.ts','utf8');
 assert.match(e,/Findings \/ workpapers/);assert.match(e,/thirdPartyRisk\?\.vendors/);assert.match(e,/policyGovernance\?\.policies/);assert.match(a,/workpaper_details/);
});

test('enterprise report carries imported document provenance without treating declared frameworks as mappings',()=>{
 const engine=fs.readFileSync('src/grc-document-intake.ts','utf8'),server=fs.readFileSync('src/server.ts','utf8'),report=fs.readFileSync('src/enterprise-grc-report.ts','utf8'),exporters=fs.readFileSync('src/enterprise-grc-exporters.ts','utf8');
 assert.match(engine,/documentIntakeReportContext/);assert.match(server,/documentIntakeReportContext/);assert.match(report,/documentDeclaredFrameworks/);assert.match(exporters,/Document declarations are provenance only until mapped to governed controls/);
});

test('every successful multi-document upload remains reachable for review',()=>{const js=fs.readFileSync('public/dashboard.js','utf8');assert.match(js,/data-action="openGrcIntake"/);assert.match(js,/Review '\+esc\(r\.file\)/);});

test('expanded intake parser covers additional GRC domains',()=>{const p=parseGrcDocumentDeterministically('Processing Activity Key: PA-01\nProcessing Activity Name: Customer Analytics\nProcessing Purpose: Service monitoring\nProcessing Ground: Contract\nRetention Rule: 365 days\nLegal Reference Key: LAW-01\nLegal Requirement Title: Governance requirement\nAuthoritative Source Reference: internal register\nBusiness Service Key: PAY-01\nBusiness Service Name: Payments\nRTO Minutes: 60\nRPO Minutes: 15\nMTD Minutes: 120\nRisk Appetite Key: OPS\nRisk Appetite Title: Operational Risk\nRisk Appetite Statement: Maintain exposure within approved management tolerance.\nMetric Key: KRI-01\nMetric Title: Open findings age\nMetric Type: KRI');for(const x of ['activityKey','legalKey','serviceKey','rtoMinutes','appetiteKey','metricKey'])assert.ok(p.some(y=>y.field===x),x+' missing')});

test('enterprise exporters include additional governed registers',()=>{const e=fs.readFileSync('src/enterprise-grc-exporters.ts','utf8');assert.match(e,/Processing Inventory/);assert.match(e,/Legal Register/)});


test('ISO 42001 AI impact intake requires independently validated current Evidence Vault versions',()=>{
 const p=parseGrcDocumentDeterministically('AI Impact Key: AI-IMPACT-DEMO-01\nReview Period: 2026-Q4\nAI System: Fraud Decision Support\nIntended Use: Assist analysts with fraud triage decisions.\nForeseeable Misuse: Automated adverse action without analyst review.\nAffected Parties: Retail banking customers and fraud analysts.\nData Exposure Impact: Customer financial data could be exposed to unauthorized recipients.\nErroneous Output Impact: False positives could delay legitimate customer transactions.\nDownstream Impact: Incorrect decisions could propagate into case-management workflows.\nHuman Oversight: Analysts review recommendations before consequential action.\nReview Triggers: Model change, material incident, or significant data drift.\nAI Risk Rating: High\nEvidence Vault Version IDs: 11111111-1111-4111-8111-111111111111');
 for(const field of ['impactKey','reviewPeriod','aiSystem','intendedUse','foreseeableMisuse','affectedParties','dataExposureImpact','erroneousOutputImpact','downstreamImpact','humanOversight','reviewTriggers','riskRating','evidenceRefs'])assert.ok(p.some(x=>x.field===field),field+' missing');
 const x=fs.readFileSync('src/grc-document-intake.ts','utf8');
 assert.match(x,/current Evidence Vault version UUIDs must be explicitly supplied and validated/);
 assert.match(x,/supplied Evidence Vault versions are not all current and independently validated/);
 assert.match(x,/validated_by IS NOT NULL/);assert.match(x,/validated_by IS DISTINCT FROM v\.submitted_by/);assert.match(x,/valid_until>now\(\)/);
 assert.match(x,/status='SUBMITTED'/);assert.doesNotMatch(x,/AI_IMPACT[\\s\\S]{0,5000}status='APPROVED'/);
});


test('organization reviewer onboarding is email based and preserves independent approval',()=>{
 const org=fs.readFileSync('src/grc-organizations.ts','utf8');
 const server=fs.readFileSync('src/server.ts','utf8');
 const html=fs.readFileSync('public/index.html','utf8');
 const dash=fs.readFileSync('public/dashboard.js','utf8');
 assert.match(org,/export async function addMemberByEmail/);
 assert.match(org,/Registered and MFA-verified AegisGRC user not found for this email/);
 assert.match(server,/members\/by-email/);
 assert.match(html,/Organization Members & Independent Reviewers/);
 assert.match(html,/value="REVIEWER"/);
 assert.match(dash,/async function addGrcMemberByEmail/);
 assert.match(dash,/loadGrcMembers\(\)/);
 assert.match(org,/review:new Set<OrgRole>\(\['GRC_MANAGER','GRC_CONSULTANT','REVIEWER','AUDITOR'\]\)/);
 assert.doesNotMatch(org,/review:new Set<OrgRole>\(\[[^\]]*'ORG_ADMIN'/);
});

test('independent reviewer can discover existing tenant intakes without re-uploading documents',()=>{
 const intake=fs.readFileSync('src/grc-document-intake.ts','utf8');
 const server=fs.readFileSync('src/server.ts','utf8');
 const html=fs.readFileSync('public/index.html','utf8');
 const dash=fs.readFileSync('public/dashboard.js','utf8');
 assert.match(intake,/export async function listGrcIntakes/);
 assert.match(server,/organizations\/:orgId\/document-intakes'/);
 assert.match(html,/Pending Reviews & Approvals/);
 assert.match(dash,/async function loadGrcIntakeQueue/);
 assert.match(dash,/Open for independent approval/);
 assert.match(dash,/loadGrcIntakeQueue\(\)/);
});


test('document approval queue exposes reviewed intakes to independent governance roles',()=>{
 const org=fs.readFileSync('src/grc-organizations.ts','utf8');
 const html=fs.readFileSync('public/index.html','utf8');
 const dash=fs.readFileSync('public/dashboard.js','utf8');
 assert.match(org,/GRC_CONSULTANT/);
 assert.match(org,/review:new Set<OrgRole>\(\['GRC_MANAGER','GRC_CONSULTANT','REVIEWER','AUDITOR'\]\)/);
 assert.doesNotMatch(org,/review:new Set<OrgRole>\([^\n]*'ORG_ADMIN'/);
 assert.match(html,/Pending Reviews & Approvals/);
 assert.match(html,/value="GRC_CONSULTANT"/);
 assert.match(dash,/async function loadGrcIntakeQueue/);
 assert.match(dash,/Open for independent approval/);
});


test('Enterprise GRC exposes live intake decisions and Offensive Defensive evidence review',()=>{const js=fs.readFileSync('public/dashboard.js','utf8'),html=fs.readFileSync('public/index.html','utf8'),server=fs.readFileSync('src/server.ts','utf8'),intake=fs.readFileSync('src/grc-document-intake.ts','utf8');assert.match(intake,/accepted_proposals/);assert.match(intake,/rejected_proposals/);assert.match(html,/Offensive \/ Defensive Evidence Review/);assert.match(js,/async function loadSecurityHandoffs/);assert.match(js,/Accept Evidence/);assert.match(js,/Download evidence/);assert.match(js,/setInterval\(\(\)=>/);assert.match(server,/handoffSource=description\.startsWith\('Offensive'\)/);assert.match(server,/createSecurityReportHandoff\(u\.userId,access\.organization_id/);});
