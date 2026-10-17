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
 assert.match(ui,/Document-to-GRC Intake/);assert.match(ui,/AI\/LLM/);assert.match(ui,/Independent Approval/);
 for(const fn of ['parseGrcIntake','saveGrcIntakeReview','approveGrcIntake','importGrcIntake'])assert.match(js,new RegExp('function '+fn+'\\('));
 assert.match(engine,/automaticComplianceDecision:false/);assert.match(engine,/Independent reviewer required/);assert.doesNotMatch(engine,/gemini|openai|anthropic|llm/i);
});
test('intake persists staging separately and never directly writes compliance state',()=>{
 const s=fs.readFileSync('src/grc-document-intake.ts','utf8');assert.match(s,/grc_document_intakes/);assert.match(s,/grc_document_intake_proposals/);assert.match(s,/status='APPROVED'/);assert.match(s,/grc_scope_controls/);assert.match(s,/automaticComplianceDecision:false/);assert.doesNotMatch(s,/UPDATE grc_control_assessments SET overall_status/);
});

test('governed import targets the live scope-control schema and requires an explicit scope',()=>{
 const s=fs.readFileSync('src/grc-document-intake.ts','utf8');
 assert.match(s,/A governed scope is required before importing control proposals/);
 assert.match(s,/INSERT INTO grc_scope_controls\(id,organization_id,scope_id,control_id,applicability,implementation,applicability_justification\)/);
 assert.doesNotMatch(s,/implementation_status|\bjustification\) VALUES/);
 assert.match(s,/nextLine=.*anchors\[i\+1\]\.source_line/);
});

test('intake validates upload trust boundaries and reviewer separation',()=>{
 const x=fs.readFileSync('src/grc-document-intake.ts','utf8');
 assert.match(x,/between 1 byte and 10 MB/);
 assert.match(x,/content signature do not match an allowed deterministic intake format/);
 assert.match(x,/Proposal not found in this intake/);
 assert.match(x,/Approver must be independent from proposal reviewer/);
 assert.match(x,/Approved or imported intake cannot be modified/);
});
test('import fails closed when nothing can be safely adapted and discloses partial adapters',()=>{
 const x=fs.readFileSync('src/grc-document-intake.ts','utf8');
 assert.match(x,/nothing was imported/);
 assert.match(x,/remain staged because no safe deterministic write adapter is enabled/);
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
