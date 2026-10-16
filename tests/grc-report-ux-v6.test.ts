import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';

test('framework report export uses explicit framework selector and governed step-up flow',async()=>{
 const html=await readFile('public/index.html','utf8'),js=await readFile('public/dashboard.js','utf8');
 assert.match(html,/id="fwReportFramework"/);
 assert.match(html,/Download Governed Report/);
 assert.match(html,/password and current 6-digit authenticator code/);
 assert.match(js,/pendingExport=\{framework,format:fwFormat\.value\}/);
 assert.match(js,/syncFrameworkReportSelector/);
 assert.match(js,/x-report-password/);
 assert.match(js,/x-report-totp/);
});

test('audit timeline accepts only selected governed UUID records',async()=>{
 const html=await readFile('public/index.html','utf8'),js=await readFile('public/dashboard.js','utf8');
 assert.match(html,/<select id="timelineId"/);
 assert.doesNotMatch(html,/id="timelineId" placeholder="Record ID"/);
 assert.match(html,/data-aegis-change="refreshTimelineRecordOptions\(\)"/);
 assert.match(js,/refreshTimelineRecordOptions/);
 assert.match(js,/Free-text identifiers are not accepted/);
 assert.match(js,/\^\[0-9a-f\]\{8\}/);
});

test('framework PDF follows governed professional report structure',async()=>{
 const pdf=await readFile('src/pdf.ts','utf8');
 for(const section of ['GOVERNED FRAMEWORK ASSESSMENT','Executive GRC Summary','Framework Control Assurance Matrix','Evidence-Backed Findings & Treatment Register','Evidence Provenance & Assurance Limitations','Consultant Review, Approval & Management Conclusion']) assert.ok(pdf.includes(section),section);
 assert.match(pdf,/not ISO certification or third-party attestation/);
 assert.match(pdf,/NOT_TESTED/);
});

test('Enterprise GRC export is exposed in workspace hero like Offensive report export',async()=>{const html=await readFile('public/index.html','utf8');const off=html.indexOf('Export Offensive Technical Report');const grc=html.indexOf('Export Enterprise GRC Report');const hero=html.indexOf('Enterprise GRC Command Center');assert.ok(off>0);assert.ok(grc>hero&&grc-hero<1200);assert.match(html,/data-aegis-click="downloadEnterpriseGrc\(\)"/);});

test('top GRC export requires explicit framework format and step-up authentication',async()=>{const html=await readFile('public/index.html','utf8'),js=await readFile('public/dashboard.js','utf8');assert.match(html,/id="grcHeroFramework"/);assert.match(html,/id="grcHeroFormat"/);assert.match(html,/Export Enterprise GRC Report/);assert.match(js,/Select the framework for this GRC report first/);assert.match(js,/pendingExport=\{kind:'enterprise',enterprise:true,framework:fw,format\}/);assert.match(js,/x-report-password/);assert.match(js,/x-report-totp/);});
