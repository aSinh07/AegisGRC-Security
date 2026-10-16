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


test('enterprise report selection is wired end-to-end and PDF footer stays inside content bounds',async()=>{const [js,server,model,pdf]=await Promise.all([readFile(new URL('../public/dashboard.js',import.meta.url),'utf8'),readFile(new URL('../src/server.ts',import.meta.url),'utf8'),readFile(new URL('../src/enterprise-grc-report.ts',import.meta.url),'utf8'),readFile(new URL('../src/enterprise-grc-exporters.ts',import.meta.url),'utf8')]);assert.match(js,/enterprise-report\.'\+encodeURIComponent\(format\)\+'\?framework='\+encodeURIComponent\(framework\)/);assert.match(server,/req\.query\.framework/);assert.match(server,/selectedFramework:selectedFramework\|\|undefined/);assert.match(model,/scopeMode:selectedFramework\?'FRAMEWORK_FILTERED':'MULTI_FRAMEWORK'/);assert.match(model,/new Map\(rows\(c\.mappings\)/);assert.match(pdf,/Framework traceability:/);assert.match(pdf,/Evidence.*Test.*ACTION_REQUIRED/);assert.match(pdf,/left,780/);assert.doesNotMatch(pdf,/left,806/)});


test('enterprise GRC cover mirrors Offensive report geometry and branding',async()=>{const pdf=await readFile(new URL('../src/enterprise-grc-exporters.ts',import.meta.url),'utf8');for(const token of ["d.rect(0,100,pageW,230).fill(coverNavy)","d.rect(left,126,52,5).fill(coverCyan)","fontSize(30).text('AEGIS'","fontSize(30).text('GRC'","GRC ASSURANCE REPORT","Enterprise Governance, Risk & Compliance Assurance","EVIDENCE ASSURANCE STATEMENT"]) assert.ok(pdf.includes(token),token);assert.match(pdf,/const coverMeta=\[\['Organization'/);assert.match(pdf,/left\+120,cy/);assert.doesNotMatch(pdf,/ENTERPRISE GRC\\nASSURANCE REPORT/);});


test('enterprise GRC repeats table headers, uses portable traceability, and discloses security evidence handoffs',async()=>{const pdf=await readFile(new URL('../src/enterprise-grc-exporters.ts',import.meta.url),'utf8');assert.match(pdf,/addContentPage\(\);draw\(headers,true,true\)/);assert.match(pdf,/Framework traceability:.*-> Evidence:.*-> Test:.*-> Readiness:/);assert.doesNotMatch(pdf,/Framework traceability:.*→/);assert.match(pdf,/Offensive \/ Defensive Security Evidence Handoff/);assert.match(pdf,/Accepted technical reports:/);assert.match(pdf,/Pending GRC review:/);assert.match(pdf,/do not automatically establish control conformity/);});


test('SoA decision save validates input and exposes deterministic success or failure feedback',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(js,/async function saveSoaDecision\(\)/);assert.match(js,/Not-applicable controls require a meaningful justification/);assert.match(js,/Saving SoA decision\.\.\./);assert.match(js,/SoA decision saved successfully\./);assert.match(js,/SoA save failed:/);assert.match(js,/controlId,applicability,justification,implementation/);});


test('SoA save uses explicit DOM bindings and local visible status',async()=>{const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(html,/id="saveSoaDecisionBtn"[^>]*type="button"/);assert.match(html,/id="soaDecisionMsg"[^>]*role="status"/);assert.match(js,/document\.getElementById\('soaControl'\)/);assert.match(js,/document\.getElementById\('soaDecisionMsg'\)/);assert.match(js,/btn\.disabled=true/);assert.match(js,/SoA decision saved successfully\./);assert.match(js,/encodeURIComponent\(scopeId\)/);});
