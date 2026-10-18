import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';

test('framework crosswalk no longer exposes redundant framework-specific download workflow',async()=>{
 const html=await readFile('public/index.html','utf8');
 assert.doesNotMatch(html,/id="fwReportFramework"/);assert.doesNotMatch(html,/Download Governed Report/);assert.match(html,/Enterprise GRC Intake/);
});
test('audit timeline accepts only selected governed UUID records',async()=>{
 const html=await readFile('public/index.html','utf8'),dashboard=await readFile('public/dashboard.js','utf8'),ops=await readFile('public/enterprise-ops.js','utf8'),js=dashboard+'\\n'+ops;
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

test('Enterprise GRC export is a final lifecycle action after intake and scope work',async()=>{const html=await readFile('public/index.html','utf8');const off=html.indexOf('Export Offensive Technical Report');const intake=html.indexOf('STEP 1 · INGEST & STAGE');const scopes=html.indexOf('<h3>Scopes</h3>');const report=html.indexOf('FINAL STEP · REPORTING');const grc=html.indexOf('Generate & Export Enterprise GRC Report');assert.ok(off>0);assert.ok(intake>0&&scopes>intake&&report>scopes&&grc>report);assert.match(html,/data-aegis-click="downloadEnterpriseGrc\(\)"/);});

test('top GRC export requires explicit framework format and step-up authentication',async()=>{const html=await readFile('public/index.html','utf8'),js=await readFile('public/dashboard.js','utf8');assert.match(html,/id="grcHeroFramework"/);assert.match(html,/id="grcHeroFormat"/);assert.match(html,/Generate & Export Enterprise GRC Report/);assert.match(js,/Select the framework for this GRC report first/);assert.match(js,/pendingExport=\{kind:'enterprise',enterprise:true,framework:fw,format\}/);assert.match(js,/x-report-password/);assert.match(js,/x-report-totp/);});


test('enterprise report selection is wired end-to-end and PDF footer stays inside content bounds',async()=>{const [js,server,model,pdf]=await Promise.all([readFile(new URL('../public/dashboard.js',import.meta.url),'utf8'),readFile(new URL('../src/server.ts',import.meta.url),'utf8'),readFile(new URL('../src/enterprise-grc-report.ts',import.meta.url),'utf8'),readFile(new URL('../src/enterprise-grc-exporters.ts',import.meta.url),'utf8')]);assert.match(js,/enterprise-report\.'\+encodeURIComponent\(format\)\+'\?framework='\+encodeURIComponent\(framework\)/);assert.match(server,/req\.query\.framework/);assert.match(server,/selectedFramework:selectedFramework\|\|undefined/);assert.match(model,/scopeMode:selectedFramework\?'FRAMEWORK_FILTERED':'MULTI_FRAMEWORK'/);assert.match(model,/new Map\(rows\(c\.mappings\)/);assert.match(pdf,/Framework traceability:/);assert.match(pdf,/Evidence.*Test.*ACTION_REQUIRED/);assert.match(pdf,/left,780/);assert.doesNotMatch(pdf,/left,806/)});


test('enterprise GRC cover mirrors Offensive report geometry and branding',async()=>{const pdf=await readFile(new URL('../src/enterprise-grc-exporters.ts',import.meta.url),'utf8');for(const token of ["d.rect(0,100,pageW,230).fill(coverNavy)","d.rect(left,126,52,5).fill(coverCyan)","fontSize(30).text('AEGIS'","fontSize(30).text('GRC'","GRC ASSURANCE REPORT","Enterprise Governance, Risk & Compliance Assurance","EVIDENCE ASSURANCE STATEMENT"]) assert.ok(pdf.includes(token),token);assert.match(pdf,/const coverMeta=\[\['Organization'/);assert.match(pdf,/left\+120,cy/);assert.doesNotMatch(pdf,/ENTERPRISE GRC\\nASSURANCE REPORT/);});


test('enterprise GRC repeats table headers, uses portable traceability, and discloses security evidence handoffs',async()=>{const pdf=await readFile(new URL('../src/enterprise-grc-exporters.ts',import.meta.url),'utf8');assert.match(pdf,/addContentPage\(\);draw\(headers,true,true\)/);assert.match(pdf,/Framework traceability:.*-> Evidence:.*-> Test:.*-> Readiness:/);assert.doesNotMatch(pdf,/Framework traceability:.*→/);assert.match(pdf,/Offensive \/ Defensive Security Evidence Handoff/);assert.match(pdf,/Accepted technical reports:/);assert.match(pdf,/Pending GRC review:/);assert.match(pdf,/do not automatically establish control conformity/);});


test('SoA decision save validates input and exposes deterministic success or failure feedback',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(js,/async function saveSoaDecision\(\)/);assert.match(js,/Not-applicable controls require a meaningful justification/);assert.match(js,/Saving SoA decision\.\.\./);assert.match(js,/SoA decision saved successfully\./);assert.match(js,/SoA save failed:/);assert.match(js,/controlId,applicability,justification,implementation/);});


test('SoA save uses explicit DOM bindings and local visible status',async()=>{const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(html,/id="saveSoaDecisionBtn"[^>]*type="button"/);assert.match(html,/id="soaDecisionMsg"[^>]*role="status"/);assert.match(js,/document\.getElementById\('soaControl'\)/);assert.match(js,/document\.getElementById\('soaDecisionMsg'\)/);assert.match(js,/btn\.disabled=true/);assert.match(js,/SoA decision saved successfully\./);assert.match(js,/encodeURIComponent\(scopeId\)/);});


test('enterprise report never silently drops populated scope and SoA when selected framework mappings are missing',async()=>{const src=await readFile(new URL('../src/enterprise-grc-report.ts',import.meta.url),'utf8');assert.match(src,/frameworkFilterFallback/);assert.match(src,/const controls=frameworkFilterFallback\?allControls:frameworkMatchedControls/);assert.match(src,/const soaControls=frameworkFilterFallback\?allSoaControls:matchedSoaControls/);assert.match(src,/Persisted scope controls and SoA decisions are retained in this report/);});


test('Enterprise GRC exposes verified control-bound evidence upload instead of relying on assessment vault uploads',async()=>{const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');for(const id of ['grcEvidenceRequest','grcEvidenceFile','uploadGrcEvidenceBtn','grcEvidenceUploadMsg'])assert.match(html,new RegExp('id="'+id+'"'));assert.match(js,/async function uploadGrcEvidence\(\)/);assert.match(js,/evidence-requests\/.*\/upload/);assert.match(js,/body\.append\('evidence',file,file\.name\)/);assert.match(js,/SHA-256 server verified/);assert.match(js,/Independent validation is still required/);});


test('document intake autofills governance performance fields',async()=>{
 const js=await readFile('public/dashboard.js','utf8');
 for(const id of ['appetiteKey','appetiteTitle','appetiteStatement','appetiteTolerance','metricKey','metricTitle','metricType']) assert.match(js,new RegExp("set\\('"+id+"'"));
});


test('every delegated dashboard UI action is callable through globalThis',async()=>{
 const html=await readFile('public/index.html','utf8'),dashboard=await readFile('public/dashboard.js','utf8'),ops=await readFile('public/enterprise-ops.js','utf8'),js=dashboard+'\\n'+ops;
 const referenced=[...html.matchAll(/data-aegis-(?:click|change)="([A-Za-z_$][A-Za-z0-9_$]*)/g)].map(m=>m[1]);
 const dynamic=[...js.matchAll(/data-action="([A-Za-z_$][A-Za-z0-9_$]*)"/g)].map(m=>m[1]);
 const exported=new Set<string>();
 for(const m of js.matchAll(/globalThis\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=/g))exported.add(m[1]);
 for(const m of js.matchAll(/Object\.assign\(globalThis,\{([^}]*)\}\)/gs))for(const n of m[1].split(',').map(x=>x.trim()).filter(Boolean))exported.add(n.split(':')[0].trim());
 const missing=[...new Set([...referenced,...dynamic])].filter(n=>!exported.has(n));
 assert.deepEqual(missing,[],`delegated UI actions not exported: ${missing.join(', ')}`);
});


test('enterprise reporting UI exposes combined GRC offensive defensive package',async()=>{const html=await readFile('public/index.html','utf8'),js=await readFile('public/dashboard.js','utf8'),server=await readFile('src/server.ts','utf8');assert.match(html,/Combined Assurance Report · GRC \+ Offensive \+ Defensive/);assert.match(js,/package=combined/);assert.match(js,/AegisGRC-Combined-Assurance-/);assert.match(server,/COMBINED_GRC_OFFENSIVE_DEFENSIVE/);});
