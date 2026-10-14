import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('Defensive workspace is security-specific and exposes the dedicated report',async()=>{const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');assert.match(html,/Download Defensive Security Report/);assert.match(html,/Defensive Security Report/);assert.doesNotMatch(html,/AI-ASSISTED REMEDIATION/);assert.doesNotMatch(html,/>AI Remediation</)});
test('Defensive PDF follows the supplied evidence-driven report structure',async()=>{const src=await readFile(new URL('../src/defensive-report.ts',import.meta.url),'utf8');for(const heading of ['Defensive Summary','System Architecture and Security Context','Findings Register','Developer Defensive Remediation Plan','Verification and Expected Evidence','Evidence Appendix','Management Conclusion','Production Readiness Checklist','Deployment Gate and Final Disposition'])assert.match(src,new RegExp(heading));assert.match(src,/AUTOMATION AND ADVISORY BOUNDARY/);assert.match(src,/Recommendations and automation are advisory unless backed by governed execution evidence/);assert.doesNotMatch(src,/AI ADVISORY BOUNDARY/);assert.match(src,/same vulnerability fingerprint/)});
test('PDF export routes remediation purpose through dedicated Defensive renderer',async()=>{const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');assert.match(server,/kind==='remediation'\?await renderDefensiveSecurityPdf/)});


test('Defensive document workflow consumes deterministic security findings without AI UI coupling',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');assert.match(server,/execution:'REAL_DOCUMENT_ASSESSMENT'/);assert.match(server,/defensive:\{analysis,findings\}/);assert.match(js,/d\.defensive\?\.findings/);assert.doesNotMatch(js,/async function ai\(\)/);assert.doesNotMatch(js,/Preparing AI remediation/)});


test('Defensive PDF consumes governed retests and authoritative layer coverage',async()=>{const src=await readFile(new URL('../src/defensive-report.ts',import.meta.url),'utf8'),server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');assert.match(src,/Analyst Decisions and Targeted Retest Traceability/);assert.match(src,/Authoritative Assessment Coverage/);assert.match(src,/c\.retests/);assert.match(src,/sourceCodeAssurance/);assert.match(server,/renderDefensiveSecurityPdf\(a,fs,ev,await assessmentTrace/)});


test('Production readiness uses authoritative assessment assurance instead of title heuristics',async()=>{const src=await readFile(new URL('../src/defensive-report.ts',import.meta.url),'utf8');assert.match(src,/readinessCoverage/);assert.match(src,/trace\?\.webAssurance/);assert.match(src,/trace\?\.infrastructureAssurance/);assert.match(src,/trace\?\.identityAssurance/);assert.match(src,/trace\?\.endpointAssurance/);assert.match(src,/trace\?\.breachTelemetryAssurance/);assert.match(src,/EVIDENCE_RECORDED/);assert.doesNotMatch(src,/cat\.split\(' '\)\[0\]/);});
