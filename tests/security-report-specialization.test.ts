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
