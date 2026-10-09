import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
test('dashboard HTML has no literal escaped newline between sections',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.doesNotMatch(html,/<\/section>\\n<section/);
});

test('dashboard exposes authenticated audit traceability workspace',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.match(html,/id="audittrace"/);
 assert.match(html,/loadAuditTrace\(\)/);
 assert.match(html,/audit-package\.\'+format/);
 assert.match(html,/Download PDF/);
 assert.match(html,/Download DOCX/);
 assert.match(html,/Download XLSX/);
});

test('premium Aegis identity and login hero are present',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.match(html,/class="brand-shield hero-shield"/);
 assert.match(html,/LIVE SECURITY CONTROL PLANE/);
 assert.match(html,/class="executive-hero"/);
 assert.match(html,/AEGIS COMMAND CENTER/);
});
test('rendered HTML has no literal escaped newline markup artifacts',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const htmlOnly=html.split('<script>')[0];
 assert.doesNotMatch(htmlOnly,/\\n/);
});
