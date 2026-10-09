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
 assert.match(html,/AEGISGRC SECURITY CONTROL PLANE/);
 assert.match(html,/class="executive-hero"/);
 assert.match(html,/AEGIS COMMAND CENTER/);
});
test('rendered HTML has no literal escaped newline markup artifacts',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const bodyMarkup=html.slice(html.indexOf('</head>')+7,html.indexOf('<script>'));
 assert.doesNotMatch(bodyMarkup,/>\\n</);
});

test('premium frontend release has a verifiable marker',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.match(html,/aegis-premium-20261010-v2/);
});
test('server prevents stale HTML shell caching',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(server,/no-store, max-age=0, must-revalidate/);
});

test('login supports profile enrollment MFA recovery and password visibility',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 for(const marker of ['Welcome!','Full name','Designation','Company name','Google Authenticator','Microsoft Authenticator','Forgot password?','togglePassword','/api/auth/reset-password','/aegis-logo.svg'])assert.equal(html.includes(marker),true,marker);
 assert.doesNotMatch(html,/Welcome back!/i);
});
