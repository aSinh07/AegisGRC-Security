import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
test('dashboard HTML has no literal escaped newline between sections',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.doesNotMatch(html,/<\/section>\\n<section/);
});

test('dashboard exposes authenticated audit traceability workspace',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 const ui=html+'\n'+js;
 assert.match(html,/id="audittrace"/);
 assert.match(ui,/loadAuditTrace\(\)/);
 assert.equal(ui.includes("/audit-package.'+format"),true);
 assert.match(html,/Download PDF/);
 assert.match(html,/Download DOCX/);
 assert.match(html,/Download XLSX/);
});

test('premium Aegis identity and login hero are present',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.match(html,/class="brand-shield hero-shield"/);
 assert.match(html,/AEGISGRC SECURITY & GRC/);
 assert.match(html,/class="[^"]*executive-hero[^"]*"/);
 assert.match(html,/AEGIS COMMAND CENTER/);
});
test('rendered HTML has no literal escaped newline markup artifacts',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const bodyMarkup=html.slice(html.indexOf('</head>')+7,html.indexOf('<script>'));
 assert.doesNotMatch(bodyMarkup,/>\\n</);
});

test('premium frontend release has a verifiable marker',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.match(html,/aegis-enterprise-20261012-v4/);
});
test('server prevents stale HTML shell caching',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(server,/no-store, max-age=0, must-revalidate/);
});

test('login supports profile enrollment MFA recovery and password visibility',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 const ui=html+'\n'+js;
 for(const marker of ['Welcome!','Full name','Job title / designation','Company / organization','Department / function','What do you work on?','Google Authenticator','Microsoft Authenticator','Forgot password?','togglePassword','/api/auth/reset-password','/aegis-logo.svg'])assert.equal(ui.includes(marker),true,marker);
 assert.doesNotMatch(html,/Welcome back!/i);
});

test('audit dashboard exposes conservative breach impact review',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.match(html,/Breach & Data Exposure Review/);
 assert.match(html,/id="breachImpactRows"/);
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 const ui=html+'\n'+js;
 assert.match(ui,/renderBreachImpact/);
 assert.match(ui,/breachAssessmentsRequiringReview/);
 assert.match(html,/never treats this panel as forensic or regulatory confirmation/);
});

test('CSP delegated auth actions are explicitly registered for login and account creation',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(js,/Object\.assign\(globalThis,\{authMode,togglePassword,openReset,closeReset,resetPassword,doLogin,startEnroll,finishEnroll\}\)/);assert.match(js,/const fn=globalThis\[m\[1\]\]/);});

test('authentication UI does not depend on named DOM elements becoming window globals',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(js,/const authEl=id=>document\.getElementById\(id\)/);for(const id of ['profileFields','signinFields','enrollStart','loginMsg','email','pw','otp','login','app'])assert.match(js,new RegExp(id+"=authEl\\('"+id+"'\\)"));});
