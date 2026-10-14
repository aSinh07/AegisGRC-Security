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

test('core UI delegation is registered before optional canvas graphics and graphics are fail-safe',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');const listener=js.indexOf("document.addEventListener('click'");const ambient=js.indexOf('try{ambient()}');const cyber=js.indexOf('try{cyber()}');assert.ok(listener>=0&&ambient>listener&&cyber>listener);assert.match(js,/if\(!c\)return;const x=c\.getContext\('2d'\);if\(!x\)return;/);assert.match(js,/Ambient graphics disabled/);assert.match(js,/Login graphics disabled/);});

test('all decorative startup canvases fail safely without disabling controls',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(js,/if\(!x\)\{c\.remove\(\);return\}/);assert.match(js,/try\{sparkle\(\)\}catch\(e\)\{console\.warn\('Sparkle graphics disabled',e\)\}/);const click=js.indexOf("document.addEventListener('click'");for(const startup of ['try{sparkle()}','try{ambient()}','try{cyber()}'])assert.ok(js.indexOf(startup)>click);});

test('authentication actions are published before non-auth dashboard startup',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');const publish=js.indexOf('Object.assign(globalThis,{authMode,togglePassword,openReset,closeReset,resetPassword,doLogin,startEnroll,finishEnroll})');assert.ok(publish>0);for(const startup of ['function showApp()','try{sparkle()}','try{ambient()}','try{cyber()}'])assert.ok(publish<js.indexOf(startup),`auth publication must precede ${startup}`);});

test('authentication controls have direct browser bindings independent of delegated action parsing',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');for(const binding of [\"authMode('signin')\",\"authMode('signup')\",'doLogin()','startEnroll()','finishEnroll()','openReset()','closeReset()'])assert.match(js,new RegExp('bind\\\\(.*'+binding.replace(/[()']/g,'\\\\$&')));assert.match(js,/document\.documentElement\.dataset\.aegisJs='ready'/);assert.match(js,/event\.target instanceof Element/);});
