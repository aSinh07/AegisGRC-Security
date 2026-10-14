import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
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


test('authentication runtime is isolated from dashboard dispatcher and loaded first',async()=>{const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');const auth=await readFile(new URL('../public/auth.js',import.meta.url),'utf8');assert.ok(html.indexOf('<script src="/auth.js"></script>')>=0);assert.ok(html.indexOf('/auth.js')<html.indexOf('/dashboard.js'));assert.match(auth,/bind\('#signinTab'/);assert.match(auth,/bind\('#signupTab'/);assert.match(auth,/dataset\.aegisAuth='ready'/);assert.match(auth,/\/api\/auth\/user-login/);assert.match(auth,/\/api\/auth\/register/);assert.match(auth,/\/api\/auth\/register\/confirm/);assert.match(auth,/\/api\/auth\/reset-password/);});

test('all shipped browser JavaScript parses successfully in Node',()=>{for(const file of ['public/auth.js','public/dashboard.js','public/enhancements.js','public/architecture-3d.js','public/enterprise-ops.js']){const result=spawnSync(process.execPath,['--check',file],{encoding:'utf8'});assert.equal(result.status,0,file+' failed syntax validation: '+result.stderr);}});

test('extracted dashboard stylesheet contains no HTML or escaped-newline migration artifacts',async()=>{const css=await readFile('public/dashboard.css','utf8');assert.equal(css.includes('<style>'),false);assert.equal(css.includes('\\n'),false);assert.match(css,/\.loginbox\.auth-reference\{[^}]*width:min\(1180px,96vw\)/);assert.match(css,/\.profile-shell\{position:relative\}/)});
test('enterprise shell presents one workspace identity and top-right profile action',async()=>{const html=await readFile('public/index.html','utf8');const css=await readFile('public/dashboard.css','utf8');assert.equal((html.match(/Security & GRC Workspace/g)||[]).length,0);assert.match(html,/class="top-actions"[\s\S]*id="profileAvatar"/);assert.match(css,/\.top\{display:flex;justify-content:space-between;align-items:center\}/);assert.match(css,/\.top-actions\{display:flex;align-items:center;gap:12px\}/);assert.match(css,/\.profile-shell\{position:relative\}/)});


test('authentication controls have one runtime owner and bypass dashboard delegation',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const auth=await readFile(new URL('../public/auth.js',import.meta.url),'utf8');
 const dashboard=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 assert.match(dashboard,/event\.target\.closest\('#login'\)\)return/);
 assert.doesNotMatch(dashboard,/\nbindAuthControls\(\);/);
 for(const action of ['doLogin()','startEnroll()','finishEnroll()','openReset()','closeReset()','resetPassword()']){
  assert.match(html,new RegExp('data-aegis-click="'+action.replace(/[()]/g,'\\$&')+'"'));
 }
 assert.match(auth,/bind\('\[data-aegis-click="doLogin\(\)"\]'/);
 assert.match(auth,/bind\('\[data-aegis-click="togglePassword\(\\'resetPw\\',this\)"\]'/);
});
