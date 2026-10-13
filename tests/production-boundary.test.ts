import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('server applies baseline security headers without exposing framework banner',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(s,/app\.disable\('x-powered-by'\)/);
 for(const header of ['Content-Security-Policy','X-Content-Type-Options','X-Frame-Options','Referrer-Policy','Permissions-Policy','Cross-Origin-Opener-Policy','Cross-Origin-Resource-Policy','Strict-Transport-Security'])assert.match(s,new RegExp(header));
});

test('only minimal readiness and authentication bootstrap routes bypass API authentication',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const marker="app.use('/api',async(req,res,next)=>";
 const start=s.indexOf(marker);
 assert.notEqual(start,-1);
 const authMiddleware=s.slice(start,start+900);
 assert.match(authMiddleware,/\/ready/);
 assert.doesNotMatch(authMiddleware,/['"]\/health['"]/);
 assert.doesNotMatch(authMiddleware,/['"]\/integrations['"]/);
});


test('browser cross-site state changes are rejected before API handling',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(s,/sec-fetch-site/);
 assert.match(s,/cross-site/);
 assert.match(s,/Cross-site state-changing requests are not allowed/);
 assert.match(s,/\['GET','HEAD','OPTIONS'\]/);
});


test('CSP denies dangerous embedding and external execution by default while inline migration remains explicit',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const line=s.split('\n').find(x=>x.includes("Content-Security-Policy"))||'';
 for(const directive of ["default-src 'self'","object-src 'none'","frame-ancestors 'none'","base-uri 'self'","form-action 'self'","connect-src 'self'"]) assert.ok(line.includes(directive),directive+' missing');
 assert.ok(!/default-src[^;]*https?:/.test(line));
});


test('knowledge hub is strict-CSP ready with external scripts styles and delegated events',async()=>{
 const html=await readFile(new URL('../public/knowledge.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/knowledge.js',import.meta.url),'utf8');
 assert.doesNotMatch(html,/<style\b/i);
 assert.doesNotMatch(html,/<script(?![^>]*\bsrc=)[^>]*>/i);
 assert.doesNotMatch(html,/\son[a-z]+\s*=/i);
 assert.doesNotMatch(html,/\sstyle\s*=/i);
 assert.match(html,/href="\/knowledge\.css"/);
 assert.match(html,/src="\/knowledge\.js"/);
 assert.match(js,/addEventListener\('click'/);
 assert.doesNotMatch(js,/onclick=/);
 assert.doesNotMatch(js,/style="/);
});


test('main dashboard keeps CSS external during CSP migration',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const css=await readFile(new URL('../public/dashboard.css',import.meta.url),'utf8');
 assert.doesNotMatch(html,/<style\b/i);
 assert.match(html,/href="\/dashboard\.css"/);
 assert.ok(css.length>1000,'dashboard stylesheet should contain migrated CSS');
});


test('main dashboard keeps application JavaScript external during CSP migration',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 assert.doesNotMatch(html,/<script(?![^>]*\bsrc=)[^>]*>/i);
 assert.match(html,/src="\/dashboard\.js"/);
 assert.ok(js.length>10000,'dashboard application script should contain migrated JavaScript');
 for(const fn of ['confirmExport','cancelExport','openLearning','tab'])assert.match(js,new RegExp('function\\s+'+fn+'\\b'));
});


test('main dashboard static controls use delegated CSP-safe event metadata',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 const staticInline=[...html.matchAll(/\s(onclick|onchange)="([^"]*)"/gi)].filter(m=>!m[2].includes("'+"));
 assert.equal(staticInline.length,0,'static executable event attributes must not return');
 assert.match(html,/data-aegis-click=/);
 assert.match(html,/data-aegis-change=/);
 assert.match(js,/document\.addEventListener\('click'/);
 assert.match(js,/document\.addEventListener\('change'/);
 assert.match(js,/runAegisUiAction/);
});


test('dashboard contains no executable inline event handlers after CSP migration',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 assert.doesNotMatch(html,/\son[a-z]+\s*=/i);
 assert.doesNotMatch(js,/\son[a-z]+\s*=/i);
 assert.doesNotMatch(js,/\beval\s*\(/);
 assert.doesNotMatch(js,/\bFunction\s*\(/);
 for(const action of ['reviewPrivacyLegalEntry','advancePrivacyBreach','submitTprmQuestionnaire','runGrcTest','selectFramework','decideReview','securityAssessDoc']){
  assert.match(html+'\n'+js,new RegExp('data-action="'+action+'"'));
 }
});


test('global CSP forbids inline JavaScript while retaining temporary inline-style compatibility',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const csp=server.match(/Content-Security-Policy',\"([^\"]+)\"/);
 assert.ok(csp,'CSP header must be configured');
 assert.match(csp[1],/script-src 'self';/);
 assert.doesNotMatch(csp[1],/script-src[^;]*'unsafe-inline'/);
 assert.match(csp[1],/style-src 'self' 'unsafe-inline'/);
});


test('main dashboard static markup contains no inline style attributes',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const css=await readFile(new URL('../public/dashboard.css',import.meta.url),'utf8');
 assert.doesNotMatch(html,/\sstyle\s*=/i);
 for(const cls of ['u-mt-8','u-mt-12','u-w-full','u-justify-between','u-overflow-auto','u-table-full'])assert.match(css,new RegExp('\\.'+cls+'\\{'));
});


test('generated dashboard tables contain no inline style attributes',async()=>{
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 assert.doesNotMatch(js,/style="/i);
 for(const cls of ['u-data-table','u-th','u-td','u-td-top','u-break-all'])assert.match(js,new RegExp('class="'+cls));
});


test('architecture workspace exposes synchronized CAD and 3D inspector UI',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/architecture-3d.js',import.meta.url),'utf8');
 for(const id of ['architectureModelState','architectureComponentCount','architectureFlowCount','architectureInferenceCount','architectureInspectorTitle','architectureInspectorKind','architectureInspectorConfidence','architectureInspectorSource'])assert.match(html,new RegExp('id="'+id+'"'));
 assert.match(js,/function syncInspector\(/);
 assert.match(js,/function syncMetrics\(/);
 assert.match(js,/Synchronized selection across technical CAD and interactive 3D views/);
});


test('enterprise shell preserves navigation and exposes assurance context',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 for(const label of ['ENTERPRISE ASSURANCE','WORKSPACES','Protected session','ASSURANCE STATE','Evidence-first'])assert.match(html,new RegExp(label));
 for(const target of ['overview','offensive','defensive','grcops','evidence','architecture','grcreview','audittrace'])assert.match(html,new RegExp("tab\\('"+target+"'"));
 assert.match(html,/id="profileAvatar"/);
 assert.match(html,/id="profileMenu"/);
});


test('executive overview preserves assessment controls in command-center layout',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 for(const id of ['target','auth','gate','quickdoc','quickdocmsg','risk','riskbar','count','state','integrations'])assert.match(html,new RegExp('id="'+id+'"'));
 for(const label of ['AUTHORIZED ASSESSMENT','DOCUMENT TRIAGE','INTEGRATION ASSURANCE','Evidence before claims','MFA protected'])assert.match(html,new RegExp(label));
 assert.match(html,/authorize\(\)/);
 assert.match(html,/scanQuickDoc\(\)/);
 assert.match(html,/downloadDocScan\(\)/);
});
