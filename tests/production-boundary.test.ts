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
 const ops=await readFile(new URL('../public/enterprise-ops.js',import.meta.url),'utf8');
 assert.doesNotMatch(html,/\son[a-z]+\s*=/i);
 assert.doesNotMatch(js,/\son[a-z]+\s*=/i);
 assert.doesNotMatch(ops,/\son[a-z]+\s*=/i);
 assert.doesNotMatch(js,/\beval\s*\(/);
 assert.doesNotMatch(js,/\bFunction\s*\(/);
 for(const action of ['reviewPrivacyLegalEntry','advancePrivacyBreach','submitTprmQuestionnaire','runGrcTest','selectFramework','decideReview','securityAssessDoc']){
  assert.match(html+'\n'+js+'\n'+ops,new RegExp('data-action="'+action+'"'));
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


test('Enterprise GRC command center preserves governed operational modules',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 for(const label of ['Enterprise GRC Command Center','CONTROL','EVIDENCE','RISK','CAPA','REVIEW','Frameworks + SoA','Evidence + Testing','Risk + CAPA','TPRM + Privacy'])assert.ok(html.includes(label),label);
 for(const id of ['grcOrg','grcMetrics','grcScopes','grcSoa','grcEvidence','grcWork','enterpriseFrameworkSummary','grcControls','grcRemediation','tprmMetrics','privacyMetrics','grcTimeline'])assert.match(html,new RegExp('id="'+id+'"'));
});


test('security operations and evidence UX preserve executable controls',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 for(const label of ['Discover → Validate → Evidence → Report','Observe → Prioritize → Remediate → Govern','Evidence & Provenance Vault','INGEST','HASH','BIND','REVIEW'])assert.ok(html.includes(label),label);
 for(const id of ['tool','findings','CRITICAL','HIGH','MEDIUM','LOW','INFO','pie','bars','grc','aiout','docs','doclist','raw'])assert.match(html,new RegExp('id="'+id+'"'));
 for(const action of ["scan()","report()","ai()","uploadDocs()"])assert.ok(html.includes(action),action);
});


test('governed outputs review and audit UX preserve protected workflows',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 for(const label of ['Assurance Report Center','Framework Crosswalk Workspace','Consultant Review Center','Audit Evidence Chain','MFA EXPORT','HUMAN GOVERNANCE GATE'])assert.ok(html.includes(label),label);
 for(const id of ['fmt-grc','fmt-remediation','fmt-architecture','fmt-technical','fmt-executive','frameworkList','frameworkConsole','fwAssessment','reviewFramework','reviewQueue','auditTraceStats','auditTraceRows','breachImpactRows'])assert.match(html,new RegExp('id="'+id+'"'));
 for(const action of ["downloadKind('grc')","assessSelectedFramework()","downloadFramework()","submitCurrentForReview()","loadAuditTrace()","downloadAuditPackage('pdf')"])assert.ok(html.includes(action),action);
});


test('enterprise finish layer includes accessibility responsive and reduced-motion states',async()=>{
 const css=await readFile(new URL('../public/dashboard.css',import.meta.url),'utf8');
 for(const token of [':focus-visible','prefers-reduced-motion','scrollbar-width','::selection','@media(max-width:560px)','--ui-accent'])assert.ok(css.includes(token),token);
 assert.match(css,/input:focus,select:focus,textarea:focus/);
 assert.match(css,/button:disabled,.btn:disabled/);
});


test('mobile navigation and AI assistant remain accessible and functional',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 const css=await readFile(new URL('../public/dashboard.css',import.meta.url),'utf8');
 for(const id of ['workspaceSidebar','mobileNavToggle','copilot','cpmode','voiceBtn','cpmsgs','cpq'])assert.match(html,new RegExp('id="'+id+'"'));
 assert.ok(html.includes('toggleMobileNav()'));
 assert.ok(js.includes('function toggleMobileNav(force)'));
 assert.ok(js.includes('toggleMobileNav(false)'));
 assert.ok(css.includes('.side.mobile-open'));
 assert.ok(css.includes('.copilot-controls'));
 assert.ok(html.includes('Context-aware workspace assistant'));
});


test('dashboard HTML has clean external-script boundaries and enterprise ops bundle',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const ops=await readFile(new URL('../public/enterprise-ops.js',import.meta.url),'utf8');
 assert.equal((html.match(/<style\b/gi)||[]).length,0);
 assert.equal((html.match(/<script(?![^>]*\bsrc=)[^>]*>/gi)||[]).length,0);
 assert.equal((html.match(/<\/style>/gi)||[]).length,0);
 assert.ok(html.includes('<script src="/architecture-3d.js" defer></script>'));
 assert.ok(html.includes('<script src="/enterprise-ops.js"></script>'));
 for(const fn of ['loadPrivacyOps','loadTprm','createPrivacyBreach','createTprmRemediation'])assert.ok(ops.includes('function '+fn),fn);
 assert.ok(!html.includes('async function loadPrivacyOps'));
});
