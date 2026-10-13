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
