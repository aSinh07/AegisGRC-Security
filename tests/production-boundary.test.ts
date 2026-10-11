import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('server applies baseline security headers without exposing framework banner',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(s,/app\.disable\('x-powered-by'\)/);
 for(const header of ['X-Content-Type-Options','X-Frame-Options','Referrer-Policy','Permissions-Policy','Cross-Origin-Opener-Policy','Cross-Origin-Resource-Policy','Strict-Transport-Security'])assert.match(s,new RegExp(header));
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
