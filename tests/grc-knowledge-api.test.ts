import fs from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';

const server=fs.readFileSync('src/server.ts','utf8');

test('knowledge registry is initialized before requests are served',()=>{
 assert.match(server,/await initKnowledgeSources\(\)/);
});

test('knowledge APIs require authenticated user context',()=>{
 const start=server.indexOf("app.get('/api/grc/organizations/:orgId/knowledge-sources'");
 const end=server.indexOf("app.get('/api/grc/organizations/:orgId/assessment-packs'",start);
 assert.ok(start>=0&&end>start);
 const routes=server.slice(start,end);
 assert.equal((routes.match(/currentUser\(req\)/g)||[]).length,8);
 assert.equal((routes.match(/User session required/g)||[]).length,8);
});

test('knowledge API exposes separate register review extraction verification and linking operations',()=>{
 for(const route of [
  "app.post('/api/grc/organizations/:orgId/knowledge-sources'",
  "app.post('/api/grc/organizations/:orgId/knowledge-sources/:sourceId/review'",
  "app.post('/api/grc/organizations/:orgId/knowledge-sources/:sourceId/supersede'",
  "app.post('/api/grc/organizations/:orgId/knowledge-sources/:sourceId/items'",
  "app.post('/api/grc/organizations/:orgId/knowledge-items/:itemId/review'",
  "app.post('/api/grc/organizations/:orgId/knowledge-items/:itemId/controls/:controlId'"
 ])assert.ok(server.includes(route),route);
});

test('server does not expose automatic PDF-to-control or automatic compliance route',()=>{
 assert.doesNotMatch(server,/knowledge-sources[^\n]*auto(?:map|approve|comply)|pdf[^\n]*auto(?:map|approve|comply)/i);
});


test('assessment pack APIs are authenticated and separated from knowledge ingestion',()=>{
 const start=server.indexOf("app.get('/api/grc/organizations/:orgId/assessment-packs'");
 const end=server.indexOf("app.get('/api/grc/organizations/:orgId/framework-requirements'",start);
 assert.ok(start>=0&&end>start);
 const routes=server.slice(start,end);
 for(const route of [
  "app.get('/api/grc/organizations/:orgId/assessment-packs'",
  "app.post('/api/grc/organizations/:orgId/assessment-packs'",
  "app.post('/api/grc/organizations/:orgId/assessment-packs/:packId/items/:itemId'",
  "app.post('/api/grc/organizations/:orgId/assessment-packs/:packId/review'"
 ])assert.ok(routes.includes(route),route);
 assert.equal((routes.match(/currentUser\(req\)/g)||[]).length,4);
 assert.equal((routes.match(/User session required/g)||[]).length,4);
});


test('assessment pack usability API is authenticated and delegates fail-closed validation',()=>{
 const start=server.indexOf("app.get('/api/grc/organizations/:orgId/assessment-packs/:packId/usable'");
 assert.ok(start>=0);
 const end=server.indexOf("app.get('/api/grc/organizations/:orgId/assessment-packs'",start+10);
 const body=server.slice(start,end);
 assert.match(body,/currentUser\(req\)/);
 assert.match(body,/requireUsableAssessmentPack/);
 assert.match(body,/usable:true/);
 assert.match(body,/usable:false/);
});
