import fs from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
import {readinessPackCatalog,readinessPackDefinition} from '../src/readiness-pack-definitions.js';

const server=fs.readFileSync('src/server.ts','utf8');

test('readiness catalog API is read-only and explicitly non-authoritative',()=>{
 assert.match(server,/app\.get\('\/api\/grc\/readiness-packs'/);
 assert.match(server,/app\.get\('\/api\/grc\/readiness-packs\/:key'/);
 assert.match(server,/Reference readiness content only/);
 assert.doesNotMatch(server,/app\.(post|put|patch|delete)\('\/api\/grc\/readiness-packs/);
});

test('readiness catalog does not bypass reviewed organization knowledge workflow',()=>{
 const start=server.indexOf("app.get('/api/grc/readiness-packs'");
 const end=server.indexOf("app.post('/api/grc/organizations/:orgId/readiness-packs/:key/adopt'",start);
 assert.ok(end>start);
 const routes=server.slice(start,end);
 assert.doesNotMatch(routes,/createKnowledgeItem|linkKnowledgeToControl|createAssessmentPack|setScopeControl/);
});


test('readiness adoption requires authentication and actual source hash input',()=>{
 const start=server.indexOf("app.post('/api/grc/organizations/:orgId/readiness-packs/:key/adopt'");
 assert.ok(start>=0);
 const end=server.indexOf("app.get('/api/grc/organizations/:orgId/knowledge-sources'",start);
 const route=server.slice(start,end);
 assert.match(route,/currentUser\(req\)/);
 assert.match(route,/sourceSha256/);
 assert.match(route,/adoptReadinessTemplate/);
});

test('readiness adoption remains draft and cannot mutate compliance state',()=>{
 const start=server.indexOf("app.post('/api/grc/organizations/:orgId/readiness-packs/:key/adopt'");
 const end=server.indexOf("app.get('/api/grc/organizations/:orgId/knowledge-sources'",start);
 const route=server.slice(start,end);
 assert.match(route,/reviewRequired:true/);
 assert.match(route,/does not verify evidence, implement controls, change compliance scores, or establish conformity/);
 assert.doesNotMatch(route,/reviewKnowledgeSource|verifyKnowledgeItem|linkKnowledgeToControl|setScopeControl|approveScopeControl/);
});


test('ISO 42001 AIMS readiness pack is exposed through the generic catalog and adoption path',()=>{
 const catalog=readinessPackCatalog();
 const entry=catalog.find(x=>x.key==='ISO42001_AIMS_READINESS');
 assert.ok(entry);
 assert.equal(entry.framework,'ISO42001');
 assert.equal(entry.frameworkVersion,'2023');
 assert.equal(entry.itemCount,8);
 const pack=readinessPackDefinition('iso42001_aims_readiness');
 assert.equal(pack?.key,'ISO42001_AIMS_READINESS');
 assert.match(server,/readinessPackDefinition\(req\.params\.key\)/);
 assert.match(server,/adoptReadinessTemplate\(u\.userId,req\.params\.orgId,pack/);
});
