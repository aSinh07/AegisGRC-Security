import fs from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';

const server=fs.readFileSync('src/server.ts','utf8');

test('readiness catalog API is read-only and explicitly non-authoritative',()=>{
 assert.match(server,/app\.get\('\/api\/grc\/readiness-packs'/);
 assert.match(server,/app\.get\('\/api\/grc\/readiness-packs\/:key'/);
 assert.match(server,/Reference readiness content only/);
 assert.doesNotMatch(server,/app\.(post|put|patch|delete)\('\/api\/grc\/readiness-packs/);
});

test('readiness catalog does not bypass reviewed organization knowledge workflow',()=>{
 const start=server.indexOf("app.get('/api/grc/readiness-packs'");
 const end=server.indexOf("app.get('/api/grc/organizations/:orgId/knowledge-sources'",start);
 const routes=server.slice(start,end);
 assert.doesNotMatch(routes,/createKnowledgeItem|linkKnowledgeToControl|createAssessmentPack|setScopeControl/);
});
