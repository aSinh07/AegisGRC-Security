import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';

test('legacy core GRC risk list requires organization scope',async()=>{
 const src=await readFile(new URL('../src/grc-core.ts',import.meta.url),'utf8');
 assert.match(src,/listRisks\(organizationId:string\)/);
 assert.match(src,/Organization scope is required/);
 assert.doesNotMatch(src,/SELECT \* FROM grc_risks ORDER BY inherent_score DESC/);
});

test('legacy core GRC dashboard metrics are organization isolated',async()=>{
 const src=await readFile(new URL('../src/grc-core.ts',import.meta.url),'utf8');
 assert.match(src,/grcDashboard\(organizationId:string\)/);
 assert.match(src,/JOIN grc_scopes s ON s\.id=ca\.scope_id WHERE s\.organization_id=\$1/);
 assert.match(src,/FROM grc_risks WHERE organization_id=\$1/);
 assert.match(src,/FROM grc_issues WHERE organization_id=\$1/);
 assert.match(src,/FROM grc_evidence WHERE organization_id=\$1/);
 assert.match(src,/return \{organizationId,controls:/);
});
