import fs from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';

const source=fs.readFileSync('src/grc-knowledge-sources.ts','utf8');

test('knowledge registry is additive and tenant scoped',()=>{
 assert.match(source,/CREATE TABLE IF NOT EXISTS grc_knowledge_sources/);
 assert.match(source,/CREATE TABLE IF NOT EXISTS grc_knowledge_items/);
 assert.match(source,/CREATE TABLE IF NOT EXISTS grc_knowledge_control_links/);
 assert.match(source,/organization_id uuid NOT NULL REFERENCES grc_organizations/);
 assert.doesNotMatch(source,/DROP TABLE|TRUNCATE/i);
});

test('knowledge registry deduplicates source documents by organization and sha256',()=>{
 assert.match(source,/UNIQUE\(organization_id,sha256\)/);
 assert.match(source,/CHECK\(sha256 ~ '\^\[a-f0-9\]\{64\}\$'\)/);
});

test('knowledge is classified by authority instead of assuming uploaded PDFs are standards',()=>{
 for(const kind of ['AUTHORITATIVE','IMPLEMENTATION_AID','EDUCATIONAL','INTERNAL'])assert.ok(source.includes(kind),kind);
 assert.match(source,/authority_class/);
});

test('unreviewed knowledge cannot become canonical-control support',()=>{
 const start=source.indexOf('export async function linkKnowledgeToControl');
 const body=source.slice(start);
 assert.match(body,/item\.review_status!=='VERIFIED'/);
 assert.match(body,/item\.source_review_status!=='REVIEWED'/);
 assert.match(body,/Only reviewed and verified knowledge can be linked to controls/);
});

test('source and extracted knowledge require independent review',()=>{
 assert.match(source,/Independent source reviewer required/);
 assert.match(source,/Independent knowledge reviewer required/);
 assert.match(source,/Source must be reviewed before knowledge can be verified/);
});

test('provenance captures page and section references and confidence',()=>{
 assert.match(source,/page_ref text,section_ref text/);
 assert.match(source,/confidence numeric\(4,3\)/);
});

test('catalog explicitly avoids certification claims',()=>{
 assert.match(source,/does not establish certification or legal conformity/);
});


test('assessment packs accept only verified knowledge from reviewed sources',()=>{
 assert.match(source,/CREATE TABLE IF NOT EXISTS grc_assessment_packs/);
 assert.match(source,/CREATE TABLE IF NOT EXISTS grc_assessment_pack_items/);
 const start=source.indexOf('export async function addKnowledgeToAssessmentPack');
 const end=source.indexOf('export async function reviewAssessmentPack',start);
 const body=source.slice(start,end);
 assert.match(body,/Only reviewed and verified knowledge can enter assessment packs/);
 assert.match(body,/pack\.status!=='DRAFT'/);
});

test('assessment pack publication requires independent review and content',()=>{
 const start=source.indexOf('export async function reviewAssessmentPack');
 const body=source.slice(start);
 assert.match(body,/Independent assessment pack reviewer required/);
 assert.match(body,/Assessment pack must contain verified knowledge/);
 assert.match(body,/does not by themselves establish compliance|do not by themselves establish compliance/);
});


test('readiness adoption is atomic and rolls back partial imports',()=>{
 const start=source.indexOf('export async function adoptReadinessTemplate');
 assert.ok(start>=0);
 const body=source.slice(start);
 assert.match(body,/pool\.connect\(\)/);
 assert.match(body,/query\('BEGIN'\)/);
 assert.match(body,/query\('COMMIT'\)/);
 assert.match(body,/query\('ROLLBACK'\)/);
 assert.match(body,/finally\{client\.release\(\)\}/);
 assert.match(body,/review_status='DRAFT'/);
});

test('atomic readiness adoption remains tenant scoped and does not self-review',()=>{
 const start=source.indexOf('export async function adoptReadinessTemplate');
 const body=source.slice(start);
 assert.match(body,/requireOrgPermission\(userId,orgId,'manageControl'\)/);
 assert.match(body,/organization_id/);
 assert.doesNotMatch(body,/review_status='REVIEWED'|review_status='VERIFIED'/);
});


test('re-adopting readiness content cannot reset or overwrite reviewed knowledge',()=>{
 const start=source.indexOf('export async function adoptReadinessTemplate');
 const body=source.slice(start);
 assert.match(body,/CASE WHEN grc_knowledge_items\.review_status='DRAFT' THEN EXCLUDED\.content ELSE grc_knowledge_items\.content END/);
 assert.match(body,/CASE WHEN grc_knowledge_items\.review_status='DRAFT' THEN EXCLUDED\.title ELSE grc_knowledge_items\.title END/);
 assert.doesNotMatch(body,/review_status='DRAFT',verified_by=NULL,verified_at=NULL/);
});


test('readiness re-adoption cannot silently replace source provenance',()=>{
 const start=source.indexOf('export async function adoptReadinessTemplate');
 const body=source.slice(start);
 assert.match(body,/SELECT source_id FROM grc_readiness_adoptions WHERE organization_id=\$1 AND readiness_key=\$2/);
 assert.match(body,/existingSource\.sha256!==sha/);
 assert.match(body,/already adopted from a different source hash/);
 assert.match(body,/statusCode:409/);
});
