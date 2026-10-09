import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('assessment tenancy migration is additive and non-destructive',async()=>{
 const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 assert.match(sql,/ALTER TABLE assessments ADD COLUMN IF NOT EXISTS organization_id/);
 assert.match(sql,/ALTER TABLE assessments ADD COLUMN IF NOT EXISTS created_by/);
 assert.doesNotMatch(sql,/DROP\s+(TABLE|COLUMN)/i);
});
test('evidence schema constrains sha256 format without rewriting legacy rows',async()=>{
 const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 assert.match(sql,/evidence_sha256_format_chk/);
 assert.match(sql,/pg_constraint/);
 assert.match(sql,/IF NOT EXISTS/);
 assert.match(sql,/NOT VALID/);
 assert.match(sql,/integrity_verified_at/);
});

test('named evidence constraint is restart-safe',async()=>{
 const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 assert.match(sql,/SELECT 1 FROM pg_constraint/);
 assert.match(sql,/conname='evidence_sha256_format_chk'/);
 assert.doesNotMatch(sql,/DROP CONSTRAINT evidence_sha256_format_chk/i);
});
