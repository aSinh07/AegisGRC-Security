import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('assessment tenancy migration is additive and non-destructive',async()=>{
 const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 assert.match(sql,/ALTER TABLE assessments ADD COLUMN IF NOT EXISTS organization_id/);
 assert.match(sql,/ALTER TABLE assessments ADD COLUMN IF NOT EXISTS created_by/);
 assert.doesNotMatch(sql,/DROP\s+(TABLE|COLUMN)/i);
});
test('evidence integrity metadata is additive without rewriting legacy rows',async()=>{
 const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 assert.match(sql,/ALTER TABLE evidence ADD COLUMN IF NOT EXISTS byte_length bigint/);
 assert.match(sql,/ALTER TABLE evidence ADD COLUMN IF NOT EXISTS integrity_verified_at timestamptz/);
 assert.doesNotMatch(sql,/UPDATE evidence/i);
});

test('evidence migration is restart-safe and does not recreate or drop named constraint',async()=>{
 const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 assert.doesNotMatch(sql,/ALTER TABLE evidence ADD CONSTRAINT evidence_sha256_format_chk/i);
 assert.doesNotMatch(sql,/DROP CONSTRAINT evidence_sha256_format_chk/i);
});
