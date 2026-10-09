import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';

test('clean database schema creates FK parent tables before assessment tenancy columns',async()=>{
 const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 const users=sql.indexOf('CREATE TABLE IF NOT EXISTS app_users');
 const orgs=sql.indexOf('CREATE TABLE IF NOT EXISTS grc_organizations');
 const assessments=sql.indexOf('CREATE TABLE IF NOT EXISTS assessments');
 const orgFk=sql.indexOf('organization_id uuid REFERENCES grc_organizations');
 const userFk=sql.indexOf('created_by uuid REFERENCES app_users');
 assert.ok(users>=0&&orgs>users&&assessments>orgs);
 assert.ok(orgFk>assessments&&userFk>assessments);
});

test('database initialization is atomic',async()=>{
 const src=await readFile(new URL('../scripts/init-db.ts',import.meta.url),'utf8');
 assert.match(src,/client\.query\('BEGIN'\)/);
 assert.match(src,/client\.query\('COMMIT'\)/);
 assert.match(src,/client\.query\('ROLLBACK'\)/);
 assert.match(src,/transaction rolled back/);
});
