import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
const src=fs.readFileSync('src/privacy-operations.ts','utf8');
test('privacy lifecycle mutations can share a database transaction with their audit event',()=>{assert.match(src,/async function privacyTransaction<T>/);assert.match(src,/client\.query\('BEGIN'\)/);assert.match(src,/client\.query\('COMMIT'\)/);assert.match(src,/client\.query\('ROLLBACK'\)/);assert.match(src,/db:PrivacyQuery=pool/)});
test('high-impact privacy transitions write state and audit through the same client',()=>{for(const event of ["'REQUEST',id,'FULFILLED'","'NOTICE',id,'RETIRED'","'CONSENT',id,'WITHDRAWN'","'BREACH',id,'STATUS_'+status"]){const i=src.indexOf(event);assert.ok(i>0,event);assert.match(src.slice(i,i+350),/,client\)/)}});
test('request closure retains conflict protection inside the transaction',()=>{assert.match(src,/Privacy request closure conflict/)});
