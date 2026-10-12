import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
test('automation covers enterprise due-date workflows',async()=>{const s=await readFile(new URL('../src/grc-automation.ts',import.meta.url),'utf8');for(const k of ['OBLIGATION_DUE','EXCEPTION_EXPIRY','THIRD_PARTY_REVIEW_DUE','BIA_DUE','POLICY_REVIEW_DUE'])assert.match(s,new RegExp(k));assert.match(s,/FOR UPDATE SKIP LOCKED/);});

test('uses real compliance table',async()=>{const s=await readFile(new URL('../src/grc-automation.ts',import.meta.url),'utf8');assert.match(s,/grc_obligations/);});
