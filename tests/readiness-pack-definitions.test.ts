import fs from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
import {SOURCE_GROUNDED_READINESS_PACKS,validateReadinessPackDefinitions} from '../src/readiness-pack-definitions.js';

test('source-grounded readiness packs are bounded and traceable',()=>{
 const result=validateReadinessPackDefinitions();
 assert.equal(result.packs,4);
 assert.ok(result.items>=18);
 for(const pack of SOURCE_GROUNDED_READINESS_PACKS){
  assert.match(pack.disclaimer,/does not reproduce or replace an official standard/);
  assert.match(pack.disclaimer,/does not establish certification/);
  for(const item of pack.items)assert.ok(item.sourceLocator.length>5);
 }
});

test('readiness catalog covers supplied ISO NIST AI-impact and LLM materials',()=>{
 assert.deepEqual(SOURCE_GROUNDED_READINESS_PACKS.map(x=>x.key),[
  'ISO27001_ISMS_READINESS','NIST_EVIDENCE_READINESS','AI_IMPACT_READINESS','OWASP_LLM_2026_READINESS'
 ]);
});

test('readiness content does not claim automatic pass or compliance',()=>{
 const raw=fs.readFileSync('src/readiness-pack-definitions.ts','utf8');
 assert.doesNotMatch(raw,/automatic(?:ally)? compliant|guarantee(?:d)? certification|100% compliant/i);
});
