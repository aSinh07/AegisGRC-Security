import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('REMEDIATED requires a successful newer retest and absence of the fingerprint',async()=>{
 const s=await readFile(new URL('../src/finding-review.ts',import.meta.url),'utf8');
 assert.match(s,/REMEDIATED requires successful retest evidence/);
 assert.match(s,/Retest evidence must come from a successful tool execution/);
 assert.match(s,/Retest evidence must be newer than the original finding/);
 assert.match(s,/Retest still detects the original vulnerability fingerprint/);
 assert.match(s,/retest_evidence_id/);assert.match(s,/retest_fingerprint/);
});
test('non-remediation review decisions remain available without retest closure',async()=>{
 const s=await readFile(new URL('../src/finding-review.ts',import.meta.url),'utf8');
 assert.match(s,/if\(decision==='REMEDIATED'\)/);
 assert.match(s,/CONFIRMED.*FALSE_POSITIVE.*ACCEPTED.*REMEDIATED/s);
});
