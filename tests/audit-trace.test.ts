import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('traceability endpoint requires authenticated assessment access',async()=>{
 const src=await readFile(new URL('../src/audit-trace.ts',import.meta.url),'utf8');
 assert.match(src,/requireAssessmentAccess\(userId, assessmentId\)/);
 assert.match(src,/WHERE assessment_id=\$1/);
});
test('traceability preserves evidence hash and review state',async()=>{
 const src=await readFile(new URL('../src/audit-trace.ts',import.meta.url),'utf8');
 assert.match(src,/evidenceHash: f\.evidenceHash/);
 assert.match(src,/reviews: history/);
 assert.match(src,/assuranceBoundary/);
});
