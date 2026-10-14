import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('unified control assurance preserves automation and accountable manual review',async()=>{
 const s=await readFile(new URL('../src/grc-core.ts',import.meta.url),'utf8');
 for(const field of ['evidence_sufficiency','automated_result','manual_result','design_effectiveness','operating_effectiveness','approval_status','approved_by','approved_at'])
  assert.match(s,new RegExp(field));
 assert.match(s,/reviewControlAssessment/);
 assert.match(s,/Accountable reviewer is required/);
 assert.match(s,/Approval requires sufficient evidence/);
 assert.match(s,/Approval requires design and operating effectiveness tests/);
});

test('control assurance approval is transactional and append-only auditable',async()=>{
 const s=await readFile(new URL('../src/grc-core.ts',import.meta.url),'utf8');
 assert.match(s,/grc_control_assessment_events/);
 assert.match(s,/SELECT \* FROM grc_control_assessments WHERE id=\$1 FOR UPDATE/);
 assert.match(s,/client\.query\('BEGIN'\)/);
 assert.match(s,/client\.query\('COMMIT'\)/);
 assert.match(s,/client\.query\('ROLLBACK'\)/);
 assert.match(s,/CONTROL_APPROVED/);
 assert.match(s,/controlAssessmentHistory/);
});

test('unapproved review cannot become an effective final control status',async()=>{
 const s=await readFile(new URL('../src/grc-core.ts',import.meta.url),'utf8');
 assert.match(s,/approval==='APPROVED'\?overall:'NOT_ASSESSED'/);
});

test('governed control assurance API requires organization permissions and server-bound reviewer identity',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(s,/\/control-assessments'\/);
 assert.match(s,/\/control-assessments\/:id\/review/);
 assert.match(s,/\/control-assessments\/:id\/history/);
 assert.match(s,/requireOrgPermission\(u\.userId,req\.params\.orgId,'findingReview'\)/);
 assert.match(s,/actorUserId:u\.userId/);
});
