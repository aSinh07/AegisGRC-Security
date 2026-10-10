import test from 'node:test';
import assert from 'node:assert/strict';
import {reportSnapshotDigest,signApprovedReport,verifyApprovedReportSignature} from '../src/report-auth.js';

test('report snapshot digest is deterministic across object key ordering',()=>{
 const a={report:'x',nested:{b:2,a:1},items:[{z:3,y:2}]};
 const b={items:[{y:2,z:3}],nested:{a:1,b:2},report:'x'};
 assert.equal(reportSnapshotDigest(a),reportSnapshotDigest(b));
});
test('report snapshot digest changes when governed content changes',()=>{
 assert.notEqual(reportSnapshotDigest({finding:{status:'OPEN'}}),reportSnapshotDigest({finding:{status:'CLOSED'}}));
});
test('approval signature is bound to report snapshot digest',()=>{
 process.env.REPORT_SIGNING_KEY='test-only-report-signing-key-32-characters-minimum';
 const base={reviewId:'r1',assessmentId:'a1',framework:'ISO27001',snapshotDigest:'a'.repeat(64),reviewerId:'u1',approvedAt:'2026-10-10T12:00:00.000Z'};
 const signature=signApprovedReport(base);
 assert.equal(verifyApprovedReportSignature({...base,signature}),true);
 assert.equal(verifyApprovedReportSignature({...base,snapshotDigest:'b'.repeat(64),signature}),false);
});

test('report digest ignores presentation clock but includes changed finding evidence',()=>{
 const base={assessmentId:'a1',generatedAt:'2026-10-10T10:00:00Z',documentControl:{generatedAt:'2026-10-10T10:00:00Z'},executiveSummary:{findings:1,overdueIssues:0},findingLifecycle:[{findingId:'f1',evidenceHash:'a'.repeat(64)}]};
 const refreshed={...base,generatedAt:'2026-10-11T10:00:00Z',documentControl:{generatedAt:'2026-10-11T10:00:00Z'},executiveSummary:{findings:1,overdueIssues:1}};
 assert.equal(reportSnapshotDigest(base),reportSnapshotDigest(refreshed));
 assert.notEqual(reportSnapshotDigest(base),reportSnapshotDigest({...base,findingLifecycle:[{findingId:'f1',evidenceHash:'b'.repeat(64)}]}));
});
