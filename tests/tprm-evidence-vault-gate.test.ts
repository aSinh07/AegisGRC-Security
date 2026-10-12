import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
const source=fs.readFileSync('src/tprm-workflow.ts','utf8');
test('TPRM remediation closure resolves evidence references against tenant-scoped vault',()=>{assert.match(source,/JOIN grc_evidence_requests r ON r\.id=v\.evidence_request_id/);assert.match(source,/r\.organization_id=\$1/);assert.match(source,/v\.id=ANY\(\$2::uuid\[\]\)/)});
test('TPRM closure requires server verified current independently validated evidence',()=>{assert.match(source,/v\.integrity_status='SERVER_VERIFIED'/);assert.match(source,/v\.validated_at IS NOT NULL/);assert.match(source,/v\.valid_until>now\(\)/);assert.match(source,/await verifiedEvidenceVersions\(org,row\.evidence\)/)});
test('TPRM evidence gate rejects partial or forged reference sets',()=>{assert.match(source,/q\.rowCount!==ids\.length/);assert.match(source,/TPRM closure requires current independently validated SERVER_VERIFIED evidence/)});
