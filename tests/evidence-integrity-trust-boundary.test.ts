import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
const src=fs.readFileSync('src/grc-evidence.ts','utf8');
test('public JSON evidence submission cannot self-assert server verification',()=>{assert.doesNotMatch(src,/input\.serverComputedSha256/);assert.match(src,/const verified=false/);assert.match(src,/requires trusted bytes\/collector provenance/)});
test('submitted evidence remains claimed until a trusted verification path exists',()=>{assert.match(src,/metadata\|\|\{},'CLAIMED',userId/);assert.match(src,/Evidence integrity must be server verified before validation/)});

const remediation=fs.readFileSync('src/grc-remediation.ts','utf8');
test('CAPA linkage rejects evidence without server-verified integrity',()=>{assert.match(remediation,/r\.status='VALID' AND v\.integrity_status='SERVER_VERIFIED'/)});
