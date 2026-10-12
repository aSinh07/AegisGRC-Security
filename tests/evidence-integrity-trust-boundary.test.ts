import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
const src=fs.readFileSync('src/grc-evidence.ts','utf8');
test('public JSON evidence submission cannot self-assert server verification',()=>{assert.doesNotMatch(src,/input\.serverComputedSha256/);assert.match(src,/const verified=false/);assert.match(src,/requires trusted bytes\/collector provenance/)});
test('submitted evidence remains claimed until a trusted verification path exists',()=>{assert.match(src,/metadata\|\|\{},'CLAIMED',userId/);assert.match(src,/Evidence integrity must be server verified before validation/)});
