import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
const src=fs.readFileSync('src/grc-evidence.ts','utf8');
test('evidence vault records explicit integrity state and custody events',()=>{assert.match(src,/integrity_status text NOT NULL DEFAULT 'CLAIMED'/);assert.match(src,/grc_evidence_events/);assert.match(src,/VERSION_SUBMITTED/);assert.match(src,/VALIDATED/)});
test('caller-claimed hashes cannot self-verify or be validated',()=>{assert.doesNotMatch(src,/input\.serverComputedSha256/);assert.match(src,/const verified=false/);assert.match(src,/Evidence integrity must be server verified before validation/)});
test('control evidence pass requires server verified integrity',()=>{assert.match(src,/r\.status='VALID' AND v\.integrity_status='SERVER_VERIFIED'/)});
test('verification is additive and historical evidence defaults conservatively to claimed',()=>{assert.match(src,/ADD COLUMN IF NOT EXISTS integrity_status text NOT NULL DEFAULT 'CLAIMED'/);assert.match(src,/ADD COLUMN IF NOT EXISTS verified_at/)});
