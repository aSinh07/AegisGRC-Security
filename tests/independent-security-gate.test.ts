import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
const doc=fs.readFileSync('docs/INDEPENDENT_SECURITY_VALIDATION_GATE.md','utf8');
test('enterprise claim requires genuinely independent security validation',()=>{
 assert.match(doc,/did not implement the tested controls/);
 assert.match(doc,/tenant isolation/);
 assert.match(doc,/Evidence Vault/);
 assert.match(doc,/SSRF\/DNS rebinding/);
 assert.match(doc,/must not say "independently penetration tested"/);
 assert.match(doc,/must not say .*100% secure/);
});
