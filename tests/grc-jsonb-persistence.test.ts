import fs from 'node:fs';import test from 'node:test';import assert from 'node:assert/strict';
test('third-party assessment serializes JSONB arrays explicitly',()=>{const s=fs.readFileSync('src/third-party-risk.ts','utf8');assert.match(s,/JSON\.stringify\(input\.findings\|\|\[\]\),JSON\.stringify\(input\.evidence\|\|\[\]\)/)});
test('audit workpaper serializes evidence refs for JSONB persistence',()=>{const s=fs.readFileSync('src/audit-management.ts','utf8');assert.match(s,/JSON\.stringify\(input\.evidenceRefs\|\|\[\]\)/)});

test('enterprise core serializes JSONB arrays instead of relying on pg array coercion',()=>{const s=fs.readFileSync('src/grc-core.ts','utf8');assert.match(s,/JSON\.stringify\(input\.relatedRiskIds\|\|\[\]\),JSON\.stringify\(input\.evidenceRefs\|\|\[\]\)/);assert.ok((s.match(/JSON\.stringify\(input\.evidenceRefs\|\|\[\]\)/g)||[]).length>=3)});
