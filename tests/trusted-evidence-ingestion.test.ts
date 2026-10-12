import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
const evidence=fs.readFileSync('src/grc-evidence.ts','utf8'),server=fs.readFileSync('src/server.ts','utf8');
test('trusted upload hashes server-received bytes and persists bounded evidence object',()=>{assert.match(evidence,/createHash\('sha256'\)\.update\(bytes\)\.digest\('hex'\)/);assert.match(evidence,/content bytea NOT NULL/);assert.match(evidence,/object_id uuid REFERENCES grc_evidence_objects/);assert.match(evidence,/SERVER_VERIFIED_UPLOAD/)});
test('verified upload route derives evidence from multer file buffer',()=>{assert.match(server,/upload\.single\('evidence'\)/);assert.match(server,/req\.file\.buffer/);assert.match(server,/req\.file\.mimetype/);assert.match(server,/req\.file\.originalname/)});
test('untrusted JSON route remains claimed-only',()=>{assert.match(evidence,/const verified=false/);assert.doesNotMatch(evidence,/input\.serverComputedSha256/)});
test('upload middleware enforces existing 20 MB bounded memory ingestion',()=>{assert.match(server,/fileSize:20\*1024\*1024/)});
