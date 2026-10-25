import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const h=fs.readFileSync('public/index.html','utf8');
const d=fs.readFileSync('public/dashboard.js','utf8');
const simple=fs.readFileSync('public/grc-simple-workflow.js','utf8');

test('Enterprise GRC uses six plain guided stages',()=>{
  for(const x of ['1 · Setup','2 · Controls','3 · Evidence','4 · Risk & Remediation','5 · Review & Assurance','6 · Extended Governance']) assert.ok(simple.includes(x),x);
  assert.match(h,/grc-simple-workflow\.js/);
  assert.match(h,/grc-simple-workflow\.css/);
});

test('workspace remains fail closed',()=>{
  assert.match(h,/id="app" class="app hidden"/);
  assert.ok(d.includes("if(!s.authenticated)return location.replace('/')"));
});

test('login styling is isolated from workspace',()=>{
  assert.doesNotMatch(h,/login-premium-v2\.css/);
  assert.match(h,/workspace-light-fix\.css/);
});
