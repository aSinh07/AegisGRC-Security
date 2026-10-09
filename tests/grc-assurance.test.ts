import test from 'node:test';
import assert from 'node:assert/strict';
import { assessFramework } from '../src/grc-engine.js';
import type { Finding } from '../src/models.js';

const finding=(overrides:Partial<Finding>={}):Finding=>({
 id:'f1',assessmentId:'a1',source:'nmap',title:'Open TCP port 443',
 description:'HTTPS service is reachable; no exploit demonstrated',
 severity:'INFO',asset:'example.test',evidenceHash:'a'.repeat(64),
 createdAt:new Date().toISOString(),mappings:{},...overrides
});

test('informational open port cannot become a framework GAP',()=>{
 const results=assessFramework('ISO27001',[finding()]);
 assert.ok(results.some(r=>r.status==='OBSERVED'));
 assert.equal(results.filter(r=>r.status==='GAP').length,0);
});
test('confirmed technical vulnerability creates candidate GAP requiring review',()=>{
 const results=assessFramework('ISO27001',[finding({
  source:'wapiti',title:'SQL injection in login',description:'CWE-89 injection',
  severity:'HIGH',status:'OPEN'
 })]);
 assert.ok(results.some(r=>r.status==='GAP'));
 assert.ok(results.filter(r=>r.status==='GAP').every(r=>r.rationale.includes('analyst verification')));
});
test('remediated or false positive findings do not create new gaps',()=>{
 for(const status of ['REMEDIATED','FALSE_POSITIVE','ACCEPTED'] as const){
  const results=assessFramework('ISO27001',[finding({
   source:'wapiti',title:'SQL injection',description:'CWE-89',severity:'HIGH',status
  })]);
  assert.equal(results.filter(r=>r.status==='GAP').length,0);
 }
});
test('no findings are not reported as passing controls',()=>{
 const results=assessFramework('ISO27001',[]);
 assert.ok(results.length>0);
 assert.ok(results.every(r=>r.status==='NOT_TESTED'));
});
test('OWASP 2025 identifiers use current edition',()=>{
 const results=assessFramework('OWASP',[finding({source:'wapiti',title:'SQL injection',description:'CWE-89',severity:'HIGH'})]);
 assert.ok(results.some(r=>r.control==='A05:2025 Injection'));
 assert.equal(results.some(r=>r.control==='A03 Injection'),false);
});
