import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {scanContainerImageWithTrivy} from '../src/trivy.js';

test('Trivy execution is restricted to workspace filesystem artifacts',async()=>{
 const s=await readFile(new URL('../src/trivy.ts',import.meta.url),'utf8');
 assert.match(s,/startsWith\('\/workspace\/'\)/);assert.match(s,/spawn\('trivy'/);assert.match(s,/shell:false/);
});
test('Trivy route requires assessment membership and manageAssessment permission',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8'),start=s.indexOf("app.post('/api/scans/trivy'");
 assert.ok(start>=0);const end=s.indexOf("app.post('/api/documents/security-scan'",start),body=s.slice(start,end);
 assert.match(body,/assessmentForUser/);assert.match(body,/requireOrgPermission\(u\.userId,access\.organization_id,'manageAssessment'\)/);
 assert.doesNotMatch(body,/status:'COMPLETED'/);
});

test('container image scanner rejects unsafe or empty references',async()=>{await assert.rejects(()=>scanContainerImageWithTrivy(''));await assert.rejects(()=>scanContainerImageWithTrivy('alpine:latest;id'));await assert.rejects(()=>scanContainerImageWithTrivy('x | sh'))});
