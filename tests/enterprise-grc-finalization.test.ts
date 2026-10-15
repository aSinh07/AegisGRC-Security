import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {builtInFrameworkLibrary} from '../src/framework-library.js';

test('enterprise framework library ships governed content for primary GRC frameworks',()=>{
 const required=['ISO27001','ISO42001','ISO27701','NIST_AI_RMF','NIST_CSF','EU_AI_ACT','CIS'];
 const frameworks=new Set(builtInFrameworkLibrary.requirements.map(x=>x.framework));
 for(const id of required)assert.ok(frameworks.has(id),id+' governed library missing');
 assert.ok(builtInFrameworkLibrary.controls.length>=15);
 assert.ok(builtInFrameworkLibrary.requirements.length>=35);
 for(const r of builtInFrameworkLibrary.requirements){
  assert.ok(r.key&&r.title&&r.summary&&r.version);
  assert.ok(r.controls.length>0,r.framework+' '+r.key+' has no canonical control mapping');
  assert.match(r.source,/^https:\/\//);
 }
});

test('built-in library uses paraphrased governance records and stable idempotent startup seeding',async()=>{
 const src=await readFile(new URL('../src/framework-library.ts',import.meta.url),'utf8');
 assert.match(src,/ON CONFLICT\(framework,framework_version,requirement_key\)/);
 assert.match(src,/ON CONFLICT\(control_key\)/);
 assert.match(src,/grc_control_framework_mappings/);
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.ok(server.indexOf('await initBuiltInFrameworkLibrary()')>server.indexOf('await initControlRegistry()'));
});

test('enterprise report renderer carries professional executive sections and assurance boundary',async()=>{
 const src=await readFile(new URL('../src/enterprise-grc-exporters.ts',import.meta.url),'utf8');
 for(const heading of ['Executive GRC Summary','Statement of Applicability','Control Assurance & Framework Traceability','Enterprise Risk Register','Evidence Register & Technical Assurance','Priority Management Action Plan','Assurance Boundary & Final Conclusion'])assert.ok(src.includes(heading),heading+' missing');
 assert.match(src,/Internal readiness and control-assurance artifact|internal readiness and control-assurance artifact/i);
 assert.match(src,/not certification/i);
});
