import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {inferArchitecture} from '../src/architecture-document-model.js';
test('document model only links explicitly documented relationships',()=>{
 const m=inferArchitecture('Browser -> WAF\nWAF -> API Gateway\nAPI Gateway -> PostgreSQL\nRedis cache');
 assert.equal(m.edges.length,3);assert.equal(m.nodes.length,5);
 assert.ok(m.nodes.some(n=>n.kind==='DATABASE'));
 assert.equal(m.summary.unverifiedComponents,1);
 assert.ok(m.edges.every(e=>e.confidence==='EXPLICIT'));
});
test('component mentions alone cannot fabricate network flows',()=>{
 const m=inferArchitecture('The organization uses AWS and PostgreSQL.\nFirewall is managed separately.');
 assert.equal(m.edges.length,0);
 assert.ok(m.limitations.some(x=>x.includes('not a verified')));
});
test('architecture UI removes old control-plane workflow and supports upload and interactive model',async()=>{
 const s=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const start=s.indexOf('<section id="architecture"'),end=s.indexOf('</section>',start),section=s.slice(start,end);
 assert.ok(start>=0);assert.doesNotMatch(section,/Control-plane workflow|Evidence-Derived Architecture/);
 assert.match(section,/architectureFile/);assert.match(section,/architecture3d/);
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(server,/api\/architecture\/document-model/);assert.match(server,/inferArchitecture/);
});
