import test from 'node:test';import assert from 'node:assert/strict';
import {parseFindingImport} from '../src/finding-import.js';
test('generic JSON findings are imported conservatively with evidence hash',()=>{
 const b=Buffer.from(JSON.stringify({findings:[{title:'SQL injection',description:'CWE-89 observed',severity:'HIGH',asset:'app/login',cwe:'CWE-89'}]}));
 const r=parseFindingImport('a','scan.json',b);assert.equal(r.format,'GENERIC_JSON');assert.equal(r.findings.length,1);
 assert.equal(r.findings[0].severity,'HIGH');assert.match(r.findings[0].evidenceHash,/^[0-9a-f]{64}$/);
});
test('SARIF preserves rule and location context',()=>{
 const b=Buffer.from(JSON.stringify({version:'2.1.0',runs:[{tool:{driver:{rules:[{id:'rule-1',shortDescription:{text:'Unsafe query'},properties:{tags:['CWE-89']}}]}},results:[{ruleId:'rule-1',level:'error',message:{text:'Unsafe SQL'},locations:[{physicalLocation:{artifactLocation:{uri:'src/db.ts'},region:{startLine:12}}}]}]}]}));
 const r=parseFindingImport('a','result.sarif',b);assert.equal(r.format,'SARIF');assert.equal(r.findings[0].asset,'src/db.ts');assert.equal(r.findings[0].severity,'HIGH');
});
test('unsupported report types remain evidence rather than invented findings',()=>{
 assert.throws(()=>parseFindingImport('a','report.pdf',Buffer.from('x')),/supports JSON and SARIF/);
});
test('malformed JSON is rejected',()=>assert.throws(()=>parseFindingImport('a','bad.json',Buffer.from('{')),/Invalid JSON/));
test('unknown severity does not inflate risk',()=>{
 const b=Buffer.from(JSON.stringify([{title:'Observation',severity:'unknown'}]));const r=parseFindingImport('a','x.json',b);assert.equal(r.findings[0].severity,'INFO');
});
