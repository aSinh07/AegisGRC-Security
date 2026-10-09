import test from 'node:test';
import assert from 'node:assert/strict';
import {correlateFindings,correlationSummary} from '../src/finding-correlation.js';
import type {Finding} from '../src/models.js';
const make=(id:string,source:Finding['source'],extra:Partial<Finding>={}):Finding=>({
 id,source,assessmentId:'assessment-1',asset:'https://example.test',
 title:'CVE-2025-12345 vulnerable dependency',description:'Observed package issue',
 severity:'MEDIUM',evidenceHash:id.padEnd(64,'0'),createdAt:'2026-10-10T00:00:00Z',
 mappings:{},status:'OPEN',...extra
});
test('same asset and CVE link scanner sources but preserve evidence',()=>{
 const groups=correlateFindings([make('one','semgrep'),make('two','zap',{severity:'HIGH'})]);
 assert.equal(groups.length,1);assert.equal(groups[0].sourceCount,2);
 assert.equal(groups[0].severity,'HIGH');assert.equal(groups[0].evidenceHashes.length,2);
 assert.equal(groups[0].findingIds.length,2);
});
test('different assets are not combined',()=>{
 assert.equal(correlateFindings([make('one','zap'),make('two','zap',{asset:'other.example'})]).length,2);
});
test('unidentified findings stay separate',()=>{
 const fs=[make('one','zap',{title:'Weak header',description:'Missing header'}),
 make('two','wapiti',{title:'Weak header',description:'Missing header'})];
 assert.equal(correlateFindings(fs).length,2);
 assert.equal(correlationSummary(fs).groupedObservations,0);
});
test('different CVEs are not combined',()=>{
 assert.equal(correlateFindings([make('one','zap'),make('two','zap',{title:'CVE-2025-54321'})]).length,2);
});
test('source record remains unchanged',()=>{
 const f=make('one','zap');const before=JSON.stringify(f);correlateFindings([f]);
 assert.equal(JSON.stringify(f),before);
});

test('same CWE on same asset is not sufficient to merge distinct observations',()=>{
 const a=make('cwe-a','zap',{cwe:'CWE-79',title:'Reflected XSS',description:'parameter q'});
 const b=make('cwe-b','wapiti',{cwe:'CWE-79',title:'Stored XSS',description:'profile field'});
 const groups=correlateFindings([a,b]);
 assert.equal(groups.length,2);
 assert.ok(groups.every(g=>g.confidence==='UNVERIFIED_SINGLE'));
});
