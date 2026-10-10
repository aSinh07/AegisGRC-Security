import test from 'node:test';
import assert from 'node:assert/strict';
import {correlateFindings,findingFingerprint} from '../src/finding-correlation.js';
import type {Finding} from '../src/models.js';
const base=(x:Partial<Finding>):Finding=>({id:'1',assessmentId:'a',source:'nuclei',title:'Finding',description:'Observed',severity:'HIGH',asset:'HTTPS://HOST.TEST/app',evidenceHash:'a'.repeat(64),createdAt:'2026-01-01T00:00:00Z',mappings:{},...x});
test('explicit scanner CVE is preferred for correlation',()=>{
 const a=base({id:'1',externalIds:{cve:['CVE-2025-12345'],scannerId:'n1'}});
 const b=base({id:'2',source:'trivy',title:'different title',externalIds:{cve:['CVE-2025-12345'],scannerId:'t1'}});
 const g=correlateFindings([a,b]);assert.equal(g.length,1);assert.equal(g[0].sourceCount,2);assert.equal(g[0].identifier,'CVE-2025-12345');
});
test('stable fingerprint survives evidence and finding id changes for same CVE asset',()=>{
 const a=base({id:'old',externalIds:{cve:['CVE-2025-12345']},evidenceHash:'a'.repeat(64)});
 const b=base({id:'new',externalIds:{cve:['CVE-2025-12345']},evidenceHash:'b'.repeat(64)});
 assert.equal(findingFingerprint(a),findingFingerprint(b));
});
test('unrelated scanner observations are not merged',()=>{
 const a=base({id:'1',externalIds:{scannerId:'check-a'}});
 const b=base({id:'2',externalIds:{scannerId:'check-b'}});
 assert.notEqual(findingFingerprint(a),findingFingerprint(b));assert.equal(correlateFindings([a,b]).length,2);
});
