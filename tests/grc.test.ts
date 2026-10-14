import test from 'node:test';
import assert from 'node:assert/strict';
import { frameworkCatalog, frameworkRefs, mapFinding } from '../src/grc.js';
import { assessFramework } from '../src/grc-engine.js';

test('maps XSS to OWASP injection and ISO/NIST controls', () => {
  const f: any = {
    id: '1',
    assessmentId: 'a',
    source: 'wapiti',
    title: 'Cross Site Scripting',
    description: 'CWE-79 XSS',
    severity: 'HIGH',
    asset: 'x',
    evidenceHash: 'h',
    createdAt: new Date().toISOString(),
    mappings: {},
  };

  const m = mapFinding(f);
  assert.ok(m.mappings.owasp?.includes('A05:2025 Injection'));
  assert.ok((m.mappings.iso27001?.length ?? 0) > 0);
  assert.ok((m.mappings.nist?.length ?? 0) > 0);
});


test('enterprise GRC exposes the five required first-class frameworks',()=>{const ids=new Set(frameworkCatalog.map(x=>x.id));for(const id of ['ISO27001','ISO42001','NIST_AI_RMF','EU_AI_ACT','ISO27701'])assert.ok(ids.has(id as any),id+' missing');});

test('AI evidence maps across ISO 42001, NIST AI RMF and EU AI Act without claiming conformity',()=>{const f:any={id:'ai1',assessmentId:'a',source:'manual',title:'LLM prompt risk',description:'AI model prompt and human oversight logging risk',severity:'HIGH',asset:'agent',evidenceHash:'h',createdAt:new Date().toISOString(),mappings:{}};const m=mapFinding(f);assert.ok(frameworkRefs(m,'ISO42001').length);assert.ok(frameworkRefs(m,'NIST_AI_RMF').includes('GOVERN'));assert.ok(frameworkRefs(m,'EU_AI_ACT').length);for(const id of ['ISO42001','NIST_AI_RMF','EU_AI_ACT'])assert.ok(assessFramework(id,[m]).length>0);});

test('privacy evidence maps to ISO 27701 while absent evidence remains NOT_TESTED',()=>{const f:any={id:'p1',assessmentId:'a',source:'manual',title:'Personal data retention',description:'PII retention and deletion evidence requires review',severity:'MEDIUM',asset:'data',evidenceHash:'p',createdAt:new Date().toISOString(),mappings:{}};const m=mapFinding(f);assert.ok(frameworkRefs(m,'ISO27701').length);assert.ok(assessFramework('ISO27701',[m]).some(x=>x.status==='GAP'));assert.ok(assessFramework('ISO27701',[]).every(x=>x.status==='NOT_TESTED'));});
