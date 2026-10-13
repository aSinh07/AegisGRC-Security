import test from 'node:test';
import assert from 'node:assert/strict';
import {capabilitiesFor,capabilitySummary,securityCapabilityCatalog} from '../src/security-capabilities.js';

test('offensive catalog covers core enterprise assessment disciplines',()=>{
 const rows=capabilitiesFor('OFFENSIVE');
 const categories=rows.map(x=>x.category);
 for(const expected of ['Attack Surface','Web / API DAST','Injection Validation','Source / SAST','Infrastructure Vulnerability','Manual Penetration Testing','Commercial / External Platforms'])
  assert.ok(categories.includes(expected),expected);
 assert.ok(rows.every(x=>x.authorizationRequired),'offensive execution must remain authorization gated');
});

test('defensive catalog separates defense from enterprise GRC',()=>{
 const rows=capabilitiesFor('DEFENSIVE');
 assert.ok(rows.some(x=>x.engines.includes('Wazuh')));
 assert.ok(rows.some(x=>x.engines.includes('Prowler')));
 assert.ok(rows.some(x=>x.engines.includes('Trivy')));
 assert.equal(rows.some(x=>x.category.includes('GRC')),false);
});

test('commercial products are connector-ready rather than falsely connected',()=>{
 const commercial=securityCapabilityCatalog.filter(x=>x.id.startsWith('commercial-'));
 assert.ok(commercial.length>=2);
 assert.ok(commercial.every(x=>x.mode==='CONNECTOR_READY'));
});

test('capability summaries expose implementation truth',()=>{
 const o=capabilitySummary('OFFENSIVE'),d=capabilitySummary('DEFENSIVE');
 assert.equal(o.total,o.native+o.evidenceImport+o.connectorReady);
 assert.equal(d.total,d.native+d.evidenceImport+d.connectorReady);
});
