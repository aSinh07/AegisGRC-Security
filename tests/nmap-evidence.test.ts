import test from 'node:test';
import assert from 'node:assert/strict';
import {nmapFindings} from '../src/parsers.js';

test('Nmap open port is recorded as observation, not invented CVE',()=>{
 const xml='<nmaprun><host><ports><port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql"/></port></ports></host></nmaprun>';
 const f=nmapFindings('a1','https://example.test','a'.repeat(64),xml);
 assert.equal(f.length,1);
 assert.equal(f[0].confidence,'OBSERVED');
 assert.equal(f[0].externalIds?.scannerId,'nmap:tcp:5432');
 assert.equal(f[0].externalIds?.cve,undefined);
 assert.match(f[0].description,/reachable|exposure/i);
});

test('Nmap parser tolerates reordered attributes and rich service tags',()=>{
 const xml='<nmaprun><host><ports><port portid="5432" protocol="tcp"><state reason="syn-ack" state="open"/><service product="PostgreSQL" version="16" name="postgresql"></service></port></ports></host></nmaprun>';
 const f=nmapFindings('a','https://example.test','b'.repeat(64),xml);
 assert.equal(f.length,1);assert.match(f[0].title,/5432/);assert.equal(f[0].externalIds?.scannerId,'nmap:tcp:5432');assert.equal(f[0].externalIds?.cve,undefined);
});
test('Nmap closed ports never become findings',()=>{
 const xml='<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>';
 assert.equal(nmapFindings('a','https://example.test','c'.repeat(64),xml).length,0);
});
