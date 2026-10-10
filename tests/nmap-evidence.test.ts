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
