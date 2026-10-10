import test from 'node:test';
import assert from 'node:assert/strict';
import {nucleiJsonlFindings,trivyJsonFindings} from '../src/infrastructure-parsers.js';

test('Nuclei parser preserves scanner supplied CVE and template identity',()=>{
 const raw=JSON.stringify({'template-id':'CVE-2024-12345','matched-at':'https://host.test/x',info:{name:'Scanner match',severity:'high',classification:{'cve-id':['CVE-2024-12345'],'cwe-id':['CWE-79'],'cvss-score':8.1}}});
 const f=nucleiJsonlFindings('a','https://host.test','a'.repeat(64),raw);
 assert.equal(f.length,1);assert.equal(f[0].confidence,'SCANNER_REPORTED');
 assert.deepEqual(f[0].externalIds?.cve,['CVE-2024-12345']);assert.equal(f[0].externalIds?.scannerId,'CVE-2024-12345');
});
test('Nuclei parser does not invent CVE when scanner did not report one',()=>{
 const raw=JSON.stringify({'template-id':'tls-check','host':'host.test',info:{name:'TLS observation',severity:'info'}});
 const f=nucleiJsonlFindings('a','host.test','a'.repeat(64),raw);assert.equal(f[0].externalIds?.cve,undefined);
});
test('Trivy parser preserves package vulnerability and fixed version',()=>{
 const raw=JSON.stringify({Results:[{Target:'image:test',Vulnerabilities:[{VulnerabilityID:'CVE-2025-11111',PkgName:'libx',InstalledVersion:'1.0',FixedVersion:'1.2',Severity:'CRITICAL',Title:'libx flaw'}]}]});
 const f=trivyJsonFindings('a','image:test','b'.repeat(64),raw);
 assert.equal(f.length,1);assert.deepEqual(f[0].externalIds?.cve,['CVE-2025-11111']);assert.match(f[0].remediation||'',/1\.2/);
});
test('malformed scanner output yields no fabricated findings',()=>{
 assert.deepEqual(nucleiJsonlFindings('a','x','a'.repeat(64),'not json'),[]);
 assert.deepEqual(trivyJsonFindings('a','x','a'.repeat(64),'not json'),[]);
});
