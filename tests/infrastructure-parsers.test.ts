import test from 'node:test';
import assert from 'node:assert/strict';
import {nucleiJsonlFindings,sqlmapTextFindings,trivyJsonFindings} from '../src/infrastructure-parsers.js';

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

test('SQLmap parser creates an evidence-backed CWE-89 finding only for reported injectable parameters',()=>{
 const raw='Parameter: id (GET)\n    Type: boolean-based blind\n    Title: AND boolean-based blind - WHERE or HAVING clause\n    Payload: id=1 AND 1=1\n';
 const f=sqlmapTextFindings('a','https://example.test','b'.repeat(64),raw);
 assert.equal(f.length,1);assert.equal(f[0].source,'sqlmap');assert.equal(f[0].cwe,'CWE-89');assert.equal(f[0].cvss,undefined);assert.equal(f[0].severity,'HIGH');assert.equal(f[0].confidence,'SCANNER_REPORTED');
 assert.equal(sqlmapTextFindings('a','https://example.test','b'.repeat(64),'all tested parameters do not appear to be injectable').length,0);
});
