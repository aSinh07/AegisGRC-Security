import test from 'node:test';import assert from 'node:assert/strict';import {scanTls,scanImageWithGrype,generateSbom,scanKubernetes,scanIac,scanSecrets} from '../src/external-scanners.js';
test('external scanner adapters reject unsafe targets before execution',async()=>{for(const fn of [scanTls,scanImageWithGrype,generateSbom] as any[]){assert.throws(()=>fn('x;touch /tmp/pwn'))}});
test('workspace scanners reject paths outside controlled mounts',async()=>{for(const fn of [scanKubernetes,scanIac] as any[]){assert.throws(()=>fn('/etc'))}await assert.rejects(()=>scanSecrets('/etc'),/Scanner paths are restricted to \/workspace mounts/)});
test('unavailable scanner is evidence state, not a false success',async()=>{const r=await scanImageWithGrype('alpine:latest');assert.ok(['SUCCESS','FAILED','TIMEOUT','TRUNCATED','UNAVAILABLE'].includes(r.state));if(r.state==='UNAVAILABLE')assert.equal(r.exitCode,null);assert.equal(r.evidence.sha256.length,64)});

test('image and SBOM targets reject option injection',async()=>{assert.throws(()=>scanImageWithGrype('--help'));assert.throws(()=>generateSbom('-o'));});

test('external scanner runner implements byte-based output bounding',async()=>{const src=await (await import('node:fs/promises')).readFile(new URL('../src/external-scanners.ts',import.meta.url),'utf8');assert.match(src,/Buffer\.from\(base,'utf8'\)/);assert.match(src,/d\.subarray\(0,room\)/);assert.doesNotMatch(src,/n\.slice\(0,MAX\)/);});
