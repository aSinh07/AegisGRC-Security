import test from 'node:test';import assert from 'node:assert/strict';import {scanTls,scanImageWithGrype,generateSbom,scanKubernetes,scanIac,scanSecrets} from '../src/external-scanners.js';
test('external scanner adapters reject unsafe targets before execution',async()=>{for(const fn of [scanTls,scanImageWithGrype,generateSbom] as any[]){await assert.rejects(()=>fn('x;touch /tmp/pwn'))}});
test('workspace scanners reject paths outside controlled mounts',async()=>{for(const fn of [scanKubernetes,scanIac,scanSecrets] as any[]){await assert.rejects(()=>fn('/etc'))}});
test('unavailable scanner is evidence state, not a false success',async()=>{const r=await scanImageWithGrype('alpine:latest');assert.ok(['SUCCESS','FAILED','TIMEOUT','TRUNCATED','UNAVAILABLE'].includes(r.state));if(r.state==='UNAVAILABLE')assert.equal(r.exitCode,null);assert.equal(r.evidence.sha256.length,64)});

test('image and SBOM targets reject option injection',async()=>{await assert.rejects(()=>scanImageWithGrype('--help'));await assert.rejects(()=>generateSbom('-o'));});
