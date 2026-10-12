import test from 'node:test';import assert from 'node:assert/strict';import {correlateExposure,exposurePriority} from '../src/exposure-prioritization.js';
test('exposure context raises actionable vulnerability priority',()=>{const base={id:'1',asset:'api',fingerprint:'f1',severity:'HIGH' as const,cvss:9};const a=exposurePriority(base),b=exposurePriority({...base,kev:true,internetExposed:true,exploitObserved:true,epss:.95});assert.ok(b.score>a.score);assert.equal(b.band,'P0')});
test('effective compensating control reduces but never erases vulnerability',()=>{const x=exposurePriority({id:'1',asset:'db',fingerprint:'f',severity:'CRITICAL',cvss:10,kev:true,controlCoverage:'EFFECTIVE'});assert.ok(x.score>0)});
test('stable fingerprint deduplicates scanner overlap',()=>{const x=correlateExposure([{id:'1',asset:'a',fingerprint:'same',severity:'HIGH'},{id:'2',asset:'a',fingerprint:'same',severity:'CRITICAL'}]);assert.equal(x.length,1)});

test('same fingerprint on separate assets remains two vulnerabilities',()=>{
 const x=correlateExposure([{id:'1',asset:'server-a',fingerprint:'CVE-2026-1',severity:'HIGH'},{id:'2',asset:'server-b',fingerprint:'CVE-2026-1',severity:'HIGH'}]);
 assert.equal(x.length,2);
});
test('scanner overlap preserves the highest-priority finding regardless of order',()=>{
 const low={id:'1',asset:'server-a',fingerprint:'same',severity:'LOW' as const};
 const high={id:'2',asset:'server-a',fingerprint:'same',severity:'CRITICAL' as const,kev:true};
 for(const list of [[low,high],[high,low]]){const x=correlateExposure(list);assert.equal(x.length,1);assert.equal(x[0].id,'2')}
});
test('risk acceptance and unverified closure cannot erase real exposure',()=>{
 const f={id:'1',asset:'server-a',fingerprint:'same',severity:'CRITICAL' as const};
 const baseline=exposurePriority(f).score;
 assert.equal(exposurePriority({...f,status:'ACCEPTED'}).score,baseline);
 assert.equal(exposurePriority({...f,status:'CLOSED'}).score,baseline);
 assert.equal(exposurePriority({...f,status:'CLOSED',verifiedClosed:true}).score,0);
});
test('invalid numeric risk signals do not propagate NaN',()=>{
 const x=exposurePriority({id:'1',asset:'server-a',fingerprint:'same',severity:'HIGH',cvss:NaN,epss:Infinity});
 assert.ok(Number.isFinite(x.score));
});
