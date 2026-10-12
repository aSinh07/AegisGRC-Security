import test from 'node:test';
import assert from 'node:assert/strict';
import {performance} from 'node:perf_hooks';
import {integrationReadiness} from '../src/integration-health.js';
import {architectureAccuracy,benchmarkArchitecture} from '../src/architecture-accuracy.js';

test('integration readiness fails closed across outage stale sync and missing permissions',()=>{
 const now=new Date('2026-10-12T10:00:00Z');
 for(const c of [
  {provider:'GitHub',state:'ERROR' as const,lastSuccessAt:'2026-10-12T09:00:00Z'},
  {provider:'GitHub',state:'CONNECTED' as const,lastSuccessAt:'2026-10-10T09:00:00Z'},
  {provider:'GitHub',state:'CONNECTED' as const,lastSuccessAt:'2026-10-12T09:00:00Z',permissions:['read'],requiredPermissions:['read','metadata']}
 ]) assert.equal(integrationReadiness([c],['GitHub'],now).ready,false);
});

test('integration readiness tolerates a failed duplicate when another verified snapshot is healthy',()=>{
 const now=new Date('2026-10-12T10:00:00Z');
 const x=integrationReadiness([
  {provider:'GitHub',state:'ERROR',lastSuccessAt:'2026-10-12T09:00:00Z'},
  {provider:'GitHub',state:'CONNECTED',lastSuccessAt:'2026-10-12T09:59:00Z',permissions:['read'],requiredPermissions:['read']}
 ],['GitHub'],now);
 assert.equal(x.ready,true);
});

test('architecture scoring handles large representative graph volumes within bounded time',()=>{
 const n=10000;
 const nodes=Array.from({length:n},(_,i)=>({label:'Component '+i,kind:i%3?'APPLICATION':'DATABASE'}));
 const edges=Array.from({length:n-1},(_,i)=>({from:'Component '+i,to:'Component '+(i+1)}));
 const start=performance.now();
 const x=architectureAccuracy({nodes,edges},{nodes:[...nodes],edges:[...edges]});
 assert.equal(x.nodes.f1,1);assert.equal(x.edges.f1,1);
 assert.ok(performance.now()-start<5000,'10k-node deterministic benchmark exceeded 5 seconds');
});

test('architecture marketing qualification remains fail closed without representative independent corpus',()=>{
 const graph={nodes:[{label:'API',kind:'APPLICATION'}],edges:[]};
 const cases=Array.from({length:10},(_,i)=>({id:String(i),format:'PDF',independentlyLabeled:true,reference:graph,predicted:graph}));
 const b=benchmarkArchitecture(cases);
 assert.equal(b.qualifiedForExternalAccuracyClaim,false);
 assert.equal(b.claimableAccuracyPercent,null);
});
