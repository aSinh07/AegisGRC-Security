import test from 'node:test';import assert from 'node:assert/strict';
import {architectureAccuracy,benchmarkArchitecture} from '../src/architecture-accuracy.js';
test('architecture accuracy measures false positives and omissions',()=>{
 const reference={nodes:[{label:'API',kind:'APPLICATION'},{label:'DB',kind:'DATABASE'}],edges:[{from:'API',to:'DB'}]};
 const predicted={nodes:[{label:'API',kind:'APPLICATION'},{label:'Redis',kind:'DATABASE'}],edges:[{from:'DB',to:'API'}]};
 const x=architectureAccuracy(reference,predicted);
 assert.equal(x.nodes.precision,.5);assert.equal(x.nodes.recall,.5);assert.equal(x.edges.f1,0);
 assert.equal(x.claimableAccuracyPercent,null);
 const b=benchmarkArchitecture([{id:'fixture-1',reference,predicted}]);assert.equal(b.component.f1,.5);assert.equal(b.qualifiedForExternalAccuracyClaim,false);
});
test('empty labeled corpus cannot produce an accuracy claim',()=>assert.throws(()=>benchmarkArchitecture([]),/No labeled/));
