import test from 'node:test';
import assert from 'node:assert/strict';
import {architectureConfidence} from '../src/architecture-confidence.js';
test('caller claimed human verification cannot suppress review',()=>{
 const x=architectureConfidence({components:[{confidence:'EXPLICIT'}],connections:[{confidence:'EXPLICIT'}],sourceQuality:1,humanVerified:true});
 assert.equal(x.requiresReview,true);
 assert.equal(x.advisoryOnly,true);
 assert.equal(x.humanReviewClaimed,true);
});
test('non-finite quality inputs never yield NaN scores',()=>{
 const x=architectureConfidence({components:[],connections:[],sourceQuality:NaN});
 assert.ok(Number.isFinite(x.score));
 assert.equal(x.requiresReview,true);
});
