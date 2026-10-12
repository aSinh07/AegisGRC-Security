import test from 'node:test';
import assert from 'node:assert/strict';
import {integrationReadiness} from '../src/integration-health.js';
const now=new Date('2026-10-12T10:00:00Z');
test('no required integrations must not be ready',()=>{
 const result=integrationReadiness([],[],now);
 assert.equal(result.ready,false);
 assert.equal(result.advisoryOnly,true);
});
test('one healthy duplicate provider satisfies required provider',()=>{
 const result=integrationReadiness([
  {provider:'AWS',state:'CONNECTED',lastSuccessAt:'2026-10-12T09:00:00Z'},
  {provider:'AWS',state:'ERROR',lastSuccessAt:'2026-10-01T09:00:00Z'}
 ],['AWS'],now);
 assert.equal(result.ready,true);
});
