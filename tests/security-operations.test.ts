import test from 'node:test';import assert from 'node:assert/strict';
import {offensiveCapabilityCatalog,defensiveAssessment,securityWorkspaceSummary} from '../src/security-operations.js';

const assessment:any={id:'a1',target:'https://example.test',authorizedAt:'2026-01-01T00:00:00Z',status:'COMPLETED',findings:[],evidenceIds:[]};
const findings:any[]=[{id:'f1',assessmentId:'a1',source:'zap',title:'Injection exposure',description:'Observed',severity:'HIGH',cvss:8.1,asset:'https://example.test',evidenceHash:'a'.repeat(64),createdAt:'2026-01-01',mappings:{},remediation:'Use parameterized queries and retest.',status:'OPEN'}];
const evidence:any[]=[{id:'e1',assessmentId:'a1',source:'zap',sha256:'a'.repeat(64),createdAt:'2026-01-01',metadata:{}}];

test('offensive catalog spans major technical security surfaces with real engine mapping',()=>{const c=offensiveCapabilityCatalog();for(const id of ['WEB_API','NETWORK_INFRA','CLOUD','CONTAINER','SOURCE_SUPPLY_CHAIN','ENDPOINT_IDENTITY','DATA'])assert.ok(c.some(x=>x.id===id),id);assert.ok(c.flatMap(x=>x.engines).includes('ZAP'));assert.ok(c.flatMap(x=>x.engines).includes('NMAP'));assert.ok(c.flatMap(x=>x.engines).includes('PROWLER'));assert.ok(c.flatMap(x=>x.engines).includes('TRIVY'));});

test('defensive analysis is derived from stored evidence and requires retest before closure',()=>{const d=defensiveAssessment(assessment,findings,evidence);assert.equal(d.posture.openFindings,1);assert.equal(d.actions[0].findingId,'f1');assert.match(d.actions[0].validation,/targeted retest/i);assert.match(d.actions[0].residualRisk,/UNTIL SUCCESSFUL RETEST/);assert.ok(d.posture.evidenceSources.includes('ZAP'));});

test('offensive and defensive workspaces reuse one assessment rather than duplicate upload',()=>{const d=securityWorkspaceSummary(assessment,findings,evidence);assert.equal(d.reuse.sameAssessment,true);assert.equal(d.reuse.reuploadRequired,false);assert.equal(d.offensive.findings,1);assert.equal(d.defensive.actions.length,1);});
