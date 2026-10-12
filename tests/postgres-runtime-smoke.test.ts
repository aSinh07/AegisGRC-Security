import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {readFile} from 'node:fs/promises';
import pg from 'pg';
import {initUsers} from '../src/user-auth.js';
import {initGrcReviews} from '../src/grc-review.js';
import {initGrcCore} from '../src/grc-core.js';
import {initOrganizations} from '../src/grc-organizations.js';
import {initControlRegistry} from '../src/grc-controls.js';
import {initThirdPartyRisk} from '../src/third-party-risk.js';
import {initArchitectureAssurance} from '../src/architecture-assurance.js';
import {initContinuousCompliance} from '../src/continuous-compliance.js';
import {initBusinessContinuity} from '../src/business-continuity.js';
import {initPolicyGovernance} from '../src/policy-governance.js';
import {initAuditManagement} from '../src/audit-management.js';
import {initEvidenceEngine} from '../src/grc-evidence.js';
import {initIssueRiskCapa} from '../src/grc-remediation.js';
import {initGrcOperations} from '../src/grc-operations.js';
import {initGrcAutomation,runDueAutomations} from '../src/grc-automation.js';
import {initFindingReview} from '../src/finding-review.js';
import {initFindingRisk} from '../src/finding-risk.js';
import {initAssessmentInventory} from '../src/assessment-inventory.js';
import {initBreachAssessment} from '../src/breach-assessment.js';
import {initScannerJobs} from '../src/scanner-jobs.js';

const ciDb=process.env.NODE_ENV==='test'&&/^postgres(?:ql)?:\/\/[^/]*@(?:localhost|127\.0\.0\.1):5432\//.test(process.env.DATABASE_URL||'');
test('real PostgreSQL schema, runtime initializers and scheduled automation smoke', {skip:!ciDb},async()=>{
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 const org=crypto.randomUUID(),rule=crypto.randomUUID();
 try{
  const schema=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
  await pool.query(schema);
  for(const init of [initUsers,initGrcReviews,initGrcCore,initOrganizations,initControlRegistry,initThirdPartyRisk,initArchitectureAssurance,initContinuousCompliance,initBusinessContinuity,initPolicyGovernance,initAuditManagement,initEvidenceEngine,initIssueRiskCapa,initGrcOperations,initGrcAutomation,initFindingReview,initFindingRisk,initAssessmentInventory,initBreachAssessment,initScannerJobs])await init();
  await pool.query('INSERT INTO grc_organizations(id,name) VALUES($1,$2)',[org,'CI automation smoke']);
  await pool.query("INSERT INTO grc_automation_rules(id,organization_id,name,kind) VALUES($1,$2,'CI due obligations','OBLIGATION_DUE')",[rule,org]);
  const results=await runDueAutomations(100);
  const result=results.find(x=>x.ruleId===rule);
  assert.equal(result?.status,'SUCCEEDED',JSON.stringify(result));
  const saved=await pool.query('SELECT status,summary FROM grc_automation_runs WHERE rule_id=$1',[rule]);
  assert.equal(saved.rows[0]?.status,'SUCCEEDED');
 }finally{
  await pool.query('DELETE FROM grc_organizations WHERE id=$1',[org]).catch(()=>{});
  await pool.end();
 }
});
