import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {builtInFrameworkLibrary} from '../src/framework-library.js';

test('governed framework library covers every framework exposed by Aegis catalog',async()=>{
 const grc=await readFile(new URL('../src/grc.ts',import.meta.url),'utf8');
 const expected=['ISO27001','ISO42001','NIST_CSF','NIST_AI_RMF','EU_AI_ACT','ISO27701','CIS','OWASP','SOC2','PCI','GDPR','DPDP','HIPAA'];
 const governed=new Set(builtInFrameworkLibrary.requirements.map(x=>x.framework));
 for(const id of expected){assert.ok(grc.includes("id:'"+id+"'"),id+' missing from catalog');assert.ok(governed.has(id),id+' missing governed requirement library')}
 assert.ok(builtInFrameworkLibrary.controls.length>=23);
 assert.ok(builtInFrameworkLibrary.requirements.length>=60);
 for(const r of builtInFrameworkLibrary.requirements){assert.ok(r.controls.length>0);assert.match(r.source,/^https:\/\//)}
});

test('enterprise governance performance is persisted, permission-gated and independently approved',async()=>{
 const src=await readFile(new URL('../src/governance-performance.ts',import.meta.url),'utf8');
 for(const table of ['grc_risk_appetite_statements','grc_performance_metrics','grc_metric_measurements','grc_management_reviews'])assert.ok(src.includes(table));
 for(const perm of ["'manageRisk'","'manageControl'","'review'","'read'"])assert.ok(src.includes(perm));
 assert.match(src,/Independent approver required for risk appetite/);
 assert.match(src,/Independent approver required for management review/);
 assert.match(src,/evidence reference required/i);
});

test('governance performance APIs and browser workflows are wired end to end',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 for(const path of ['/governance-performance','/risk-appetite','/performance-metrics','/management-reviews'])assert.ok(server.includes(path),path+' route missing');
 assert.ok(server.includes('await initGovernancePerformance()'));
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 for(const id of ['governancePerformanceSummary','appetiteKey','metricKey','managementReviewKey','governancePerformanceTables'])assert.ok(html.includes('id="'+id+'"'),id+' UI missing');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 for(const fn of ['loadGovernancePerformance','saveRiskAppetite','saveGovernanceMetric','saveManagementReview'])assert.ok(js.includes('function '+fn),fn+' browser workflow missing');
});

test('enterprise executive report includes governance performance evidence',async()=>{
 const model=await readFile(new URL('../src/enterprise-grc-report.ts',import.meta.url),'utf8');
 const pdf=await readFile(new URL('../src/enterprise-grc-exporters.ts',import.meta.url),'utf8');
 assert.ok(model.includes('governancePerformance'));
 assert.ok(pdf.includes('Governance Performance & Management Oversight'));
 assert.ok(pdf.includes('Approved risk appetite statements'));
 assert.ok(pdf.includes('KPI/KRI/KCI metrics'));
});
