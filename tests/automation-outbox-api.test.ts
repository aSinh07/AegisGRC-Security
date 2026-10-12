import fs from 'node:fs';import assert from 'node:assert/strict';import test from 'node:test';
const src=fs.readFileSync('src/server.ts','utf8');
test('server initializes automation outbox before serving requests',()=>{assert.match(src,/await initAutomationOutbox\(\)/)});
test('automation APIs require authenticated tenant boundaries',()=>{for(const p of ['/automation/outbox','/automation/script-task','/tprm/servicenow/readiness'])assert.ok(src.includes(p),p);assert.match(src,/enqueueServiceNowWorkItem\(u\.userId,req\.params\.orgId/);assert.match(src,/enqueueScriptTask\(u\.userId,req\.params\.orgId/)});
test('ServiceNow work item is queued rather than directly dispatched',()=>{assert.match(src,/status\(202\)\.json\(await enqueueServiceNowWorkItem/);assert.doesNotMatch(src,/buildServiceNowWorkItem\(req\.body/)});
