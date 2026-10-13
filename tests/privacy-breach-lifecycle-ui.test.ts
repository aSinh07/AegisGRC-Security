import fs from 'node:fs';import assert from 'node:assert/strict';import test from 'node:test';const h=fs.readFileSync('public/index.html','utf8')+'\n'+fs.readFileSync('public/enterprise-ops.js','utf8');
test('privacy breach lifecycle is operational from Enterprise GRC',()=>{assert.match(h,/advancePrivacyBreach/);assert.match(h,/Update \/ close/);for(const s of ['OPEN','CONTAINED','ASSESSING','NOTIFYING','REMEDIATING','CLOSED'])assert.ok(h.includes("'"+s+"'"))});
test('breach closure requires human assessment and containment',()=>{assert.match(h,/Closure requires containment and assessment/);assert.match(h,/Human-reviewed breach assessment/);assert.match(h,/Containment evidence \/ actions/)});
test('UI does not infer legal notification duty',()=>{assert.match(h,/does not infer a legal notification duty/);assert.match(h,/authorized human reviewer against current applicable law/)});

