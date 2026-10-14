import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

test('premium workspace keeps reports contextual and profile driven',()=>{
 const html=fs.readFileSync('public/index.html','utf8');
 const js=fs.readFileSync('public/dashboard.js','utf8');
 const ui=html+'\n'+js;
 assert.doesNotMatch(ui,/onclick="tab\('reports',this\)"[^>]*>[^<]*Report Center/);
 assert.match(ui,/OFFENSIVE SECURITY/);
 assert.match(ui,/Export Offensive Technical Report/);
 assert.match(ui,/DEFENSIVE SECURITY/);
 assert.match(ui,/Export Defensive Remediation Report/);
 assert.match(ui,/profileAvatar/);
 assert.match(ui,/\/api\/auth\/profile/);
 assert.match(ui,/department:department\.value/);
 assert.match(ui,/workProfile:workProfile\.value/);
});

test('onboarding metadata is descriptive and does not replace RBAC role',()=>{
 const auth=fs.readFileSync('src/user-auth.ts','utf8');
 assert.match(auth,/ADD COLUMN IF NOT EXISTS department text/);
 assert.match(auth,/ADD COLUMN IF NOT EXISTS work_profile text/);
 assert.match(auth,/role text NOT NULL DEFAULT 'analyst'/);
 assert.match(auth,/u\.role,s\.expires_at AS exp/);
});

test('framework crosswalk remains inside enterprise GRC workflow',()=>{
 const ui=fs.readFileSync('public/index.html','utf8');
 assert.match(ui,/Frameworks & Controls/);
 assert.match(ui,/openEnterpriseFrameworks/);
 assert.match(ui,/GRC Framework Crosswalk/);
 assert.match(ui,/operational readiness—not certification/);
});
