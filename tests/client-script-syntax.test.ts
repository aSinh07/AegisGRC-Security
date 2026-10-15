import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';
for(const file of ['public/dashboard.js','public/enterprise-ops.js','public/architecture-3d.js'])test(file+' parses as shipped browser JavaScript',()=>{const source=fs.readFileSync(file,'utf8');assert.doesNotThrow(()=>new vm.Script(source,{filename:file}))});
