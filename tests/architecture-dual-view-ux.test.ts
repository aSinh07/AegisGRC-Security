import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
const html=fs.readFileSync('public/index.html','utf8'),css=fs.readFileSync('public/enhancements.css','utf8'),js=fs.readFileSync('public/architecture-3d.js','utf8');
test('architecture workspace explicitly separates CAD and simulated 3D purposes',()=>{for(const x of ['CAD DESIGN','Technical CAD / Engineering View','INTERACTIVE 3D','Real-Life Simulated 3D View','native DWG/BIM geometry','Spatial positions are visualization aids'])assert.ok(html.includes(x))});
test('both architecture views derive from one evidence graph',()=>{assert.match(js,/renderCad\(\)/);assert.match(js,/graph=data/);assert.match(js,/graph\.nodes/);assert.match(js,/graph\.edges/)});
test('profile account control is anchored at far right of title bar',()=>{assert.match(css,/\.profile-shell\{margin-left:auto/);assert.match(css,/\.profile-shell\{order:2/);assert.match(html,/class="profile-shell"/)});
test('dual workspace is responsive',()=>{assert.match(css,/architecture-dual\{display:grid/);assert.match(css,/@media\(max-width:1150px\)/)});

test('CAD blueprint remains evidence-graph driven and synchronizes selection with 3D',()=>{assert.match(js,/cad-blueprint/);assert.match(js,/graph\.edges\.map/);assert.match(js,/data-node/);assert.match(js,/selected=Number/);assert.match(js,/renderCad\(\)/);assert.match(css,/\.cad-links/);assert.match(css,/\.cad-node\.selected/)});

test('interactive 3D is an enterprise infrastructure flow map rather than a radial/house layout',()=>{for(const k of ['CLIENT','IDENTITY','NETWORK','FIREWALL','LOAD_BALANCER','APPLICATION','CLOUD','DATABASE','STORAGE'])assert.ok(js.includes(k));assert.match(js,/zoneOrder/);assert.match(js,/drawZones/);assert.doesNotMatch(js,/const ring=i%12/)});
