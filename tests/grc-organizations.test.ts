import test from 'node:test';import assert from 'node:assert/strict';import {roleAllows} from '../src/grc-organizations.js';
test('viewer is read only',()=>{assert.equal(roleAllows('VIEWER','read'),true);assert.equal(roleAllows('VIEWER','manageRisk'),false)});
test('control owner cannot approve reviews',()=>assert.equal(roleAllows('CONTROL_OWNER','review'),false));
test('reviewer cannot manage organization',()=>assert.equal(roleAllows('REVIEWER','manageOrg'),false));
test('org admin can manage scopes',()=>assert.equal(roleAllows('ORG_ADMIN','manageScope'),true));
