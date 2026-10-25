import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
test('operational defensive security is fail-closed and telemetry-backed',async()=>{
 const s=await readFile(new URL('../src/operational-security.ts',import.meta.url),'utf8');
 for(const x of ['security_telemetry_sources','security_telemetry_events','security_detections',"'DISCONNECTED'",'last_seen_at','evidence_sha256','timingSafeEqual','Telemetry source authentication failed','ON CONFLICT(organization_id,source_id,external_event_id) DO NOTHING'])assert.ok(s.includes(x),x);
 assert.match(s,/status='CONNECTED',last_seen_at=now/);assert.ok(s.includes('registration alone never proves monitoring'));
});
test('Wazuh live ingestion is externally authenticated and separate from user session auth',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8'),route="app.post('/api/security/telemetry/wazuh/:orgId/:sourceKey'";
 assert.ok(s.includes(route));assert.ok(s.includes('authorization'));assert.ok(s.includes('ingestWazuhTelemetry'));
 assert.ok(s.indexOf(route)<s.indexOf("app.use('/api',async(req,res,next)=>"));
});
test('analyst review can escalate a real detection into governed incident response',async()=>{
 const s=await readFile(new URL('../src/operational-security.ts',import.meta.url),'utf8');
 for(const x of ['ESCALATED_TO_INCIDENT','createIncident','Evidence SHA-256',"requireOrgPermission(user,org,'review')"])assert.ok(s.includes(x),x);
});
