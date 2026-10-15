import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import {initUsers,beginRegistration,confirmRegistration} from '../src/user-auth.js';
import {initOrganizations,createOrganization} from '../src/grc-organizations.js';
import {initIncidentResponse,ingestIdentitySignal,reviewIdentitySignal,incidentDashboard} from '../src/incident-response.js';

function b32buf(s:string){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const c of s){const n=a.indexOf(c);if(n>=0)bits+=n.toString(2).padStart(5,'0')}const out:number[]=[];for(let i=0;i+8<=bits.length;i+=8)out.push(parseInt(bits.slice(i,i+8),2));return Buffer.from(out)}
function totp(secret:string){const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const h=crypto.createHmac('sha1',b32buf(secret)).update(b).digest();const o=h[h.length-1]&15;return String((h.readUInt32BE(o)&0x7fffffff)%1e6).padStart(6,'0')}

test('IDR risk, tenant isolation, review and escalation persist correctly', {timeout:30000}, async()=>{
 if(!process.env.DATABASE_URL)return;
 process.env.TOTP_ENCRYPTION_KEY ||= crypto.randomBytes(32).toString('base64');
 await initUsers();await initOrganizations();await initIncidentResponse();
 const suffix=crypto.randomUUID(),password='Aegis-IDR-'+crypto.randomBytes(10).toString('hex');
 const a=await beginRegistration('idr-a-'+suffix+'@example.test',password,{fullName:'IDR A Tester',designation:'Security Analyst',companyName:'Aegis Test'});
 const b=await beginRegistration('idr-b-'+suffix+'@example.test',password,{fullName:'IDR B Tester',designation:'Security Analyst',companyName:'Aegis Test'});
 assert.ok(await confirmRegistration(a.userId,totp(a.secret)));assert.ok(await confirmRegistration(b.userId,totp(b.secret)));
 const org=await createOrganization(a.userId,{name:'IDR Tenant '+suffix});
 const signal=await ingestIdentitySignal(a.userId,org.id,{kind:'MFA_FATIGUE',principalId:'user@example.test',observedAt:new Date().toISOString(),source:'IDR-INTEGRATION-TEST',evidenceRefs:['EVIDENCE-IDR-001']});
 assert.equal(signal.risk_score,80);assert.equal(signal.risk_level,'HIGH');assert.equal(signal.status,'REVIEW_REQUIRED');assert.ok(signal.correlation_key);
 await assert.rejects(()=>ingestIdentitySignal(b.userId,org.id,{kind:'MFA_FATIGUE',principalId:'other@example.test',observedAt:new Date().toISOString(),source:'IDR-INTEGRATION-TEST',evidenceRefs:[]}),/Organization membership required/);
 const reviewed=await reviewIdentitySignal(a.userId,org.id,signal.id,{disposition:'ESCALATED_TO_INCIDENT',reason:'Confirmed MFA fatigue requires incident investigation'});
 assert.equal(reviewed.status,'REVIEWED');assert.ok(reviewed.incident_id);
 await assert.rejects(()=>reviewIdentitySignal(a.userId,org.id,signal.id,{disposition:'BENIGN',reason:'Second review must fail'}),/already reviewed/);
 const dash=await incidentDashboard(a.userId,org.id);
 const incident=dash.incidents.find((x:any)=>x.id===reviewed.incident_id);assert.ok(incident);assert.equal(incident.phase,'DETECTED');assert.match(incident.summary,/Identity risk HIGH \(80\/100\)/);
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 try{
  const ev=(await pool.query('SELECT reason,evidence_refs FROM security_incident_events WHERE incident_id=$1',[reviewed.incident_id])).rows[0];
  assert.ok(ev);assert.deepEqual(ev.evidence_refs,['EVIDENCE-IDR-001']);
  await pool.query('DELETE FROM grc_organizations WHERE id=$1',[org.id]);await pool.query('DELETE FROM app_users WHERE id=ANY($1::uuid[])',[[a.userId,b.userId]]);
 }finally{await pool.end()}
});
