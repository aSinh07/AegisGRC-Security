import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import {initUsers,beginRegistration,confirmRegistration,userLogin,userSession,userLogout} from '../src/user-auth.js';
import {initOrganizations,createOrganization,createScope,listScopes} from '../src/grc-organizations.js';

function b32buf(s:string){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const c of s){const n=a.indexOf(c);if(n>=0)bits+=n.toString(2).padStart(5,'0')}const out:number[]=[];for(let i=0;i+8<=bits.length;i+=8)out.push(parseInt(bits.slice(i,i+8),2));return Buffer.from(out)}
function totp(secret:string){const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const h=crypto.createHmac('sha1',b32buf(secret)).update(b).digest();const o=h[h.length-1]&15;return String((h.readUInt32BE(o)&0x7fffffff)%1e6).padStart(6,'0')}

test('real PostgreSQL auth MFA session and tenant isolation workflow', {timeout:30000}, async()=>{
 if(!process.env.DATABASE_URL)return;
 process.env.TOTP_ENCRYPTION_KEY ||= crypto.randomBytes(32).toString('base64');
 await initUsers();await initOrganizations();
 const suffix=crypto.randomUUID(),password='Aegis-Test-'+crypto.randomBytes(10).toString('hex');
 const a=await beginRegistration('a-'+suffix+'@example.test',password,{fullName:'Tenant A Tester',designation:'Security Tester',companyName:'Aegis Test'});
 const b=await beginRegistration('b-'+suffix+'@example.test',password,{fullName:'Tenant B Tester',designation:'Security Tester',companyName:'Aegis Test'});
 const tokenA=await confirmRegistration(a.userId,totp(a.secret));const tokenB=await confirmRegistration(b.userId,totp(b.secret));
 assert.ok(tokenA);assert.ok(tokenB);assert.equal((await userSession(tokenA!))?.userId,a.userId);
 const login=await userLogin(a.email,password,totp(a.secret));assert.ok(login,'password + TOTP login must succeed');
 const org=await createOrganization(a.userId,{name:'Tenant Isolation '+suffix});const scope=await createScope(a.userId,org.id,{name:'Production Scope'});
 assert.equal(scope.organization_id,org.id);assert.equal((await listScopes(a.userId,org.id)).length,1);
 await assert.rejects(()=>listScopes(b.userId,org.id),/Organization membership required/);
 await userLogout(login!);assert.equal(await userSession(login!),null,'logout must invalidate session');
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 try{await pool.query('DELETE FROM grc_organizations WHERE id=$1',[org.id]);await pool.query('DELETE FROM app_users WHERE id=ANY($1::uuid[])',[[a.userId,b.userId]])}finally{await pool.end()}
});
