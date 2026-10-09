import crypto from 'node:crypto';import pg from 'pg';import QRCode from 'qrcode';
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
const TTL=8*60*60*1000;
function b32buf(s:string){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const c of s.toUpperCase().replace(/[^A-Z2-7]/g,'')){const n=a.indexOf(c);if(n>=0)bits+=n.toString(2).padStart(5,'0')}const out=[];for(let i=0;i+8<=bits.length;i+=8)out.push(parseInt(bits.slice(i,i+8),2));return Buffer.from(out)}
function b32enc(b:Buffer){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const x of b)bits+=x.toString(2).padStart(8,'0');let out='';for(let i=0;i<bits.length;i+=5)out+=a[parseInt(bits.slice(i,i+5).padEnd(5,'0'),2)];return out}
function totp(secret:string,step=Math.floor(Date.now()/30000)){const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(step));const h=crypto.createHmac('sha1',b32buf(secret)).update(b).digest(),o=h[h.length-1]&15;return String((h.readUInt32BE(o)&0x7fffffff)%1e6).padStart(6,'0')}
function verify(secret:string,code:string){code=code.trim();return /^\d{6}$/.test(code)&&[-1,0,1].some(d=>{const a=Buffer.from(code),b=Buffer.from(totp(secret,Math.floor(Date.now()/30000)+d));return a.length===b.length&&crypto.timingSafeEqual(a,b)})}
function hashPassword(p:string,salt=crypto.randomBytes(16)){return {salt:salt.toString('hex'),hash:crypto.scryptSync(p,salt,64).toString('hex')}}
function pass(p:string,salt:string,hash:string){const h=crypto.scryptSync(p,Buffer.from(salt,'hex'),64),x=Buffer.from(hash,'hex');return h.length===x.length&&crypto.timingSafeEqual(h,x)}
const tokenHash=(t:string)=>crypto.createHash('sha256').update(t).digest('hex');
export async function initUsers(){
 await pool.query('CREATE TABLE IF NOT EXISTS app_users(id uuid PRIMARY KEY,email text UNIQUE NOT NULL,password_hash text NOT NULL,password_salt text NOT NULL,totp_secret text NOT NULL,totp_verified boolean NOT NULL DEFAULT false,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now())');
 await pool.query('ALTER TABLE app_users ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now()');
 await pool.query('ALTER TABLE app_users ADD COLUMN IF NOT EXISTS full_name text');
 await pool.query('ALTER TABLE app_users ADD COLUMN IF NOT EXISTS designation text');
 await pool.query('ALTER TABLE app_users ADD COLUMN IF NOT EXISTS company_name text');
 await pool.query("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'analyst'");
 await pool.query('CREATE TABLE IF NOT EXISTS app_sessions(token_hash text PRIMARY KEY,user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now())');
 await pool.query('CREATE INDEX IF NOT EXISTS app_sessions_expires_idx ON app_sessions(expires_at)');
 await pool.query('DELETE FROM app_sessions WHERE expires_at<=now()');
}
export async function beginRegistration(email:string,password:string,profile:{fullName?:string;designation?:string;companyName?:string}={}){
 email=email.trim().toLowerCase();if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)||password.length<10)throw Error('Valid email and password of at least 10 characters required');
 const fullName=String(profile.fullName||'').trim(),designation=String(profile.designation||'').trim(),companyName=String(profile.companyName||'').trim();
 if(fullName.length<2||fullName.length>120)throw Error('Full name must be 2-120 characters');
 if(designation.length<2||designation.length>120)throw Error('Designation must be 2-120 characters');
 if(companyName.length<2||companyName.length>160)throw Error('Company name must be 2-160 characters');
 const existing=await pool.query('SELECT id FROM app_users WHERE email=$1',[email]);
 if(existing.rows[0])throw Error('Account already exists or registration is already pending; sign in or complete recovery instead');
 const secret=b32enc(crypto.randomBytes(20)),h=hashPassword(password),id=crypto.randomUUID();
 await pool.query('INSERT INTO app_users(id,email,password_hash,password_salt,totp_secret,totp_verified,full_name,designation,company_name) VALUES($1,$2,$3,$4,$5,false,$6,$7,$8)',[id,email,h.hash,h.salt,secret,fullName,designation,companyName]);
 const otpauth='otpauth://totp/'+encodeURIComponent('AegisGRC:'+email)+'?secret='+secret+'&issuer='+encodeURIComponent('AegisGRC');const qrDataUrl=await QRCode.toDataURL(otpauth,{errorCorrectionLevel:'M',margin:2,width:220});return {userId:id,email,secret,qrDataUrl};
}
export async function confirmRegistration(userId:string,code:string){const r=await pool.query('SELECT * FROM app_users WHERE id=$1',[userId]),u=r.rows[0];if(!u||!verify(u.totp_secret,code))return null;await pool.query('UPDATE app_users SET totp_verified=true,updated_at=now() WHERE id=$1',[userId]);const token=crypto.randomBytes(32).toString('base64url'),expires=new Date(Date.now()+TTL);await pool.query('INSERT INTO app_sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)',[tokenHash(token),u.id,expires]);return token}
export async function resetPasswordWithTotp(email:string,code:string,newPassword:string){
 email=email.trim().toLowerCase();if(newPassword.length<10)throw Error('New password must be at least 10 characters');
 const r=await pool.query('SELECT id,totp_secret,totp_verified FROM app_users WHERE email=$1',[email]),u=r.rows[0];
 // Keep the public failure generic to avoid account enumeration.
 if(!u||!u.totp_verified||!verify(u.totp_secret,code))return false;
 const h=hashPassword(newPassword);
 const client=await pool.connect();try{await client.query('BEGIN');
  await client.query('UPDATE app_users SET password_hash=$2,password_salt=$3,updated_at=now() WHERE id=$1',[u.id,h.hash,h.salt]);
  await client.query('DELETE FROM app_sessions WHERE user_id=$1',[u.id]);
  await client.query('COMMIT');return true;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function userLogin(email:string,password:string,code:string){const r=await pool.query('SELECT * FROM app_users WHERE email=$1',[email.trim().toLowerCase()]),u=r.rows[0];if(!u||!u.totp_verified||!pass(password,u.password_salt,u.password_hash)||!verify(u.totp_secret,code))return null;const token=crypto.randomBytes(32).toString('base64url'),expires=new Date(Date.now()+TTL);await pool.query('INSERT INTO app_sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)',[tokenHash(token),u.id,expires]);return token}
export async function userSession(token:string){if(!token)return null;const r=await pool.query('SELECT s.user_id AS "userId",u.email,u.full_name AS "fullName",u.designation,u.company_name AS "companyName",s.expires_at AS exp FROM app_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()',[tokenHash(token)]);return r.rows[0]||null}
export async function userLogout(token:string){if(token)await pool.query('DELETE FROM app_sessions WHERE token_hash=$1',[tokenHash(token)])}

export async function userRole(userId:string){const r=await pool.query('SELECT role,email FROM app_users WHERE id=$1',[userId]);if(!r.rows[0])return null;const configured=(process.env.GRC_REVIEWER_EMAILS||'').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean);const role=configured.includes(String(r.rows[0].email).toLowerCase())?'grc_reviewer':r.rows[0].role;if(role!==r.rows[0].role)await pool.query('UPDATE app_users SET role=$2,updated_at=now() WHERE id=$1',[userId,role]);return role}

export async function verifyUserStepUp(userId:string,password:string,code:string){const r=await pool.query('SELECT * FROM app_users WHERE id=$1',[userId]),u=r.rows[0];if(!u)return {ok:false,reason:'USER_NOT_FOUND'};if(!u.totp_verified)return {ok:false,reason:'MFA_NOT_ENROLLED'};if(!pass(password,u.password_salt,u.password_hash))return {ok:false,reason:'PASSWORD_INVALID'};if(!verify(u.totp_secret,code))return {ok:false,reason:'TOTP_INVALID'};return {ok:true,reason:'OK'}}
