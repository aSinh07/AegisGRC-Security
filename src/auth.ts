import crypto from 'node:crypto';

const sessions=new Map<string,number>();
const TTL=8*60*60*1000;

function b32(s:string){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const c of s.toUpperCase().replace(/[^A-Z2-7]/g,'')){const n=a.indexOf(c);if(n<0)continue;bits+=n.toString(2).padStart(5,'0')}const out=[];for(let i=0;i+8<=bits.length;i+=8)out.push(parseInt(bits.slice(i,i+8),2));return Buffer.from(out)}
function totp(secret:string,step=Math.floor(Date.now()/30000)){const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(step));const h=crypto.createHmac('sha1',b32(secret)).update(b).digest();const o=h[h.length-1]&15;return (((h.readUInt32BE(o)&0x7fffffff)%1e6)+'').padStart(6,'0')}
function eq(a:string,b:string){const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&crypto.timingSafeEqual(x,y)}
export function authConfigured(){return Boolean(process.env.ADMIN_PASSWORD&&process.env.ADMIN_TOTP_SECRET)}
export function verifyCredentials(password:string,code:string){const p=process.env.ADMIN_PASSWORD||'',s=process.env.ADMIN_TOTP_SECRET||'';if(!p||!s||!eq(password,p))return false;return [-1,0,1].some(d=>eq(code,totp(s,Math.floor(Date.now()/30000)+d)))}
export function login(password:string,code:string){if(!verifyCredentials(password,code))return null;const token=crypto.randomBytes(32).toString('base64url');sessions.set(token,Date.now()+TTL);return token}
export function valid(token:string){const exp=sessions.get(token)||0;if(exp<Date.now()){sessions.delete(token);return false}return true}
export function logout(token:string){sessions.delete(token)}
