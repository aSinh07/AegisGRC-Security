import dns from 'node:dns/promises';
import net from 'node:net';

export const blockedNetworkAddress=(ip:string)=>{
 if(net.isIP(ip)===4){const p=ip.split('.').map(Number);return p[0]===10||p[0]===127||p[0]===0||(p[0]===169&&p[1]===254)||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168)||(p[0]>=224)}
 const x=ip.toLowerCase();return x==='::1'||x==='::'||x.startsWith('fc')||x.startsWith('fd')||x.startsWith('fe8')||x.startsWith('fe9')||x.startsWith('fea')||x.startsWith('feb')||x.startsWith('ff');
};
export async function validatePublicHttpTarget(raw:string){
 const u=new URL(raw);if(!['http:','https:'].includes(u.protocol))throw new Error('Only HTTP(S) targets are supported');if(u.username||u.password)throw new Error('Credentials in target URLs are not allowed');if(u.port&&u.port!=='80'&&u.port!=='443')throw new Error('Only standard HTTP(S) target ports are allowed');if(net.isIP(u.hostname)&&blockedNetworkAddress(u.hostname))throw new Error('Private, local, reserved or link-local targets are blocked');
 const records=await dns.lookup(u.hostname,{all:true,verbatim:true});if(!records.length||records.some(r=>blockedNetworkAddress(r.address)))throw new Error('Private, local, reserved or link-local targets are blocked');return {url:u,addresses:[...new Set(records.map(r=>r.address))]};
}
export async function revalidatePublicHttpTarget(t:{url:URL,addresses:string[]}){const records=await dns.lookup(t.url.hostname,{all:true,verbatim:true});if(!records.length||records.some(r=>blockedNetworkAddress(r.address)))throw new Error('Target DNS changed to a blocked address');const addresses=[...new Set(records.map(r=>r.address))];if(addresses.some(ip=>!t.addresses.includes(ip)))throw new Error('Target DNS changed after authorization; scan refused');return {...t,addresses};}
