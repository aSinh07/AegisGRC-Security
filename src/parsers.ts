import crypto from 'node:crypto'; import type { Finding,Severity } from './models.js'; import { mapFinding } from './grc.js';
const sev=(x:string):Severity=>{const s=x.toUpperCase();return ['INFO','LOW','MEDIUM','HIGH','CRITICAL'].includes(s)?s as Severity:'MEDIUM'};
export function semgrepFindings(assessmentId:string,asset:string,evidenceHash:string,results:any[]):Finding[]{
 return results.map((r:any)=>mapFinding({id:crypto.randomUUID(),assessmentId,source:'semgrep',title:r.check_id||'Semgrep finding',description:r.extra?.message||'Static analysis finding',severity:sev(r.extra?.severity||'MEDIUM'),cwe:r.extra?.metadata?.cwe?.[0],asset,evidenceHash,createdAt:new Date().toISOString(),mappings:{}}))
}
export function wapitiFindings(assessmentId:string,asset:string,evidenceHash:string,raw:string):Finding[]{
 let x:any={};try{x=JSON.parse(raw)}catch{return []}; const out:Finding[]=[];
 for(const [category,items] of Object.entries(x.vulnerabilities||{})) for(const i of (items as any[])) out.push(mapFinding({id:crypto.randomUUID(),assessmentId,source:'wapiti',title:category,description:i.info||i.parameter||'DAST finding',severity:sev(i.level===3?'HIGH':i.level===2?'MEDIUM':'LOW'),asset,evidenceHash,createdAt:new Date().toISOString(),mappings:{}}));
 return out;
}
function xmlAttrs(tag:string){const out:Record<string,string>={};for(const m of tag.matchAll(/([:\w.-]+)\s*=\s*(['"])(.*?)\2/g))out[m[1]]=m[3];return out}
export function nmapFindings(assessmentId:string,asset:string,evidenceHash:string,xml:string):Finding[]{
 const out:Finding[]=[];const common:any={
 '21':['FTP','An FTP service is reachable from the assessed network. FTP commonly sends credentials and data without transport encryption unless protected by another control.','Confirm the service is required. Prefer SFTP/SSH or another encrypted transfer service; otherwise restrict source networks and disable anonymous access.'],
 '22':['SSH','An SSH administration service is reachable. This is not automatically a vulnerability, but unnecessary internet exposure increases authentication and software attack surface.','Restrict SSH to approved administration networks or VPN/bastion access, use key-based authentication, disable direct root login, patch the SSH service, and monitor authentication events.'],
 '23':['Telnet','A Telnet service is reachable. Telnet does not provide modern transport encryption and can expose credentials and session data.','Disable Telnet and migrate administration to SSH. Restrict the port at the firewall while migration is completed.'],
 '25':['SMTP','An SMTP service is reachable. Public SMTP may be expected for a mail server, but relay configuration, TLS and authentication controls require validation.','Confirm public exposure is required, enforce supported TLS, disable open relay, patch the mail service, and restrict administrative interfaces.'],
 '53':['DNS','A DNS service is reachable. This may be expected, but recursion and zone-transfer settings should be reviewed because misconfiguration can enable abuse or information disclosure.','Disable public recursion unless required, restrict zone transfers to approved servers, apply response-rate limiting where appropriate, and patch the DNS service.'],
 '80':['HTTP','The target exposes an unencrypted HTTP service. If sensitive traffic or authentication is accepted here, data can be exposed or modified in transit.','Redirect HTTP to HTTPS, avoid serving sensitive content over cleartext, and validate TLS/HSTS configuration on the HTTPS endpoint.'],
 '443':['HTTPS','An HTTPS service is reachable. Port 443 itself is expected for many web applications and is not a vulnerability; TLS configuration and the application still require separate validation.','Keep the TLS stack and web server patched, use strong protocol/cipher configuration, and validate headers and application controls with the web assessment results.'],
 '3306':['MySQL','A MySQL database service is network reachable. Direct database exposure can increase the impact of credential compromise or database vulnerabilities.','Keep the database on a private network where possible, allow only approved application/administration sources, require strong authentication/TLS, and patch the database server.'],
 '5432':['PostgreSQL','A PostgreSQL database service is network reachable. Database ports normally should not be broadly exposed unless there is a documented requirement.','Restrict PostgreSQL to trusted application/administration networks, enforce pg_hba.conf least privilege and TLS, remove public exposure where unnecessary, and patch regularly.'],
 '6379':['Redis','A Redis service is reachable. Redis is normally intended for trusted networks; broad exposure can create significant data and administration risk.','Bind Redis to trusted interfaces, block public access, require authentication/ACLs and TLS where supported, and keep Redis patched.'],
 '8080':['HTTP alternate','An alternate web service is reachable on port 8080. It may expose an application, proxy, management interface or development service.','Identify the service owner and business purpose, remove unnecessary public exposure, require authentication for management functions, patch it, and place web traffic behind the approved HTTPS boundary.']
 };
 for(const m of xml.matchAll(/<port\b([^>]*)>([\s\S]*?)<\/port>/gi)){
  const pa=xmlAttrs(m[1]),protocol=pa.protocol||'tcp',port=pa.portid;if(!port)continue;const body=m[2];
  const stateTag=body.match(/<state\b([^>]*)\/?\s*>/i);if(!stateTag||xmlAttrs(stateTag[1]).state!=='open')continue;
  const serviceTag=body.match(/<service\b([^>]*)\/?\s*>/i),service=serviceTag?(xmlAttrs(serviceTag[1]).name||'unknown'):'unknown',cc=common[port];
  const desc=cc?cc[1]:`Network discovery confirmed that ${protocol.toUpperCase()} port ${port} is open and the service was identified as ${service}. An open port is exposure, not proof of a vulnerability. Risk depends on business necessity, service version, configuration, authentication and network restrictions.`;
  const remediation=cc?cc[2]:`Confirm whether ${service} on ${protocol.toUpperCase()} ${port} is required. If not, disable the listener or block it at the firewall/security group. If required, restrict access to approved sources, patch the service, use strong authentication/encryption where applicable, and monitor it.`;
  out.push(mapFinding({id:crypto.randomUUID(),assessmentId,source:'nmap',title:`Open ${protocol.toUpperCase()} port ${port} · ${cc?.[0]||service}`,description:desc,severity:['23','6379'].includes(port)?'HIGH':['21','3306','5432','8080'].includes(port)?'MEDIUM':port==='80'?'LOW':'INFO',asset,evidenceHash,createdAt:new Date().toISOString(),mappings:{},remediation,status:'OPEN',confidence:'OBSERVED',externalIds:{scannerId:`nmap:${protocol}:${port}`}}))
 }
 return out;
}
