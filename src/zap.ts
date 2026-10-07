import crypto from 'node:crypto';
import type { Finding,Severity } from './models.js';
import { mapFinding } from './grc.js';

const base=(process.env.ZAP_URL||'').replace(/\/$/,'');
const key=process.env.ZAP_API_KEY||'';
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));

async function api(path:string,params:Record<string,string>={}){
 if(!base) throw new Error('OWASP ZAP is not configured');
 const q=new URLSearchParams({...params,apikey:key});
 const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),15000);
 try{const r=await fetch(base+path+'?'+q,{signal:controller.signal});if(!r.ok)throw new Error('ZAP HTTP '+r.status);return await r.json() as any}
 finally{clearTimeout(timer)}
}
export async function zapReady(){try{await api('/JSON/core/view/version/');return true}catch{return false}}
async function wait(path:string,id:string,limitMs=120000){const started=Date.now();while(Date.now()-started<limitMs){const d=await api(path,{scanId:id});const n=Number(d.status||0);if(n>=100)return;await pause(1500)}throw new Error('ZAP scan timed out')}
export async function zapScan(target:string){
 const spider=await api('/JSON/spider/action/scan/',{url:target,maxChildren:'20',recurse:'true',subtreeOnly:'true'});
 if(!spider.scan)throw new Error('ZAP spider did not start');await wait('/JSON/spider/view/status/',String(spider.scan),90000);
 const active=await api('/JSON/ascan/action/scan/',{url:target,recurse:'true',inScopeOnly:'false'});
 if(!active.scan)throw new Error('ZAP active scan did not start');await wait('/JSON/ascan/view/status/',String(active.scan),120000);
 const alerts=await api('/JSON/core/view/alerts/',{baseurl:target,start:'0',count:'500'});
 return Array.isArray(alerts.alerts)?alerts.alerts:[];
}
function sev(risk:string):Severity{const x=risk.toLowerCase();return x.includes('high')?'HIGH':x.includes('medium')?'MEDIUM':x.includes('low')?'LOW':'INFO'}
export function zapFindings(assessmentId:string,asset:string,evidenceHash:string,alerts:any[]):Finding[]{
 return alerts.map(a=>mapFinding({id:crypto.randomUUID(),assessmentId,source:'zap',title:String(a.alert||a.name||'ZAP alert'),description:String(a.description||a.evidence||'OWASP ZAP reported an alert.'),severity:sev(String(a.risk||a.riskdesc||'')),cwe:a.cweid&&String(a.cweid)!=='0'?'CWE-'+a.cweid:undefined,asset:String(a.url||asset),evidenceHash,createdAt:new Date().toISOString(),mappings:{owasp:[]},remediation:String(a.solution||a.reference||'Review the ZAP evidence and remediate the affected control.')}));
}
