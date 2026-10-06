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