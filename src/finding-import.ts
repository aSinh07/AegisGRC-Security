import crypto from 'node:crypto';
import type {Finding,Severity} from './models.js';
import {mapFinding} from './grc.js';

export type ImportResult={format:string;findings:Finding[];warnings:string[]};
const severity=(v:unknown):Severity=>{
 const s=String(v||'').trim().toUpperCase();
 if(['INFO','LOW','MEDIUM','HIGH','CRITICAL'].includes(s))return s as Severity;
 const n=Number(v);if(Number.isFinite(n)){if(n>=9)return'CRITICAL';if(n>=7)return'HIGH';if(n>=4)return'MEDIUM';if(n>0)return'LOW'}
 return 'INFO';
};
const clean=(v:unknown,max=12000)=>String(v??'').replace(/\0/g,'').trim().slice(0,max);
function finding(assessmentId:string,evidenceHash:string,source:Finding['source'],x:any):Finding{
 const title=clean(x.title||x.name||x.ruleId||x.id||'Imported finding',500);
 const description=clean(x.description||x.message||x.detail||x.help||'Imported security observation');
 const asset=clean(x.asset||x.host||x.url||x.path||x.location||'Imported evidence',1000);
 const cwe=clean(x.cwe||'',64)||undefined;
 return mapFinding({id:crypto.randomUUID(),assessmentId,source,title,description,
  severity:severity(x.severity??x.cvss),cwe,cvss:Number.isFinite(Number(x.cvss))?Number(x.cvss):undefined,
  asset,evidenceHash,createdAt:new Date().toISOString(),mappings:{},remediation:clean(x.remediation||x.fix||'',4000)||undefined,status:'OPEN'});
}
function sarif(assessmentId:string,hash:string,j:any):ImportResult{
 const findings:Finding[]=[];for(const run of j.runs||[]){const rules=new Map((run.tool?.driver?.rules||[]).map((r:any)=>[r.id,r]));
  for(const r of run.results||[]){const rule:any=rules.get(r.ruleId)||{};const loc=r.locations?.[0]?.physicalLocation;
   findings.push(finding(assessmentId,hash,'semgrep',{ruleId:r.ruleId,title:rule.shortDescription?.text||r.ruleId,
    description:r.message?.text,severity:r.level==='error'?'HIGH':r.level==='warning'?'MEDIUM':'LOW',
    path:loc?.artifactLocation?.uri,location:loc?.region?.startLine?String(loc.artifactLocation?.uri||'')+':'+loc.region.startLine:undefined,
    cwe:(rule.properties?.tags||[]).find((x:any)=>/^CWE-/i.test(String(x))) }));}}
 return {format:'SARIF',findings,warnings:[]};
}
function genericJson(assessmentId:string,hash:string,j:any):ImportResult{
 const arr=Array.isArray(j)?j:Array.isArray(j.findings)?j.findings:Array.isArray(j.vulnerabilities)?j.vulnerabilities:Array.isArray(j.results)?j.results:null;
 if(!arr)throw new Error('JSON import requires an array or findings/vulnerabilities/results array');
 return {format:'GENERIC_JSON',findings:arr.slice(0,10000).map((x:any)=>finding(assessmentId,hash,'document',x)),warnings:['Generic JSON field mapping is conservative; analyst validation is required.']};
}
export function parseFindingImport(assessmentId:string,filename:string,content:Buffer):ImportResult{
 const lower=filename.toLowerCase();if(!/\.(json|sarif)$/i.test(lower))throw new Error('Finding import currently supports JSON and SARIF. Other documents remain evidence, not automatically parsed findings.');
 let j:any;try{j=JSON.parse(content.toString('utf8'))}catch{throw new Error('Invalid JSON/SARIF document')};
 const hash=crypto.createHash('sha256').update(content).digest('hex');
 if(lower.endsWith('.sarif')||String(j.version||'').startsWith('2.')&&Array.isArray(j.runs))return sarif(assessmentId,hash,j);
 return genericJson(assessmentId,hash,j);
}
