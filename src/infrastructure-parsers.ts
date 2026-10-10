import crypto from 'node:crypto';
import type {Finding,Severity} from './models.js';
import {mapFinding} from './grc.js';

const severity=(s:any):Severity=>{
 const x=String(s||'').toUpperCase();
 return (['INFO','LOW','MEDIUM','HIGH','CRITICAL'].includes(x)?x:'MEDIUM') as Severity;
};
const cves=(value:any)=>[...new Set((JSON.stringify(value||{}).match(/CVE-\d{4}-\d{4,}/gi)||[]).map(x=>x.toUpperCase()))];
const cwes=(value:any)=>[...new Set((JSON.stringify(value||{}).match(/CWE-\d+/gi)||[]).map(x=>x.toUpperCase()))];

export function nucleiJsonlFindings(assessmentId:string,asset:string,evidenceHash:string,raw:string):Finding[]{
 const out:Finding[]=[];
 for(const line of raw.split(/\r?\n/).filter(Boolean)){
  let x:any;try{x=JSON.parse(line)}catch{continue}
  const info=x.info||{},ids=cves(x),weaknesses=cwes(x);
  out.push(mapFinding({
   id:crypto.randomUUID(),assessmentId,source:'nuclei',title:String(info.name||x['template-id']||'Nuclei scanner finding'),
   description:String(info.description||info.name||'Nuclei template matched the assessed asset.'),
   severity:severity(info.severity),cwe:weaknesses[0],cvss:Number(info.classification?.['cvss-score'])||undefined,
   asset:String(x['matched-at']||x.host||asset),evidenceHash,createdAt:new Date().toISOString(),mappings:{},
   remediation:String(info.remediation||''),status:'OPEN',confidence:'SCANNER_REPORTED',
   externalIds:{cve:ids.length?ids:undefined,cwe:weaknesses.length?weaknesses:undefined,scannerId:String(x['template-id']||'nuclei')}
  }));
 }
 return out;
}

export function trivyJsonFindings(assessmentId:string,asset:string,evidenceHash:string,raw:string):Finding[]{
 let doc:any;try{doc=JSON.parse(raw)}catch{return []}
 const out:Finding[]=[];
 for(const result of doc.Results||[]){
  for(const v of result.Vulnerabilities||[]){
   const id=String(v.VulnerabilityID||''),ids=/^CVE-\d{4}-\d{4,}$/i.test(id)?[id.toUpperCase()]:cves(v);
   out.push(mapFinding({
    id:crypto.randomUUID(),assessmentId,source:'trivy',title:(id?id+' · ':'')+String(v.Title||v.PkgName||'Trivy vulnerability'),
    description:String(v.Description||('Affected package '+String(v.PkgName||'unknown')+' '+String(v.InstalledVersion||''))),
    severity:severity(v.Severity),cvss:undefined,asset:String(result.Target||asset),evidenceHash,createdAt:new Date().toISOString(),mappings:{},
    remediation:v.FixedVersion?'Upgrade '+String(v.PkgName||'package')+' to '+String(v.FixedVersion)+' or later.':'Review vendor advisory and available remediation.',
    status:'OPEN',confidence:'SCANNER_REPORTED',externalIds:{cve:ids.length?ids:undefined,scannerId:id||String(v.PkgIdentifier?.PURL||'trivy')}
   }));
  }
 }
 return out;
}


export function openvasJsonFindings(assessmentId:string,asset:string,evidenceHash:string,raw:string):Finding[]{
 let doc:any;try{doc=JSON.parse(raw)}catch{return []}
 const rows=Array.isArray(doc)?doc:Array.isArray(doc.results)?doc.results:Array.isArray(doc.vulnerabilities)?doc.vulnerabilities:[];
 const out:Finding[]=[];
 for(const v of rows){
  const score=Number(v.cvss??v.cvss_base??v.severity_score);const ids=cves(v),weaknesses=cwes(v);
  const sev:Severity=score>=9?'CRITICAL':score>=7?'HIGH':score>=4?'MEDIUM':score>0?'LOW':severity(v.severity);
  out.push(mapFinding({id:crypto.randomUUID(),assessmentId,source:'openvas',title:String(v.name||v.title||v.nvt_name||'OpenVAS finding'),
   description:String(v.description||v.summary||v.threat||'Greenbone/OpenVAS reported a vulnerability on the assessed asset.'),severity:sev,cvss:Number.isFinite(score)?score:undefined,cwe:weaknesses[0],
   asset:String(v.host||v.hostname||asset),evidenceHash,createdAt:new Date().toISOString(),mappings:{},remediation:String(v.solution||v.remediation||'Review the Greenbone vulnerability result and vendor remediation guidance.'),
   status:'OPEN',confidence:'SCANNER_REPORTED',externalIds:{cve:ids.length?ids:undefined,cwe:weaknesses.length?weaknesses:undefined,scannerId:String(v.oid||v.nvt_oid||v.id||'openvas')}}));
 }
 return out;
}
