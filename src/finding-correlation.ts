import crypto from 'node:crypto';
import type { Finding,Severity } from './models.js';

/** Conservative grouping: only explicit CVE/CWE identifiers on the same asset are merged.
 * Unknown/ambiguous identifiers remain separate; this avoids falsely merging unrelated issues.
 * Correlation is advisory and never modifies the original finding or evidence.
 */
export type CorrelatedFinding={
 fingerprint:string;asset:string;identifier:string;title:string;
 severity:Severity;sourceCount:number;sources:string[];evidenceHashes:string[];
 findingIds:string[];statuses:string[];confidence:'IDENTIFIER_MATCH'|'UNVERIFIED_SINGLE';
};
const ranks:Record<Severity,number>={INFO:0,LOW:1,MEDIUM:2,HIGH:3,CRITICAL:4};
function identifier(f:Finding):string|null{
 const cve=(f.title+' '+f.description).match(/\bCVE-\d{4}-\d{4,}\b/i);
 if(cve)return cve[0].toUpperCase();
 const cwe=f.cwe?.match(/^CWE-\d+$/i);
 return cwe?cwe[0].toUpperCase():null;
}
export function correlateFindings(findings:Finding[]):CorrelatedFinding[]{
 const groups=new Map<string,Finding[]>();
 for(const f of findings){
  const asset=f.asset.trim().toLowerCase();
  const id=identifier(f);
  // Do not merge two unrelated findings merely because they share an asset.
  const key=id?JSON.stringify([asset,id]):JSON.stringify([asset,'UNVERIFIED',f.id]);
  const arr=groups.get(key)||[];arr.push(f);groups.set(key,arr);
 }
 return [...groups].map(([key,fs])=>{
  const lead=fs[0],id=identifier(lead)||'UNVERIFIED';
  const strongest=fs.reduce((a,b)=>ranks[b.severity]>ranks[a.severity]?b:a);
  return {
   fingerprint:crypto.createHash('sha256').update(key).digest('hex'),
   asset:lead.asset,identifier:id,title:strongest.title,severity:strongest.severity,
   sourceCount:new Set(fs.map(f=>f.source)).size,
   sources:[...new Set(fs.map(f=>f.source))].sort(),
   evidenceHashes:[...new Set(fs.map(f=>f.evidenceHash).filter(Boolean))].sort(),
   findingIds:fs.map(f=>f.id),statuses:[...new Set(fs.map(f=>f.status||'UNREVIEWED'))],
   confidence:id==='UNVERIFIED'?'UNVERIFIED_SINGLE':'IDENTIFIER_MATCH'
  };
 }).sort((a,b)=>ranks[b.severity]-ranks[a.severity]||a.asset.localeCompare(b.asset));
}
export function correlationSummary(findings:Finding[]){
 const groups=correlateFindings(findings);
 return {rawFindings:findings.length,correlatedGroups:groups.length,
  groupedObservations:findings.length-groups.length,
  evidenceSources:[...new Set(findings.map(f=>f.source))].sort(),
  limitations:'Identifier/asset grouping is advisory. Shared CWE alone does not prove identical root cause. Analyst confirmation required before deduplication or closure.'};
}
