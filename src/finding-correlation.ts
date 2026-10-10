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
 const explicit=(f.externalIds?.cve||[]).find(x=>/^CVE-\d{4}-\d{4,}$/i.test(x));
 if(explicit)return explicit.toUpperCase();
 const cve=(f.title+' '+f.description).match(/\bCVE-\d{4}-\d{4,}\b/i);
 if(cve)return cve[0].toUpperCase();
 // CWE is a weakness class, not a unique vulnerability identifier. Never merge on CWE alone.
 return null;
}
export function findingFingerprint(f:Finding){
 const asset=f.asset.trim().toLowerCase(),id=identifier(f);
 const stable=id?JSON.stringify([asset,id]):JSON.stringify([asset,'SCANNER',f.source,f.externalIds?.scannerId||f.title.trim().toLowerCase()]);
 return crypto.createHash('sha256').update(stable).digest('hex');
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
   confidence:(id==='UNVERIFIED'?'UNVERIFIED_SINGLE':'IDENTIFIER_MATCH') as CorrelatedFinding['confidence']
  };
 }).sort((a,b)=>ranks[b.severity]-ranks[a.severity]||a.asset.localeCompare(b.asset));
}
export function correlationSummary(findings:Finding[]){
 const groups=correlateFindings(findings);
 return {rawFindings:findings.length,correlatedGroups:groups.length,
  groupedObservations:findings.length-groups.length,
  evidenceSources:[...new Set(findings.map(f=>f.source))].sort(),
  limitations:'Only explicit CVE plus normalized asset can group observations automatically. CWE is classification only and never a deduplication key. Analyst confirmation is required before closure.'};
}
