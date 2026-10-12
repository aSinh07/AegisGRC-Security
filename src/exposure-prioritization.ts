export type ExposureFinding={id:string;asset:string;fingerprint:string;severity:'INFO'|'LOW'|'MEDIUM'|'HIGH'|'CRITICAL';cve?:string|null;cvss?:number|null;epss?:number|null;kev?:boolean;internetExposed?:boolean;exploitObserved?:boolean;controlCoverage?:'NONE'|'PARTIAL'|'EFFECTIVE';status?:'OPEN'|'ACCEPTED'|'MITIGATED'|'CLOSED';verifiedClosed?:boolean};
const sev={INFO:0,LOW:10,MEDIUM:25,HIGH:45,CRITICAL:65};
const bounded=(value:number|null|undefined,max:number)=>Number.isFinite(value)?Math.min(max,Math.max(0,value!)):0;
export function exposurePriority(f:ExposureFinding){
 if(!(f.severity in sev))throw Error('Invalid finding severity');
 let score=sev[f.severity]+bounded(f.cvss,10)+Math.round(bounded(f.epss,1)*10);
 if(f.kev)score+=15;if(f.internetExposed)score+=10;if(f.exploitObserved)score+=15;
 if(f.controlCoverage==='EFFECTIVE')score-=15;else if(f.controlCoverage==='PARTIAL')score-=5;
 // Risk acceptance is an administrative decision, not vulnerability remediation.
 // A closed label alone must never erase exposure without verified remediation.
 if(f.status==='CLOSED'&&f.verifiedClosed===true)score=0;
 score=Math.round(Math.max(0,Math.min(100,score)));
 const band=score>=80?'P0':score>=60?'P1':score>=35?'P2':'P3';
 return {score,band,reasons:[f.kev&&'CISA KEV/catalog signal',f.internetExposed&&'Internet exposed',f.exploitObserved&&'Exploit activity observed',f.epss!=null&&'Exploit probability signal',f.controlCoverage==='EFFECTIVE'&&'Effective compensating control',f.status==='CLOSED'&&!f.verifiedClosed&&'Unverified closure: exposure retained'].filter(Boolean)};
}
export function correlateExposure(findings:ExposureFinding[]){
 // Fingerprints identify findings only within a specific asset. Do not discard
 // the same CVE reported on a different system.
 const byAssetFingerprint=new Map<string,ExposureFinding & {priority:ReturnType<typeof exposurePriority>}>();
 for(const f of findings){
  const asset=String(f.asset||'').trim().toLowerCase(),fingerprint=String(f.fingerprint||'').trim().toLowerCase();
  if(!asset||!fingerprint)continue;
  const key=JSON.stringify([asset,fingerprint]),candidate={...f,priority:exposurePriority(f)};
  const previous=byAssetFingerprint.get(key);
  if(!previous||candidate.priority.score>previous.priority.score||(candidate.priority.score===previous.priority.score&&candidate.id<previous.id))byAssetFingerprint.set(key,candidate);
 }
 return [...byAssetFingerprint.values()].sort((a,b)=>b.priority.score-a.priority.score||a.asset.localeCompare(b.asset)||a.fingerprint.localeCompare(b.fingerprint));
}
