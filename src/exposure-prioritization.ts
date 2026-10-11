export type ExposureFinding={id:string;asset:string;fingerprint:string;severity:'INFO'|'LOW'|'MEDIUM'|'HIGH'|'CRITICAL';cve?:string|null;cvss?:number|null;epss?:number|null;kev?:boolean;internetExposed?:boolean;exploitObserved?:boolean;controlCoverage?:'NONE'|'PARTIAL'|'EFFECTIVE';status?:'OPEN'|'ACCEPTED'|'MITIGATED'|'CLOSED'};
const sev={INFO:0,LOW:10,MEDIUM:25,HIGH:45,CRITICAL:65};
export function exposurePriority(f:ExposureFinding){
 let score=sev[f.severity]+Math.min(10,Math.max(0,Number(f.cvss||0)))+Math.round(Math.min(1,Math.max(0,Number(f.epss||0)))*10);
 if(f.kev)score+=15;if(f.internetExposed)score+=10;if(f.exploitObserved)score+=15;
 if(f.controlCoverage==='EFFECTIVE')score-=15;else if(f.controlCoverage==='PARTIAL')score-=5;
 if(f.status==='ACCEPTED')score-=5;if(f.status==='CLOSED')score=0;
 score=Math.max(0,Math.min(100,score));
 const band=score>=80?'P0':score>=60?'P1':score>=35?'P2':'P3';
 return {score,band,reasons:[f.kev&&'CISA KEV/catalog signal',f.internetExposed&&'Internet exposed',f.exploitObserved&&'Exploit activity observed',f.epss!=null&&'Exploit probability signal',f.controlCoverage==='EFFECTIVE'&&'Effective compensating control'].filter(Boolean)};
}
export function correlateExposure(findings:ExposureFinding[]){
 const seen=new Set<string>();return findings.filter(f=>{const k=f.fingerprint.trim();if(!k||seen.has(k))return false;seen.add(k);return true}).map(f=>({...f,priority:exposurePriority(f)})).sort((a,b)=>b.priority.score-a.priority.score);
}
