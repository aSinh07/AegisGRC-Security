import { promises as fs } from 'node:fs'; import path from 'node:path';
import type { Assessment,Evidence,Finding,AuditEvent } from './models.js';
const dir=process.env.DATA_DIR||'/tmp/aegis-data';
async function rw<T>(name:string,f:(x:T[])=>T[]){await fs.mkdir(dir,{recursive:true});const p=path.join(dir,name);let a:T[]=[];try{a=JSON.parse(await fs.readFile(p,'utf8'))}catch{};a=f(a);await fs.writeFile(p,JSON.stringify(a,null,2));return a}
async function read<T>(name:string){try{return JSON.parse(await fs.readFile(path.join(dir,name),'utf8')) as T[]}catch{return []}}
export const db={
 assessments:()=>read<Assessment>('assessments.json'), evidence:()=>read<Evidence>('evidence.json'), findings:()=>read<Finding>('findings.json'),
 saveAssessment:(x:Assessment)=>rw<Assessment>('assessments.json',a=>[...a.filter(v=>v.id!==x.id),x]),
 saveEvidence:(x:Evidence)=>rw<Evidence>('evidence.json',a=>[...a,x]),
 saveFindings:(xs:Finding[])=>rw<Finding>('findings.json',a=>[...a,...xs.filter(x=>!a.some(v=>v.id===x.id))]),
 audits:()=>read<AuditEvent>('audit.json'), saveAudit:(x:AuditEvent)=>rw<AuditEvent>('audit.json',a=>[...a,x])
};