import {spawn} from 'node:child_process';
import crypto from 'node:crypto';

const MAX=8*1024*1024;
const TIMEOUT=Number(process.env.TRIVY_TIMEOUT_MS||180000);
export async function scanFilesystemWithTrivy(sourcePath:string){
 if(!sourcePath.startsWith('/workspace/'))throw new Error('Trivy filesystem scans are restricted to /workspace mounts');
 return new Promise<any>((resolve,reject)=>{
  const started=Date.now(),p=spawn('trivy',['fs','--format','json','--scanners','vuln,misconfig','--quiet',sourcePath],{shell:false,stdio:['ignore','pipe','pipe']});
  let out='',err='',done=false;
  const append=(base:string,d:Buffer)=>(base+d.toString()).slice(0,MAX);
  const timer=setTimeout(()=>p.kill('SIGKILL'),TIMEOUT);
  p.stdout.on('data',(d:Buffer)=>out=append(out,d));p.stderr.on('data',(d:Buffer)=>err=append(err,d));
  p.on('error',e=>{if(!done){done=true;clearTimeout(timer);reject(e)}});
  p.on('close',code=>{if(done)return;done=true;clearTimeout(timer);const sha256=crypto.createHash('sha256').update(JSON.stringify({tool:'trivy',sourcePath,stdout:out,stderr:err,exitCode:code})).digest('hex');resolve({execution:'REAL_TOOL_EXECUTION',tool:'trivy',sourcePath,exitCode:code,stdout:out,stderr:err,durationMs:Date.now()-started,evidence:{sha256}})});
 });
}

export async function scanContainerImageWithTrivy(imageRef:string){
 const ref=String(imageRef||'').trim();if(!ref||ref.length>300||/[\s;&|<>$\x00-\x1f]/.test(ref))throw new Error('Invalid container image reference');
 return new Promise<any>((resolve,reject)=>{const started=Date.now(),p=spawn('trivy',['image','--format','json','--scanners','vuln,misconfig','--quiet',ref],{shell:false,stdio:['ignore','pipe','pipe']});let out='',err='',done=false,truncated=false,timedOut=false;
 const append=(base:string,d:Buffer)=>{const next=base+d.toString();if(next.length>MAX)truncated=true;return next.slice(0,MAX)};const timer=setTimeout(()=>{timedOut=true;p.kill('SIGKILL')},TIMEOUT);
 p.stdout.on('data',(d:Buffer)=>out=append(out,d));p.stderr.on('data',(d:Buffer)=>err=append(err,d));p.on('error',e=>{if(!done){done=true;clearTimeout(timer);reject(e)}});
 p.on('close',code=>{if(done)return;done=true;clearTimeout(timer);const sha256=crypto.createHash('sha256').update(JSON.stringify({tool:'trivy-image',imageRef:ref,stdout:out,stderr:err,exitCode:code,timedOut,truncated})).digest('hex');resolve({execution:'REAL_TOOL_EXECUTION',tool:'trivy',scanType:'IMAGE',imageRef:ref,exitCode:code,stdout:out,stderr:err,timedOut,truncated,durationMs:Date.now()-started,evidence:{sha256}})})})
}
