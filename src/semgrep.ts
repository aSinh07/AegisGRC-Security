import { spawn } from 'node:child_process'; import crypto from 'node:crypto';
export async function scanSource(sourcePath:string){
 if(!sourcePath.startsWith('/workspace/')) throw new Error('Source scans are restricted to /workspace mounts');
 return new Promise<any>((resolve,reject)=>{
  const p=spawn('semgrep',['scan','--config','p/owasp-top-ten','--json','--metrics','off',sourcePath],{shell:false});
  let out='',err=''; p.stdout.on('data',d=>out+=d);p.stderr.on('data',d=>err+=d);
  p.on('error',reject);p.on('close',code=>{const sha256=crypto.createHash('sha256').update(out).digest('hex');let parsed:any={};try{parsed=JSON.parse(out)}catch{};resolve({execution:'REAL_TOOL_EXECUTION',tool:'semgrep',exitCode:code,stdout:out,stderr:err,evidence:{sha256},results:parsed.results||[]})})
 })
}