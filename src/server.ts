import 'dotenv/config';
import express from 'express';
import dns from 'node:dns/promises';
import net from 'node:net';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { db } from './store.js';
import { scanSource } from './semgrep.js';
import { semgrepFindings, wapitiFindings, nmapFindings } from './parsers.js';
import { assessmentReport } from './reports.js';
import type { Assessment,Evidence } from './models.js';
import { explainFindings } from './ai.js';
import { issueSession, verifySession } from './session.js';
import { renderPdf } from './pdf.js';

const app=express();
app.use(express.json({limit:'1mb'}));
app.use(express.static('public'));
const PORT=Number(process.env.PORT||8080);
const TIMEOUT=Number(process.env.SCAN_TIMEOUT_MS||90000);
const MAX=Number(process.env.MAX_OUTPUT_BYTES||1048576);

type Tool='nmap'|'wapiti';
const blocked=(ip:string)=>{
  if(net.isIP(ip)===4){
    const p=ip.split('.').map(Number);
    return p[0]===10||p[0]===127||p[0]===0||(p[0]===169&&p[1]===254)||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168)||(p[0]>=224);
  }
  const x=ip.toLowerCase();
  return x==='::1'||x==='::'||x.startsWith('fc')||x.startsWith('fd')||x.startsWith('fe8')||x.startsWith('fe9')||x.startsWith('fea')||x.startsWith('feb')||x.startsWith('ff');
};
async function validateTarget(raw:string){
  const u=new URL(raw);
  if(!['http:','https:'].includes(u.protocol)) throw new Error('Only HTTP(S) targets are supported');
  if(u.username||u.password) throw new Error('Credentials in target URLs are not allowed');
  const records=await dns.lookup(u.hostname,{all:true,verbatim:true});
  if(!records.length) throw new Error('Target did not resolve');
  if(records.some(r=>blocked(r.address))) throw new Error('Private, local, reserved or link-local targets are blocked');
  return {url:u,addresses:records.map(r=>r.address)};
}
function run(cmd:string,args:string[]){
  return new Promise<{stdout:string;stderr:string;exitCode:number|null;durationMs:number}>((resolve,reject)=>{
    const started=Date.now(); let out='',err='',done=false;
    const child=spawn(cmd,args,{shell:false,stdio:['ignore','pipe','pipe']});
    const timer=setTimeout(()=>child.kill('SIGKILL'),TIMEOUT);
    const append=(base:string,chunk:Buffer)=> (base+chunk.toString()).slice(0,MAX);
    child.stdout.on('data',(d:Buffer)=>out=append(out,d));
    child.stderr.on('data',(d:Buffer)=>err=append(err,d));
    child.on('error',e=>{if(!done){done=true;clearTimeout(timer);reject(e)}});
    child.on('close',code=>{if(!done){done=true;clearTimeout(timer);resolve({stdout:out,stderr:err,exitCode:code,durationMs:Date.now()-started})}});
  });
}
app.get('/api/ready',async(_req,res)=>{try{res.json(await db.ready())}catch(e:any){res.status(503).json({ok:false,error:e.message})}});
app.get('/api/health',async(_req,res)=>{
  const check=async(cmd:string,args:string[])=>{try{const r=await run(cmd,args);return {available:r.exitCode===0,version:(r.stdout||r.stderr).split('\n')[0]}}catch{return {available:false}}};
  res.json({ok:true,service:'AegisGRC Security',tools:{nmap:await check('nmap',['--version']),wapiti:await check('wapiti',['--version'])}});
});
app.post('/api/assessment/authorize',async(req,res)=>{
  try{
    if(req.body?.authorized!==true) return res.status(403).json({error:'Explicit authorization confirmation is required'});
    const t=await validateTarget(String(req.body.targetUrl||''));
    const token=crypto.createHmac('sha256',process.env.EVIDENCE_HMAC_KEY||'dev-only').update(t.url.origin+'|'+Date.now()).digest('hex');
    const assessment:Assessment={id:crypto.randomUUID(),target:t.url.origin,authorizedAt:new Date().toISOString(),status:'AUTHORIZED',findings:[],evidenceIds:[]};
    await db.saveAssessment(assessment);
    const sessionToken=issueSession(assessment.id,t.url.origin);
    await db.saveAudit({id:crypto.randomUUID(),assessmentId:assessment.id,action:'ASSESSMENT_AUTHORIZED',actor:'operator',createdAt:new Date().toISOString(),metadata:{target:t.url.origin,resolvedAddresses:t.addresses}});
    res.json({authorized:true,assessmentId:assessment.id,targetOrigin:t.url.origin,resolvedAddresses:t.addresses,sessionToken});
  }catch(e:any){res.status(400).json({error:e.message})}
});
app.post('/api/scans/run',async(req,res)=>{
  try{
    const session=verifySession(String(req.headers['x-assessment-session']||''));
    const assessmentId=session.assessmentId;
    const assessments=await db.assessments(); const assessment=assessments.find(a=>a.id===assessmentId);
    if(!assessment) return res.status(404).json({error:'Assessment not found; enter through the authorization gate first'});
    const tool=String(req.body.tool||'') as Tool;
    if(!['nmap','wapiti'].includes(tool)) return res.status(400).json({error:'Tool is not enabled for real execution'});
    const t=await validateTarget(String(req.body.targetUrl||''));
    if(t.url.origin!==session.targetOrigin || assessment.target!==session.targetOrigin) return res.status(403).json({error:'Target is outside the authorized assessment scope'});
    const args=tool==='nmap'
      ? ['-sT','-sV','--version-light','-Pn','-p','80,443,8080,8443','-oX','-',t.url.hostname]
      : ['-u',t.url.origin,'--scope','url','--max-scan-time','60','--flush-session'];
    const startedAt=new Date().toISOString();
    const result=await run(tool,args);
    const completedAt=new Date().toISOString();
    const evidence=JSON.stringify({tool,target:t.url.origin,startedAt,completedAt,...result});
    const sha256=crypto.createHash('sha256').update(evidence).digest('hex');
    const ev:Evidence={id:crypto.randomUUID(),assessmentId,source:tool,sha256,createdAt:completedAt,exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,metadata:{target:t.url.origin,resolvedAddresses:t.addresses,durationMs:result.durationMs}};
    await db.saveEvidence(ev);
    const findings=tool==='wapiti'?wapitiFindings(assessmentId,t.url.origin,sha256,result.stdout):nmapFindings(assessmentId,t.url.origin,sha256,result.stdout);
    await db.saveAudit({id:crypto.randomUUID(),assessmentId,action:'REAL_SCAN_COMPLETED',actor:'operator',createdAt:completedAt,metadata:{tool,exitCode:result.exitCode,evidenceHash:sha256,durationMs:result.durationMs}});
    if(findings.length) await db.saveFindings(findings);
    await db.saveAssessment({...assessment,status:result.exitCode===0?'COMPLETED':'FAILED',evidenceIds:[...assessment.evidenceIds,ev.id],findings:[...assessment.findings,...findings]});
    res.status(result.exitCode===0?200:502).json({execution:'REAL_TOOL_EXECUTION',tool,target:t.url.origin,resolvedAddresses:t.addresses,startedAt,completedAt,...result,evidence:{sha256}});
  }catch(e:any){res.status(400).json({error:e.message})}
});
app.post('/api/source/semgrep',async(req,res)=>{
 try{
  const session=verifySession(String(req.headers['x-assessment-session']||'')); const assessmentId=session.assessmentId; const assessments=await db.assessments(); const assessment=assessments.find(a=>a.id===assessmentId);
  if(!assessment) return res.status(404).json({error:'Assessment not found'});
  const result=await scanSource(String(req.body.sourcePath||'/workspace/source'));
  const ev:Evidence={id:crypto.randomUUID(),assessmentId,source:'semgrep',sha256:result.evidence.sha256,createdAt:new Date().toISOString(),exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,metadata:{sourcePath:req.body.sourcePath||'/workspace/source'}};
  await db.saveEvidence(ev); const findings=semgrepFindings(assessmentId,String(req.body.sourcePath||'/workspace/source'),ev.sha256,result.results); await db.saveFindings(findings);
  await db.saveAssessment({...assessment,status:'COMPLETED',evidenceIds:[...assessment.evidenceIds,ev.id],findings:[...assessment.findings,...findings]});
  res.json({...result,assessmentId,findings});
 }catch(e:any){res.status(400).json({error:e.message})}
});
app.get('/api/assessments',async(_req,res)=>res.json(await db.assessments()));
app.get('/api/assessments/:id',async(req,res)=>{const a=(await db.assessments()).find(x=>x.id===req.params.id);if(!a)return res.status(404).json({error:'Not found'});res.json(a)});
app.get('/api/assessments/:id/audit',async(req,res)=>res.json((await db.audits()).filter(x=>x.assessmentId===req.params.id)));
app.get('/api/assessments/:id/evidence',async(req,res)=>res.json((await db.evidence()).filter(x=>x.assessmentId===req.params.id)));
app.get('/api/assessments/:id/report',async(req,res)=>{const a=(await db.assessments()).find(x=>x.id===req.params.id);if(!a)return res.status(404).json({error:'Not found'});const fs=(await db.findings()).filter(x=>x.assessmentId===req.params.id);res.json(assessmentReport(a,fs))});

app.get('/api/integrations',async(_req,res)=>{
 const health:any={nmap:false,wapiti:false,semgrep:false,gemini:Boolean(process.env.GEMINI_API_KEY)};
 const check=async(cmd:string,args:string[])=>{try{return (await run(cmd,args)).exitCode===0}catch{return false}};
 health.nmap=await check('nmap',['--version']); health.wapiti=await check('wapiti',['--version']); health.semgrep=await check('semgrep',['--version']);
 res.json({integrations:[
  {id:'nmap',kind:'scanner',status:health.nmap?'REAL':'UNAVAILABLE'},
  {id:'wapiti',kind:'scanner',status:health.wapiti?'REAL':'UNAVAILABLE'},
  {id:'semgrep',kind:'source-scanner',status:health.semgrep?'REAL':'UNAVAILABLE'},
  {id:'gemini',kind:'ai-analysis',status:health.gemini?'CONNECTED':'UNAVAILABLE'},
  {id:'burp',kind:'external-provider',status:'UNAVAILABLE'},
  {id:'wireshark',kind:'capture-provider',status:'UNAVAILABLE'},
  {id:'metasploit',kind:'exploit-framework',status:'DISABLED'}
 ]});
});
app.post('/api/assessments/:id/ai-remediation',async(req,res)=>{
 try{const fs=(await db.findings()).filter(x=>x.assessmentId===req.params.id);res.json(await explainFindings(fs))}
 catch(e:any){res.status(502).json({mode:'UNAVAILABLE',error:e.message})}
});
app.get('/api/assessments/:id/report.pdf',async(req,res)=>{
 const a=(await db.assessments()).find(x=>x.id===req.params.id);if(!a)return res.status(404).json({error:'Not found'});
 const fs=(await db.findings()).filter(x=>x.assessmentId===req.params.id);const pdf=await renderPdf(a,fs);
 res.setHeader('Content-Disposition',`attachment; filename="aegis-${a.id}.pdf"`);res.type('application/pdf').send(pdf);
});
app.get('/api/assessments/:id/report/download',async(req,res)=>{
 const a=(await db.assessments()).find(x=>x.id===req.params.id);if(!a)return res.status(404).json({error:'Not found'});
 const fs=(await db.findings()).filter(x=>x.assessmentId===req.params.id);const report=assessmentReport(a,fs);
 res.setHeader('Content-Disposition',`attachment; filename="aegis-${a.id}.json"`);res.type('application/json').send(JSON.stringify(report,null,2));
});

app.listen(PORT,()=>console.log(`AegisGRC Security listening on :${PORT}`));
