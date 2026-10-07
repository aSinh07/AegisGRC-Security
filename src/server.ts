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
import { authConfigured, login, logout, valid, verifyCredentials } from './auth.js';
import { initUsers,beginRegistration,confirmRegistration,userLogin,userSession,userLogout } from './user-auth.js';
import multer from 'multer';
import { frameworkCatalog } from './grc.js';
import { analyzeDocumentText } from './document-ai.js';
import { zapReady,zapScan,zapFindings } from './zap.js';
import { askCopilot } from './copilot.js';
import { knowledgeCatalog } from './knowledge.js';
import { extractDocument } from './document-extract.js';
import { cyberIntel,nvdCve } from './cyber-intel.js';
import { analyzeIntel } from './intel-ai.js';
import { docxReport,pptxReport,xlsxReport,csvReport,txtReport,reportModel,frameworkReportModel,frameworkDocx,frameworkXlsx,frameworkCsv,frameworkTxt,type ReportKind } from './exporters.js';

const app=express();
await initUsers();
const authBuckets=new Map<string,{count:number,reset:number}>();
function authLimit(max:number,windowMs:number){return (req:any,res:any,next:any)=>{const key=(req.ip||req.socket?.remoteAddress||'unknown')+':'+req.path,now=Date.now();let b=authBuckets.get(key);if(!b||b.reset<now)b={count:0,reset:now+windowMs};b.count++;authBuckets.set(key,b);if(b.count>max){res.setHeader('Retry-After',String(Math.ceil((b.reset-now)/1000)));return res.status(429).json({error:'Too many authentication attempts. Try again later.'})}next()}}

app.use(express.json({limit:'1mb'}));
app.use(express.static('public'));
app.post('/api/auth/login',(req,res)=>{const token=login(String(req.body?.password||''),String(req.body?.code||''));if(!token)return res.status(401).json({error:authConfigured()?'Invalid password or authenticator code':'Server login is not configured'});res.cookie('aegis_auth',token,{httpOnly:true,sameSite:'strict',secure:process.env.COOKIE_SECURE==='true',path:'/',maxAge:28800000});res.json({ok:true})});
app.post('/api/auth/register',authLimit(5,15*60*1000),async(req,res)=>{try{res.json(await beginRegistration(String(req.body?.email||''),String(req.body?.password||'')))}catch(e:any){res.status(400).json({error:e.code==='23505'?'Account already exists':e.message})}});
app.post('/api/auth/register/confirm',authLimit(10,15*60*1000),async(req,res)=>{try{if(!await confirmRegistration(String(req.body?.userId||''),String(req.body?.code||'')))return res.status(401).json({error:'Invalid authenticator code'});res.json({ok:true,message:'Authenticator enrolled. You can now sign in.'})}catch(e:any){res.status(400).json({error:e.message})}});
app.post('/api/auth/user-login',authLimit(10,15*60*1000),async(req,res)=>{try{const token=await userLogin(String(req.body?.email||''),String(req.body?.password||''),String(req.body?.code||''));if(!token)return res.status(401).json({error:'Invalid email, password or authenticator code'});res.cookie('aegis_user',token,{httpOnly:true,sameSite:'strict',secure:process.env.COOKIE_SECURE==='true',path:'/',maxAge:28800000});res.json({ok:true})}catch(e:any){res.status(400).json({error:e.message})}});
app.post('/api/auth/logout',(req,res)=>{const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_auth='))?.slice(11)||'';logout(token);const ut=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_user='))?.slice(11)||'';userLogout(ut);res.setHeader('Set-Cookie',['aegis_auth=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/','aegis_user=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/']);res.json({ok:true})});
app.get('/api/auth/status',(req,res)=>{const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_auth='))?.slice(11)||'';const ut=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_user='))?.slice(11)||'';res.json({authenticated:valid(token)||Boolean(userSession(ut)),configured:authConfigured()})});
app.use('/api',(req,res,next)=>{if(['/ready','/health','/integrations','/auth/login','/auth/user-login','/auth/register','/auth/register/confirm','/auth/status'].includes(req.path))return next();const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_auth='))?.slice(11)||'';const ut=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_user='))?.slice(11)||'';if(!valid(token)&&!userSession(ut))return res.status(401).json({error:'Login required'});next()});
const PORT=Number(process.env.PORT||8080);
const TIMEOUT=Number(process.env.SCAN_TIMEOUT_MS||90000);
const MAX=Number(process.env.MAX_OUTPUT_BYTES||1048576);
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:20*1024*1024,files:10}});

type Tool='nmap'|'wapiti'|'sqlmap'|'zap';
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
    if(!['nmap','wapiti','sqlmap','zap'].includes(tool)) return res.status(400).json({error:'Tool is not enabled for real execution'});
    const t=await validateTarget(String(req.body.targetUrl||''));
    if(t.url.origin!==session.targetOrigin || assessment.target!==session.targetOrigin) return res.status(403).json({error:'Target is outside the authorized assessment scope'});
    const startedAt=new Date().toISOString();
    let result:{stdout:string;stderr:string;exitCode:number|null;durationMs:number}; let zapAlerts:any[]=[];
    if(tool==='zap'){const z0=Date.now();zapAlerts=await zapScan(t.url.origin);result={stdout:JSON.stringify(zapAlerts),stderr:'',exitCode:0,durationMs:Date.now()-z0}}
    else {const args=tool==='nmap'?['-sT','-sV','--version-light','-Pn','-p','80,443,8080,8443','-oX','-',t.url.hostname]:tool==='wapiti'?['-u',t.url.origin,'--scope','url','--max-scan-time','60','--flush-session']:['-u',t.url.toString(),'--batch','--level=1','--risk=1','--threads=1','--timeout=10','--retries=1','--output-dir=/tmp/sqlmap'];result=await run(tool,args)}
    const completedAt=new Date().toISOString();
    const evidence=JSON.stringify({tool,target:t.url.origin,startedAt,completedAt,...result});
    const sha256=crypto.createHash('sha256').update(evidence).digest('hex');
    const ev:Evidence={id:crypto.randomUUID(),assessmentId,source:tool,sha256,createdAt:completedAt,exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,metadata:{target:t.url.origin,resolvedAddresses:t.addresses,durationMs:result.durationMs}};
    await db.saveEvidence(ev);
    const findings=tool==='wapiti'?wapitiFindings(assessmentId,t.url.origin,sha256,result.stdout):tool==='nmap'?nmapFindings(assessmentId,t.url.origin,sha256,result.stdout):tool==='zap'?zapFindings(assessmentId,t.url.origin,sha256,zapAlerts):[];
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

app.get('/api/knowledge',(_req,res)=>res.json(knowledgeCatalog()));
app.get('/api/cyber-intel',async(req,res)=>{try{res.json(await cyberIntel(req.query.refresh==='1'))}catch(e:any){res.status(502).json({error:e.message})}});
app.get('/api/cve/:cve',async(req,res)=>{try{res.json(await nvdCve(req.params.cve))}catch(e:any){res.status(502).json({error:e.message})}});
app.post('/api/cyber-intel/analyze',async(req,res)=>{try{const item=req.body?.item;if(!item?.title||!item?.source)return res.status(400).json({error:'Intelligence item required'});res.json(await analyzeIntel(item,String(req.body?.context||'')))}catch(e:any){res.status(502).json({error:e.message})}});
app.get('/api/frameworks',(_req,res)=>res.json({frameworks:frameworkCatalog,note:'Mappings are evidence-driven cross-references, not certification or reproduced standards text.'}));
app.post('/api/assessments/:id/documents',upload.array('files',10),async(req,res)=>{
 try{const a=(await db.assessments()).find(x=>x.id===req.params.id);if(!a)return res.status(404).json({error:'Assessment not found'});const files=(req.files||[]) as Express.Multer.File[];if(!files.length)return res.status(400).json({error:'No files supplied'});const denied=/\.(exe|dll|so|dylib|msi|apk|bat|cmd|ps1|sh|scr|com|jar)$/i;const saved=[];for(const file of files){if(denied.test(file.originalname))return res.status(400).json({error:'Executable/script uploads are not accepted'});const id=crypto.randomUUID(),sha256=crypto.createHash('sha256').update(file.buffer).digest('hex'),createdAt=new Date().toISOString();await db.saveDocument({id,assessmentId:a.id,filename:file.originalname.replace(/[\\/\0]/g,'_'),mimeType:file.mimetype||'application/octet-stream',size:file.size,sha256,createdAt,content:file.buffer});await db.saveAudit({id:crypto.randomUUID(),assessmentId:a.id,action:'DOCUMENT_UPLOADED',actor:'operator',createdAt,metadata:{documentId:id,filename:file.originalname,size:file.size,sha256}});saved.push({id,filename:file.originalname,size:file.size,sha256,createdAt})}res.json({stored:true,documents:saved})}catch(e:any){res.status(400).json({error:e.message})}
});
app.get('/api/assessments/:id/documents',async(req,res)=>res.json(await db.documents(req.params.id)));
app.post('/api/assessments/:id/documents/:docId/analyze',async(req,res)=>{try{
 const d=await db.document(req.params.docId);if(!d||d.assessmentId!==req.params.id)return res.status(404).json({error:'Not found'});
 const extracted=await extractDocument(d.filename,d.mimeType,d.content);
 if(!extracted.text.trim())return res.status(422).json({error:'No extractable text found in this document'});
 const analysis=await analyzeDocumentText(d.filename,extracted.text);
 await db.saveAudit({id:crypto.randomUUID(),assessmentId:req.params.id,action:'DOCUMENT_ANALYZED',actor:'operator',createdAt:new Date().toISOString(),metadata:{documentId:d.id,sha256:d.sha256,extraction:extracted.kind,pages:(extracted as any).pages||null,analysisMode:(analysis as any).mode}});
 res.json({document:{id:d.id,filename:d.filename,sha256:d.sha256,extraction:extracted.kind,pages:(extracted as any).pages||null},...analysis})
}catch(e:any){res.status(400).json({error:e.message})}});
app.get('/api/assessments/:id/documents/:docId',async(req,res)=>{const d=await db.document(req.params.docId);if(!d||d.assessmentId!==req.params.id)return res.status(404).json({error:'Not found'});res.setHeader('Content-Disposition',`attachment; filename="${String(d.filename).replace(/"/g,'')}"`);res.type(d.mimeType).send(d.content)});
app.delete('/api/assessments/:id/documents/:docId',async(req,res)=>{const d=await db.document(req.params.docId);if(!d||d.assessmentId!==req.params.id)return res.status(404).json({error:'Not found'});await db.deleteDocument(req.params.docId);await db.saveAudit({id:crypto.randomUUID(),assessmentId:req.params.id,action:'DOCUMENT_DELETED',actor:'operator',createdAt:new Date().toISOString(),metadata:{documentId:req.params.docId,sha256:d.sha256}});res.json({deleted:true})});

app.get('/api/integrations',async(_req,res)=>{
 const health:any={nmap:false,wapiti:false,semgrep:false,sqlmap:false,tshark:false,zap:false,gemini:Boolean(process.env.GEMINI_API_KEY)};
 const check=async(cmd:string,args:string[])=>{try{return (await run(cmd,args)).exitCode===0}catch{return false}};
 health.nmap=await check('nmap',['--version']); health.wapiti=await check('wapiti',['--version']); health.semgrep=await check('semgrep',['--version']); health.sqlmap=await check('sqlmap',['--version']); health.tshark=await check('tshark',['--version']); health.zap=await zapReady();
 res.json({integrations:[
  {id:'nmap',kind:'scanner',status:health.nmap?'REAL':'UNAVAILABLE'},
  {id:'zap',kind:'web-dast',status:health.zap?'REAL':'UNAVAILABLE'},
  {id:'wapiti',kind:'scanner',status:health.wapiti?'REAL':'UNAVAILABLE'},
  {id:'semgrep',kind:'source-scanner',status:health.semgrep?'REAL':'UNAVAILABLE'},
  {id:'sqlmap',kind:'authorized-sqli-validation',status:health.sqlmap?'REAL':'UNAVAILABLE'},
  {id:'tshark',kind:'packet-analysis',status:health.tshark?'REAL':'UNAVAILABLE'},
  {id:'gemini',kind:'ai-analysis',status:health.gemini?'CONNECTED':'UNAVAILABLE'},
  {id:'burp',kind:'external-provider',status:'UNAVAILABLE'},
  {id:'wireshark',kind:'capture-provider',status:'UNAVAILABLE'},
  {id:'metasploit',kind:'exploit-framework',status:'DISABLED'}
 ]});
});
app.post('/api/assessments/:id/copilot',async(req,res)=>{try{
 const a=(await db.assessments()).find(x=>x.id===req.params.id);if(!a)return res.status(404).json({error:'Assessment not found'});
 const question=String(req.body?.question||'').trim();if(!question||question.length>2000)return res.status(400).json({error:'Question must be between 1 and 2000 characters'});
 const fs=(await db.findings()).filter(x=>x.assessmentId===req.params.id);
 const answer=await askCopilot(question,String(req.body?.mode||'beginner'),a,fs);
 await db.saveAudit({id:crypto.randomUUID(),assessmentId:a.id,action:'AI_EXPLANATION_REQUESTED',actor:'operator',createdAt:new Date().toISOString(),metadata:{mode:String(req.body?.mode||'beginner'),findingCount:fs.length}});
 res.json(answer);
}catch(e:any){res.status(502).json({mode:'UNAVAILABLE',error:e.message})}});
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

app.get('/api/assessments/:id/framework-report/:framework/:format',async(req,res)=>{try{if(!verifyCredentials(String(req.headers['x-report-password']||''),String(req.headers['x-report-totp']||'')))return res.status(401).json({error:'Fresh password and authenticator code required for report export'});const a=(await db.assessments()).find(x=>x.id===req.params.id);if(!a)return res.status(404).json({error:'Not found'});const fs=(await db.findings()).filter(x=>x.assessmentId===req.params.id),framework=req.params.framework.toUpperCase(),format=req.params.format.toLowerCase();let body:Buffer,mime='application/octet-stream';if(format==='docx'){body=await frameworkDocx(a,fs,framework);mime='application/vnd.openxmlformats-officedocument.wordprocessingml.document'}else if(format==='xlsx'){body=frameworkXlsx(a,fs,framework);mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}else if(format==='csv'){body=frameworkCsv(fs,framework);mime='text/csv'}else if(format==='txt'){body=frameworkTxt(a,fs,framework);mime='text/plain'}else if(format==='json'){body=Buffer.from(JSON.stringify(frameworkReportModel(a,fs,framework),null,2));mime='application/json'}else return res.status(400).json({error:'Framework export currently supports DOCX, XLSX, CSV, JSON and TXT'});res.setHeader('Content-Disposition',`attachment; filename="aegis-${framework.toLowerCase()}-${a.id}.${format}"`);res.type(mime).send(body)}catch(e:any){res.status(400).json({error:e.message})}});

app.get('/api/assessments/:id/export/:kind/:format',async(req,res)=>{
 try{
  if(!verifyCredentials(String(req.headers['x-report-password']||''),String(req.headers['x-report-totp']||'')))return res.status(401).json({error:'Fresh password and authenticator code required for report export'});
  const a=(await db.assessments()).find(x=>x.id===req.params.id);if(!a)return res.status(404).json({error:'Not found'});
  const fs=(await db.findings()).filter(x=>x.assessmentId===req.params.id);
  const kinds=['grc','remediation','architecture','technical','executive']; const formats=['pdf','docx','pptx','xlsx','csv','json','txt'];
  const kind=(kinds.includes(req.params.kind)?req.params.kind:'grc') as ReportKind, format=req.params.format.toLowerCase();
  if(!formats.includes(format))return res.status(400).json({error:'Unsupported report format'});
  let body:Buffer; let mime='application/octet-stream';
  if(format==='pdf'){body=await renderPdf(a,fs);mime='application/pdf'}
  else if(format==='docx'){body=await docxReport(a,fs,kind);mime='application/vnd.openxmlformats-officedocument.wordprocessingml.document'}
  else if(format==='pptx'){body=await pptxReport(a,fs,kind);mime='application/vnd.openxmlformats-officedocument.presentationml.presentation'}
  else if(format==='xlsx'){body=xlsxReport(a,fs,kind);mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}
  else if(format==='csv'){body=csvReport(fs);mime='text/csv'}
  else if(format==='txt'){body=txtReport(a,fs,kind);mime='text/plain'}
  else {body=Buffer.from(JSON.stringify(reportModel(a,fs,kind),null,2));mime='application/json'}
  res.setHeader('Content-Disposition',`attachment; filename="aegis-${kind}-${a.id}.${format}"`);res.type(mime).send(body);
 }catch(e:any){res.status(500).json({error:e.message})}
});

app.listen(PORT,()=>console.log(`AegisGRC Security listening on :${PORT}`));
