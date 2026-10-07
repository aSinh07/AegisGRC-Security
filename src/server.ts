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
import { frameworkCatalog,mapFinding } from './grc.js';
import { analyzeDocumentText } from './document-ai.js';
import { zapReady,zapScan,zapFindings } from './zap.js';
import { askCopilot } from './copilot.js';
import { knowledgeCatalog } from './knowledge.js';
import { extractDocument } from './document-extract.js';
import { cyberIntel,nvdCve,authoritativeResources } from './cyber-intel.js';
import { analyzeIntel } from './intel-ai.js';
import { docxReport,pptxReport,xlsxReport,csvReport,txtReport,reportModel,frameworkReportModel,frameworkDocx,frameworkXlsx,frameworkCsv,frameworkTxt,type ReportKind } from './exporters.js';

const app=express();
app.set('trust proxy',1);
await initUsers();

app.use(express.json({limit:'1mb'}));
app.use(express.static('public'));
app.post('/api/auth/login',(req,res)=>{const token=login(String(req.body?.password||''),String(req.body?.code||''));if(!token)return res.status(401).json({error:authConfigured()?'Invalid password or authenticator code':'Server login is not configured'});res.cookie('aegis_auth',token,{httpOnly:true,sameSite:'strict',secure:process.env.COOKIE_SECURE==='true',path:'/',maxAge:28800000});res.json({ok:true})});
app.post('/api/auth/register',async(req,res)=>{try{res.json(await beginRegistration(String(req.body?.email||''),String(req.body?.password||'')))}catch(e:any){res.status(400).json({error:e.code==='23505'?'Account already exists':e.message})}});
app.post('/api/auth/register/confirm',async(req,res)=>{try{if(!await confirmRegistration(String(req.body?.userId||''),String(req.body?.code||'')))return res.status(401).json({error:'Invalid authenticator code'});res.json({ok:true,message:'Authenticator enrolled. You can now sign in.'})}catch(e:any){res.status(400).json({error:e.message})}});
app.post('/api/auth/user-login',async(req,res)=>{try{const token=await userLogin(String(req.body?.email||''),String(req.body?.password||''),String(req.body?.code||''));if(!token)return res.status(401).json({error:'Invalid email, password or authenticator code'});res.cookie('aegis_user',token,{httpOnly:true,sameSite:'strict',secure:process.env.COOKIE_SECURE==='true',path:'/',maxAge:28800000});res.json({ok:true})}catch(e:any){res.status(400).json({error:e.message})}});
app.post('/api/auth/logout',async(req,res)=>{const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_auth='))?.slice(11)||'';logout(token);const ut=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_user='))?.slice(11)||'';await userLogout(ut);res.setHeader('Set-Cookie',['aegis_auth=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/','aegis_user=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/']);res.json({ok:true})});
app.get('/api/auth/status',async(req,res)=>{const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_auth='))?.slice(11)||'';const ut=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_user='))?.slice(11)||'';res.json({authenticated:valid(token)||Boolean(await userSession(ut)),configured:authConfigured()})});
app.use('/api',async(req,res,next)=>{if(['/ready','/health','/integrations','/auth/login','/auth/user-login','/auth/register','/auth/register/confirm','/auth/status'].includes(req.path))return next();const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_auth='))?.slice(11)||'';const ut=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_user='))?.slice(11)||'';if(!valid(token)&&!await userSession(ut))return res.status(401).json({error:'Login required'});next()});
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
async function quickPosture(assessmentId:string,t:{url:URL,addresses:string[]}){
 const started=Date.now(),createdAt=new Date().toISOString();
 const ctl=new AbortController();const timer=setTimeout(()=>ctl.abort(),1200);
 let status=0,headers:any={},error='';
 try{const r=await fetch(t.url.origin,{method:'GET',redirect:'manual',signal:ctl.signal,headers:{'User-Agent':'AegisGRC-Posture/1.0'}});status=r.status;headers=Object.fromEntries(r.headers.entries());try{await r.body?.cancel()}catch{}}
 catch(e:any){error=e?.name==='AbortError'?'HTTP posture probe exceeded 1.2s':String(e?.message||e)}
 finally{clearTimeout(timer)}
 const checks=[
  {bad:t.url.protocol!=='https:',title:'Transport is not HTTPS',severity:'HIGH',cvss:7.4,desc:'The authorized target uses plaintext HTTP.',rem:'Enforce HTTPS and redirect HTTP to HTTPS.'},
  {bad:!headers['strict-transport-security']&&t.url.protocol==='https:',title:'HSTS header not observed',severity:'MEDIUM',cvss:5.3,desc:'Strict-Transport-Security was not observed in the live HTTP response.',rem:'Enable HSTS after validating HTTPS coverage.'},
  {bad:!headers['content-security-policy'],title:'Content Security Policy not observed',severity:'MEDIUM',cvss:5.3,desc:'Content-Security-Policy was not observed in the live HTTP response.',rem:'Deploy a restrictive CSP appropriate to the application.'},
  {bad:!headers['x-content-type-options'],title:'MIME sniffing protection not observed',severity:'LOW',cvss:3.1,desc:'X-Content-Type-Options was not observed.',rem:'Set X-Content-Type-Options: nosniff.'},
  {bad:!headers['x-frame-options']&&!String(headers['content-security-policy']||'').includes('frame-ancestors'),title:'Framing protection not observed',severity:'MEDIUM',cvss:4.3,desc:'Neither X-Frame-Options nor CSP frame-ancestors was observed.',rem:'Set CSP frame-ancestors or X-Frame-Options.'},
  {bad:Boolean(headers['server']),title:'Server technology disclosed',severity:'LOW',cvss:2.6,desc:'The live response exposes a Server header: '+String(headers['server']||''),rem:'Minimize unnecessary server banner disclosure.'}
 ] as const;
 const evidence=JSON.stringify({kind:'LIVE_HTTP_POSTURE',target:t.url.origin,status,headers,error,addresses:t.addresses});
 const sha256=crypto.createHash('sha256').update(evidence).digest('hex');
 const findings:any[]=checks.filter(x=>x.bad).map(x=>({id:crypto.randomUUID(),assessmentId,source:'http',title:x.title,description:x.desc,severity:x.severity,cvss:x.cvss,asset:t.url.origin,evidenceHash:sha256,createdAt,mappings:{owasp:['A05:2025 Security Misconfiguration'],nistCsf:['PR.PS']},remediation:x.rem,status:'OPEN'}));
 return {startedAt:createdAt,completedAt:new Date().toISOString(),durationMs:Date.now()-started,status,headers,error,sha256,findings};
}
function documentSecurityScan(file:Express.Multer.File){
 const b=file.buffer,ascii=b.toString('latin1'),name=file.originalname.toLowerCase(),sha256=crypto.createHash('sha256').update(b).digest('hex');
 const signals:{signal:string,severity:string,detail:string}[]=[];
 const add=(signal:string,severity:string,detail:string)=>signals.push({signal,severity,detail});
 if(ascii.includes('/JavaScript')||ascii.includes('/JS'))add('PDF_JAVASCRIPT','HIGH','PDF contains a JavaScript action marker.');
 if(ascii.includes('/OpenAction')||ascii.includes('/AA'))add('PDF_AUTO_ACTION','HIGH','PDF contains an automatic action marker.');
 if(ascii.includes('/Launch'))add('PDF_LAUNCH_ACTION','CRITICAL','PDF contains a Launch action marker.');
 if(ascii.includes('/EmbeddedFile'))add('PDF_EMBEDDED_FILE','MEDIUM','PDF contains an embedded-file marker.');
 if(/\.(docm|xlsm|pptm)$/.test(name))add('MACRO_ENABLED_OFFICE','HIGH','Macro-enabled Microsoft Office format.');
 if(b.length>=8&&b.subarray(0,8).equals(Buffer.from([0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1])))add('OLE_COMPOUND_DOCUMENT','MEDIUM','Legacy OLE compound document; macro inspection is recommended.');
 if(/powershell|cmd\.exe|wscript|cscript|javascript:|eval\s*\(|fromcharcode/i.test(ascii))add('SUSPICIOUS_SCRIPT_STRING','MEDIUM','Suspicious script/process-launch text was found in file bytes.');
 const score=Math.min(10,signals.reduce((n,x)=>n+(x.severity==='CRITICAL'?4:x.severity==='HIGH'?3:x.severity==='MEDIUM'?2:1),0));
 return {execution:'IN_MEMORY_STATIC_DOCUMENT_SECURITY_SCAN',filename:file.originalname,mimeType:file.mimetype,size:file.size,sha256,verdict:signals.some(x=>x.severity==='CRITICAL')?'HIGH_RISK':signals.length?'SUSPICIOUS':'NO_STATIC_INDICATORS_OBSERVED',riskScore:score,signals,note:'Static triage only; no file is executed and this is not a malware-free guarantee. Upload bytes are held in memory for this request and are not stored by this endpoint.'};
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
app.post('/api/scans/quick',async(req,res)=>{try{
 const session=verifySession(String(req.headers['x-assessment-session']||''));const assessmentId=session.assessmentId;
 const assessments=await db.assessments();const assessment=assessments.find(a=>a.id===assessmentId);if(!assessment)return res.status(404).json({error:'Assessment not found'});
 const t=await validateTarget(String(req.body.targetUrl||''));if(t.url.origin!==session.targetOrigin||assessment.target!==session.targetOrigin)return res.status(403).json({error:'Target is outside the authorized assessment scope'});
 const q=await quickPosture(assessmentId,t);const ev:Evidence={id:crypto.randomUUID(),assessmentId,source:'http',sha256:q.sha256,createdAt:q.completedAt,exitCode:q.error?1:0,stdout:JSON.stringify({status:q.status,headers:q.headers}),stderr:q.error,metadata:{target:t.url.origin,durationMs:q.durationMs,mode:'live-http-posture'}};
 await db.saveEvidence(ev);if(q.findings.length)await db.saveFindings(q.findings);await db.saveAssessment({...assessment,status:q.error?'FAILED':'COMPLETED',evidenceIds:[...assessment.evidenceIds,ev.id],findings:[...assessment.findings,...q.findings]});
 res.json({execution:'REAL_LIVE_HTTP_POSTURE',target:t.url.origin,...q,evidence:{sha256:q.sha256}});
}catch(e:any){res.status(400).json({error:e.message})}});
app.post('/api/documents/security-scan',upload.single('file'),async(req,res)=>{try{const file=req.file;if(!file)return res.status(400).json({error:'Choose a document'});if(file.size>20*1024*1024)return res.status(413).json({error:'20 MB maximum'});res.json(documentSecurityScan(file))}catch(e:any){res.status(400).json({error:e.message})}});
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
    else {const args=tool==='nmap'?['-sT','-sV','--version-light','-Pn','-p-','--open','-oX','-',t.url.hostname]:tool==='wapiti'?['-u',t.url.origin,'--scope','url','--max-scan-time','60','--flush-session']:['-u',t.url.toString(),'--batch','--level=1','--risk=1','--threads=1','--timeout=10','--retries=1','--output-dir=/tmp/sqlmap'];result=await run(tool,args)}
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

app.get('/api/knowledge',(_req,res)=>res.json({modules:knowledgeCatalog(),authoritativeResources:authoritativeResources(),provenance:'Aegis learning modules plus direct authoritative resources. Live intelligence is retrieved from CISA/NIST endpoints.'}));
app.get('/api/cyber-intel',async(req,res)=>{try{res.json(await cyberIntel(req.query.refresh==='1'))}catch(e:any){res.status(502).json({error:e.message})}});
app.get('/api/cve/:cve',async(req,res)=>{try{res.json(await nvdCve(req.params.cve))}catch(e:any){res.status(502).json({error:e.message})}});
app.post('/api/cyber-intel/analyze',async(req,res)=>{try{const item=req.body?.item;if(!item?.title||!item?.source)return res.status(400).json({error:'Intelligence item required'});res.json(await analyzeIntel(item,String(req.body?.context||'')))}catch(e:any){res.status(502).json({error:e.message})}});
app.get('/api/frameworks',(_req,res)=>res.json({frameworks:frameworkCatalog,note:'Mappings are evidence-driven cross-references, not certification or reproduced standards text.'}));
app.post('/api/assessments/:id/documents',upload.array('files',10),async(req,res)=>{
 try{const a=(await db.assessments()).find(x=>x.id===req.params.id);if(!a)return res.status(404).json({error:'Assessment not found'});const files=(req.files||[]) as Express.Multer.File[];if(!files.length)return res.status(400).json({error:'No files supplied'});const denied=/\.(exe|dll|so|dylib|msi|apk|bat|cmd|ps1|sh|scr|com|jar)$/i;const saved=[];for(const file of files){if(denied.test(file.originalname))return res.status(400).json({error:'Executable/script uploads are not accepted'});const id=crypto.randomUUID(),sha256=crypto.createHash('sha256').update(file.buffer).digest('hex'),createdAt=new Date().toISOString();await db.saveDocument({id,assessmentId:a.id,filename:file.originalname.replace(/[\\/\0]/g,'_'),mimeType:file.mimetype||'application/octet-stream',size:file.size,sha256,createdAt,content:file.buffer});await db.saveAudit({id:crypto.randomUUID(),assessmentId:a.id,action:'DOCUMENT_UPLOADED',actor:'operator',createdAt,metadata:{documentId:id,filename:file.originalname,size:file.size,sha256}});saved.push({id,filename:file.originalname,size:file.size,sha256,createdAt})}res.json({stored:true,documents:saved})}catch(e:any){res.status(400).json({error:e.message})}
});
app.get('/api/assessments/:id/documents',async(req,res)=>res.json(await db.documents(req.params.id)));
app.post('/api/assessments/:id/documents/:docId/security-assess',async(req,res)=>{try{
 const a=(await db.assessments()).find(x=>x.id===req.params.id);if(!a)return res.status(404).json({error:'Assessment not found'});
 const d=await db.document(req.params.docId);if(!d||d.assessmentId!==a.id)return res.status(404).json({error:'Document not found'});
 const staticScan=documentSecurityScan({buffer:d.content,originalname:d.filename,mimetype:d.mimeType,size:d.size} as Express.Multer.File);
 const extracted=await extractDocument(d.filename,d.mimeType,d.content);
 const analysis=extracted.text.trim()?await analyzeDocumentText(d.filename,extracted.text):{mode:'NO_TEXT',message:'No extractable text; static file triage still completed.'};
 const createdAt=new Date().toISOString(),findings:any[]=staticScan.signals.map((x:any)=>mapFinding({id:crypto.randomUUID(),assessmentId:a.id,source:'document',title:x.signal.replaceAll('_',' '),description:x.detail,severity:x.severity,cvss:x.severity==='CRITICAL'?9.1:x.severity==='HIGH'?7.5:x.severity==='MEDIUM'?5.3:3.1,asset:d.filename,evidenceHash:d.sha256,createdAt,mappings:{},remediation:'Review the flagged document feature, validate business necessity, remove active content where unnecessary, and rescan before distribution.',status:'OPEN'} as any));
 if(findings.length)await db.saveFindings(findings);
 await db.saveAssessment({...a,status:'COMPLETED',findings:[...a.findings,...findings]});
 await db.saveAudit({id:crypto.randomUUID(),assessmentId:a.id,action:'DOCUMENT_SECURITY_ASSESSED',actor:'operator',createdAt,metadata:{documentId:d.id,sha256:d.sha256,staticSignals:staticScan.signals.length,extraction:extracted.kind,findings:findings.length}});
 res.json({execution:'REAL_DOCUMENT_ASSESSMENT',document:{id:d.id,filename:d.filename,sha256:d.sha256},offensive:{scope:'Static file attack-surface triage; the document is never executed.',...staticScan},defensive:{analysis},grc:{mappedFindings:findings},remediation:findings.map(x=>({finding:x.title,action:x.remediation})),limitations:['Nmap, ZAP, Wapiti and SQLmap test network/web targets and are not valid document scanners. They are intentionally not run against file bytes.']});
}catch(e:any){res.status(400).json({error:e.message})}});
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
app.post('/api/copilot',async(req,res)=>{try{
 const question=String(req.body?.question||'').trim();if(!question||question.length>2000)return res.status(400).json({error:'Question must be between 1 and 2000 characters'});
 const requestedId=String(req.body?.assessmentId||'');const a=requestedId?(await db.assessments()).find(x=>x.id===requestedId):null;
 const fs=a?(await db.findings()).filter(x=>x.assessmentId===a.id):[];
 const answer=await askCopilot(question,String(req.body?.mode||'beginner'),a,fs);
 if(a)await db.saveAudit({id:crypto.randomUUID(),assessmentId:a.id,action:'AI_CHAT_REQUESTED',actor:'operator',createdAt:new Date().toISOString(),metadata:{mode:String(req.body?.mode||'beginner'),findingCount:fs.length}});
 res.json(answer);
}catch(e:any){res.status(502).json({mode:'UNAVAILABLE',error:e.message})}});
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
