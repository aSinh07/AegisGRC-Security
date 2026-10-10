import 'dotenv/config';
import express from 'express';
import dns from 'node:dns/promises';
import net from 'node:net';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { db } from './store.js';
import { scanSource } from './semgrep.js';
import { semgrepFindings, wapitiFindings, nmapFindings } from './parsers.js';
import {nucleiJsonlFindings,trivyJsonFindings,openvasJsonFindings} from './infrastructure-parsers.js';
import {wazuhJsonFindings} from './endpoint-parsers.js';
import {prowlerEvidence} from './prowler.js';
import {scanFilesystemWithTrivy,scanContainerImageWithTrivy} from './trivy.js';
import { assessmentReport } from './reports.js';
import type { Assessment,Evidence } from './models.js';
import { explainFindings } from './ai.js';
import { issueSession, verifySession } from './session.js';
import { renderPdf,renderFrameworkPdf } from './pdf.js';
import { authConfigured, login, logout } from './auth.js';
import { initUsers,beginRegistration,confirmRegistration,userLogin,userSession,userLogout,userRole,verifyUserStepUp,resetPasswordWithTotp,authAttemptAllowed,recordAuthFailure,clearAuthFailures } from './user-auth.js';
import { initGrcReviews,submitGrcReview,listGrcReviews,reviewGrcReport,verifyGrcReview } from './grc-review.js';
import { initGrcCore } from './grc-core.js';
import { initOrganizations,createOrganization,memberships,createScope,listScopes,addMember,setMemberStatus,listMembers,assignAssessmentToOrganization,requireAssessmentAccess,requireOrgPermission } from './grc-organizations.js';
import {organizationAuditReadiness,auditReadinessReportModel} from './grc-readiness.js';
import {readinessPdf,readinessDocx,readinessXlsx} from './readiness-exporters.js';
import { initControlRegistry,createCanonicalControl,createFrameworkRequirement,mapControl,setScopeControl,approveScopeControl,statementOfApplicability,listCanonicalControls,listFrameworkRequirements } from './grc-controls.js';
import { initEvidenceEngine,createEvidenceRequest,submitEvidence,validateEvidence,createTestDefinition,runControlTest,listEvidence,listControlTests } from './grc-evidence.js';
import { initIssueRiskCapa,listIssues,createRiskFromIssue,approveRiskAcceptance,createCapa,submitCapaEvidence,attachRetest,closeCapa,listCapa,listEnterpriseRisks } from './grc-remediation.js';
import { initGrcOperations,myWork,timeline,operationsDashboard,sla,notifications,markNotification } from './grc-operations.js';
import {initGrcAutomation,createAutomationRule,listAutomation,runAutomationRule,runDueAutomations} from './grc-automation.js';
import multer from 'multer';
import { frameworkCatalog,mapFinding } from './grc.js';
import { assessFramework } from './grc-engine.js';
import { analyzeDocumentText } from './document-ai.js';
import { zapReady,zapScan,zapFindings } from './zap.js';
import { askCopilot } from './copilot.js';
import { knowledgeCatalog } from './knowledge.js';
import { extractDocument } from './document-extract.js';
import { parseFindingImport } from './finding-import.js';
import { initFindingReview,reviewFinding,findingReviewHistory } from './finding-review.js';
import { initFindingRisk,slaPolicy,setSlaPolicy,promoteFindingToIssue } from './finding-risk.js';
import { assessmentTrace } from './audit-trace.js';
import { auditDocx,auditXlsx,auditPdf } from './audit-exporters.js';
import { auditPackageModel } from './audit-trace.js';
import {reportSnapshotDigest} from './report-auth.js';
import {scanCoverage,assessmentStatusForCoverage,scannerRunStatus} from './scan-coverage.js';
import {findingFingerprint} from './finding-correlation.js';
import {initAssessmentInventory,createAssessmentAsset,listAssessmentAssets,initializeLayerCoverage,recordLayerResult,assessmentLayerCoverage,reconcileInfrastructureCoverage,reconcileEndpointCoverage,reconcileWebCoverage,reconcileApiCoverage,reconcileSourceCodeCoverage,reconcileDependencyCoverage,reconcileContainerCoverage,activeContainerAsset,reconcileCloudCoverage,activeCloudAsset} from './assessment-inventory.js';
import { cyberIntel,nvdCve,authoritativeResources } from './cyber-intel.js';
import { analyzeIntel } from './intel-ai.js';
import { docxReport,pptxReport,xlsxReport,csvReport,txtReport,reportModel,frameworkReportModel,frameworkDocx,frameworkXlsx,frameworkCsv,frameworkTxt,type ReportKind } from './exporters.js';

const app=express();
app.set('trust proxy',1);
await initUsers();
await initGrcReviews();
await initGrcCore();
await initOrganizations();
await initControlRegistry();
await initEvidenceEngine();
await initIssueRiskCapa();
await initGrcOperations();
await initGrcAutomation();
await initFindingReview();
await initFindingRisk();
await initAssessmentInventory();

app.use(express.json({limit:'1mb'}));
// The HTML shell must never be served stale after a UI release. Static assets can be revalidated.
app.use((req,res,next)=>{
 if(req.path==='/'||req.path==='/index.html'){
  res.setHeader('Cache-Control','no-store, max-age=0, must-revalidate');
  res.setHeader('Pragma','no-cache');
  res.setHeader('Expires','0');
 }
 next();
});
app.use(express.static('public',{etag:true,maxAge:0,setHeaders:(res,filePath)=>{
 if(filePath.endsWith('.html'))res.setHeader('Cache-Control','no-store, max-age=0, must-revalidate');
 else res.setHeader('Cache-Control','public, max-age=0, must-revalidate');
}}));
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:20*1024*1024,files:10}});
function authAttemptKey(req:any,kind:string,identity=''){return kind+':'+String(req.ip||req.socket?.remoteAddress||'unknown')+':'+identity.trim().toLowerCase()}
app.post('/api/auth/login',(_req,res)=>res.status(410).json({error:'Legacy administrator login is disabled. Use the user account sign-in flow.'}));
app.post('/api/auth/register',async(req,res)=>{try{const email=String(req.body?.email||'').trim().toLowerCase(),attemptKey=authAttemptKey(req,'register',email);if(!await authAttemptAllowed(attemptKey,5,30))return res.status(429).json({error:'Too many registration attempts. Try again later.'});const out=await beginRegistration(email,String(req.body?.password||''),{fullName:req.body?.fullName,designation:req.body?.designation,companyName:req.body?.companyName});await clearAuthFailures(attemptKey);res.json(out)}catch(e:any){const email=String(req.body?.email||'').trim().toLowerCase();await recordAuthFailure(authAttemptKey(req,'register',email),5,30);res.status(400).json({error:e.code==='23505'?'Account already exists':e.message})}});
app.post('/api/auth/register/confirm',async(req,res)=>{try{const userId=String(req.body?.userId||''),attemptKey=authAttemptKey(req,'register-confirm',userId);if(!await authAttemptAllowed(attemptKey,8,15))return res.status(429).json({error:'Too many authenticator attempts. Try again later.'});const token=await confirmRegistration(userId,String(req.body?.code||''));if(!token){await recordAuthFailure(attemptKey,8,15);return res.status(401).json({error:'Invalid authenticator code. Check that the server and authenticator device clocks are synchronized.'})}await clearAuthFailures(attemptKey);res.cookie('aegis_user',token,{httpOnly:true,sameSite:'strict',secure:process.env.COOKIE_SECURE==='true',path:'/',maxAge:28800000});res.json({ok:true,authenticated:true,message:'Authenticator verified. You are signed in.'})}catch(e:any){res.status(400).json({error:e.message})}});
app.post('/api/auth/user-login',async(req,res)=>{try{const email=String(req.body?.email||'').trim().toLowerCase(),attemptKey=authAttemptKey(req,'user-login',email);if(!await authAttemptAllowed(attemptKey))return res.status(429).json({error:'Too many authentication attempts. Try again later.'});const token=await userLogin(email,String(req.body?.password||''),String(req.body?.code||''));if(!token){await recordAuthFailure(attemptKey);return res.status(401).json({error:'Invalid email, password or authenticator code'})}await clearAuthFailures(attemptKey);res.cookie('aegis_user',token,{httpOnly:true,sameSite:'strict',secure:process.env.COOKIE_SECURE==='true',path:'/',maxAge:28800000});res.json({ok:true})}catch(e:any){res.status(400).json({error:e.message})}});
app.post('/api/auth/reset-password',async(req,res)=>{try{const email=String(req.body?.email||'').trim().toLowerCase(),attemptKey=authAttemptKey(req,'reset-password',email);if(!await authAttemptAllowed(attemptKey))return res.status(429).json({error:'Too many recovery attempts. Try again later.'});
 const ok=await resetPasswordWithTotp(email,String(req.body?.code||''),String(req.body?.newPassword||''));
 if(!ok){await recordAuthFailure(attemptKey);return res.status(401).json({error:'Password reset could not be verified. Check the email and current authenticator code.'})}
 await clearAuthFailures(attemptKey);res.json({ok:true,message:'Password reset. Existing sessions were revoked; sign in with the new password.'});
}catch(e:any){res.status(400).json({error:e.message})}});
app.post('/api/auth/logout',async(req,res)=>{const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_auth='))?.slice(11)||'';logout(token);const ut=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_user='))?.slice(11)||'';await userLogout(ut);res.setHeader('Set-Cookie',['aegis_auth=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/','aegis_user=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/']);res.json({ok:true})});
app.get('/api/auth/status',async(req,res)=>{const ut=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_user='))?.slice(11)||'';res.json({authenticated:Boolean(await userSession(ut)),configured:true,legacyAdminConfigured:authConfigured()})});
app.use('/api',async(req,res,next)=>{if(['/ready','/health','/integrations','/auth/login','/auth/user-login','/auth/register','/auth/register/confirm','/auth/reset-password','/auth/status'].includes(req.path))return next();const ut=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aegis_user='))?.slice(11)||'';if(!await userSession(ut))return res.status(401).json({error:'User login required'});next()});

// Tenant-safe GRC organization and scope onboarding. Higher-risk GRC modules remain fail-closed.
app.get('/api/grc/organizations',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({organizations:await memberships(u.userId)})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await createOrganization(u.userId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/scopes',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({scopes:await listScopes(u.userId,req.params.orgId)})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/scopes',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await createScope(u.userId,req.params.orgId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/assets',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({assets:await listAssessmentAssets(u.userId,req.params.orgId)})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/assets',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await createAssessmentAsset(u.userId,req.params.orgId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/assessments/:assessmentId/coverage/initialize',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await initializeLayerCoverage(u.userId,req.params.orgId,req.params.assessmentId,req.body?.requirements||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.put('/api/grc/organizations/:orgId/assessments/:assessmentId/coverage/:layer',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await recordLayerResult(u.userId,req.params.orgId,req.params.assessmentId,req.params.layer as any,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/assessments/:assessmentId/coverage',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await assessmentLayerCoverage(u.userId,req.params.orgId,req.params.assessmentId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/members',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await addMember(u.userId,req.params.orgId,String(req.body?.userId||''),String(req.body?.role||'') as any))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.patch('/api/grc/organizations/:orgId/members/:userId/status',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await setMemberStatus(u.userId,req.params.orgId,req.params.userId,String(req.body?.status||'').toUpperCase() as any))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/members',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({members:await listMembers(u.userId,req.params.orgId)})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/controls',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({controls:await listCanonicalControls(u.userId,req.params.orgId)})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/framework-requirements',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({requirements:await listFrameworkRequirements(u.userId,req.params.orgId)})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/control-tests',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({tests:await listControlTests(u.userId,req.params.orgId)})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/controls',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await createCanonicalControl(u.userId,req.params.orgId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/framework-requirements',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await createFrameworkRequirement(u.userId,req.params.orgId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/control-mappings',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await mapControl(u.userId,req.params.orgId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.put('/api/grc/organizations/:orgId/scopes/:scopeId/controls',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await setScopeControl(u.userId,req.params.orgId,req.params.scopeId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/scopes/:scopeId/controls/:scopeControlId/approve',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await approveScopeControl(u.userId,req.params.orgId,req.params.scopeId,req.params.scopeControlId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/scopes/:scopeId/soa',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await statementOfApplicability(u.userId,req.params.orgId,req.params.scopeId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/assessments/:assessmentId/assign',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await assignAssessmentToOrganization(u.userId,req.params.orgId,req.params.assessmentId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/assessments/:assessmentId/finding-import',upload.single('file'),async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});
 const access=await requireAssessmentAccess(u.userId,req.params.assessmentId);
 await requireOrgPermission(u.userId,access.organization_id,'findingReview');
 const file=req.file;if(!file)return res.status(400).json({error:'JSON or SARIF file required'});
 const sha256=crypto.createHash('sha256').update(file.buffer).digest('hex');
 const parsed=parseFindingImport(req.params.assessmentId,file.originalname,file.buffer);
 const evidenceId=crypto.randomUUID(),createdAt=new Date().toISOString();
 const ev:Evidence={id:evidenceId,assessmentId:req.params.assessmentId,source:'finding-import',sha256,createdAt,exitCode:0,
  stdout:'',stderr:'',metadata:{filename:file.originalname.replace(/[\\/\0]/g,'_'),mimeType:file.mimetype,size:file.size,format:parsed.format,importedFindings:parsed.findings.length}};
 const audit={id:crypto.randomUUID(),assessmentId:req.params.assessmentId,action:'FINDINGS_IMPORTED',actor:u.email,createdAt,metadata:{evidenceId,sha256,format:parsed.format,count:parsed.findings.length}};
 await db.saveFindingImport(ev,parsed.findings,audit);
 res.status(201).json({imported:true,evidence:{id:evidenceId,sha256,hashComputedByServer:true,integrityStatus:'HASHED_AT_INGEST'},format:parsed.format,count:parsed.findings.length,warnings:parsed.warnings,findings:parsed.findings});
 }catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/assessments/:assessmentId/prowler-report',upload.single('report'),async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const access=await requireAssessmentAccess(u.userId,req.params.assessmentId);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');if(!req.file)return res.status(400).json({error:'Prowler JSON report required'});const assetId=String(req.body?.assetId||''),asset=await activeCloudAsset(u.userId,access.organization_id,assetId);if(!asset)return res.status(400).json({error:'Active cloud account asset required'});const raw=req.file.buffer.toString('utf8'),provider=String(req.body?.provider||asset.metadata?.provider||'').toUpperCase();if(!['AWS','AZURE','GCP'].includes(provider))return res.status(400).json({error:'Cloud provider must be AWS, AZURE, or GCP'});const scanCompleted=String(req.body?.scanCompleted||'').toLowerCase()==='true';if(!scanCompleted)return res.status(422).json({error:'Completed Prowler scan attestation required'});const parsed=prowlerEvidence(raw,{assetId,accountKey:asset.asset_key,provider,scanCompleted:true,startedAt:req.body?.startedAt,completedAt:req.body?.completedAt});const evidence:Evidence={id:crypto.randomUUID(),assessmentId:req.params.assessmentId,source:'prowler',sha256:parsed.sha256,exitCode:0,stdout:raw,stderr:'',metadata:parsed.metadata,createdAt:new Date().toISOString()};const findings=parsed.findings.filter(x=>x.status==='FAIL').map(x=>({id:crypto.randomUUID(),assessmentId:req.params.assessmentId,source:'prowler' as const,title:x.title,description:x.description,severity:(['LOW','MEDIUM','HIGH','CRITICAL'].includes(x.severity)?x.severity:'INFO') as any,asset:asset.asset_key,evidenceHash:parsed.sha256,createdAt:new Date().toISOString(),mappings:{},confidence:'SCANNER_REPORTED' as const,externalIds:{scannerId:['PROWLER',x.checkId,x.resource||''].filter(Boolean).join('|')}}));const audit={id:crypto.randomUUID(),assessmentId:req.params.assessmentId,action:'PROWLER_CLOUD_EVIDENCE_INGESTED',actor:u.userId,createdAt:new Date().toISOString(),metadata:{assetId,provider,evidenceHash:parsed.sha256,findingCount:findings.length}};await db.saveFindingImport(evidence,findings,audit);res.status(201).json({evidenceHash:parsed.sha256,findings:findings.length,provider,assetId})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/assessments/:assessmentId/cloud/reconcile',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await reconcileCloudCoverage(u.userId,req.params.orgId,req.params.assessmentId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/assessments/:assessmentId/container/reconcile',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await reconcileContainerCoverage(u.userId,req.params.orgId,req.params.assessmentId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/assessments/:assessmentId/dependencies/reconcile',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await reconcileDependencyCoverage(u.userId,req.params.orgId,req.params.assessmentId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/assessments/:assessmentId/source-code/reconcile',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await reconcileSourceCodeCoverage(u.userId,req.params.orgId,req.params.assessmentId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/assessments/:assessmentId/api/reconcile',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await reconcileApiCoverage(u.userId,req.params.orgId,req.params.assessmentId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/assessments/:assessmentId/web/reconcile',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await reconcileWebCoverage(u.userId,req.params.orgId,req.params.assessmentId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/assessments/:assessmentId/endpoint/reconcile',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await reconcileEndpointCoverage(u.userId,req.params.orgId,req.params.assessmentId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/assessments/:assessmentId/infrastructure/reconcile',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await reconcileInfrastructureCoverage(u.userId,req.params.orgId,req.params.assessmentId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/assessments/:assessmentId/wazuh-report',upload.single('file'),async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const access=await requireAssessmentAccess(u.userId,req.params.assessmentId);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');const file=req.file;if(!file)return res.status(400).json({error:'Wazuh JSON evidence required'});
 const raw=file.buffer.toString('utf8'),sha256=crypto.createHash('sha256').update(file.buffer).digest('hex'),createdAt=new Date().toISOString(),findings=wazuhJsonFindings(req.params.assessmentId,access.target,sha256,raw);
 const ev:Evidence={id:crypto.randomUUID(),assessmentId:req.params.assessmentId,source:'wazuh',sha256,createdAt,exitCode:0,stdout:raw,stderr:'',metadata:{filename:file.originalname.replace(/[\\/\0]/g,'_'),size:file.size,format:'WAZUH_JSON',findingCount:findings.length}};
 await db.saveFindingImport(ev,findings,{id:crypto.randomUUID(),assessmentId:req.params.assessmentId,action:'WAZUH_EVIDENCE_INGESTED',actor:u.userId,createdAt,metadata:{evidenceId:ev.id,sha256,findingCount:findings.length}});
 res.status(201).json({ingested:true,evidence:{id:ev.id,sha256},findingCount:findings.length,findings});
}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/assessments/:assessmentId/openvas-report',upload.single('file'),async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const access=await requireAssessmentAccess(u.userId,req.params.assessmentId);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');
 const file=req.file;if(!file)return res.status(400).json({error:'Greenbone/OpenVAS JSON report required'});const raw=file.buffer.toString('utf8');const sha256=crypto.createHash('sha256').update(file.buffer).digest('hex'),createdAt=new Date().toISOString();
 const findings=openvasJsonFindings(req.params.assessmentId,access.target,sha256,raw);if(!findings.length)return res.status(422).json({error:'Report contained no parseable OpenVAS vulnerability results; assessment coverage was not advanced'});
 const ev:Evidence={id:crypto.randomUUID(),assessmentId:req.params.assessmentId,source:'openvas',sha256,createdAt,exitCode:0,stdout:raw,stderr:'',metadata:{filename:file.originalname.replace(/[\\/\0]/g,'_'),size:file.size,format:'GREENBONE_JSON',findingCount:findings.length}};
 const audit={id:crypto.randomUUID(),assessmentId:req.params.assessmentId,action:'OPENVAS_REPORT_INGESTED',actor:u.userId,createdAt,metadata:{evidenceId:ev.id,sha256,findingCount:findings.length}};
 await db.saveFindingImport(ev,findings,audit);res.status(201).json({ingested:true,assessmentId:req.params.assessmentId,evidence:{id:ev.id,sha256},findingCount:findings.length,findings});
}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/assessments/:assessmentId/findings/:findingId/review',async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});
 const result=await reviewFinding(u.userId,req.params.assessmentId,req.params.findingId,req.body||{});
 res.json(result);
 }catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/assessments/:assessmentId/findings/:findingId/reviews',async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});
 res.json({reviews:await findingReviewHistory(u.userId,req.params.assessmentId,req.params.findingId)});
 }catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/sla-policy',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({policy:await slaPolicy(u.userId,req.params.orgId),note:'Organization policy; defaults are configurable operational targets, not regulatory promises.'})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.put('/api/grc/organizations/:orgId/sla-policy',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({policy:await setSlaPolicy(u.userId,req.params.orgId,req.body||{})})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/assessments/:assessmentId/findings/:findingId/issue',async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});
 const issue=await promoteFindingToIssue(u.userId,req.params.orgId,req.params.assessmentId,req.params.findingId,req.body||{});
 res.status(201).json({issue});
 }catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/assessments/:assessmentId/audit-package.:format',async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});
 const model=auditPackageModel(await assessmentTrace(u.userId,req.params.assessmentId));
 const reviewId=String(req.query.reviewId||'');
 if(!reviewId)return res.status(409).json({error:'Approved GRC review is required for authenticated audit export'});
 const verification=await verifyGrcReview(reviewId,reportSnapshotDigest(model));
 if(verification.assessmentId&&verification.assessmentId!==req.params.assessmentId)return res.status(404).json({error:'Review not found for assessment'});
 if(!verification.valid)return res.status(409).json({error:'Approved report snapshot is missing, invalid, or stale',verification});
 const format=String(req.params.format||'').toLowerCase();
 let body:Buffer,contentType:string,ext:string;
 if(format==='docx'){body=await auditDocx(model);contentType='application/vnd.openxmlformats-officedocument.wordprocessingml.document';ext='docx'}
 else if(format==='xlsx'){body=auditXlsx(model);contentType='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';ext='xlsx'}
 else if(format==='pdf'){body=await auditPdf(model);contentType='application/pdf';ext='pdf'}
 else return res.status(400).json({error:'Audit package format must be pdf, docx or xlsx'});
 res.setHeader('Content-Type',contentType);res.setHeader('Content-Disposition','attachment; filename="AegisGRC-Audit-'+req.params.assessmentId+'.'+ext+'"');res.send(body);
 }catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/assessments/:assessmentId/traceability',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await assessmentTrace(u.userId,req.params.assessmentId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/assessments/:assessmentId/correlated-findings',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});await requireAssessmentAccess(u.userId,req.params.assessmentId);const {correlateFindings,correlationSummary}=await import('./finding-correlation.js');const fs=await db.findingsForAssessment(req.params.assessmentId);res.json({assessmentId:req.params.assessmentId,summary:correlationSummary(fs),groups:correlateFindings(fs),assurance:'Advisory correlation; original evidence and findings remain immutable inputs and analyst confirmation is required.'})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/evidence',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({evidence:await listEvidence(u.userId,req.params.orgId)})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/evidence-requests',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await createEvidenceRequest(u.userId,req.params.orgId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/evidence-requests/:requestId/versions',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await submitEvidence(u.userId,req.params.orgId,req.params.requestId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/evidence-requests/:requestId/versions/:versionId/validate',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await validateEvidence(u.userId,req.params.orgId,req.params.requestId,req.params.versionId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/control-tests',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await createTestDefinition(u.userId,req.params.orgId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/control-tests/:testId/run',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await runControlTest(u.userId,req.params.orgId,req.params.testId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/issues',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({issues:await listIssues(u.userId,req.params.orgId)})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/risks',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({risks:await listEnterpriseRisks(u.userId,req.params.orgId)})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/issues/:issueId/risks',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await createRiskFromIssue(u.userId,req.params.orgId,req.params.issueId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/risks/:riskId/accept',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await approveRiskAcceptance(u.userId,req.params.orgId,req.params.riskId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/capa',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({capa:await listCapa(u.userId,req.params.orgId)})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/issues/:issueId/capa',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await createCapa(u.userId,req.params.orgId,req.params.issueId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/capa/:capaId/evidence/:evidenceVersionId',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await submitCapaEvidence(u.userId,req.params.orgId,req.params.capaId,req.params.evidenceVersionId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/capa/:capaId/retest/:testRunId',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await attachRetest(u.userId,req.params.orgId,req.params.capaId,req.params.testRunId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/capa/:capaId/close',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await closeCapa(u.userId,req.params.orgId,req.params.capaId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/notifications',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await notifications(u.userId,req.params.orgId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.patch('/api/grc/organizations/:orgId/notifications/:id',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await markNotification(u.userId,req.params.orgId,req.params.id,String(req.body?.status||'').toUpperCase()))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/my-work',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await myWork(u.userId,req.params.orgId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/scopes/:scopeId/audit-readiness',async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});
 res.json(await organizationAuditReadiness(u.userId,req.params.orgId,req.params.scopeId));
 }catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/scopes/:scopeId/audit-readiness.:format',async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});
 const model=auditReadinessReportModel(await organizationAuditReadiness(u.userId,req.params.orgId,req.params.scopeId));
 const format=String(req.params.format||'').toLowerCase();let body:Buffer,contentType:string,ext:string;
 if(format==='pdf'){body=await readinessPdf(model);contentType='application/pdf';ext='pdf'}
 else if(format==='docx'){body=await readinessDocx(model);contentType='application/vnd.openxmlformats-officedocument.wordprocessingml.document';ext='docx'}
 else if(format==='xlsx'){body=readinessXlsx(model);contentType='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';ext='xlsx'}
 else return res.status(400).json({error:'Audit readiness format must be pdf, docx or xlsx'});
 res.setHeader('Content-Type',contentType);res.setHeader('Content-Disposition','attachment; filename="AegisGRC-Readiness-'+req.params.scopeId+'.'+ext+'"');res.send(body);
 }catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/internal/grc/automation/run-due',async(req,res)=>{try{
 const expected=String(process.env.GRC_AUTOMATION_SECRET||'');const supplied=String(req.get('x-aegis-automation-secret')||'');
 if(expected.length<32)return res.status(503).json({error:'GRC automation scheduler is not configured'});
 const a=Buffer.from(expected),b=Buffer.from(supplied);
 if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).json({error:'Invalid automation scheduler credential'});
 const results=await runDueAutomations(Number(req.body?.limit||50));
 res.json({executed:results.length,results});
 }catch(e:any){res.status(500).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/automation',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await listAutomation(u.userId,req.params.orgId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/automation/rules',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.status(201).json(await createAutomationRule(u.userId,req.params.orgId,req.body||{}))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/organizations/:orgId/automation/rules/:ruleId/run',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await runAutomationRule(u.userId,req.params.orgId,req.params.ruleId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/dashboard',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await operationsDashboard(u.userId,req.params.orgId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/sla',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await sla(u.userId,req.params.orgId))}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/grc/organizations/:orgId/timeline/:type/:recordId',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json({events:await timeline(u.userId,req.params.orgId,req.params.type,req.params.recordId)})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.use('/api/grc',(_req,res)=>res.status(503).json({error:'This GRC module remains gated until tenant authorization and workflow enforcement are complete',code:'GRC_MODULE_IMPLEMENTATION_PENDING'}));

const PORT=Number(process.env.PORT||8080);
const TIMEOUT=Number(process.env.SCAN_TIMEOUT_MS||90000);
const MAX=Number(process.env.MAX_OUTPUT_BYTES||1048576);

async function currentUser(req:any){const ut=(req.headers.cookie||'').split(';').map((x:string)=>x.trim()).find((x:string)=>x.startsWith('aegis_user='))?.slice(11)||'';return userSession(ut)}
async function reportAuthorized(req:any){const u=await currentUser(req);if(!u)return {ok:false,reason:'USER_SESSION_MISSING'};const attemptKey=authAttemptKey(req,'report-step-up',u.userId);if(!await authAttemptAllowed(attemptKey,6,15))return {ok:false,reason:'STEP_UP_RATE_LIMITED'};const v=await verifyUserStepUp(u.userId,String(req.headers['x-report-password']||''),String(req.headers['x-report-totp']||''));if(!v.ok){await recordAuthFailure(attemptKey,6,15);return {ok:false,reason:v.reason}}await clearAuthFailures(attemptKey);return {ok:true,mode:'user'}}


type Tool='nmap'|'wapiti'|'sqlmap'|'zap'|'nuclei'|'all';
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
  if(u.port&&u.port!=='80'&&u.port!=='443') throw new Error('Only standard HTTP(S) target ports are allowed');
  if(net.isIP(u.hostname)&&blocked(u.hostname)) throw new Error('Private, local, reserved or link-local targets are blocked');
  const records=await dns.lookup(u.hostname,{all:true,verbatim:true});
  if(!records.length) throw new Error('Target did not resolve');
  if(records.some(r=>blocked(r.address))) throw new Error('Private, local, reserved or link-local targets are blocked');
  return {url:u,addresses:[...new Set(records.map(r=>r.address))]};
}
async function revalidateTarget(t:{url:URL,addresses:string[]}){
 const records=await dns.lookup(t.url.hostname,{all:true,verbatim:true});
 if(!records.length||records.some(r=>blocked(r.address)))throw new Error('Target DNS changed to a blocked address');
 const addresses=[...new Set(records.map(r=>r.address))];
 if(addresses.some(ip=>!t.addresses.includes(ip)))throw new Error('Target DNS changed after authorization; scan refused');
 return {...t,addresses};
}
async function quickPosture(assessmentId:string,t:{url:URL,addresses:string[]}){
 t=await revalidateTarget(t);
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
 // EICAR is a safe industry-standard anti-malware test signature. Detect the canonical
 // ASCII sequence without executing it. Split literals keep this source file itself
 // from being accidentally flagged by endpoint security during build/deploy.
 const eicarParts=['X5O!P%@AP','[4',String.fromCharCode(92),'PZX54(P^)7CC)7}' , '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!' , '$H+H*'];
 const eicarCanonical=eicarParts.join('');
 if(ascii.includes(eicarCanonical))add('EICAR_TEST_SIGNATURE','HIGH','Canonical EICAR anti-malware test signature detected. EICAR is a safe test artifact, not proof of a real malware infection.');
 if(/EICAR[-_ ]?(STANDARD[-_ ]?)?(ANTIVIRUS[-_ ]?)?TEST/i.test(ascii)&&!ascii.includes(eicarCanonical))add('EICAR_REFERENCE_ONLY','INFO','Document references EICAR terminology but does not contain the canonical EICAR test signature.');
 if(/ignore previous instructions|reveal system prompt|system override directive|administrative bypass/i.test(ascii))add('DOCUMENT_PROMPT_INJECTION_TEXT','MEDIUM','Untrusted document text contains prompt-injection or instruction-override language. Treat it as data and never as tool authorization.');
 if(/(?:api[_ -]?key|secret|password|token)\s*[:=]\s*[A-Za-z0-9_\-]{12,}/i.test(ascii))add('POSSIBLE_SECRET_PATTERN','MEDIUM','Credential-like or secret-like text was observed. Validate whether it is synthetic or sensitive before escalation.');
 const score=Math.min(10,signals.reduce((n,x)=>n+(x.severity==='CRITICAL'?4:x.severity==='HIGH'?3:x.severity==='MEDIUM'?2:1),0));
 return {execution:'IN_MEMORY_STATIC_DOCUMENT_SECURITY_SCAN',filename:file.originalname,mimeType:file.mimetype,size:file.size,sha256,verdict:signals.some(x=>x.severity==='CRITICAL')?'HIGH_RISK':signals.length?'SUSPICIOUS':'NO_STATIC_INDICATORS_OBSERVED',riskScore:score,signals,note:'Static triage only; no file is executed and this is not a malware-free guarantee. Upload bytes are held in memory for this request and are not stored by this endpoint.'};
}
function run(cmd:string,args:string[]){
  return new Promise<{stdout:string;stderr:string;exitCode:number|null;durationMs:number;timedOut:boolean;stdoutTruncated:boolean;stderrTruncated:boolean}>((resolve,reject)=>{
    const started=Date.now();let out='',err='',done=false,timedOut=false,stdoutTruncated=false,stderrTruncated=false;
    const child=spawn(cmd,args,{shell:false,stdio:['ignore','pipe','pipe']});
    const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL')},TIMEOUT);
    const append=(base:string,chunk:Buffer,which:'stdout'|'stderr')=>{const next=base+chunk.toString();if(next.length>MAX){if(which==='stdout')stdoutTruncated=true;else stderrTruncated=true}return next.slice(0,MAX)};
    child.stdout.on('data',(d:Buffer)=>out=append(out,d,'stdout'));
    child.stderr.on('data',(d:Buffer)=>err=append(err,d,'stderr'));
    child.on('error',e=>{if(!done){done=true;clearTimeout(timer);reject(e)}});
    child.on('close',code=>{if(!done){done=true;clearTimeout(timer);resolve({stdout:out,stderr:err,exitCode:code,durationMs:Date.now()-started,timedOut,stdoutTruncated,stderrTruncated})}});
  });
}
app.get('/api/ready',async(_req,res)=>{try{res.json(await db.ready())}catch(e:any){res.status(503).json({ok:false,error:e.message})}});
app.get('/api/health',async(_req,res)=>{
 const check=async(cmd:string,args:string[])=>{try{const r=await run(cmd,args);return {available:r.exitCode===0,version:(r.stdout||r.stderr).split('\n')[0]}}catch(e:any){return {available:false,error:e.message}}};
 const [nmap,wapiti,semgrep,sqlmap,tshark,nuclei,trivy]=await Promise.all([check('nmap',['--version']),check('wapiti',['--version']),check('semgrep',['--version']),check('sqlmap',['--version']),check('tshark',['--version']),check('nuclei',['-version']),check('trivy',['--version'])]);
 let zap:any={available:false};try{zap={available:await zapReady()}}catch(e:any){zap={available:false,error:e.message}}
 const tools={nmap,zap,wapiti,semgrep,sqlmap,tshark,nuclei,trivy};const coreReady=nmap.available&&zap.available&&wapiti.available&&sqlmap.available&&nuclei.available;
 res.status(coreReady?200:503).json({ok:coreReady,service:'AegisGRC Security',coreUrlAssessmentReady:coreReady,tools,note:'Availability confirms executable/service readiness only; finding correctness depends on scanner evidence and parser interpretation.'});
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
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const assessment=await db.assessmentForUser(u.userId,assessmentId);if(!assessment)return res.status(404).json({error:'Assessment not found'});const access=await requireAssessmentAccess(u.userId,assessmentId);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');
 const t=await validateTarget(String(req.body.targetUrl||''));if(t.url.origin!==session.targetOrigin||assessment.target!==session.targetOrigin)return res.status(403).json({error:'Target is outside the authorized assessment scope'});
 const q=await quickPosture(assessmentId,t);const ev:Evidence={id:crypto.randomUUID(),assessmentId,source:'http',sha256:q.sha256,createdAt:q.completedAt,exitCode:q.error?1:0,stdout:JSON.stringify({status:q.status,headers:q.headers}),stderr:q.error,metadata:{target:t.url.origin,durationMs:q.durationMs,mode:'live-http-posture'}};
 await db.saveEvidence(ev);if(q.findings.length)await db.saveFindings(q.findings);await db.saveAssessment({...assessment,status:q.error?'FAILED':'COMPLETED',evidenceIds:[...assessment.evidenceIds,ev.id],findings:[...assessment.findings,...q.findings]});
 res.json({execution:'REAL_LIVE_HTTP_POSTURE',target:t.url.origin,...q,evidence:{sha256:q.sha256}});
}catch(e:any){res.status(400).json({error:e.message})}});
app.post('/api/scans/trivy',async(req,res)=>{try{
 const session=verifySession(String(req.headers['x-assessment-session']||''));const assessmentId=session.assessmentId;
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});
 const assessment=await db.assessmentForUser(u.userId,assessmentId);if(!assessment)return res.status(404).json({error:'Assessment not found'});
 const access=await requireAssessmentAccess(u.userId,assessmentId);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');
 const sourcePath=String(req.body?.sourcePath||'/workspace/source');const result=await scanFilesystemWithTrivy(sourcePath);
 const completedAt=new Date().toISOString();const ev:Evidence={id:crypto.randomUUID(),assessmentId,source:'trivy',sha256:result.evidence.sha256,createdAt:completedAt,exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,metadata:{sourcePath,durationMs:result.durationMs,mode:'filesystem-vulnerability-misconfiguration'}};
 await db.saveEvidence(ev);const findings=result.exitCode===0?trivyJsonFindings(assessmentId,sourcePath,ev.sha256,result.stdout):[];if(findings.length)await db.saveFindings(findings);
 const scanStatus=result.exitCode===0?'SUCCEEDED':'FAILED';await db.saveAssessment({...assessment,evidenceIds:[...assessment.evidenceIds,ev.id],findings:[...assessment.findings,...findings]});
 res.status(result.exitCode===0?200:502).json({execution:'REAL_TRIVY_FILESYSTEM_SCAN',scanStatus,assessmentId,sourcePath,evidence:{sha256:ev.sha256},findings});
}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/documents/security-scan',upload.single('file'),async(req,res)=>{try{const file=req.file;if(!file)return res.status(400).json({error:'Choose a document'});if(file.size>20*1024*1024)return res.status(413).json({error:'20 MB maximum'});res.json(documentSecurityScan(file))}catch(e:any){res.status(400).json({error:e.message})}});
async function executeRealTool(tool:'nmap'|'wapiti'|'sqlmap'|'zap'|'nuclei',assessmentId:string,t:{url:URL,addresses:string[]}){
 t=await revalidateTarget(t);
 const startedAt=new Date().toISOString();let result:{stdout:string;stderr:string;exitCode:number|null;durationMs:number;timedOut:boolean;stdoutTruncated:boolean;stderrTruncated:boolean};let zapAlerts:any[]=[];
 if(tool==='zap'){const z0=Date.now();zapAlerts=await zapScan(t.url.origin);result={stdout:JSON.stringify(zapAlerts),stderr:'',exitCode:0,durationMs:Date.now()-z0,timedOut:false,stdoutTruncated:false,stderrTruncated:false}}
 else {const args=tool==='nmap'?['-sT','-sV','--version-light','-Pn','-p-','--open','-oX','-',t.url.hostname]:tool==='wapiti'?['-u',t.url.origin,'--scope','url','--max-scan-time','60','--flush-session']:tool==='nuclei'?['-u',t.url.origin,'-jsonl','-silent','-severity','info,low,medium,high,critical','-timeout','10','-retries','1']:['-u',t.url.toString(),'--batch','--level=1','--risk=1','--threads=1','--timeout=10','--retries=1','--output-dir=/tmp/sqlmap'];result=await run(tool,args)}
 const completedAt=new Date().toISOString(),evidence=JSON.stringify({tool,target:t.url.origin,startedAt,completedAt,...result}),sha256=crypto.createHash('sha256').update(evidence).digest('hex');
 const ev:Evidence={id:crypto.randomUUID(),assessmentId,source:tool,sha256,createdAt:completedAt,exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,metadata:{target:t.url.origin,resolvedAddresses:t.addresses,durationMs:result.durationMs,timedOut:result.timedOut,stdoutTruncated:result.stdoutTruncated,stderrTruncated:result.stderrTruncated}};
 await db.saveEvidence(ev);
 const findings=tool==='wapiti'?wapitiFindings(assessmentId,t.url.origin,sha256,result.stdout):tool==='nmap'?nmapFindings(assessmentId,t.url.origin,sha256,result.stdout):tool==='nuclei'?nucleiJsonlFindings(assessmentId,t.url.origin,sha256,result.stdout):tool==='zap'?zapFindings(assessmentId,t.url.origin,sha256,zapAlerts):[];
 if(findings.length)await db.saveFindings(findings);
 await db.saveAudit({id:crypto.randomUUID(),assessmentId,action:'REAL_SCAN_COMPLETED',actor:'operator',createdAt:completedAt,metadata:{tool,exitCode:result.exitCode,evidenceHash:sha256,durationMs:result.durationMs,timedOut:result.timedOut,stdoutTruncated:result.stdoutTruncated,stderrTruncated:result.stderrTruncated,findingCount:findings.length}});
 console.log('\n[AEGIS REAL SCAN] '+tool.toUpperCase()+' | '+t.url.origin+' | exit='+result.exitCode+' | '+result.durationMs+'ms | findings='+findings.length);
 console.log('[AEGIS EVIDENCE] SHA-256 '+sha256);
 for(const x of findings)console.log('[AEGIS FINDING] ['+x.severity+'] '+x.title+' | '+x.description+' | evidence='+x.evidenceHash);
 if(result.stderr)console.log('[AEGIS STDERR] '+result.stderr.slice(0,4000));
 return {tool,startedAt,completedAt,...result,evidence:{sha256},findings};
}
app.post('/api/grc/assessments/:assessmentId/findings/:findingId/wazuh-retest',upload.single('file'),async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const access=await requireAssessmentAccess(u.userId,req.params.assessmentId);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');const original=(await db.findingsForAssessment(req.params.assessmentId)).find(x=>x.id===req.params.findingId);if(!original)return res.status(404).json({error:'Finding not found'});if(original.source!=='wazuh')return res.status(409).json({error:'Wazuh retest endpoint only accepts Wazuh findings'});
 const file=req.file;if(!file)return res.status(400).json({error:'Wazuh retest JSON evidence required'});const raw=file.buffer.toString('utf8'),sha256=crypto.createHash('sha256').update(file.buffer).digest('hex'),createdAt=new Date().toISOString(),findings=wazuhJsonFindings(req.params.assessmentId,original.asset,sha256,raw),fingerprint=original.fingerprint||findingFingerprint(original),stillPresent=findings.some(x=>(x.fingerprint||findingFingerprint(x))===fingerprint);
 const ev:Evidence={id:crypto.randomUUID(),assessmentId:req.params.assessmentId,source:'wazuh',sha256,createdAt,exitCode:0,stdout:raw,stderr:'',metadata:{filename:file.originalname.replace(/[\\/\0]/g,'_'),format:'WAZUH_JSON_RETEST',originalFindingId:original.id,originalFingerprint:fingerprint,stillPresent}};
 await db.saveEvidence(ev);if(findings.length)await db.saveFindings(findings);await db.saveFindingRetest({id:crypto.randomUUID(),findingId:original.id,assessmentId:req.params.assessmentId,evidenceId:ev.id,fingerprint,scannerSource:'wazuh',scannerId:original.externalIds?.scannerId||null,createdBy:u.userId},{id:crypto.randomUUID(),assessmentId:req.params.assessmentId,action:'TARGETED_RETEST_COMPLETED',actor:u.userId,createdAt,metadata:{findingId:original.id,fingerprint,source:'wazuh',evidenceId:ev.id,evidenceHash:sha256,stillPresent}});
 res.status(stillPresent?409:200).json({execution:'IMPORTED_WAZUH_TARGETED_RETEST',findingId:original.id,fingerprint,evidenceId:ev.id,evidence:{sha256},stillPresent,findings});
}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/grc/assessments/:assessmentId/findings/:findingId/openvas-retest',upload.single('file'),async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const access=await requireAssessmentAccess(u.userId,req.params.assessmentId);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');
 const original=(await db.findingsForAssessment(req.params.assessmentId)).find(x=>x.id===req.params.findingId);if(!original)return res.status(404).json({error:'Finding not found'});if(original.source!=='openvas')return res.status(409).json({error:'OpenVAS retest endpoint only accepts OpenVAS findings'});
 const file=req.file;if(!file)return res.status(400).json({error:'Greenbone/OpenVAS retest JSON report required'});const raw=file.buffer.toString('utf8'),sha256=crypto.createHash('sha256').update(file.buffer).digest('hex'),createdAt=new Date().toISOString();
 const findings=openvasJsonFindings(req.params.assessmentId,original.asset,sha256,raw);const fingerprint=original.fingerprint||findingFingerprint(original),stillPresent=findings.some(x=>(x.fingerprint||findingFingerprint(x))===fingerprint);
 const ev:Evidence={id:crypto.randomUUID(),assessmentId:req.params.assessmentId,source:'openvas',sha256,createdAt,exitCode:0,stdout:raw,stderr:'',metadata:{filename:file.originalname.replace(/[\\/\0]/g,'_'),size:file.size,format:'GREENBONE_JSON_RETEST',findingCount:findings.length,originalFindingId:original.id,originalFingerprint:fingerprint,stillPresent}};
 await db.saveEvidence(ev);if(findings.length)await db.saveFindings(findings);
 const audit={id:crypto.randomUUID(),assessmentId:req.params.assessmentId,action:'TARGETED_RETEST_COMPLETED',actor:u.userId,createdAt,metadata:{findingId:original.id,fingerprint,source:'openvas',evidenceId:ev.id,evidenceHash:sha256,stillPresent,findingCount:findings.length}};
 await db.saveFindingRetest({id:crypto.randomUUID(),findingId:original.id,assessmentId:req.params.assessmentId,evidenceId:ev.id,fingerprint,scannerSource:'openvas',scannerId:original.externalIds?.scannerId||null,createdBy:u.userId},audit);
 res.status(stillPresent?409:200).json({execution:'IMPORTED_OPENVAS_TARGETED_RETEST',findingId:original.id,fingerprint,evidenceId:ev.id,evidence:{sha256},stillPresent,findings});
}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/findings/:findingId/retest',async(req,res)=>{try{
 const session=verifySession(String(req.headers['x-assessment-session']||'')),assessmentId=session.assessmentId;
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});
 const assessment=await db.assessmentForUser(u.userId,assessmentId);if(!assessment)return res.status(404).json({error:'Assessment not found'});
 const access=await requireAssessmentAccess(u.userId,assessmentId);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');
 const original=(await db.findingsForAssessment(assessmentId)).find(x=>x.id===req.params.findingId);if(!original)return res.status(404).json({error:'Finding not found'});
 if(!['nmap','wapiti','zap','nuclei'].includes(original.source))return res.status(409).json({error:'This finding source does not yet support deterministic server-side retest'});
 const fingerprint=original.fingerprint||findingFingerprint(original);
 const t=await validateTarget(assessment.target);if(t.url.origin!==session.targetOrigin)return res.status(403).json({error:'Assessment target is outside the authorized session scope'});
 const rr:any=await executeRealTool(original.source as 'nmap'|'wapiti'|'zap'|'nuclei',assessmentId,t);
 const records=await db.evidenceForAssessment(assessmentId),ev=records.find(x=>x.sha256===rr.evidence.sha256);
 if(!ev)throw new Error('Retest evidence persistence failed');
 const retestAudit={id:crypto.randomUUID(),assessmentId,action:'TARGETED_RETEST_COMPLETED',actor:u.userId,createdAt:new Date().toISOString(),metadata:{findingId:original.id,fingerprint,source:original.source,evidenceId:ev.id,evidenceHash:ev.sha256,exitCode:rr.exitCode}};
 await db.saveFindingRetest({id:crypto.randomUUID(),findingId:original.id,assessmentId,evidenceId:ev.id,fingerprint,scannerSource:original.source,scannerId:original.externalIds?.scannerId||null,createdBy:u.userId},retestAudit);
 return res.status(rr.exitCode===0?200:502).json({execution:'TARGETED_RETEST',findingId:original.id,fingerprint,source:original.source,evidenceId:ev.id,evidence:{sha256:ev.sha256},exitCode:rr.exitCode,findings:rr.findings});
}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.post('/api/scans/run',async(req,res)=>{
  try{
    const session=verifySession(String(req.headers['x-assessment-session']||''));
    const assessmentId=session.assessmentId;
    const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const assessment=await db.assessmentForUser(u.userId,assessmentId);
    if(!assessment) return res.status(404).json({error:'Assessment not found; enter through the authorization gate first'});
    const access=await requireAssessmentAccess(u.userId,assessmentId);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');
    const tool=String(req.body.tool||'') as Tool;
    if(!['nmap','wapiti','sqlmap','zap','nuclei','all'].includes(tool)) return res.status(400).json({error:'Tool is not enabled for real execution'});
    const t=await validateTarget(String(req.body.targetUrl||''));
    if(t.url.origin!==session.targetOrigin || assessment.target!==session.targetOrigin) return res.status(403).json({error:'Target is outside the authorized assessment scope'});
    if(tool==='all'){
      console.log('\n[AEGIS FULL ASSESSMENT] START '+t.url.origin+' assessment='+assessmentId);
      const q=await quickPosture(assessmentId,t);const qev:Evidence={id:crypto.randomUUID(),assessmentId,source:'http',sha256:q.sha256,createdAt:q.completedAt,exitCode:q.error?1:0,stdout:JSON.stringify({status:q.status,headers:q.headers}),stderr:q.error,metadata:{target:t.url.origin,durationMs:q.durationMs,mode:'live-http-posture'}};await db.saveEvidence(qev);if(q.findings.length)await db.saveFindings(q.findings);console.log('[AEGIS REAL SCAN] HTTP POSTURE | findings='+q.findings.length+' | evidence='+q.sha256);
      const runs:any[]=[];for(const name of ['nmap','zap','wapiti','sqlmap','nuclei'] as const){try{const rr:any=await executeRealTool(name,assessmentId,t);runs.push({...rr,tool:name,status:scannerRunStatus(rr.exitCode,undefined,Boolean(rr.timedOut||rr.stdoutTruncated||rr.stderrTruncated))})}catch(e:any){console.log('[AEGIS TOOL ERROR] '+name.toUpperCase()+' | '+e.message);runs.push({tool:name,status:'FAILED',error:e.message,findings:[]})}}
      const required=['http-posture','nmap','zap','wapiti','sqlmap','nuclei'];const coverage=scanCoverage(required,[{tool:'http-posture',status:q.error?'FAILED':'SUCCEEDED'},...runs]);const finalStatus=assessmentStatusForCoverage(coverage);const fresh=await db.assessmentForUser(u.userId,assessmentId)||assessment;const allFindings=await db.findingsForAssessment(assessmentId);const allEvidence=await db.evidenceForAssessment(assessmentId);await db.saveAssessment({...fresh,status:finalStatus,scanCoverage:coverage,findings:allFindings,evidenceIds:allEvidence.map(x=>x.id)});console.log('[AEGIS FULL ASSESSMENT] '+finalStatus+' | findings='+allFindings.length+' | evidence='+allEvidence.length);return res.json({execution:'REAL_FULL_ASSESSMENT',status:finalStatus,target:t.url.origin,assessmentId,tools:required,runs,coverage,summary:{findings:allFindings.length,evidenceRecords:allEvidence.length},findings:allFindings});
    }
    const safeTarget=await revalidateTarget(t);
    const startedAt=new Date().toISOString();
    let result:{stdout:string;stderr:string;exitCode:number|null;durationMs:number}; let zapAlerts:any[]=[];
    if(tool==='zap'){const z0=Date.now();zapAlerts=await zapScan(safeTarget.url.origin);result={stdout:JSON.stringify(zapAlerts),stderr:'',exitCode:0,durationMs:Date.now()-z0}}
    else {const args=tool==='nmap'?['-sT','-sV','--version-light','-Pn','-p-','--open','-oX','-',safeTarget.url.hostname]:tool==='wapiti'?['-u',safeTarget.url.origin,'--scope','url','--max-scan-time','60','--flush-session']:['-u',safeTarget.url.toString(),'--batch','--level=1','--risk=1','--threads=1','--timeout=10','--retries=1','--output-dir=/tmp/sqlmap'];result=await run(tool,args)}
    const completedAt=new Date().toISOString();
    const evidence=JSON.stringify({tool,target:safeTarget.url.origin,startedAt,completedAt,...result});
    const sha256=crypto.createHash('sha256').update(evidence).digest('hex');
    const ev:Evidence={id:crypto.randomUUID(),assessmentId,source:tool,sha256,createdAt:completedAt,exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,metadata:{target:safeTarget.url.origin,resolvedAddresses:safeTarget.addresses,durationMs:result.durationMs}};
    await db.saveEvidence(ev);
    const findings=tool==='wapiti'?wapitiFindings(assessmentId,safeTarget.url.origin,sha256,result.stdout):tool==='nmap'?nmapFindings(assessmentId,safeTarget.url.origin,sha256,result.stdout):tool==='zap'?zapFindings(assessmentId,safeTarget.url.origin,sha256,zapAlerts):[];
    await db.saveAudit({id:crypto.randomUUID(),assessmentId,action:'REAL_SCAN_COMPLETED',actor:'operator',createdAt:completedAt,metadata:{tool,exitCode:result.exitCode,evidenceHash:sha256,durationMs:result.durationMs}});
    if(findings.length) await db.saveFindings(findings);
    await db.saveAssessment({...assessment,status:result.exitCode===0?'COMPLETED':'FAILED',evidenceIds:[...assessment.evidenceIds,ev.id],findings:[...assessment.findings,...findings]});
    res.status(result.exitCode===0?200:502).json({execution:'REAL_TOOL_EXECUTION',tool,target:t.url.origin,resolvedAddresses:t.addresses,startedAt,completedAt,...result,evidence:{sha256}});
  }catch(e:any){res.status(400).json({error:e.message})}
});
app.post('/api/source/semgrep',async(req,res)=>{
 try{
  const session=verifySession(String(req.headers['x-assessment-session']||'')); const assessmentId=session.assessmentId; const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const assessment=await db.assessmentForUser(u.userId,assessmentId);
  if(!assessment) return res.status(404).json({error:'Assessment not found'});
  const result=await scanSource(String(req.body.sourcePath||'/workspace/source'));
  const ev:Evidence={id:crypto.randomUUID(),assessmentId,source:'semgrep',sha256:result.evidence.sha256,createdAt:new Date().toISOString(),exitCode:result.exitCode,stdout:result.stdout,stderr:result.stderr,metadata:{sourcePath:req.body.sourcePath||'/workspace/source'}};
  await db.saveEvidence(ev); const findings=semgrepFindings(assessmentId,String(req.body.sourcePath||'/workspace/source'),ev.sha256,result.results); await db.saveFindings(findings);
  await db.saveAssessment({...assessment,status:'COMPLETED',evidenceIds:[...assessment.evidenceIds,ev.id],findings:[...assessment.findings,...findings]});
  res.json({...result,assessmentId,findings});
 }catch(e:any){res.status(400).json({error:e.message})}
});
app.get('/api/assessments',async(req,res)=>{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});res.json(await db.assessmentsForUser(u.userId))});
app.get('/api/assessments/:id',async(req,res)=>{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const a=await db.assessmentForUser(u.userId,req.params.id);if(!a)return res.status(404).json({error:'Not found'});res.json(a)});
app.get('/api/assessments/:id/audit',async(req,res)=>{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});await requireAssessmentAccess(u.userId,req.params.id);res.json(await db.auditsForAssessment(req.params.id))});
app.get('/api/assessments/:id/evidence',async(req,res)=>{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});await requireAssessmentAccess(u.userId,req.params.id);res.json(await db.evidenceForAssessment(req.params.id))});
app.get('/api/assessments/:id/report',async(req,res)=>{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const a=await db.assessmentForUser(u.userId,req.params.id);if(!a)return res.status(404).json({error:'Not found'});const fs=await db.findingsForAssessment(req.params.id);res.json(assessmentReport(a,fs))});

app.get('/api/knowledge',(_req,res)=>res.json({modules:knowledgeCatalog(),authoritativeResources:authoritativeResources(),provenance:'Aegis learning modules plus direct authoritative resources. Live intelligence is retrieved from CISA/NIST endpoints.'}));
app.get('/api/cyber-intel',async(req,res)=>{try{res.json(await cyberIntel(req.query.refresh==='1'))}catch(e:any){res.status(502).json({error:e.message})}});
app.get('/api/cve/:cve',async(req,res)=>{try{res.json(await nvdCve(req.params.cve))}catch(e:any){res.status(502).json({error:e.message})}});
app.post('/api/cyber-intel/analyze',async(req,res)=>{try{const item=req.body?.item;if(!item?.title||!item?.source)return res.status(400).json({error:'Intelligence item required'});res.json(await analyzeIntel(item,String(req.body?.context||'')))}catch(e:any){res.status(502).json({error:e.message})}});
app.get('/api/frameworks',(_req,res)=>res.json({frameworks:frameworkCatalog,note:'Mappings are evidence-driven cross-references, not certification or reproduced standards text.'}));
app.post('/api/assessments/:id/documents',upload.array('files',10),async(req,res)=>{
 try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const a=await db.assessmentForUser(u.userId,req.params.id);if(!a)return res.status(404).json({error:'Assessment not found'});const access=await requireAssessmentAccess(u.userId,req.params.id);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');const files=(req.files||[]) as Express.Multer.File[];if(!files.length)return res.status(400).json({error:'No files supplied'});const denied=/\.(exe|dll|so|dylib|msi|apk|bat|cmd|ps1|sh|scr|com|jar)$/i;const saved=[];for(const file of files){if(denied.test(file.originalname))return res.status(400).json({error:'Executable/script uploads are not accepted'});const id=crypto.randomUUID(),sha256=crypto.createHash('sha256').update(file.buffer).digest('hex'),createdAt=new Date().toISOString();await db.saveDocument({id,assessmentId:a.id,filename:file.originalname.replace(/[\\/\0]/g,'_'),mimeType:file.mimetype||'application/octet-stream',size:file.size,sha256,createdAt,content:file.buffer});await db.saveAudit({id:crypto.randomUUID(),assessmentId:a.id,action:'DOCUMENT_UPLOADED',actor:'operator',createdAt,metadata:{documentId:id,filename:file.originalname,size:file.size,sha256}});saved.push({id,filename:file.originalname,size:file.size,sha256,createdAt})}res.json({stored:true,documents:saved})}catch(e:any){res.status(400).json({error:e.message})}
});
app.get('/api/assessments/:id/documents',async(req,res)=>{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});await requireAssessmentAccess(u.userId,req.params.id);res.json(await db.documents(req.params.id))});
app.post('/api/assessments/:id/documents/:docId/security-assess',async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const a=await db.assessmentForUser(u.userId,req.params.id);if(!a)return res.status(404).json({error:'Assessment not found'});const access=await requireAssessmentAccess(u.userId,req.params.id);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');
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
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const access=await requireAssessmentAccess(u.userId,req.params.id);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');
 const d=await db.document(req.params.docId);if(!d||d.assessmentId!==req.params.id)return res.status(404).json({error:'Not found'});
 const extracted=await extractDocument(d.filename,d.mimeType,d.content);
 if(!extracted.text.trim())return res.status(422).json({error:'No extractable text found in this document'});
 const analysis=await analyzeDocumentText(d.filename,extracted.text);
 await db.saveAudit({id:crypto.randomUUID(),assessmentId:req.params.id,action:'DOCUMENT_ANALYZED',actor:'operator',createdAt:new Date().toISOString(),metadata:{documentId:d.id,sha256:d.sha256,extraction:extracted.kind,pages:(extracted as any).pages||null,analysisMode:(analysis as any).mode}});
 res.json({document:{id:d.id,filename:d.filename,sha256:d.sha256,extraction:extracted.kind,pages:(extracted as any).pages||null},...analysis})
}catch(e:any){res.status(400).json({error:e.message})}});
app.get('/api/assessments/:id/documents/:docId',async(req,res)=>{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});await requireAssessmentAccess(u.userId,req.params.id);const d=await db.document(req.params.docId);if(!d||d.assessmentId!==req.params.id)return res.status(404).json({error:'Not found'});res.setHeader('Content-Disposition',`attachment; filename="${String(d.filename).replace(/"/g,'')}"`);res.type(d.mimeType).send(d.content)});
app.delete('/api/assessments/:id/documents/:docId',async(req,res)=>{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});await requireAssessmentAccess(u.userId,req.params.id);const d=await db.document(req.params.docId);if(!d||d.assessmentId!==req.params.id)return res.status(404).json({error:'Not found'});await db.deleteDocument(req.params.docId);await db.saveAudit({id:crypto.randomUUID(),assessmentId:req.params.id,action:'DOCUMENT_DELETED',actor:'operator',createdAt:new Date().toISOString(),metadata:{documentId:req.params.docId,sha256:d.sha256}});res.json({deleted:true})});

app.post('/api/assessments/:id/grc-reviews/:framework/submit',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const a=await db.assessmentForUser(u.userId,req.params.id);if(!a)return res.status(404).json({error:'Assessment not found'});const fw=req.params.framework.toUpperCase();if(!frameworkCatalog.some((x:any)=>String(x.id).toUpperCase()===fw))return res.status(400).json({error:'Unknown framework'});const snapshot=auditPackageModel(await assessmentTrace(u.userId,a.id));const snapshotDigest=reportSnapshotDigest(snapshot);const review=await submitGrcReview(a.id,fw,u.userId,snapshotDigest);await db.saveAudit({id:crypto.randomUUID(),assessmentId:a.id,action:'GRC_REPORT_SUBMITTED_FOR_REVIEW',actor:u.email,createdAt:new Date().toISOString(),metadata:{framework:fw,reviewId:review.id}});res.json({review,meaning:'Submitted for independent GRC consultant review. This is not yet approved or certified.'})}catch(e:any){res.status(400).json({error:e.message})}});
app.get('/api/assessments/:id/grc-reviews',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});await requireAssessmentAccess(u.userId,req.params.id);res.json({reviews:await listGrcReviews(req.params.id)})}catch(e:any){res.status(400).json({error:e.message})}});
app.get('/api/assessments/:id/grc-reviews/:reviewId/verify',async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});
 await requireAssessmentAccess(u.userId,req.params.id);
 const digest=reportSnapshotDigest(auditPackageModel(await assessmentTrace(u.userId,req.params.id)));
 const verification=await verifyGrcReview(req.params.reviewId,digest);
 if(verification.assessmentId&&verification.assessmentId!==req.params.id)return res.status(404).json({error:'Review not found for assessment'});
 res.json({...verification,meaning:verification.valid?'Approval signature is valid and the current report content matches the approved snapshot.':'The report is not currently authenticated; inspect reason/signature/snapshot state.'});
 }catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});
app.get('/api/report-verification/:reviewId',async(req,res)=>{try{
 const verification=await verifyGrcReview(req.params.reviewId);
 if(verification.reason==='REVIEW_NOT_FOUND')return res.status(404).json({valid:false,reason:'REVIEW_NOT_FOUND'});
 res.json({...verification,verificationScope:'Cryptographic AegisGRC issuance/approval verification only. This is not external certification or a compliance opinion.'});
 }catch(e:any){res.status(400).json({error:e.message})}});
app.get('/api/grc-review-queue',async(req,res)=>{try{const u=await currentUser(req);if(!u||!['grc_reviewer','admin'].includes(String(await userRole(u.userId))))return res.status(403).json({error:'GRC reviewer role required'});res.json({reviews:await listGrcReviews()})}catch(e:any){res.status(400).json({error:e.message})}});
app.post('/api/grc-reviews/:reviewId/decision',async(req,res)=>{try{const u=await currentUser(req);if(!u||!['grc_reviewer','admin'].includes(String(await userRole(u.userId))))return res.status(403).json({error:'GRC reviewer role required'});const status=String(req.body?.status||'').toUpperCase() as any;const review=await reviewGrcReport(req.params.reviewId,u.userId,status,String(req.body?.notes||''));await db.saveAudit({id:crypto.randomUUID(),assessmentId:review.assessment_id,action:'GRC_REVIEW_'+status,actor:u.email,createdAt:new Date().toISOString(),metadata:{framework:review.framework,reviewId:review.id,approvalHash:review.approval_hash||null}});res.json({review,disclaimer:status==='APPROVED'?'Approved by an authorized AegisGRC reviewer for the recorded assessment evidence; this does not equal external certification.':'Review decision recorded.'})}catch(e:any){res.status(400).json({error:e.message})}});

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
 const requestedId=String(req.body?.assessmentId||''),u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const a=requestedId?await db.assessmentForUser(u.userId,requestedId):null;
 if(requestedId&&!a)return res.status(404).json({error:'Assessment not found'});const fs=a?await db.findingsForAssessment(a.id):[];
 const answer=await askCopilot(question,String(req.body?.mode||'beginner'),a,fs);
 if(a)await db.saveAudit({id:crypto.randomUUID(),assessmentId:a.id,action:'AI_CHAT_REQUESTED',actor:'operator',createdAt:new Date().toISOString(),metadata:{mode:String(req.body?.mode||'beginner'),findingCount:fs.length}});
 res.json(answer);
}catch(e:any){res.status(502).json({mode:'UNAVAILABLE',error:e.message})}});
app.post('/api/assessments/:id/copilot',async(req,res)=>{try{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const a=await db.assessmentForUser(u.userId,req.params.id);if(!a)return res.status(404).json({error:'Assessment not found'});
 const question=String(req.body?.question||'').trim();if(!question||question.length>2000)return res.status(400).json({error:'Question must be between 1 and 2000 characters'});
 const fs=await db.findingsForAssessment(req.params.id);
 const answer=await askCopilot(question,String(req.body?.mode||'beginner'),a,fs);
 await db.saveAudit({id:crypto.randomUUID(),assessmentId:a.id,action:'AI_EXPLANATION_REQUESTED',actor:'operator',createdAt:new Date().toISOString(),metadata:{mode:String(req.body?.mode||'beginner'),findingCount:fs.length}});
 res.json(answer);
}catch(e:any){res.status(502).json({mode:'UNAVAILABLE',error:e.message})}});
app.post('/api/assessments/:id/ai-remediation',async(req,res)=>{
 try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});await requireAssessmentAccess(u.userId,req.params.id);const fs=await db.findingsForAssessment(req.params.id);res.json(await explainFindings(fs))}
 catch(e:any){res.status(502).json({mode:'UNAVAILABLE',error:e.message})}
});
app.get('/api/assessments/:id/report.pdf',async(req,res)=>{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const a=await db.assessmentForUser(u.userId,req.params.id);if(!a)return res.status(404).json({error:'Not found'});
 const fs=await db.findingsForAssessment(req.params.id);const ev=await db.evidenceForAssessment(req.params.id);const pdf=await renderPdf(a,fs,ev);
 res.setHeader('Content-Disposition',`attachment; filename="aegis-${a.id}.pdf"`);res.type('application/pdf').send(pdf);
});
app.get('/api/assessments/:id/report/download',async(req,res)=>{
 const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const a=await db.assessmentForUser(u.userId,req.params.id);if(!a)return res.status(404).json({error:'Not found'});
 const fs=await db.findingsForAssessment(req.params.id);const report=assessmentReport(a,fs);
 res.setHeader('Content-Disposition',`attachment; filename="aegis-${a.id}.json"`);res.type('application/json').send(JSON.stringify(report,null,2));
});

app.get('/api/assessments/:id/framework-assessment/:framework',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const a=await db.assessmentForUser(u.userId,req.params.id);if(!a)return res.status(404).json({error:'Not found'});const framework=req.params.framework.toUpperCase();if(!frameworkCatalog.some(x=>x.id===framework))return res.status(400).json({error:'Unknown framework'});const fs=await db.findingsForAssessment(a.id);const controls=assessFramework(framework,fs);res.json({engine:'DETERMINISTIC_BACKEND_GRC_ENGINE',framework,assessmentId:a.id,target:a.target,summary:{findings:fs.length,gaps:controls.filter(x=>x.status==='GAP').length,notTested:controls.filter(x=>x.status==='NOT_TESTED').length},controls,note:'NOT_TESTED is not PASS. URL testing can provide technical evidence for applicable controls but cannot prove the entire management system or regulatory framework.'})}catch(e:any){res.status(400).json({error:e.message})}});
app.get('/api/assessments/:id/framework-report/:framework/:format',async(req,res)=>{try{const step=await reportAuthorized(req);if(!step.ok)return res.status(401).json({error:'Report verification failed: '+step.reason+'. Use the same password registered for this account and a fresh authenticator code.'});const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const a=await db.assessmentForUser(u.userId,req.params.id);if(!a)return res.status(404).json({error:'Not found'});const fs=await db.findingsForAssessment(req.params.id),framework=req.params.framework.toUpperCase(),format=req.params.format.toLowerCase();let body:Buffer,mime='application/octet-stream';if(format==='pdf'){const reviews=await listGrcReviews(a.id);const review=reviews.find((x:any)=>String(x.framework).toUpperCase()===framework);body=await renderFrameworkPdf(a,fs,framework,review);mime='application/pdf'}else if(format==='docx'){body=await frameworkDocx(a,fs,framework);mime='application/vnd.openxmlformats-officedocument.wordprocessingml.document'}else if(format==='xlsx'){body=frameworkXlsx(a,fs,framework);mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}else if(format==='csv'){body=frameworkCsv(fs,framework);mime='text/csv'}else if(format==='txt'){body=frameworkTxt(a,fs,framework);mime='text/plain'}else if(format==='json'){body=Buffer.from(JSON.stringify(frameworkReportModel(a,fs,framework),null,2));mime='application/json'}else return res.status(400).json({error:'Framework export supports PDF, DOCX, XLSX, CSV, JSON and TXT'});res.setHeader('Content-Disposition',`attachment; filename="aegis-${framework.toLowerCase()}-${a.id}.${format}"`);res.type(mime).send(body)}catch(e:any){res.status(400).json({error:e.message})}});

app.get('/api/assessments/:id/export/:kind/:format',async(req,res)=>{
 try{
  const step=await reportAuthorized(req);if(!step.ok)return res.status(401).json({error:'Report verification failed: '+step.reason+'. Use the same password registered for this account and a fresh authenticator code.'});
  const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const a=await db.assessmentForUser(u.userId,req.params.id);if(!a)return res.status(404).json({error:'Not found'});
  const fs=await db.findingsForAssessment(req.params.id);const ev=await db.evidenceForAssessment(req.params.id);
  const kinds=['grc','remediation','architecture','technical','executive']; const formats=['pdf','docx','pptx','xlsx','csv','json','txt'];
  const kind=(kinds.includes(req.params.kind)?req.params.kind:'grc') as ReportKind, format=req.params.format.toLowerCase();
  if(!formats.includes(format))return res.status(400).json({error:'Unsupported report format'});
  let body:Buffer; let mime='application/octet-stream';
  if(format==='pdf'){body=await renderPdf(a,fs,ev);mime='application/pdf'}
  else if(format==='docx'){body=await docxReport(a,fs,kind,ev);mime='application/vnd.openxmlformats-officedocument.wordprocessingml.document'}
  else if(format==='pptx'){body=await pptxReport(a,fs,kind,ev);mime='application/vnd.openxmlformats-officedocument.presentationml.presentation'}
  else if(format==='xlsx'){body=xlsxReport(a,fs,kind,ev);mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}
  else if(format==='csv'){body=csvReport(fs);mime='text/csv'}
  else if(format==='txt'){body=txtReport(a,fs,kind,ev);mime='text/plain'}
  else {body=Buffer.from(JSON.stringify(reportModel(a,fs,kind),null,2));mime='application/json'}
  res.setHeader('Content-Disposition',`attachment; filename="aegis-${kind}-${a.id}.${format}"`);res.type(mime).send(body);
 }catch(e:any){res.status(500).json({error:e.message})}
});

app.listen(PORT,()=>console.log(`AegisGRC Security listening on :${PORT}`));app.post('/api/grc/assessments/:assessmentId/trivy-image',async(req,res)=>{try{const u=await currentUser(req);if(!u)return res.status(401).json({error:'User session required'});const access=await requireAssessmentAccess(u.userId,req.params.assessmentId);await requireOrgPermission(u.userId,access.organization_id,'manageAssessment');const assetId=String(req.body?.assetId||''),imageRef=String(req.body?.imageRef||'');const asset=await activeContainerAsset(u.userId,access.organization_id,assetId);if(!asset)return res.status(400).json({error:'Active container asset required'});const out=await scanContainerImageWithTrivy(imageRef);const evidenceHash=out.evidence.sha256;const findings=trivyJsonFindings(req.params.assessmentId,asset.asset_key,evidenceHash,out.stdout);const evidence:Evidence={id:crypto.randomUUID(),assessmentId:req.params.assessmentId,source:'trivy',sha256:evidenceHash,exitCode:out.exitCode,stdout:out.stdout,stderr:out.stderr,metadata:{scanType:'IMAGE',assetId,imageRef,timedOut:out.timedOut,truncated:out.truncated,durationMs:out.durationMs},createdAt:new Date().toISOString()};await db.saveFindingImport(evidence,findings,{id:crypto.randomUUID(),assessmentId:req.params.assessmentId,action:'TRIVY_CONTAINER_EVIDENCE_INGESTED',actor:u.userId,createdAt:new Date().toISOString(),metadata:{assetId,imageRef,evidenceHash,findingCount:findings.length}});res.status(out.exitCode===0&&!out.timedOut&&!out.truncated?201:422).json({evidenceHash,findings:findings.length,exitCode:out.exitCode,timedOut:out.timedOut,truncated:out.truncated})}catch(e:any){res.status(e.statusCode||400).json({error:e.message})}});

