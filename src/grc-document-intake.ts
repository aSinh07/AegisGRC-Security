import crypto from 'node:crypto';
import {pool} from './db-pool.js';
import {requireOrgPermission} from './grc-organizations.js';
import {extractDocument} from './document-extract.js';

export type IntakeKind='CONTROL'|'RISK'|'VENDOR'|'POLICY'|'AUDIT'|'INCIDENT'|'SCOPE'|'UNKNOWN';
export type IntakeProposal={id:string;kind:IntakeKind;field:string;value:string;confidence:number;source:{line:number;excerpt:string};rule:string;status:'PROPOSED'|'ACCEPTED'|'REJECTED';targetKey?:string};

const labels:{kind:IntakeKind;field:string;patterns:RegExp[]}[]=[
 {kind:'CONTROL',field:'controlKey',patterns:[/\b(?:control(?:\s+id|\s+key)?|control reference)\s*[:#-]\s*([A-Z][A-Z0-9_.-]{1,30})/i]},
 {kind:'CONTROL',field:'implementation',patterns:[/\b(?:implementation(?:\s+status)?|control status)\s*[:#-]\s*(implemented|partial|planned|not implemented)\b/i]},
 {kind:'CONTROL',field:'applicability',patterns:[/\bapplicability\s*[:#-]\s*(applicable|not[_ -]?applicable|pending)\b/i]},
 {kind:'CONTROL',field:'owner',patterns:[/\b(?:control\s+owner|owner)\s*[:#-]\s*([^|;,]{2,100})/i]},
 {kind:'RISK',field:'riskKey',patterns:[/\b(?:risk(?:\s+id|\s+key)?)\s*[:#-]\s*([A-Z][A-Z0-9_.-]{1,30})/i]},
 {kind:'RISK',field:'riskTitle',patterns:[/\b(?:risk\s+title|risk)\s*[:#-]\s*([^|;]{4,180})/i]},
 {kind:'VENDOR',field:'vendorName',patterns:[/\b(?:vendor|supplier|third party)\s*(?:name)?\s*[:#-]\s*([^|;,]{2,160})/i]},
 {kind:'POLICY',field:'policyTitle',patterns:[/\b(?:policy\s+(?:name|title))\s*[:#-]\s*([^|;]{3,180})/i]},
 {kind:'AUDIT',field:'auditFinding',patterns:[/\b(?:audit\s+finding|observation|nonconformity)\s*[:#-]\s*([^|;]{4,240})/i]},
 {kind:'INCIDENT',field:'incidentTitle',patterns:[/\b(?:incident(?:\s+title)?)\s*[:#-]\s*([^|;]{4,180})/i]},
 {kind:'SCOPE',field:'scopeName',patterns:[/\b(?:scope|system\s+name)\s*[:#-]\s*([^|;]{3,180})/i]}
];
function clean(v:string){return v.replace(/\s+/g,' ').trim().slice(0,500)}
function confidence(line:string,match:string){let n=.72;if(/[:#-]/.test(line))n+=.08;if(match.length>=4)n+=.05;if(line.length<220)n+=.05;return Math.min(.95,Math.round(n*100)/100)}
export function parseGrcDocumentDeterministically(text:string){
 const lines=String(text||'').split(/\r?\n/).map(clean).filter(Boolean).slice(0,20000),proposals:IntakeProposal[]=[];
 lines.forEach((line,idx)=>{for(const def of labels)for(const pattern of def.patterns){const m=line.match(pattern);if(!m?.[1])continue;const value=clean(m[1]);if(value.length<2)continue;proposals.push({id:crypto.createHash('sha256').update(idx+'|'+def.kind+'|'+def.field+'|'+value).digest('hex').slice(0,24),kind:def.kind,field:def.field,value,confidence:confidence(line,value),source:{line:idx+1,excerpt:line.slice(0,260)},rule:'LABEL_'+def.field.toUpperCase(),status:'PROPOSED'});break}});
 const seen=new Set<string>();return proposals.filter(p=>{const k=p.kind+'|'+p.field+'|'+p.value.toLowerCase();if(seen.has(k))return false;seen.add(k);return true});
}
export async function initGrcIntake(){await pool.query(`
 CREATE TABLE IF NOT EXISTS grc_document_intakes(
  id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
  scope_id uuid REFERENCES grc_scopes(id) ON DELETE CASCADE,filename text NOT NULL,mime_type text NOT NULL,
  sha256 text NOT NULL,document_kind text NOT NULL,extracted_text_sha256 text NOT NULL,
  status text NOT NULL DEFAULT 'REVIEW_REQUIRED',proposal_count integer NOT NULL DEFAULT 0,
  created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,approved_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
  approved_at timestamptz,created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(organization_id,scope_id,sha256)
 );
 CREATE TABLE IF NOT EXISTS grc_document_intake_proposals(
  intake_id uuid NOT NULL REFERENCES grc_document_intakes(id) ON DELETE CASCADE,proposal_id text NOT NULL,
  kind text NOT NULL,field text NOT NULL,value text NOT NULL,confidence numeric NOT NULL,
  source_line integer NOT NULL,source_excerpt text NOT NULL,rule text NOT NULL,status text NOT NULL DEFAULT 'PROPOSED',
  reviewer_value text,reviewed_by uuid REFERENCES app_users(id) ON DELETE SET NULL,reviewed_at timestamptz,
  PRIMARY KEY(intake_id,proposal_id)
 ); CREATE INDEX IF NOT EXISTS grc_intake_org_scope_idx ON grc_document_intakes(organization_id,scope_id,created_at DESC);`)}
export async function createGrcIntake(user:string,org:string,scopeId:string|undefined,file:{originalname:string;mimetype:string;buffer:Buffer}){
 await requireOrgPermission(user,org,'manageControl');
 const filename=String(file.originalname||'').replace(/[\\/\0]/g,'_').trim(),mime=String(file.mimetype||'').toLowerCase(),size=file.buffer?.length||0;
 if(!filename||size<1||size>10*1024*1024)throw Object.assign(new Error('Document must be between 1 byte and 10 MB'),{statusCode:413});
 const ext=(filename.toLowerCase().match(/\.[a-z0-9]+$/)?.[0]||''),textExt=new Set(['.txt','.md','.csv','.json','.xml','.yaml','.yml','.log']);
 const isPdf=ext==='.pdf'&&mime==='application/pdf'&&file.buffer.subarray(0,5).toString('ascii')==='%PDF-';
 const isDocx=ext==='.docx'&&mime==='application/vnd.openxmlformats-officedocument.wordprocessingml.document'&&file.buffer[0]===0x50&&file.buffer[1]===0x4b;
 const isSheet=['.xlsx','.xls'].includes(ext)&&['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','application/vnd.ms-excel'].includes(mime);
 const isText=textExt.has(ext)&&(mime.startsWith('text/')||['application/json','application/xml','application/yaml','application/x-yaml','application/octet-stream'].includes(mime))&&!file.buffer.subarray(0,4096).some((byte:number)=>byte===0);
 if(!(isPdf||isDocx||isSheet||isText))throw Object.assign(new Error('File type, extension, and content signature do not match an allowed deterministic intake format'),{statusCode:415});if(scopeId){const s=(await pool.query('SELECT 1 FROM grc_scopes WHERE id=$1 AND organization_id=$2',[scopeId,org])).rows[0];if(!s)throw Object.assign(new Error('Scope not found in organization'),{statusCode:404})}
 const extracted=await extractDocument(filename,mime,file.buffer);const text=String(extracted.text||'');if(text.trim().length<20)throw Object.assign(new Error('Document has no usable text layer; scanned/image-only documents require text extraction before deterministic intake'),{statusCode:422});
 const sha=crypto.createHash('sha256').update(file.buffer).digest('hex'),textSha=crypto.createHash('sha256').update(text).digest('hex'),proposals=parseGrcDocumentDeterministically(text),id=crypto.randomUUID();
 const kinds=[...new Set(proposals.map(x=>x.kind).filter(x=>x!=='UNKNOWN'))],docKind=kinds.length===1?kinds[0]:kinds.length?'MIXED':'UNCLASSIFIED';const client=await pool.connect();
 try{await client.query('BEGIN');const prior=(await client.query('SELECT id FROM grc_document_intakes WHERE organization_id=$1 AND scope_id IS NOT DISTINCT FROM $2 AND sha256=$3',[org,scopeId||null,sha])).rows[0];if(prior)throw Object.assign(new Error('This exact document is already staged for this organization and scope'),{statusCode:409});
 await client.query('INSERT INTO grc_document_intakes(id,organization_id,scope_id,filename,mime_type,sha256,document_kind,extracted_text_sha256,proposal_count,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[id,org,scopeId||null,filename,mime,sha,docKind,textSha,proposals.length,user]);
 for(const p of proposals)await client.query('INSERT INTO grc_document_intake_proposals(intake_id,proposal_id,kind,field,value,confidence,source_line,source_excerpt,rule) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[id,p.id,p.kind,p.field,p.value,p.confidence,p.source.line,p.source.excerpt,p.rule]);
 await client.query('COMMIT');return {id,filename,sha256:sha,documentKind:docKind,pages:(extracted as any).pages||null,proposalCount:proposals.length,status:'REVIEW_REQUIRED',engine:'DETERMINISTIC_RULE_ENGINE_V1',aiUsed:false};
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}
export async function getGrcIntake(user:string,org:string,id:string){await requireOrgPermission(user,org,'read');const intake=(await pool.query('SELECT * FROM grc_document_intakes WHERE id=$1 AND organization_id=$2',[id,org])).rows[0];if(!intake)throw Object.assign(new Error('Intake not found'),{statusCode:404});const proposals=(await pool.query('SELECT * FROM grc_document_intake_proposals WHERE intake_id=$1 ORDER BY source_line,proposal_id',[id])).rows;return {intake,proposals,assurance:{aiUsed:false,automaticComplianceDecision:false,requiresHumanApproval:true}}}
export async function reviewGrcIntake(user:string,org:string,id:string,input:any){await requireOrgPermission(user,org,'manageControl');const decisions=Array.isArray(input?.decisions)?input.decisions:[];if(!decisions.length)throw new Error('At least one proposal decision is required');const client=await pool.connect();try{await client.query('BEGIN');const row=(await client.query('SELECT id,status FROM grc_document_intakes WHERE id=$1 AND organization_id=$2 FOR UPDATE',[id,org])).rows[0];if(!row)throw Object.assign(new Error('Intake not found'),{statusCode:404});if(['APPROVED','IMPORTED'].includes(String(row.status)))throw Object.assign(new Error('Approved or imported intake cannot be modified'),{statusCode:409});for(const d of decisions){const status=String(d.status||'').toUpperCase();if(!['ACCEPTED','REJECTED'].includes(status))throw new Error('Proposal decision must be ACCEPTED or REJECTED');const updated=await client.query('UPDATE grc_document_intake_proposals SET status=$3,reviewer_value=$4,reviewed_by=$5,reviewed_at=now() WHERE intake_id=$1 AND proposal_id=$2 RETURNING proposal_id',[id,String(d.proposalId),status,d.value==null?null:clean(String(d.value)),user]);if(!updated.rowCount)throw Object.assign(new Error('Proposal not found in this intake'),{statusCode:404})}await client.query("UPDATE grc_document_intakes SET status='REVIEWED' WHERE id=$1",[id]);await client.query('COMMIT');return getGrcIntake(user,org,id)}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}
export async function approveGrcIntake(user:string,org:string,id:string){await requireOrgPermission(user,org,'review');const client=await pool.connect();try{await client.query('BEGIN');const intake=(await client.query('SELECT * FROM grc_document_intakes WHERE id=$1 AND organization_id=$2 FOR UPDATE',[id,org])).rows[0];if(!intake)throw Object.assign(new Error('Intake not found'),{statusCode:404});if(intake.created_by===user)throw Object.assign(new Error('Independent reviewer required to approve document intake'),{statusCode:409});const selfReviewed=Number((await client.query('SELECT count(*) n FROM grc_document_intake_proposals WHERE intake_id=$1 AND reviewed_by=$2',[id,user])).rows[0]?.n||0);if(selfReviewed)throw Object.assign(new Error('Approver must be independent from proposal reviewer(s)'),{statusCode:409});const pending=Number((await client.query("SELECT count(*) n FROM grc_document_intake_proposals WHERE intake_id=$1 AND status='PROPOSED'",[id])).rows[0]?.n||0);if(pending)throw Object.assign(new Error('Every extracted proposal must be accepted or rejected before approval'),{statusCode:409});await client.query("UPDATE grc_document_intakes SET status='APPROVED',approved_by=$2,approved_at=now() WHERE id=$1",[id,user]);await client.query('COMMIT');return {id,status:'APPROVED',automaticWriteToGrc:false,nextStep:'Explicit governed import is required; approval does not establish compliance.'}}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}

export async function importApprovedGrcIntake(user:string,org:string,id:string){
 await requireOrgPermission(user,org,'manageControl');const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const intake=(await client.query("SELECT * FROM grc_document_intakes WHERE id=$1 AND organization_id=$2 AND status='APPROVED' FOR UPDATE",[id,org])).rows[0];
  if(!intake)throw Object.assign(new Error('Approved intake not found'),{statusCode:409});
  if(!intake.scope_id)throw Object.assign(new Error('A governed scope is required before importing control proposals'),{statusCode:409});
  const ps=(await client.query("SELECT *,COALESCE(NULLIF(reviewer_value,''),value) final_value FROM grc_document_intake_proposals WHERE intake_id=$1 AND status='ACCEPTED' ORDER BY source_line,proposal_id",[id])).rows;
  let imported=0;
  const controls=ps.filter((p:any)=>p.kind==='CONTROL');
  const anchors=controls.filter((p:any)=>p.field==='controlKey');
  for(let i=0;i<anchors.length;i++){
   const anchor=anchors[i],nextLine=i+1<anchors.length?Number(anchors[i+1].source_line):Number.MAX_SAFE_INTEGER;
   const related=controls.filter((p:any)=>Number(p.source_line)>=Number(anchor.source_line)&&Number(p.source_line)<nextLine);
   const key=clean(anchor.final_value).toUpperCase();
   const control=(await client.query('SELECT id FROM grc_canonical_controls WHERE upper(control_key)=upper($1)',[key])).rows[0];
   if(!control)continue;
   const applicability=clean(related.find((x:any)=>x.field==='applicability')?.final_value||'PENDING').toUpperCase().replace(/[ -]/g,'_');
   const implementation=clean(related.find((x:any)=>x.field==='implementation')?.final_value||'NOT_IMPLEMENTED').toUpperCase().replace(/ /g,'_');
   if(!['APPLICABLE','NOT_APPLICABLE','PENDING'].includes(applicability)||!['NOT_IMPLEMENTED','PLANNED','PARTIAL','IMPLEMENTED'].includes(implementation))continue;
   await client.query(`INSERT INTO grc_scope_controls(id,organization_id,scope_id,control_id,applicability,implementation,applicability_justification)
    VALUES($1,$2,$3,$4,$5,$6,$7)
    ON CONFLICT(scope_id,control_id) DO UPDATE SET applicability=EXCLUDED.applicability,implementation=EXCLUDED.implementation,
    applicability_justification=EXCLUDED.applicability_justification,updated_at=now()`,
    [crypto.randomUUID(),org,intake.scope_id,control.id,applicability,implementation,'Imported from approved deterministic intake '+id]);
   imported++;
  }
  if(!imported)throw Object.assign(new Error('No accepted proposal matched a safe deterministic write adapter; approved staged data was preserved and nothing was imported'),{statusCode:409});
  const skippedKinds=[...new Set(ps.filter((p:any)=>p.kind!=='CONTROL').map((p:any)=>String(p.kind)))];
  await client.query("UPDATE grc_document_intakes SET status='IMPORTED' WHERE id=$1",[id]);
  await client.query('COMMIT');
  return {id,status:'IMPORTED',recordsImported:imported,automaticComplianceDecision:false,limitations:skippedKinds.length?['Accepted '+skippedKinds.join(', ')+' proposals remain staged because no safe deterministic write adapter is enabled for those record types.']:[]};
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
