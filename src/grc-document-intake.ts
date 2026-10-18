import crypto from 'node:crypto';
import {pool} from './db-pool.js';
import {requireOrgPermission,membership,roleAllows} from './grc-organizations.js';
import {extractDocument} from './document-extract.js';

export type IntakeKind='CONTROL'|'RISK'|'VENDOR'|'POLICY'|'AUDIT'|'INCIDENT'|'SCOPE'|'PRIVACY'|'LEGAL'|'ARCHITECTURE'|'RESILIENCE'|'GOVERNANCE'|'COMPLIANCE'|'AI_IMPACT'|'UNKNOWN';
export type IntakeProposal={id:string;kind:IntakeKind;field:string;value:string;confidence:number;source:{line:number;excerpt:string};rule:string;status:'PROPOSED'|'ACCEPTED'|'REJECTED';targetKey?:string};

const labels:{kind:IntakeKind;field:string;patterns:RegExp[]}[]=[
 {kind:'CONTROL',field:'controlKey',patterns:[/\b(?:control(?:\s+id|\s+key)?|control reference)\s*[:#-]\s*([A-Z][A-Z0-9_.-]{1,40})/i]},
 {kind:'CONTROL',field:'controlTitle',patterns:[/\b(?:control\s+title|control\s+name)\s*[:#-]\s*([^|;]{3,220})/i]},
 {kind:'CONTROL',field:'controlDomain',patterns:[/\b(?:control\s+domain|domain)\s*[:#-]\s*([^|;,]{2,100})/i]},
 {kind:'CONTROL',field:'implementation',patterns:[/\b(?:implementation(?:\s+status|\s+state)?|control status)\s*[:#-]\s*(implemented|partial|planned|not implemented)\b/i]},
 {kind:'CONTROL',field:'applicability',patterns:[/\bapplicability\s*[:#-]\s*(applicable|not[_ -]?applicable|pending)\b/i]},
 {kind:'CONTROL',field:'justification',patterns:[/\b(?:applicability\s+justification|justification)\s*[:#-]\s*([^|;]{4,500})/i]},
 {kind:'CONTROL',field:'owner',patterns:[/\b(?:control\s+owner|owner)\s*[:#-]\s*([^|;,]{2,100})/i]},
 {kind:'CONTROL',field:'framework',patterns:[/\b(?:framework|standard)\s*[:#-]\s*([^|;,]{2,100})/i]},
 {kind:'CONTROL',field:'frameworkControl',patterns:[/\b(?:framework\s+control|requirement|clause)\s*[:#-]\s*([A-Z0-9][A-Z0-9_.-]{1,60})/i]},
 {kind:'RISK',field:'riskKey',patterns:[/\b(?:risk(?:\s+id|\s+key)?)\s*[:#-]\s*([A-Z][A-Z0-9_.-]{1,40})/i]},
 {kind:'RISK',field:'riskTitle',patterns:[/\b(?:risk\s+title|risk\s+scenario|risk)\s*[:#-]\s*([^|;]{4,220})/i]},
 {kind:'RISK',field:'riskDescription',patterns:[/\b(?:risk\s+description|scenario\s+description)\s*[:#-]\s*([^|;]{4,500})/i]},
 {kind:'RISK',field:'riskCategory',patterns:[/\b(?:risk\s+category)\s*[:#-]\s*([^|;,]{2,100})/i]},
 {kind:'RISK',field:'likelihood',patterns:[/\b(?:likelihood|probability)\s*[:#-]\s*([1-5])\b/i]},
 {kind:'RISK',field:'impact',patterns:[/\b(?:impact|severity)\s*[:#-]\s*([1-5])\b/i]},
 {kind:'RISK',field:'treatment',patterns:[/\b(?:risk\s+treatment|treatment)\s*[:#-]\s*(mitigate|accept|transfer|avoid)\b/i]},
 {kind:'VENDOR',field:'vendorName',patterns:[/\b(?:vendor|supplier|third party)\s*(?:name)?\s*[:#-]\s*([^|;,]{2,160})/i]},
 {kind:'VENDOR',field:'vendorKey',patterns:[/\b(?:vendor|supplier)\s+(?:id|key)\s*[:#-]\s*([A-Z0-9._-]{2,60})/i]},
 {kind:'VENDOR',field:'vendorService',patterns:[/\b(?:vendor|supplier)\s+(?:service|dependency)\s*[:#-]\s*([^|;]{2,220})/i]},
 {kind:'VENDOR',field:'vendorTier',patterns:[/\b(?:vendor|supplier)\s+tier\s*[:#-]\s*(tier[_ -]?[1-4]|[1-4])\b/i]},
 {kind:'VENDOR',field:'vendorCriticality',patterns:[/\b(?:vendor|supplier)\s+criticality\s*[:#-]\s*(low|medium|high|critical)\b/i]},
 {kind:'POLICY',field:'policyTitle',patterns:[/\b(?:policy\s+(?:name|title)|policy)\s*[:#-]\s*([^|;]{3,220})/i]},
 {kind:'POLICY',field:'policyKey',patterns:[/\bpolicy\s+(?:id|key)\s*[:#-]\s*([A-Z0-9._-]{2,60})/i]},
 {kind:'POLICY',field:'policyCategory',patterns:[/\bpolicy\s+category\s*[:#-]\s*([^|;,]{2,100})/i]},
 {kind:'POLICY',field:'policyVersion',patterns:[/\bpolicy\s+version\s*[:#-]\s*([^|;,]{1,40})/i]},
 {kind:'AUDIT',field:'auditKey',patterns:[/\b(?:audit\s+(?:id|key))\s*[:#-]\s*([A-Z0-9._-]{2,60})/i]},
 {kind:'AUDIT',field:'auditTitle',patterns:[/\b(?:audit\s+(?:name|title)|audit)\s*[:#-]\s*([^|;]{3,220})/i]},
 {kind:'AUDIT',field:'auditType',patterns:[/\b(?:audit\s+type)\s*[:#-]\s*(internal|external|supplier|regulatory|certification|follow[_ -]?up)\b/i]},
 {kind:'AUDIT',field:'auditObjective',patterns:[/\b(?:audit\s+objective|objective)\s*[:#-]\s*([^|;]{5,500})/i]},
 {kind:'AUDIT',field:'auditCriteria',patterns:[/\b(?:audit\s+criteria|criteria)\s*[:#-]\s*([^|;]{3,500})/i]},
 {kind:'AUDIT',field:'auditFinding',patterns:[/\b(?:audit\s+finding|finding|observation|nonconformity)\s*[:#-]\s*([^|;]{4,500})/i]},
 {kind:'INCIDENT',field:'incidentTitle',patterns:[/\b(?:incident(?:\s+title)?)\s*[:#-]\s*([^|;]{4,220})/i]},
 {kind:'SCOPE',field:'scopeName',patterns:[/\b(?:scope|system\s+name|assessment\s+scope|in[- ]scope)\s*[:#-]\s*([^|;]{3,220})/i]},
 {kind:'SCOPE',field:'scopeDescription',patterns:[/\b(?:scope\s+description|scope\s+statement|scope\s+includes?|scope\s+covers?)\s*[:#-]\s*([^|;]{4,500})/i]},
 {kind:'PRIVACY',field:'activityKey',patterns:[/\b(?:processing\s+activity\s+(?:id|key)|activity\s+key)\s*[:#-]\s*([A-Z0-9._-]{2,60})/i]},
 {kind:'PRIVACY',field:'activityName',patterns:[/\b(?:processing\s+activity\s+(?:name|title)|activity\s+name)\s*[:#-]\s*([^|;]{3,220})/i]},
 {kind:'PRIVACY',field:'processingPurpose',patterns:[/\b(?:processing\s+purpose|specific\s+purpose|purpose)\s*[:#-]\s*([^|;]{3,500})/i]},
 {kind:'PRIVACY',field:'processingGround',patterns:[/\b(?:processing\s+ground|lawful\s+basis|legal\s+basis)\s*[:#-]\s*([^|;]{2,220})/i]},
 {kind:'PRIVACY',field:'retentionRule',patterns:[/\b(?:retention\s+rule|retention\s+period|retention)\s*[:#-]\s*([^|;]{2,220})/i]},
 {kind:'PRIVACY',field:'dataCategories',patterns:[/\b(?:personal\s+data\s+categories|data\s+categories)\s*[:#-]\s*([^|;]{2,500})/i]},
 {kind:'PRIVACY',field:'systems',patterns:[/\b(?:processing\s+systems|systems)\s*[:#-]\s*([^|;]{2,500})/i]},
 {kind:'PRIVACY',field:'recipients',patterns:[/\b(?:data\s+recipients|recipients)\s*[:#-]\s*([^|;]{2,500})/i]},
 {kind:'LEGAL',field:'legalKey',patterns:[/\b(?:legal\s+reference\s+key|legal\s+key|requirement\s+key)\s*[:#-]\s*([A-Z0-9._-]{2,80})/i]},
 {kind:'LEGAL',field:'legalTitle',patterns:[/\b(?:legal\s+requirement\s+title|legal\s+title|requirement\s+title)\s*[:#-]\s*([^|;]{3,300})/i]},
 {kind:'LEGAL',field:'legalSource',patterns:[/\b(?:authoritative\s+source(?:\s+reference)?|legal\s+source)\s*[:#-]\s*([^|;]{3,500})/i]},
 {kind:'ARCHITECTURE',field:'componentKey',patterns:[/\b(?:component\s+(?:id|key)|asset\s+key)\s*[:#-]\s*([A-Z0-9._-]{2,80})/i]},
 {kind:'ARCHITECTURE',field:'componentName',patterns:[/\b(?:component\s+(?:name|title)|asset\s+name)\s*[:#-]\s*([^|;]{2,220})/i]},
 {kind:'ARCHITECTURE',field:'componentType',patterns:[/\b(?:component\s+type|asset\s+type)\s*[:#-]\s*(FIREWALL|WAF|LOAD[_ -]?BALANCER|ROUTER|SWITCH|VPN[_ -]?GATEWAY|IDS[_ -]?IPS|CDN|DNS|REVERSE[_ -]?PROXY|SERVICE|DATA[_ -]?FLOW|TRUST[_ -]?BOUNDARY)\b/i]},
 {kind:'ARCHITECTURE',field:'componentCriticality',patterns:[/\b(?:component\s+criticality|asset\s+criticality)\s*[:#-]\s*(low|medium|high|critical)\b/i]},
 {kind:'ARCHITECTURE',field:'internetExposed',patterns:[/\b(?:internet[- ]exposed|publicly\s+exposed)\s*[:#-]\s*(yes|no|true|false)\b/i]},
 {kind:'RESILIENCE',field:'serviceKey',patterns:[/\b(?:business\s+service\s+(?:id|key)|service\s+key)\s*[:#-]\s*([A-Z0-9._-]{2,80})/i]},
 {kind:'RESILIENCE',field:'serviceName',patterns:[/\b(?:business\s+service\s+(?:name|title)|service\s+name)\s*[:#-]\s*([^|;]{3,220})/i]},
 {kind:'RESILIENCE',field:'serviceCriticality',patterns:[/\b(?:service\s+criticality|business\s+criticality)\s*[:#-]\s*(low|medium|high|critical)\b/i]},
 {kind:'RESILIENCE',field:'rtoMinutes',patterns:[/\bRTO(?:\s+minutes)?\s*[:#-]\s*(\d{1,8})\b/i]},
 {kind:'RESILIENCE',field:'rpoMinutes',patterns:[/\bRPO(?:\s+minutes)?\s*[:#-]\s*(\d{1,8})\b/i]},
 {kind:'RESILIENCE',field:'mtdMinutes',patterns:[/\b(?:MTD|maximum\s+tolerable\s+downtime)(?:\s+minutes)?\s*[:#-]\s*(\d{1,8})\b/i]},
 {kind:'RESILIENCE',field:'recoveryStrategy',patterns:[/\b(?:recovery\s+strategy)\s*[:#-]\s*([^|;]{3,500})/i]},
 {kind:'GOVERNANCE',field:'appetiteKey',patterns:[/\b(?:risk\s+appetite\s+(?:id|key)|appetite\s+key)\s*[:#-]\s*([A-Z0-9._-]{2,80})/i]},
 {kind:'GOVERNANCE',field:'appetiteTitle',patterns:[/\b(?:risk\s+appetite\s+title|appetite\s+title)\s*[:#-]\s*([^|;]{3,220})/i]},
 {kind:'GOVERNANCE',field:'appetiteStatement',patterns:[/\b(?:risk\s+appetite\s+statement|appetite\s+statement)\s*[:#-]\s*([^|;]{15,500})/i]},
 {kind:'GOVERNANCE',field:'toleranceRating',patterns:[/\b(?:tolerance\s+rating|risk\s+tolerance)\s*[:#-]\s*(low|medium|high|critical)\b/i]},
 {kind:'GOVERNANCE',field:'metricKey',patterns:[/\b(?:metric\s+(?:id|key)|KPI\s+key|KRI\s+key|KCI\s+key)\s*[:#-]\s*([A-Z0-9._-]{2,80})/i]},
 {kind:'GOVERNANCE',field:'metricTitle',patterns:[/\b(?:metric\s+(?:name|title)|KPI\s+title|KRI\s+title|KCI\s+title)\s*[:#-]\s*([^|;]{3,220})/i]},
 {kind:'GOVERNANCE',field:'metricType',patterns:[/\b(?:metric\s+type)\s*[:#-]\s*(KPI|KRI|KCI)\b/i]},
 {kind:'GOVERNANCE',field:'metricDirection',patterns:[/\b(?:metric\s+direction|direction)\s*[:#-]\s*(MAX|MIN|RANGE)\b/i]},
 {kind:'GOVERNANCE',field:'metricUnit',patterns:[/\b(?:metric\s+unit|unit)\s*[:#-]\s*([^|;,]{1,40})/i]},
 {kind:'COMPLIANCE',field:'obligationKey',patterns:[/\b(?:obligation\s+(?:id|key))\s*[:#-]\s*([A-Z0-9._-]{2,80})/i]},
 {kind:'COMPLIANCE',field:'obligationTitle',patterns:[/\b(?:obligation\s+(?:name|title)|obligation)\s*[:#-]\s*([^|;]{3,220})/i]},
 {kind:'COMPLIANCE',field:'obligationSource',patterns:[/\b(?:obligation\s+source|compliance\s+source)\s*[:#-]\s*([^|;]{3,500})/i]},
 {kind:'COMPLIANCE',field:'frequencyDays',patterns:[/\b(?:frequency\s+days|recurrence\s+days)\s*[:#-]\s*(\d{1,6})\b/i]},
 {kind:'COMPLIANCE',field:'nextDueAt',patterns:[/\b(?:next\s+due(?:\s+date)?|due\s+date)\s*[:#-]\s*(\d{4}-\d{2}-\d{2}(?:[T ][0-9:.+-Z]+)?)/i]},
 {kind:'AI_IMPACT',field:'impactKey',patterns:[/\b(?:ai\s+impact\s+(?:assessment\s+)?(?:id|key)|assessment\s+key)\s*[:#-]\s*([A-Z0-9._-]{2,80})/i]},
 {kind:'AI_IMPACT',field:'reviewPeriod',patterns:[/\b(?:ai\s+impact\s+)?review\s+period\s*[:#-]\s*([^|;]{2,120})/i]},
 {kind:'AI_IMPACT',field:'aiSystem',patterns:[/\b(?:ai\s+system|ai\s+use\s+case)\s*[:#-]\s*([^|;]{3,300})/i]},
 {kind:'AI_IMPACT',field:'intendedUse',patterns:[/\bintended\s+use\s*[:#-]\s*([^|;]{10,500})/i]},
 {kind:'AI_IMPACT',field:'foreseeableMisuse',patterns:[/\bforeseeable\s+misuse\s*[:#-]\s*([^|;]{10,500})/i]},
 {kind:'AI_IMPACT',field:'affectedParties',patterns:[/\b(?:affected\s+(?:parties|groups|persons)|impacted\s+groups)\s*[:#-]\s*([^|;]{10,500})/i]},
 {kind:'AI_IMPACT',field:'dataExposureImpact',patterns:[/\b(?:data(?:\/privacy)?\s+(?:exposure\s+)?impact|privacy\s+impact)\s*[:#-]\s*([^|;]{10,500})/i]},
 {kind:'AI_IMPACT',field:'erroneousOutputImpact',patterns:[/\b(?:erroneous\s+output\s+(?:impact|consequence)|incorrect\s+output\s+(?:impact|consequence))\s*[:#-]\s*([^|;]{10,500})/i]},
 {kind:'AI_IMPACT',field:'downstreamImpact',patterns:[/\b(?:downstream\s+(?:impact|effects?))\s*[:#-]\s*([^|;]{10,500})/i]},
 {kind:'AI_IMPACT',field:'humanOversight',patterns:[/\bhuman\s+oversight\s*[:#-]\s*([^|;]{10,500})/i]},
 {kind:'AI_IMPACT',field:'reviewTriggers',patterns:[/\b(?:review|change)\s+triggers?\s*[:#-]\s*([^|;]{10,500})/i]},
 {kind:'AI_IMPACT',field:'riskRating',patterns:[/\b(?:ai\s+impact\s+)?risk\s+(?:rating|level)\s*[:#-]\s*(low|medium|high|critical)\b/i]},
 {kind:'AI_IMPACT',field:'evidenceRefs',patterns:[/\b(?:validated\s+evidence(?:\s+vault)?\s+(?:version\s+)?(?:ids?|refs?)|evidence\s+vault\s+version\s+(?:ids?|refs?))\s*[:#-]\s*([^|;]{10,500})/i]}
];
function clean(v:string){return v.replace(/\s+/g,' ').trim().slice(0,500)}
function confidence(line:string,match:string){let n=.72;if(/[:#-]/.test(line))n+=.08;if(match.length>=4)n+=.05;if(line.length<220)n+=.05;return Math.min(.95,Math.round(n*100)/100)}
export function parseGrcDocumentDeterministically(text:string){
 const lines=String(text||'').split(/\r?\n/).map(clean).filter(Boolean).slice(0,20000),proposals:IntakeProposal[]=[];
 lines.forEach((line,idx)=>{for(const def of labels)for(const pattern of def.patterns){const m=line.match(pattern);if(!m?.[1])continue;const value=clean(m[1]);if(value.length<2&&!['likelihood','impact','rtoMinutes','rpoMinutes','mtdMinutes','frequencyDays'].includes(def.field))continue;proposals.push({id:crypto.createHash('sha256').update(idx+'|'+def.kind+'|'+def.field+'|'+value).digest('hex').slice(0,24),kind:def.kind,field:def.field,value,confidence:confidence(line,value),source:{line:idx+1,excerpt:line.slice(0,260)},rule:'LABEL_'+def.field.toUpperCase(),status:'PROPOSED'});break}});
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
 );
 CREATE TABLE IF NOT EXISTS grc_document_governed_records(
  id uuid PRIMARY KEY,intake_id uuid NOT NULL REFERENCES grc_document_intakes(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,scope_id uuid REFERENCES grc_scopes(id) ON DELETE CASCADE,
  record_type text NOT NULL,record_id uuid NOT NULL,source_line integer,source_excerpt text,created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(intake_id,record_type,record_id)
 );
 CREATE INDEX IF NOT EXISTS grc_intake_org_scope_idx ON grc_document_intakes(organization_id,scope_id,created_at DESC);
 CREATE INDEX IF NOT EXISTS grc_document_governed_records_intake_idx ON grc_document_governed_records(intake_id,record_type);`)}
export async function createGrcIntake(user:string,org:string,scopeId:string|undefined,file:{originalname:string;mimetype:string;buffer:Buffer}){
 await requireOrgPermission(user,org,'manageControl');
 const filename=String(file.originalname||'').replace(/[\\/\0]/g,'_').trim(),mime=String(file.mimetype||'').toLowerCase(),size=file.buffer?.length||0;
 if(!filename||size<1||size>10*1024*1024)throw Object.assign(new Error('Document must be between 1 byte and 10 MB'),{statusCode:413});
 const ext=(filename.toLowerCase().match(/\.[a-z0-9]+$/)?.[0]||''),textExt=new Set(['.txt','.md','.csv','.json','.xml','.yaml','.yml','.log']);
 const isPdf=ext==='.pdf'&&mime==='application/pdf'&&file.buffer.subarray(0,5).toString('ascii')==='%PDF-';
 const isDocx=ext==='.docx'&&mime==='application/vnd.openxmlformats-officedocument.wordprocessingml.document'&&file.buffer[0]===0x50&&file.buffer[1]===0x4b;
 const isSheet=['.xlsx','.xls'].includes(ext)&&['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','application/vnd.ms-excel'].includes(mime);
 let hasNul=false;for(let i=0;i<Math.min(file.buffer.length,4096);i++){if(file.buffer.readUInt8(i)===0){hasNul=true;break}}
 const isText=textExt.has(ext)&&(mime.startsWith('text/')||['application/json','application/xml','application/yaml','application/x-yaml','application/octet-stream'].includes(mime))&&!hasNul;
 if(!(isPdf||isDocx||isSheet||isText))throw Object.assign(new Error('File type, extension, and content signature do not match an allowed deterministic intake format'),{statusCode:415});if(scopeId){const s=(await pool.query('SELECT 1 FROM grc_scopes WHERE id=$1 AND organization_id=$2',[scopeId,org])).rows[0];if(!s)throw Object.assign(new Error('Scope not found in organization'),{statusCode:404})}
 const extracted=await extractDocument(filename,mime,file.buffer);const text=String(extracted.text||'');if(text.trim().length<20)throw Object.assign(new Error('Document has no usable text layer; scanned/image-only documents require text extraction before deterministic intake'),{statusCode:422});
 const sha=crypto.createHash('sha256').update(file.buffer).digest('hex'),textSha=crypto.createHash('sha256').update(text).digest('hex'),proposals=parseGrcDocumentDeterministically(text),id=crypto.randomUUID();
 const kinds=[...new Set(proposals.map(x=>x.kind).filter(x=>x!=='UNKNOWN'))],docKind=kinds.length===1?kinds[0]:kinds.length?'MIXED':'UNCLASSIFIED';const client=await pool.connect();
 try{await client.query('BEGIN');const prior=(await client.query('SELECT id,status,proposal_count FROM grc_document_intakes WHERE organization_id=$1 AND scope_id IS NOT DISTINCT FROM $2 AND sha256=$3',[org,scopeId||null,sha])).rows[0];
 if(prior){await client.query('ROLLBACK');return {id:prior.id,filename,sha256:sha,documentKind:docKind,pages:(extracted as any).pages||null,proposalCount:Number(prior.proposal_count||0),status:prior.status,engine:'DETERMINISTIC_RULE_ENGINE_V1',aiUsed:false,reused:true};}
 await client.query('INSERT INTO grc_document_intakes(id,organization_id,scope_id,filename,mime_type,sha256,document_kind,extracted_text_sha256,proposal_count,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[id,org,scopeId||null,filename,mime,sha,docKind,textSha,proposals.length,user]);
 for(const p of proposals)await client.query('INSERT INTO grc_document_intake_proposals(intake_id,proposal_id,kind,field,value,confidence,source_line,source_excerpt,rule) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[id,p.id,p.kind,p.field,p.value,p.confidence,p.source.line,p.source.excerpt,p.rule]);
 await client.query('COMMIT');return {id,filename,sha256:sha,documentKind:docKind,pages:(extracted as any).pages||null,proposalCount:proposals.length,status:'REVIEW_REQUIRED',engine:'DETERMINISTIC_RULE_ENGINE_V1',aiUsed:false};
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}
export async function listGrcIntakes(user:string,org:string){await requireOrgPermission(user,org,'read');const m=await membership(user,org);const canReviewRole=!!m&&roleAllows(m.role as any,'review');const intakes=(await pool.query(`SELECT i.id,i.scope_id,i.filename,i.document_kind,i.status,i.proposal_count,i.created_by,i.approved_by,i.approved_at,i.created_at,
 (SELECT count(*)::int FROM grc_document_intake_proposals p WHERE p.intake_id=i.id AND p.status='PROPOSED') pending_proposals,
 (SELECT count(*)::int FROM grc_document_intake_proposals p WHERE p.intake_id=i.id AND p.status='ACCEPTED') accepted_proposals,
 (SELECT count(*)::int FROM grc_document_intake_proposals p WHERE p.intake_id=i.id AND p.status='REJECTED') rejected_proposals,
 (SELECT count(*)::int FROM grc_document_intake_proposals p WHERE p.intake_id=i.id AND p.reviewed_by=$2) self_reviewed_proposals
 FROM grc_document_intakes i WHERE i.organization_id=$1 ORDER BY i.created_at DESC LIMIT 100`,[org,user])).rows.map((i:any)=>{const independent=i.created_by!==user&&Number(i.self_reviewed_proposals||0)===0;const ready=i.status==='REVIEWED'&&Number(i.pending_proposals||0)===0;const canApprove=canReviewRole&&independent&&ready;let approvalBlocker:string|null=null;if(!canReviewRole)approvalBlocker='Role '+String(m?.role||'MEMBER')+' does not have independent approval permission';else if(i.created_by===user)approvalBlocker='Uploader cannot independently approve the same intake';else if(Number(i.self_reviewed_proposals||0)>0)approvalBlocker='Proposal reviewer cannot independently approve the same intake';else if(i.status!=='REVIEWED')approvalBlocker='Intake must be REVIEWED before independent approval';else if(Number(i.pending_proposals||0)>0)approvalBlocker='All proposals must be accepted or rejected before approval';return {...i,viewer_role:m?.role||null,can_approve:canApprove,approval_blocker:canApprove?null:approvalBlocker}});return {intakes,viewerRole:m?.role||null}}
export async function getGrcIntake(user:string,org:string,id:string){await requireOrgPermission(user,org,'read');const intake=(await pool.query('SELECT * FROM grc_document_intakes WHERE id=$1 AND organization_id=$2',[id,org])).rows[0];if(!intake)throw Object.assign(new Error('Intake not found'),{statusCode:404});const proposals=(await pool.query('SELECT * FROM grc_document_intake_proposals WHERE intake_id=$1 ORDER BY source_line,proposal_id',[id])).rows;const governedRecords=(await pool.query('SELECT record_type,record_id,source_line,source_excerpt,created_at FROM grc_document_governed_records WHERE intake_id=$1 ORDER BY record_type,created_at',[id])).rows;return {intake,proposals,governedRecords,assurance:{aiUsed:false,automaticComplianceDecision:false,requiresHumanApproval:true,sourceProvenancePreserved:true}}}
export async function reviewGrcIntake(user:string,org:string,id:string,input:any){await requireOrgPermission(user,org,'manageControl');const decisions=Array.isArray(input?.decisions)?input.decisions:[];if(!decisions.length)throw new Error('At least one proposal decision is required');const client=await pool.connect();try{await client.query('BEGIN');const row=(await client.query('SELECT id,status FROM grc_document_intakes WHERE id=$1 AND organization_id=$2 FOR UPDATE',[id,org])).rows[0];if(!row)throw Object.assign(new Error('Intake not found'),{statusCode:404});if(['APPROVED','IMPORTED'].includes(String(row.status)))throw Object.assign(new Error('Approved or imported intake cannot be modified'),{statusCode:409});for(const d of decisions){const status=String(d.status||'').toUpperCase();if(!['ACCEPTED','REJECTED'].includes(status))throw new Error('Proposal decision must be ACCEPTED or REJECTED');const updated=await client.query('UPDATE grc_document_intake_proposals SET status=$3,reviewer_value=$4,reviewed_by=$5,reviewed_at=now() WHERE intake_id=$1 AND proposal_id=$2 RETURNING proposal_id',[id,String(d.proposalId),status,d.value==null?null:clean(String(d.value)),user]);if(!updated.rowCount)throw Object.assign(new Error('Proposal not found in this intake'),{statusCode:404})}await client.query("UPDATE grc_document_intakes SET status='REVIEWED' WHERE id=$1",[id]);await client.query('COMMIT');return getGrcIntake(user,org,id)}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}
export async function approveGrcIntake(user:string,org:string,id:string){await requireOrgPermission(user,org,'review');const client=await pool.connect();try{await client.query('BEGIN');const intake=(await client.query('SELECT * FROM grc_document_intakes WHERE id=$1 AND organization_id=$2 FOR UPDATE',[id,org])).rows[0];if(!intake)throw Object.assign(new Error('Intake not found'),{statusCode:404});if(intake.created_by===user)throw Object.assign(new Error('Independent reviewer required to approve document intake'),{statusCode:409});const selfReviewed=Number((await client.query('SELECT count(*) n FROM grc_document_intake_proposals WHERE intake_id=$1 AND reviewed_by=$2',[id,user])).rows[0]?.n||0);if(selfReviewed)throw Object.assign(new Error('Approver must be independent from proposal reviewer(s)'),{statusCode:409});const pending=Number((await client.query("SELECT count(*) n FROM grc_document_intake_proposals WHERE intake_id=$1 AND status='PROPOSED'",[id])).rows[0]?.n||0);if(pending)throw Object.assign(new Error('Every extracted proposal must be accepted or rejected before approval'),{statusCode:409});await client.query("UPDATE grc_document_intakes SET status='APPROVED',approved_by=$2,approved_at=now() WHERE id=$1",[id,user]);await client.query('COMMIT');return {id,status:'APPROVED',automaticWriteToGrc:false,nextStep:'Explicit governed import is required; approval does not establish compliance.'}}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}

export async function bindGrcIntakeScope(user:string,org:string,id:string,scopeId:string){
 await requireOrgPermission(user,org,'manageControl');const client=await pool.connect();
 try{await client.query('BEGIN');const intake=(await client.query("SELECT id,status FROM grc_document_intakes WHERE id=$1 AND organization_id=$2 FOR UPDATE",[id,org])).rows[0];
  if(!intake)throw Object.assign(new Error('Document intake not found'),{statusCode:404});
  if(!['REVIEW_REQUIRED','REVIEWED','APPROVED'].includes(String(intake.status)))throw Object.assign(new Error('Imported intake scope cannot be changed'),{statusCode:409});
  const scope=(await client.query('SELECT id FROM grc_scopes WHERE id=$1 AND organization_id=$2',[scopeId,org])).rows[0];if(!scope)throw Object.assign(new Error('Scope not found in organization'),{statusCode:404});
  await client.query('UPDATE grc_document_intakes SET scope_id=$1 WHERE id=$2',[scopeId,id]);await client.query('COMMIT');return {id,scopeId,status:intake.status};
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function importApprovedGrcIntake(user:string,org:string,id:string){
 await requireOrgPermission(user,org,'manageControl');const client=await pool.connect();
 try{await client.query('BEGIN');
  const intake=(await client.query("SELECT * FROM grc_document_intakes WHERE id=$1 AND organization_id=$2 AND status='APPROVED' FOR UPDATE",[id,org])).rows[0];
  if(!intake)throw Object.assign(new Error('Approved intake not found'),{statusCode:409});
  if(!intake.scope_id)throw Object.assign(new Error('A governed scope is required before importing document proposals'),{statusCode:409});
  const ps=(await client.query("SELECT *,COALESCE(NULLIF(reviewer_value,''),value) final_value FROM grc_document_intake_proposals WHERE intake_id=$1 AND status='ACCEPTED' ORDER BY source_line,proposal_id",[id])).rows;
  let imported=0;const importedByType:Record<string,number>={},limitations:string[]=[];
  const note=async(type:string,recordId:string,p:any)=>{await client.query('INSERT INTO grc_document_governed_records(id,intake_id,organization_id,scope_id,record_type,record_id,source_line,source_excerpt) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING',[crypto.randomUUID(),id,org,intake.scope_id,type,recordId,p?.source_line||null,p?.source_excerpt||null]);imported++;importedByType[type]=(importedByType[type]||0)+1};
  const groups=(kind:string,anchorField:string)=>{const rows=ps.filter((p:any)=>p.kind===kind),anchors=rows.filter((p:any)=>p.field===anchorField);return anchors.map((anchor:any,i:number)=>({anchor,rows:rows.filter((p:any)=>Number(p.source_line)>=Number(anchor.source_line)&&Number(p.source_line)<(i+1<anchors.length?Number(anchors[i+1].source_line):Number.MAX_SAFE_INTEGER))}))};
  const val=(rows:any[],field:string)=>clean(String(rows.find((x:any)=>x.field===field)?.final_value||''));
  for(const g of groups('CONTROL','controlKey')){
   const key=val(g.rows,'controlKey').toUpperCase();let control=(await client.query('SELECT id FROM grc_canonical_controls WHERE upper(control_key)=upper($1)',[key])).rows[0];if(!control){const title=val(g.rows,'controlTitle');if(title.length>=3)control=(await client.query("INSERT INTO grc_canonical_controls(id,control_key,title,description,domain) VALUES($1,$2,$3,'',$4) ON CONFLICT(control_key) DO UPDATE SET title=EXCLUDED.title,domain=EXCLUDED.domain,updated_at=now() RETURNING id",[crypto.randomUUID(),key,title,(val(g.rows,'controlDomain')||'GENERAL').toUpperCase()])).rows[0];else{limitations.push('Control '+key+' remains staged because an unknown control requires a document-supplied title.');continue}}
   const suppliedApplicability=val(g.rows,'applicability').toUpperCase().replace(/[ -]/g,'_'),suppliedImplementation=val(g.rows,'implementation').toUpperCase().replace(/ /g,'_');
   const applicability=suppliedApplicability||'PENDING',implementation=suppliedImplementation||'NOT_IMPLEMENTED';
   if(!['APPLICABLE','NOT_APPLICABLE','PENDING'].includes(applicability)||!['NOT_IMPLEMENTED','PLANNED','PARTIAL','IMPLEMENTED'].includes(implementation)){limitations.push('Control '+key+' has unsupported applicability or implementation.');continue}
   const suppliedJustification=val(g.rows,'justification'),justification=suppliedJustification||(suppliedApplicability?'Document did not supply applicability justification; accountable human review required.':'Document did not supply an applicability decision; accountable human review required.');
   if(!suppliedApplicability)limitations.push('Control '+key+' imported with PENDING applicability because the document supplied no applicability decision; human review is required.');
   if(!suppliedImplementation)limitations.push('Control '+key+' imported as NOT_IMPLEMENTED because the document supplied no implementation state; human review is required.');
   const row=(await client.query('INSERT INTO grc_scope_controls(id,organization_id,scope_id,control_id,applicability,implementation,applicability_justification) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(scope_id,control_id) DO UPDATE SET applicability=EXCLUDED.applicability,implementation=EXCLUDED.implementation,applicability_justification=EXCLUDED.applicability_justification,updated_at=now() RETURNING id',[crypto.randomUUID(),org,intake.scope_id,control.id,applicability,implementation,justification])).rows[0];await note('CONTROL',row.id,g.anchor);
  }
  if(ps.some((p:any)=>['RISK','VENDOR'].includes(p.kind)))await requireOrgPermission(user,org,'manageRisk');if(ps.some((p:any)=>p.kind==='AUDIT'))await requireOrgPermission(user,org,'review');
  for(const g of groups('RISK','riskTitle')){
   const title=val(g.rows,'riskTitle'),likelihood=Number(val(g.rows,'likelihood')),impact=Number(val(g.rows,'impact'));if(!title||!Number.isInteger(likelihood)||likelihood<1||likelihood>5||!Number.isInteger(impact)||impact<1||impact>5){limitations.push('Risk '+(title||'(untitled)')+' remains staged because likelihood and impact 1-5 are required.');continue}
   const score=likelihood*impact,rating=score>=20?'CRITICAL':score>=15?'HIGH':score>=8?'MEDIUM':score>=4?'LOW':'VERY_LOW',rawKey=val(g.rows,'riskKey').toUpperCase(),key=rawKey||('DOC-'+id.slice(0,8).toUpperCase()+'-RISK-'+g.anchor.source_line),treatment=val(g.rows,'treatment').toUpperCase();
   if(!treatment||!['MITIGATE','ACCEPT','TRANSFER','AVOID'].includes(treatment)){limitations.push('Risk '+key+' has unsupported treatment.');continue}
   const row=(await client.query("INSERT INTO grc_enterprise_risks(id,organization_id,risk_key,title,description,likelihood,impact,inherent_score,inherent_rating,treatment,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'OPEN',$11) ON CONFLICT(risk_key) DO UPDATE SET title=EXCLUDED.title,description=EXCLUDED.description,likelihood=EXCLUDED.likelihood,impact=EXCLUDED.impact,inherent_score=EXCLUDED.inherent_score,inherent_rating=EXCLUDED.inherent_rating,treatment=EXCLUDED.treatment,updated_at=now() WHERE grc_enterprise_risks.organization_id=EXCLUDED.organization_id RETURNING id",[crypto.randomUUID(),org,key,title,val(g.rows,'riskDescription'),likelihood,impact,score,rating,treatment,user])).rows[0];if(row)await note('RISK',row.id,g.anchor);
  }
  for(const g of groups('VENDOR','vendorName')){
   const name=val(g.rows,'vendorName');if(!name)continue;const generated=name.toUpperCase().replace(/[^A-Z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,50),key=val(g.rows,'vendorKey').toUpperCase()||generated||('VENDOR-'+g.anchor.source_line),tier0=val(g.rows,'vendorTier').toUpperCase().replace(/[ -]/g,'_'),tier=/^[1-4]$/.test(tier0)?'TIER_'+tier0:tier0,crit=val(g.rows,'vendorCriticality').toUpperCase();
   if(!/^TIER_[1-4]$/.test(tier)||!['LOW','MEDIUM','HIGH','CRITICAL'].includes(crit)){limitations.push('Vendor '+name+' has unsupported tier or criticality.');continue}
   const row=(await client.query("INSERT INTO grc_third_parties(id,organization_id,vendor_key,name,service,tier,criticality,status,metadata,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,'DUE_DILIGENCE',$8,$9) ON CONFLICT(organization_id,vendor_key) DO UPDATE SET name=EXCLUDED.name,service=EXCLUDED.service,tier=EXCLUDED.tier,criticality=EXCLUDED.criticality,updated_at=now() RETURNING id",[crypto.randomUUID(),org,key,name,val(g.rows,'vendorService'),tier,crit,{documentIntakeId:id,sourceLine:g.anchor.source_line},user])).rows[0];await note('VENDOR',row.id,g.anchor);
  }
  for(const g of groups('POLICY','policyTitle')){
   const title=val(g.rows,'policyTitle'),category=val(g.rows,'policyCategory'),version=val(g.rows,'policyVersion');if(!title)continue;if(!category||!version){limitations.push('Policy '+title+' remains staged because category and version must be explicitly supplied by the document.');continue}const generated=title.toUpperCase().replace(/[^A-Z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,50),key=val(g.rows,'policyKey').toUpperCase()||generated||('POLICY-'+g.anchor.source_line);
   const row=(await client.query("INSERT INTO grc_policies(id,organization_id,scope_id,policy_key,title,category,version,status,content_ref,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,'DRAFT',$8,$9) ON CONFLICT(organization_id,policy_key) DO UPDATE SET title=EXCLUDED.title,category=EXCLUDED.category,version=EXCLUDED.version,content_ref=EXCLUDED.content_ref,updated_at=now() RETURNING id",[crypto.randomUUID(),org,intake.scope_id,key,title,category,version,'DOCUMENT_INTAKE:'+id+'#line:'+g.anchor.source_line,user])).rows[0];await note('POLICY',row.id,g.anchor);
  }
  for(const g of groups('AUDIT','auditTitle')){
   const title=val(g.rows,'auditTitle'),objective=val(g.rows,'auditObjective'),criteria=val(g.rows,'auditCriteria');if(!title||objective.length<5||criteria.length<3){limitations.push('Audit '+(title||'(untitled)')+' remains staged because title, objective and criteria are required.');continue}
   const key=val(g.rows,'auditKey').toUpperCase()||('DOC-'+id.slice(0,8).toUpperCase()+'-AUDIT-'+g.anchor.source_line),type=val(g.rows,'auditType').toUpperCase().replace(/[- ]/g,'_');if(!['INTERNAL','EXTERNAL','SUPPLIER','REGULATORY','CERTIFICATION','FOLLOW_UP'].includes(type)){limitations.push('Audit '+key+' has unsupported type.');continue}
   const row=(await client.query("INSERT INTO grc_audits(id,organization_id,scope_id,audit_key,title,audit_type,objective,criteria,lead_auditor_id,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'PLANNED',$9) ON CONFLICT(organization_id,audit_key) DO UPDATE SET title=EXCLUDED.title,objective=EXCLUDED.objective,criteria=EXCLUDED.criteria,updated_at=now() RETURNING id",[crypto.randomUUID(),org,intake.scope_id,key,title,type,objective,criteria,user])).rows[0];await note('AUDIT',row.id,g.anchor);
   for(const finding of g.rows.filter((x:any)=>x.field==='auditFinding')){const title2=clean(finding.final_value),exists=(await client.query('SELECT 1 FROM grc_audit_workpapers WHERE audit_id=$1 AND title=$2',[row.id,title2])).rows[0];if(!exists)await client.query("INSERT INTO grc_audit_workpapers(id,organization_id,audit_id,title,procedure,conclusion,result,prepared_by) VALUES($1,$2,$3,$4,$5,'','NOT_TESTED',$6)",[crypto.randomUUID(),org,row.id,title2,'Validate document-derived audit observation against governed evidence.',user])}
  }
  for(const g of groups('PRIVACY','activityKey')){
   const key=val(g.rows,'activityKey').toUpperCase(),name=val(g.rows,'activityName'),purpose=val(g.rows,'processingPurpose'),ground=val(g.rows,'processingGround'),retention=val(g.rows,'retentionRule');
   if(!key||name.length<3||purpose.length<3||!ground||!retention){limitations.push('Privacy processing activity '+(key||'(unkeyed)')+' remains staged because key, name, purpose, processing ground and retention are required.');continue}
   const split=(x:string)=>x.split(/[,;]/).map(v=>clean(v)).filter(Boolean);
   const row=(await client.query("INSERT INTO grc_privacy_processing_inventory(id,organization_id,activity_key,name,purpose,processing_ground,data_categories,systems,recipients,retention_rule,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'DRAFT',$11) ON CONFLICT(organization_id,activity_key) DO UPDATE SET name=EXCLUDED.name,purpose=EXCLUDED.purpose,processing_ground=EXCLUDED.processing_ground,data_categories=EXCLUDED.data_categories,systems=EXCLUDED.systems,recipients=EXCLUDED.recipients,retention_rule=EXCLUDED.retention_rule,status='DRAFT',updated_at=now() RETURNING id",[crypto.randomUUID(),org,key,name,purpose,ground,split(val(g.rows,'dataCategories')),split(val(g.rows,'systems')),split(val(g.rows,'recipients')),retention,user])).rows[0];await note('PRIVACY_PROCESSING_ACTIVITY',row.id,g.anchor);
  }
  for(const g of groups('LEGAL','legalKey')){
   const key=val(g.rows,'legalKey').toUpperCase(),title=val(g.rows,'legalTitle'),source=val(g.rows,'legalSource');if(!key||title.length<3||source.length<3){limitations.push('Legal reference '+(key||'(unkeyed)')+' remains staged because key, title and authoritative source reference are required.');continue}
   const row=(await client.query("INSERT INTO grc_privacy_legal_register(id,organization_id,reference_key,title,source_reference,applicability_status,commencement_status,rationale,created_by) VALUES($1,$2,$3,$4,$5,'REVIEW_REQUIRED','VERIFY_CURRENT',$6,$7) ON CONFLICT(organization_id,reference_key) DO UPDATE SET title=EXCLUDED.title,source_reference=EXCLUDED.source_reference,applicability_status='REVIEW_REQUIRED',commencement_status='VERIFY_CURRENT',rationale=EXCLUDED.rationale,reviewed_by=NULL,reviewed_at=NULL,updated_at=now() RETURNING id",[crypto.randomUUID(),org,key,title,source,'Imported from approved document; legal applicability and commencement require independent review.',user])).rows[0];await note('LEGAL_REFERENCE',row.id,g.anchor);
  }
  for(const g of groups('ARCHITECTURE','componentKey')){
   const key=val(g.rows,'componentKey').toUpperCase(),name=val(g.rows,'componentName'),type=val(g.rows,'componentType').toUpperCase().replace(/[ -]/g,'_'),crit=val(g.rows,'componentCriticality').toUpperCase(),exposed=/^(YES|TRUE)$/i.test(val(g.rows,'internetExposed'));
   if(!key||!name||!['FIREWALL','WAF','LOAD_BALANCER','ROUTER','SWITCH','VPN_GATEWAY','IDS_IPS','CDN','DNS','REVERSE_PROXY','SERVICE','DATA_FLOW','TRUST_BOUNDARY'].includes(type)||!['LOW','MEDIUM','HIGH','CRITICAL'].includes(crit)){limitations.push('Architecture component '+(key||'(unkeyed)')+' remains staged because key, name, supported type and criticality are required.');continue}
   const row=(await client.query("INSERT INTO grc_architecture_components(id,organization_id,scope_id,component_key,name,component_type,criticality,internet_exposed,metadata,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'ACTIVE',$10) ON CONFLICT(organization_id,component_key) DO UPDATE SET scope_id=EXCLUDED.scope_id,name=EXCLUDED.name,component_type=EXCLUDED.component_type,criticality=EXCLUDED.criticality,internet_exposed=EXCLUDED.internet_exposed,metadata=EXCLUDED.metadata,updated_at=now() RETURNING id",[crypto.randomUUID(),org,intake.scope_id,key,name,type,crit,exposed,{documentIntakeId:id,sourceLine:g.anchor.source_line},user])).rows[0];await note('ARCHITECTURE_COMPONENT',row.id,g.anchor);
  }
  for(const g of groups('RESILIENCE','serviceKey')){
   await requireOrgPermission(user,org,'manageRisk');const key=val(g.rows,'serviceKey').toUpperCase(),name=val(g.rows,'serviceName'),rto=Number(val(g.rows,'rtoMinutes')),rpo=Number(val(g.rows,'rpoMinutes')),mtd=Number(val(g.rows,'mtdMinutes')),crit=val(g.rows,'serviceCriticality').toUpperCase();
   if(!key||name.length<3||!Number.isInteger(rto)||rto<1||!Number.isInteger(rpo)||rpo<0||!Number.isInteger(mtd)||mtd<rto||!['LOW','MEDIUM','HIGH','CRITICAL'].includes(crit)){limitations.push('Business service '+(key||'(unkeyed)')+' remains staged because valid key, name, criticality, RTO, RPO and MTD are required.');continue}
   const row=(await client.query("INSERT INTO grc_business_services(id,organization_id,scope_id,service_key,name,criticality,rto_minutes,rpo_minutes,mtd_minutes,recovery_strategy,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'ACTIVE',$11) ON CONFLICT(organization_id,service_key) DO UPDATE SET scope_id=EXCLUDED.scope_id,name=EXCLUDED.name,criticality=EXCLUDED.criticality,rto_minutes=EXCLUDED.rto_minutes,rpo_minutes=EXCLUDED.rpo_minutes,mtd_minutes=EXCLUDED.mtd_minutes,recovery_strategy=EXCLUDED.recovery_strategy,updated_at=now() RETURNING id",[crypto.randomUUID(),org,intake.scope_id,key,name,crit,rto,rpo,mtd,val(g.rows,'recoveryStrategy'),user])).rows[0];await note('BUSINESS_SERVICE',row.id,g.anchor);
  }
  for(const g of groups('GOVERNANCE','appetiteKey')){
   await requireOrgPermission(user,org,'manageRisk');const key=val(g.rows,'appetiteKey').toUpperCase(),title=val(g.rows,'appetiteTitle'),statement=val(g.rows,'appetiteStatement'),rating=val(g.rows,'toleranceRating').toUpperCase();
   if(!key||title.length<3||statement.length<15||!['LOW','MEDIUM','HIGH','CRITICAL'].includes(rating)){limitations.push('Risk appetite '+(key||'(unkeyed)')+' remains staged because key, title, meaningful statement and valid tolerance are required.');continue}
   const row=(await client.query("INSERT INTO grc_risk_appetite_statements(id,organization_id,appetite_key,title,category,statement,tolerance_rating,status,created_by) VALUES($1,$2,$3,$4,'ENTERPRISE',$5,$6,'DRAFT',$7) ON CONFLICT(organization_id,appetite_key) DO UPDATE SET title=EXCLUDED.title,statement=EXCLUDED.statement,tolerance_rating=EXCLUDED.tolerance_rating,status='DRAFT',approved_by=NULL,approved_at=NULL,updated_at=now() RETURNING id",[crypto.randomUUID(),org,key,title,statement,rating,user])).rows[0];await note('RISK_APPETITE',row.id,g.anchor);
  }
  for(const g of groups('GOVERNANCE','metricKey')){
   const key=val(g.rows,'metricKey').toUpperCase(),title=val(g.rows,'metricTitle'),type=val(g.rows,'metricType').toUpperCase(),direction=val(g.rows,'metricDirection').toUpperCase(),unit=val(g.rows,'metricUnit');if(!key||title.length<3||!['KPI','KRI','KCI'].includes(type)||!['MAX','MIN','RANGE'].includes(direction)||!unit){limitations.push('Governance metric '+(key||'(unkeyed)')+' remains staged because key, title, type, direction and unit are required.');continue}
   const row=(await client.query("INSERT INTO grc_performance_metrics(id,organization_id,scope_id,metric_key,title,metric_type,direction,unit,active,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,true,$9) ON CONFLICT(organization_id,metric_key) DO UPDATE SET scope_id=EXCLUDED.scope_id,title=EXCLUDED.title,metric_type=EXCLUDED.metric_type,direction=EXCLUDED.direction,unit=EXCLUDED.unit,active=true,updated_at=now() RETURNING id",[crypto.randomUUID(),org,intake.scope_id,key,title,type,direction,unit,user])).rows[0];await note('GOVERNANCE_METRIC',row.id,g.anchor);
  }
  for(const g of groups('AI_IMPACT','impactKey')){
   await requireOrgPermission(user,org,'manageRisk');
   const key=val(g.rows,'impactKey').toUpperCase(),period=val(g.rows,'reviewPeriod'),risk=val(g.rows,'riskRating').toUpperCase();
   const impact:any={aiSystem:val(g.rows,'aiSystem'),intendedUse:val(g.rows,'intendedUse'),foreseeableMisuse:val(g.rows,'foreseeableMisuse'),affectedParties:val(g.rows,'affectedParties'),dataExposureImpact:val(g.rows,'dataExposureImpact'),erroneousOutputImpact:val(g.rows,'erroneousOutputImpact'),downstreamImpact:val(g.rows,'downstreamImpact'),humanOversight:val(g.rows,'humanOversight'),reviewTriggers:val(g.rows,'reviewTriggers'),riskRating:risk};
   const missing=Object.entries(impact).filter(([k,v])=>k==='riskRating'?!['LOW','MEDIUM','HIGH','CRITICAL'].includes(String(v)):String(v||'').trim().length<10).map(([k])=>k);
   if(!key||!period||missing.length){limitations.push('AI impact assessment '+(key||'(unkeyed)')+' remains staged because review period and all governed impact dimensions are required'+(missing.length?': '+missing.join(', '):'.'));continue}
   const refs=val(g.rows,'evidenceRefs').split(/[\s,]+/).map(x=>x.trim()).filter(Boolean),uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
   if(!refs.length||refs.some(x=>!uuid.test(x))){limitations.push('AI impact assessment '+key+' remains staged because current Evidence Vault version UUIDs must be explicitly supplied and validated.');continue}
   const ev=(await client.query("SELECT count(*)::int n FROM grc_evidence_versions v JOIN grc_evidence_requests r ON r.id=v.evidence_request_id WHERE r.organization_id=$1 AND v.id=ANY($2::uuid[]) AND r.status='VALID' AND v.integrity_status='SERVER_VERIFIED' AND v.validated_at IS NOT NULL AND v.validated_by IS NOT NULL AND v.validated_by IS DISTINCT FROM v.submitted_by AND v.valid_until>now()",[org,[...new Set(refs)]])).rows[0];
   if(Number(ev?.n)!==new Set(refs).size){limitations.push('AI impact assessment '+key+' remains staged because supplied Evidence Vault versions are not all current and independently validated.');continue}
   impact.evidenceRefs=[...new Set(refs)];const reviewKey=key.startsWith('AI-IMPACT-')?key:'AI-IMPACT-'+key;
   const row=(await client.query("INSERT INTO grc_management_reviews(id,organization_id,scope_id,review_key,title,review_period,inputs,decisions,actions,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,'[]'::jsonb,'[]'::jsonb,'SUBMITTED',$8) ON CONFLICT(organization_id,review_key) DO UPDATE SET scope_id=EXCLUDED.scope_id,title=EXCLUDED.title,review_period=EXCLUDED.review_period,inputs=EXCLUDED.inputs,decisions='[]'::jsonb,actions='[]'::jsonb,status='SUBMITTED',approved_by=NULL,approved_at=NULL,updated_at=now() RETURNING id",[crypto.randomUUID(),org,intake.scope_id,reviewKey,'ISO 42001 AI Impact Assessment',period,JSON.stringify({profile:'ISO42001_AI_IMPACT',impact}),user])).rows[0];await note('AI_IMPACT_ASSESSMENT',row.id,g.anchor);
  }
  for(const g of groups('COMPLIANCE','obligationKey')){
   const key=val(g.rows,'obligationKey').toUpperCase(),title=val(g.rows,'obligationTitle'),source=val(g.rows,'obligationSource'),frequency=Number(val(g.rows,'frequencyDays')),dueRaw=val(g.rows,'nextDueAt'),due=new Date(dueRaw);
   if(!key||title.length<3||source.length<3||!Number.isInteger(frequency)||frequency<1||!dueRaw||Number.isNaN(due.getTime())){limitations.push('Compliance obligation '+(key||'(unkeyed)')+' remains staged because key, title, source, frequency days and next due date are required.');continue}
   const row=(await client.query("INSERT INTO grc_obligations(id,organization_id,scope_id,obligation_key,title,source,frequency_days,next_due_at,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'OPEN',$9) ON CONFLICT(organization_id,obligation_key) DO UPDATE SET scope_id=EXCLUDED.scope_id,title=EXCLUDED.title,source=EXCLUDED.source,frequency_days=EXCLUDED.frequency_days,next_due_at=EXCLUDED.next_due_at,status='OPEN',updated_at=now() RETURNING id",[crypto.randomUUID(),org,intake.scope_id,key,title,source,frequency,due,user])).rows[0];await note('COMPLIANCE_OBLIGATION',row.id,g.anchor);
  }
  if(!imported)throw Object.assign(new Error('No accepted proposal matched a safe governed write adapter; approved staged data was preserved and nothing was imported'),{statusCode:409});
  await client.query("UPDATE grc_document_intakes SET status='IMPORTED' WHERE id=$1",[id]);await client.query('COMMIT');return {id,status:'IMPORTED',recordsImported:imported,importedByType,automaticComplianceDecision:false,governedRecords:true,limitations:[...new Set(limitations)]};
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}

export async function applyGrcIntakeAutofill(user:string,org:string,id:string){
 await requireOrgPermission(user,org,'manageScope');const client=await pool.connect();
 try{await client.query('BEGIN');const intake=(await client.query('SELECT * FROM grc_document_intakes WHERE id=$1 AND organization_id=$2 FOR UPDATE',[id,org])).rows[0];
  if(!intake)throw Object.assign(new Error('Document intake not found'),{statusCode:404});
  const ps=(await client.query("SELECT *,COALESCE(NULLIF(reviewer_value,''),value) final_value FROM grc_document_intake_proposals WHERE intake_id=$1 ORDER BY confidence DESC,source_line",[id])).rows;
  const pick=(kind:string,field:string)=>ps.find((p:any)=>p.kind===kind&&p.field===field)?.final_value;
  const name=clean(String(pick('SCOPE','scopeName')||'')),description=clean(String(pick('SCOPE','scopeDescription')||''));let scope:any=null;
  if(name){scope=(await client.query('SELECT * FROM grc_scopes WHERE organization_id=$1 AND lower(name)=lower($2)',[org,name])).rows[0];if(!scope)scope=(await client.query('INSERT INTO grc_scopes(id,organization_id,name,description,created_by) VALUES($1,$2,$3,$4,$5) RETURNING *',[crypto.randomUUID(),org,name,description||('Autofilled from governed document '+intake.filename),user])).rows[0];else if(description&&!scope.description)scope=(await client.query('UPDATE grc_scopes SET description=$3,updated_at=now() WHERE id=$1 AND organization_id=$2 RETURNING *',[scope.id,org,description])).rows[0];await client.query('UPDATE grc_document_intakes SET scope_id=$1 WHERE id=$2',[scope.id,id])}
  const facts=ps.map((p:any)=>({proposalId:p.proposal_id,kind:p.kind,field:p.field,value:p.final_value,confidence:Number(p.confidence),sourceLine:p.source_line,sourceExcerpt:p.source_excerpt,rule:p.rule,status:p.status}));
  const byKind=facts.reduce((a:any,x:any)=>{(a[x.kind]||(a[x.kind]=[])).push(x);return a},{});
  await client.query('COMMIT');return {id,scope,autofill:{scopeName:name||null,scopeDescription:description||null,facts,byKind},proposalCount:ps.length,assurance:{automaticComplianceDecision:false,requiresHumanReview:true,provenancePreserved:true}};
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function documentIntakeReportContext(user:string,org:string,scopeId:string){await requireOrgPermission(user,org,'read');const intakes=(await pool.query("SELECT id,filename,sha256,document_kind,status,created_at,approved_at FROM grc_document_intakes WHERE organization_id=$1 AND scope_id=$2 AND status='IMPORTED' ORDER BY created_at DESC",[org,scopeId])).rows;const ids=intakes.map((x:any)=>x.id);if(!ids.length)return {intakes:[],declaredFrameworks:[],governedRecords:[]};const frameworks=(await pool.query("SELECT DISTINCT value FROM grc_document_intake_proposals WHERE intake_id=ANY($1::uuid[]) AND kind='CONTROL' AND field='framework' AND status='ACCEPTED' ORDER BY value",[ids])).rows.map((x:any)=>x.value);const governedRecords=(await pool.query('SELECT intake_id,record_type,record_id,source_line,source_excerpt,created_at FROM grc_document_governed_records WHERE intake_id=ANY($1::uuid[]) ORDER BY created_at',[ids])).rows;return {intakes,declaredFrameworks:frameworks,governedRecords}}
