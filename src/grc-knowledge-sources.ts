import crypto from 'node:crypto';
import pg from 'pg';
import {requireOrgPermission} from './grc-organizations.js';

const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});

export type KnowledgeAuthority='AUTHORITATIVE'|'IMPLEMENTATION_AID'|'EDUCATIONAL'|'INTERNAL';
export type KnowledgeItemType='GUIDANCE'|'ASSESSMENT_QUESTION'|'EVIDENCE_EXPECTATION'|'CONTROL_CANDIDATE'|'TERM'|'RISK_PATTERN';

export async function initKnowledgeSources(){
 await pool.query(`
 CREATE TABLE IF NOT EXISTS grc_knowledge_sources(
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
  sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'),
  title text NOT NULL,
  source_type text NOT NULL DEFAULT 'PDF' CHECK(source_type IN ('PDF','WEB','STANDARD','REGULATION','INTERNAL','OTHER')),
  authority_class text NOT NULL CHECK(authority_class IN ('AUTHORITATIVE','IMPLEMENTATION_AID','EDUCATIONAL','INTERNAL')),
  framework text,framework_version text,publisher text,publication_date date,
  source_ref text,license_note text,
  review_status text NOT NULL DEFAULT 'PENDING' CHECK(review_status IN ('PENDING','REVIEWED','REJECTED')),
  reviewed_by uuid REFERENCES app_users(id) ON DELETE SET NULL,reviewed_at timestamptz,
  created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(organization_id,sha256)
 );
 CREATE TABLE IF NOT EXISTS grc_knowledge_items(
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
  source_id uuid NOT NULL REFERENCES grc_knowledge_sources(id) ON DELETE CASCADE,
  item_key text NOT NULL,
  item_type text NOT NULL CHECK(item_type IN ('GUIDANCE','ASSESSMENT_QUESTION','EVIDENCE_EXPECTATION','CONTROL_CANDIDATE','TERM','RISK_PATTERN')),
  title text NOT NULL,content text NOT NULL,
  page_ref text,section_ref text,
  confidence numeric(4,3) CHECK(confidence IS NULL OR (confidence>=0 AND confidence<=1)),
  review_status text NOT NULL DEFAULT 'DRAFT' CHECK(review_status IN ('DRAFT','VERIFIED','REJECTED')),
  verified_by uuid REFERENCES app_users(id) ON DELETE SET NULL,verified_at timestamptz,
  created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(source_id,item_key)
 );
 CREATE TABLE IF NOT EXISTS grc_knowledge_control_links(
  knowledge_item_id uuid NOT NULL REFERENCES grc_knowledge_items(id) ON DELETE CASCADE,
  control_id uuid NOT NULL REFERENCES grc_canonical_controls(id) ON DELETE CASCADE,
  link_type text NOT NULL DEFAULT 'SUPPORTS' CHECK(link_type IN ('SUPPORTS','EVIDENCE_FOR','ASSESSMENT_FOR','CONTEXT_FOR')),
  linked_by uuid REFERENCES app_users(id) ON DELETE SET NULL,linked_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(knowledge_item_id,control_id,link_type)
 );
 CREATE INDEX IF NOT EXISTS grc_knowledge_sources_org_idx ON grc_knowledge_sources(organization_id,review_status,authority_class);
 CREATE INDEX IF NOT EXISTS grc_knowledge_items_org_idx ON grc_knowledge_items(organization_id,source_id,review_status);
 `);
}

const clean=(x:any,n=1000)=>String(x??'').trim().slice(0,n);

export async function registerKnowledgeSource(userId:string,orgId:string,input:any){
 await requireOrgPermission(userId,orgId,'manageControl');
 const sha=clean(input.sha256,64).toLowerCase();
 if(!/^[a-f0-9]{64}$/.test(sha))throw new Error('Valid source SHA-256 is required');
 const title=clean(input.title,300);if(title.length<3)throw new Error('Source title required');
 const authority=clean(input.authorityClass,40).toUpperCase() as KnowledgeAuthority;
 if(!['AUTHORITATIVE','IMPLEMENTATION_AID','EDUCATIONAL','INTERNAL'].includes(authority))throw new Error('Invalid authority class');
 const sourceType=clean(input.sourceType||'PDF',20).toUpperCase();
 if(!['PDF','WEB','STANDARD','REGULATION','INTERNAL','OTHER'].includes(sourceType))throw new Error('Invalid source type');
 return (await pool.query(`INSERT INTO grc_knowledge_sources(id,organization_id,sha256,title,source_type,authority_class,framework,framework_version,publisher,publication_date,source_ref,license_note,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
 ON CONFLICT(organization_id,sha256) DO UPDATE SET title=EXCLUDED.title,source_ref=COALESCE(EXCLUDED.source_ref,grc_knowledge_sources.source_ref)
 RETURNING *`,[crypto.randomUUID(),orgId,sha,title,sourceType,authority,clean(input.framework,100)||null,clean(input.frameworkVersion,80)||null,clean(input.publisher,200)||null,input.publicationDate||null,clean(input.sourceRef,1000)||null,clean(input.licenseNote,1000)||null,userId])).rows[0];
}

export async function reviewKnowledgeSource(userId:string,orgId:string,sourceId:string,decision:'REVIEWED'|'REJECTED'){
 await requireOrgPermission(userId,orgId,'review');
 const d=String(decision).toUpperCase();if(!['REVIEWED','REJECTED'].includes(d))throw new Error('Invalid source review decision');
 const row=(await pool.query('SELECT * FROM grc_knowledge_sources WHERE id=$1 AND organization_id=$2',[sourceId,orgId])).rows[0];
 if(!row)throw Object.assign(new Error('Knowledge source not found'),{statusCode:404});
 if(row.created_by===userId)throw Object.assign(new Error('Independent source reviewer required'),{statusCode:409});
 return (await pool.query('UPDATE grc_knowledge_sources SET review_status=$3,reviewed_by=$4,reviewed_at=now() WHERE id=$1 AND organization_id=$2 RETURNING *',[sourceId,orgId,d,userId])).rows[0];
}

export async function createKnowledgeItem(userId:string,orgId:string,sourceId:string,input:any){
 await requireOrgPermission(userId,orgId,'manageControl');
 const source=(await pool.query('SELECT id FROM grc_knowledge_sources WHERE id=$1 AND organization_id=$2',[sourceId,orgId])).rows[0];
 if(!source)throw Object.assign(new Error('Knowledge source not found'),{statusCode:404});
 const type=clean(input.itemType,40).toUpperCase() as KnowledgeItemType;
 if(!['GUIDANCE','ASSESSMENT_QUESTION','EVIDENCE_EXPECTATION','CONTROL_CANDIDATE','TERM','RISK_PATTERN'].includes(type))throw new Error('Invalid knowledge item type');
 const key=clean(input.itemKey,120).toUpperCase(),title=clean(input.title,300),body=clean(input.content,4000);
 if(!key||title.length<3||body.length<3)throw new Error('Knowledge item key, title and content are required');
 const confidence=input.confidence==null?null:Number(input.confidence);if(confidence!=null&&(!Number.isFinite(confidence)||confidence<0||confidence>1))throw new Error('Confidence must be between 0 and 1');
 return (await pool.query(`INSERT INTO grc_knowledge_items(id,organization_id,source_id,item_key,item_type,title,content,page_ref,section_ref,confidence,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
 ON CONFLICT(source_id,item_key) DO UPDATE SET item_type=EXCLUDED.item_type,title=EXCLUDED.title,content=EXCLUDED.content,page_ref=EXCLUDED.page_ref,section_ref=EXCLUDED.section_ref,confidence=EXCLUDED.confidence,review_status='DRAFT',verified_by=NULL,verified_at=NULL
 RETURNING *`,[crypto.randomUUID(),orgId,sourceId,key,type,title,body,clean(input.pageRef,80)||null,clean(input.sectionRef,300)||null,confidence,userId])).rows[0];
}

export async function verifyKnowledgeItem(userId:string,orgId:string,itemId:string,decision:'VERIFIED'|'REJECTED'){
 await requireOrgPermission(userId,orgId,'review');
 const d=String(decision).toUpperCase();if(!['VERIFIED','REJECTED'].includes(d))throw new Error('Invalid knowledge item review decision');
 const row=(await pool.query(`SELECT i.*,s.review_status source_review_status FROM grc_knowledge_items i
 JOIN grc_knowledge_sources s ON s.id=i.source_id AND s.organization_id=i.organization_id
 WHERE i.id=$1 AND i.organization_id=$2`,[itemId,orgId])).rows[0];
 if(!row)throw Object.assign(new Error('Knowledge item not found'),{statusCode:404});
 if(d==='VERIFIED'&&row.source_review_status!=='REVIEWED')throw Object.assign(new Error('Source must be reviewed before knowledge can be verified'),{statusCode:409});
 if(row.created_by===userId)throw Object.assign(new Error('Independent knowledge reviewer required'),{statusCode:409});
 return (await pool.query('UPDATE grc_knowledge_items SET review_status=$3,verified_by=$4,verified_at=now() WHERE id=$1 AND organization_id=$2 RETURNING *',[itemId,orgId,d,userId])).rows[0];
}

export async function linkKnowledgeToControl(userId:string,orgId:string,itemId:string,controlId:string,linkType='SUPPORTS'){
 await requireOrgPermission(userId,orgId,'manageControl');
 const type=clean(linkType,30).toUpperCase();if(!['SUPPORTS','EVIDENCE_FOR','ASSESSMENT_FOR','CONTEXT_FOR'].includes(type))throw new Error('Invalid knowledge-control link type');
 const item=(await pool.query(`SELECT i.id,i.review_status,s.review_status source_review_status FROM grc_knowledge_items i
 JOIN grc_knowledge_sources s ON s.id=i.source_id AND s.organization_id=i.organization_id
 WHERE i.id=$1 AND i.organization_id=$2`,[itemId,orgId])).rows[0];
 if(!item)throw Object.assign(new Error('Knowledge item not found'),{statusCode:404});
 if(item.review_status!=='VERIFIED'||item.source_review_status!=='REVIEWED')throw Object.assign(new Error('Only reviewed and verified knowledge can be linked to controls'),{statusCode:409});
 const control=(await pool.query('SELECT id FROM grc_canonical_controls WHERE id=$1 AND active=true',[controlId])).rows[0];
 if(!control)throw Object.assign(new Error('Canonical control not found'),{statusCode:404});
 await pool.query('INSERT INTO grc_knowledge_control_links(knowledge_item_id,control_id,link_type,linked_by) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[itemId,controlId,type,userId]);
 return {ok:true};
}

export async function knowledgeSourceCatalog(userId:string,orgId:string){
 await requireOrgPermission(userId,orgId,'read');
 const sources=(await pool.query(`SELECT s.*,
  (SELECT count(*)::int FROM grc_knowledge_items i WHERE i.source_id=s.id) item_count,
  (SELECT count(*)::int FROM grc_knowledge_items i WHERE i.source_id=s.id AND i.review_status='VERIFIED') verified_item_count
 FROM grc_knowledge_sources s WHERE s.organization_id=$1 ORDER BY s.created_at DESC`,[orgId])).rows;
 return {sources,guardrail:'Knowledge sources and extracted items are reference material. Only independently reviewed sources and verified items may be linked to canonical controls; linkage does not establish certification or legal conformity.'};
}
