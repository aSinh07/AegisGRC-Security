import crypto from 'node:crypto';
import pg from 'pg';
import {requireOrgPermission} from './grc-organizations.js';

const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});

export type KnowledgeAuthority='AUTHORITATIVE'|'IMPLEMENTATION_AID'|'EDUCATIONAL'|'INTERNAL';
export type KnowledgeItemType='GUIDANCE'|'ASSESSMENT_QUESTION'|'EVIDENCE_EXPECTATION'|'CONTROL_CANDIDATE'|'TERM'|'RISK_PATTERN';
export type AssessmentPackStatus='DRAFT'|'REVIEWED'|'RETIRED';

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
 CREATE TABLE IF NOT EXISTS grc_readiness_adoptions(
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
  readiness_key text NOT NULL,
  source_id uuid NOT NULL REFERENCES grc_knowledge_sources(id) ON DELETE CASCADE,
  adopted_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
  adopted_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(organization_id,readiness_key)
 );
 CREATE TABLE IF NOT EXISTS grc_assessment_packs(
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
  pack_key text NOT NULL,title text NOT NULL,framework text,framework_version text,
  status text NOT NULL DEFAULT 'DRAFT' CHECK(status IN ('DRAFT','REVIEWED','RETIRED')),
  created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,reviewed_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),reviewed_at timestamptz,
  UNIQUE(organization_id,pack_key)
 );
 CREATE TABLE IF NOT EXISTS grc_assessment_pack_items(
  pack_id uuid NOT NULL REFERENCES grc_assessment_packs(id) ON DELETE CASCADE,
  knowledge_item_id uuid NOT NULL REFERENCES grc_knowledge_items(id) ON DELETE CASCADE,
  ordinal int NOT NULL DEFAULT 0,
  PRIMARY KEY(pack_id,knowledge_item_id)
 );
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


export async function createAssessmentPack(userId:string,orgId:string,input:any){
 await requireOrgPermission(userId,orgId,'manageControl');
 const key=clean(input.packKey,120).toUpperCase(),title=clean(input.title,300);
 if(!key||title.length<3)throw new Error('Assessment pack key and title are required');
 return (await pool.query(`INSERT INTO grc_assessment_packs(id,organization_id,pack_key,title,framework,framework_version,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(organization_id,pack_key) DO UPDATE SET title=EXCLUDED.title,framework=EXCLUDED.framework,framework_version=EXCLUDED.framework_version,status='DRAFT',reviewed_by=NULL,reviewed_at=NULL RETURNING *`,
 [crypto.randomUUID(),orgId,key,title,clean(input.framework,100)||null,clean(input.frameworkVersion,80)||null,userId])).rows[0];
}

export async function addKnowledgeToAssessmentPack(userId:string,orgId:string,packId:string,itemId:string,ordinal=0){
 await requireOrgPermission(userId,orgId,'manageControl');
 const pack=(await pool.query('SELECT id,status FROM grc_assessment_packs WHERE id=$1 AND organization_id=$2',[packId,orgId])).rows[0];
 if(!pack)throw Object.assign(new Error('Assessment pack not found'),{statusCode:404});
 if(pack.status!=='DRAFT')throw Object.assign(new Error('Only draft assessment packs can be changed'),{statusCode:409});
 const item=(await pool.query(`SELECT i.id,i.review_status,s.review_status source_review_status FROM grc_knowledge_items i JOIN grc_knowledge_sources s ON s.id=i.source_id AND s.organization_id=i.organization_id WHERE i.id=$1 AND i.organization_id=$2`,[itemId,orgId])).rows[0];
 if(!item)throw Object.assign(new Error('Knowledge item not found'),{statusCode:404});
 if(item.review_status!=='VERIFIED'||item.source_review_status!=='REVIEWED')throw Object.assign(new Error('Only reviewed and verified knowledge can enter assessment packs'),{statusCode:409});
 await pool.query('INSERT INTO grc_assessment_pack_items(pack_id,knowledge_item_id,ordinal) VALUES($1,$2,$3) ON CONFLICT(pack_id,knowledge_item_id) DO UPDATE SET ordinal=EXCLUDED.ordinal',[packId,itemId,Math.max(0,Number(ordinal)||0)]);
 return {ok:true};
}

export async function reviewAssessmentPack(userId:string,orgId:string,packId:string){
 await requireOrgPermission(userId,orgId,'review');
 const pack=(await pool.query('SELECT * FROM grc_assessment_packs WHERE id=$1 AND organization_id=$2',[packId,orgId])).rows[0];
 if(!pack)throw Object.assign(new Error('Assessment pack not found'),{statusCode:404});
 if(pack.created_by===userId)throw Object.assign(new Error('Independent assessment pack reviewer required'),{statusCode:409});
 const validation=(await pool.query(`SELECT count(*)::int total,
   count(*) FILTER (WHERE i.review_status='VERIFIED' AND s.review_status='REVIEWED' AND i.organization_id=$2 AND s.organization_id=$2)::int valid
  FROM grc_assessment_pack_items pi
  JOIN grc_knowledge_items i ON i.id=pi.knowledge_item_id
  JOIN grc_knowledge_sources s ON s.id=i.source_id
  WHERE pi.pack_id=$1`,[packId,orgId])).rows[0];
 const total=Number(validation?.total||0),valid=Number(validation?.valid||0);
 if(total<1)throw Object.assign(new Error('Assessment pack must contain verified knowledge'),{statusCode:409});
 if(valid!==total)throw Object.assign(new Error('Assessment pack contains knowledge that is no longer verified or whose source is no longer reviewed'),{statusCode:409});
 return (await pool.query("UPDATE grc_assessment_packs SET status='REVIEWED',reviewed_by=$3,reviewed_at=now() WHERE id=$1 AND organization_id=$2 RETURNING *",[packId,orgId,userId])).rows[0];
}

export async function assessmentPackCatalog(userId:string,orgId:string){
 await requireOrgPermission(userId,orgId,'read');
 const packs=(await pool.query(`SELECT p.*,count(pi.knowledge_item_id)::int item_count FROM grc_assessment_packs p LEFT JOIN grc_assessment_pack_items pi ON pi.pack_id=p.id WHERE p.organization_id=$1 GROUP BY p.id ORDER BY p.created_at DESC`,[orgId])).rows;
 const health=(await pool.query(`SELECT pi.pack_id,
  count(*)::int total,
  count(*) FILTER (WHERE i.review_status='VERIFIED' AND s.review_status='REVIEWED' AND i.organization_id=$1 AND s.organization_id=$1)::int valid
 FROM grc_assessment_pack_items pi
 JOIN grc_knowledge_items i ON i.id=pi.knowledge_item_id
 JOIN grc_knowledge_sources s ON s.id=i.source_id
 JOIN grc_assessment_packs p ON p.id=pi.pack_id AND p.organization_id=$1
 GROUP BY pi.pack_id`,[orgId])).rows;
 const byPack=new Map(health.map((x:any)=>[x.pack_id,{total:Number(x.total||0),valid:Number(x.valid||0)}]));
 const assessed=packs.map((p:any)=>{const h=byPack.get(p.id)||{total:0,valid:0};return {...p,knowledge_health:h.total>0&&h.total===h.valid?'VALID':'STALE',valid_item_count:h.valid}});
 return {packs:assessed,guardrail:'Assessment packs are reviewed readiness content assembled from verified knowledge. A STALE pack must not be relied upon until its knowledge and sources are re-reviewed. Packs do not by themselves establish compliance, certification, or legal conformity.'};
}


export async function recordReadinessAdoption(userId:string,orgId:string,readinessKey:string,sourceId:string){
 await requireOrgPermission(userId,orgId,'manageControl');
 const source=(await pool.query('SELECT id,review_status FROM grc_knowledge_sources WHERE id=$1 AND organization_id=$2',[sourceId,orgId])).rows[0];
 if(!source)throw Object.assign(new Error('Knowledge source not found'),{statusCode:404});
 const key=clean(readinessKey,120).toUpperCase();if(!key)throw new Error('Readiness key required');
 return (await pool.query(`INSERT INTO grc_readiness_adoptions(id,organization_id,readiness_key,source_id,adopted_by)
 VALUES($1,$2,$3,$4,$5) ON CONFLICT(organization_id,readiness_key) DO UPDATE SET source_id=EXCLUDED.source_id,adopted_by=EXCLUDED.adopted_by,adopted_at=now() RETURNING *`,
 [crypto.randomUUID(),orgId,key,sourceId,userId])).rows[0];
}


export async function adoptReadinessTemplate(userId:string,orgId:string,pack:any,sourceInput:any){
 await requireOrgPermission(userId,orgId,'manageControl');
 const sha=clean(sourceInput.sha256,64).toLowerCase();
 if(!/^[a-f0-9]{64}$/.test(sha))throw new Error('Valid source SHA-256 is required');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const existingAdoption=(await client.query('SELECT source_id FROM grc_readiness_adoptions WHERE organization_id=$1 AND readiness_key=$2',[orgId,clean(pack.key,120).toUpperCase()])).rows[0];
  if(existingAdoption){
   const existingSource=(await client.query('SELECT sha256 FROM grc_knowledge_sources WHERE id=$1 AND organization_id=$2',[existingAdoption.source_id,orgId])).rows[0];
   if(existingSource&&existingSource.sha256!==sha)throw Object.assign(new Error('Readiness template is already adopted from a different source hash; create a new reviewed source/version instead of silently replacing provenance'),{statusCode:409});
  }
  const source=(await client.query(`INSERT INTO grc_knowledge_sources(id,organization_id,sha256,title,source_type,authority_class,framework,framework_version,publisher,publication_date,source_ref,license_note,created_by)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
   ON CONFLICT(organization_id,sha256) DO UPDATE SET title=EXCLUDED.title,source_ref=COALESCE(EXCLUDED.source_ref,grc_knowledge_sources.source_ref)
   RETURNING *`,[crypto.randomUUID(),orgId,sha,clean(sourceInput.title||pack.title,300),clean(sourceInput.sourceType||'PDF',20).toUpperCase(),pack.sourceClass,clean(pack.framework,100)||null,clean(pack.frameworkVersion,80)||null,clean(sourceInput.publisher,200)||null,sourceInput.publicationDate||null,clean(sourceInput.sourceRef,1000)||null,clean(sourceInput.licenseNote,1000)||null,userId])).rows[0];
  const items=[];
  for(const item of pack.items){
   const row=(await client.query(`INSERT INTO grc_knowledge_items(id,organization_id,source_id,item_key,item_type,title,content,section_ref,confidence,created_by)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    ON CONFLICT(source_id,item_key) DO UPDATE SET
      item_type=CASE WHEN grc_knowledge_items.review_status='DRAFT' THEN EXCLUDED.item_type ELSE grc_knowledge_items.item_type END,
      title=CASE WHEN grc_knowledge_items.review_status='DRAFT' THEN EXCLUDED.title ELSE grc_knowledge_items.title END,
      content=CASE WHEN grc_knowledge_items.review_status='DRAFT' THEN EXCLUDED.content ELSE grc_knowledge_items.content END,
      section_ref=CASE WHEN grc_knowledge_items.review_status='DRAFT' THEN EXCLUDED.section_ref ELSE grc_knowledge_items.section_ref END,
      confidence=CASE WHEN grc_knowledge_items.review_status='DRAFT' THEN EXCLUDED.confidence ELSE grc_knowledge_items.confidence END
    RETURNING *`,[crypto.randomUUID(),orgId,source.id,clean(item.key,120).toUpperCase(),item.type,clean(item.title,300),clean(item.prompt,4000),clean(item.sourceLocator,300),null,userId])).rows[0];
   items.push(row);
  }
  const adoption=(await client.query(`INSERT INTO grc_readiness_adoptions(id,organization_id,readiness_key,source_id,adopted_by)
   VALUES($1,$2,$3,$4,$5) ON CONFLICT(organization_id,readiness_key) DO UPDATE SET source_id=EXCLUDED.source_id,adopted_by=EXCLUDED.adopted_by,adopted_at=now() RETURNING *`,
   [crypto.randomUUID(),orgId,clean(pack.key,120).toUpperCase(),source.id,userId])).rows[0];
  await client.query('COMMIT');
  return {adoption,source,items};
 }catch(error){
  await client.query('ROLLBACK');
  throw error;
 }finally{client.release()}
}
