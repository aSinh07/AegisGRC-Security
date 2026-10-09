import crypto from 'node:crypto';
import pg from 'pg';
import {requireOrgPermission} from './grc-organizations.js';

const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
export type Applicability='APPLICABLE'|'NOT_APPLICABLE'|'PENDING';
export type Implementation='NOT_IMPLEMENTED'|'PLANNED'|'PARTIAL'|'IMPLEMENTED';

export async function initControlRegistry(){
 await pool.query(`
 CREATE TABLE IF NOT EXISTS grc_canonical_controls(
  id uuid PRIMARY KEY,control_key text UNIQUE NOT NULL,title text NOT NULL,description text NOT NULL DEFAULT '',
  domain text NOT NULL DEFAULT 'GENERAL',version integer NOT NULL DEFAULT 1,active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()
 );
 CREATE TABLE IF NOT EXISTS grc_framework_requirements(
  id uuid PRIMARY KEY,framework text NOT NULL,framework_version text NOT NULL,requirement_key text NOT NULL,
  title text NOT NULL,summary text NOT NULL DEFAULT '',active boolean NOT NULL DEFAULT true,
  UNIQUE(framework,framework_version,requirement_key)
 );
 CREATE TABLE IF NOT EXISTS grc_control_framework_mappings(
  control_id uuid NOT NULL REFERENCES grc_canonical_controls(id) ON DELETE CASCADE,
  requirement_id uuid NOT NULL REFERENCES grc_framework_requirements(id) ON DELETE CASCADE,
  mapping_type text NOT NULL DEFAULT 'SUPPORTS' CHECK(mapping_type IN ('SUPPORTS','PARTIAL','PRIMARY')),
  mapping_version integer NOT NULL DEFAULT 1,created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(control_id,requirement_id,mapping_version)
 );
 CREATE TABLE IF NOT EXISTS grc_scope_controls(
  id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
  scope_id uuid NOT NULL REFERENCES grc_scopes(id) ON DELETE CASCADE,
  control_id uuid NOT NULL REFERENCES grc_canonical_controls(id),
  applicability text NOT NULL DEFAULT 'PENDING' CHECK(applicability IN ('APPLICABLE','NOT_APPLICABLE','PENDING')),
  applicability_justification text,
  implementation text NOT NULL DEFAULT 'NOT_IMPLEMENTED' CHECK(implementation IN ('NOT_IMPLEMENTED','PLANNED','PARTIAL','IMPLEMENTED')),
  owner_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,
  approved_by uuid REFERENCES app_users(id) ON DELETE SET NULL,approved_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(scope_id,control_id)
 );
 CREATE INDEX IF NOT EXISTS grc_scope_controls_org_scope_idx ON grc_scope_controls(organization_id,scope_id);
 `);
}
export async function createCanonicalControl(userId:string,orgId:string,input:{controlKey:string;title:string;description?:string;domain?:string}){
 await requireOrgPermission(userId,orgId,'manageControl');
 const key=String(input.controlKey||'').trim().toUpperCase(),title=String(input.title||'').trim();
 if(!/^[A-Z0-9._-]{2,40}$/.test(key))throw new Error('Invalid canonical control key');
 if(title.length<3||title.length>200)throw new Error('Control title must be 3-200 characters');
 return (await pool.query(`INSERT INTO grc_canonical_controls(id,control_key,title,description,domain)
 VALUES($1,$2,$3,$4,$5) ON CONFLICT(control_key) DO UPDATE SET title=EXCLUDED.title,description=EXCLUDED.description,domain=EXCLUDED.domain,updated_at=now() RETURNING *`,
 [crypto.randomUUID(),key,title,String(input.description||'').trim(),String(input.domain||'GENERAL').trim().toUpperCase()])).rows[0];
}
export async function createFrameworkRequirement(userId:string,orgId:string,input:{framework:string;frameworkVersion:string;requirementKey:string;title:string;summary?:string}){
 await requireOrgPermission(userId,orgId,'manageControl');
 const f=String(input.framework||'').trim().toUpperCase(),v=String(input.frameworkVersion||'').trim(),k=String(input.requirementKey||'').trim(),title=String(input.title||'').trim();
 if(!f||!v||!k||title.length<3)throw new Error('Framework, version, requirement key and title are required');
 return (await pool.query(`INSERT INTO grc_framework_requirements(id,framework,framework_version,requirement_key,title,summary)
 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(framework,framework_version,requirement_key) DO UPDATE SET title=EXCLUDED.title,summary=EXCLUDED.summary RETURNING *`,
 [crypto.randomUUID(),f,v,k,title,String(input.summary||'').trim()])).rows[0];
}
export async function mapControl(userId:string,orgId:string,input:{controlId:string;requirementId:string;mappingType?:string}){
 await requireOrgPermission(userId,orgId,'manageControl');
 const type=String(input.mappingType||'SUPPORTS').toUpperCase();if(!['SUPPORTS','PARTIAL','PRIMARY'].includes(type))throw new Error('Invalid mapping type');
 return (await pool.query(`INSERT INTO grc_control_framework_mappings(control_id,requirement_id,mapping_type)
 VALUES($1,$2,$3) ON CONFLICT(control_id,requirement_id,mapping_version) DO UPDATE SET mapping_type=EXCLUDED.mapping_type RETURNING *`,
 [input.controlId,input.requirementId,type])).rows[0];
}
async function assertScope(orgId:string,scopeId:string){
 const r=(await pool.query('SELECT id FROM grc_scopes WHERE id=$1 AND organization_id=$2',[scopeId,orgId])).rows[0];
 if(!r)throw Object.assign(new Error('Scope not found in organization'),{statusCode:404});
}
export async function setScopeControl(userId:string,orgId:string,scopeId:string,input:{controlId:string;applicability:Applicability;justification?:string;implementation?:Implementation;ownerUserId?:string}){
 await requireOrgPermission(userId,orgId,'manageControl');await assertScope(orgId,scopeId);
 const applicability=String(input.applicability||'PENDING').toUpperCase() as Applicability;
 if(!['APPLICABLE','NOT_APPLICABLE','PENDING'].includes(applicability))throw new Error('Invalid applicability');
 const justification=String(input.justification||'').trim();
 if(applicability==='NOT_APPLICABLE'&&justification.length<10)throw new Error('Not-applicable controls require a meaningful justification');
 const implementation=String(input.implementation||'NOT_IMPLEMENTED').toUpperCase() as Implementation;
 if(!['NOT_IMPLEMENTED','PLANNED','PARTIAL','IMPLEMENTED'].includes(implementation))throw new Error('Invalid implementation status');
 if(input.ownerUserId)await requireOrgPermission(input.ownerUserId,orgId,'read');
 return (await pool.query(`INSERT INTO grc_scope_controls(id,organization_id,scope_id,control_id,applicability,applicability_justification,implementation,owner_user_id)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(scope_id,control_id) DO UPDATE SET applicability=EXCLUDED.applicability,
 applicability_justification=EXCLUDED.applicability_justification,implementation=EXCLUDED.implementation,owner_user_id=EXCLUDED.owner_user_id,approved_by=NULL,approved_at=NULL,updated_at=now() RETURNING *`,
 [crypto.randomUUID(),orgId,scopeId,input.controlId,applicability,justification||null,implementation,input.ownerUserId||null])).rows[0];
}
export async function approveScopeControl(userId:string,orgId:string,scopeId:string,scopeControlId:string){
 const reviewer=await requireOrgPermission(userId,orgId,'review');await assertScope(orgId,scopeId);
 const row=(await pool.query('SELECT * FROM grc_scope_controls WHERE id=$1 AND organization_id=$2 AND scope_id=$3',[scopeControlId,orgId,scopeId])).rows[0];
 if(!row)throw Object.assign(new Error('Scope control not found'),{statusCode:404});
 if(row.owner_user_id===userId)throw Object.assign(new Error('Control owner cannot approve own applicability decision'),{statusCode:409});
 if(row.applicability==='PENDING')throw Object.assign(new Error('Pending applicability cannot be approved'),{statusCode:409});
 return (await pool.query('UPDATE grc_scope_controls SET approved_by=$2,approved_at=now(),updated_at=now() WHERE id=$1 RETURNING *',[scopeControlId,userId])).rows[0];
}
export async function statementOfApplicability(userId:string,orgId:string,scopeId:string){
 await requireOrgPermission(userId,orgId,'read');await assertScope(orgId,scopeId);
 const rows=(await pool.query(`SELECT sc.id,sc.applicability,sc.applicability_justification,sc.implementation,sc.owner_user_id,sc.approved_by,sc.approved_at,
 c.control_key,c.title,c.domain,
 COALESCE(json_agg(json_build_object('framework',fr.framework,'version',fr.framework_version,'requirementKey',fr.requirement_key,'title',fr.title,'mappingType',m.mapping_type))
 FILTER(WHERE fr.id IS NOT NULL),'[]'::json) mappings
 FROM grc_scope_controls sc JOIN grc_canonical_controls c ON c.id=sc.control_id
 LEFT JOIN grc_control_framework_mappings m ON m.control_id=c.id
 LEFT JOIN grc_framework_requirements fr ON fr.id=m.requirement_id
 WHERE sc.organization_id=$1 AND sc.scope_id=$2
 GROUP BY sc.id,c.id ORDER BY c.control_key`,[orgId,scopeId])).rows;
 return {organizationId:orgId,scopeId,generatedAt:new Date().toISOString(),controls:rows,
 summary:{total:rows.length,applicable:rows.filter((x:any)=>x.applicability==='APPLICABLE').length,notApplicable:rows.filter((x:any)=>x.applicability==='NOT_APPLICABLE').length,pending:rows.filter((x:any)=>x.applicability==='PENDING').length,approved:rows.filter((x:any)=>x.approved_at).length},
 disclaimer:'Statement of Applicability workspace record; internal approval is not external certification.'};
}


export async function listCanonicalControls(userId:string,orgId:string){
 await requireOrgPermission(userId,orgId,'read');
 return (await pool.query(`SELECT id,control_key,title,description,domain,version,active,created_at,updated_at
 FROM grc_canonical_controls WHERE active=true ORDER BY domain,control_key`)).rows;
}
export async function listFrameworkRequirements(userId:string,orgId:string){
 await requireOrgPermission(userId,orgId,'read');
 return (await pool.query(`SELECT id,framework,framework_version,requirement_key,title,summary,active
 FROM grc_framework_requirements WHERE active=true ORDER BY framework,framework_version,requirement_key`)).rows;
}
