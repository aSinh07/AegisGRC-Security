import crypto from 'node:crypto';import pg from 'pg';import {requireOrgPermission} from './grc-organizations.js';import {normalizeArchitectureModel,transitionArchitectureReview,architectureModelDigest,type ArchitectureModelRecord,type ArchitectureReviewStatus} from './architecture-model-review.js';
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
export async function initArchitectureModels(){await pool.query(`
CREATE TABLE IF NOT EXISTS grc_architecture_models(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 name text NOT NULL,source_name text NOT NULL,source_sha256 text NOT NULL,model_digest text NOT NULL,
 status text NOT NULL CHECK(status IN ('DRAFT','IN_REVIEW','VERIFIED','REJECTED')),
 model jsonb NOT NULL,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now(),
 reviewed_by uuid REFERENCES app_users(id) ON DELETE SET NULL,reviewed_at timestamptz,review_note text
);
CREATE INDEX IF NOT EXISTS grc_arch_models_org_idx ON grc_architecture_models(organization_id,created_at DESC);
`)}
const map=(r:any):ArchitectureModelRecord=>({...r.model,id:r.id,organizationId:r.organization_id,name:r.name,sourceName:r.source_name,sourceSha256:r.source_sha256,status:r.status,createdBy:r.created_by,createdAt:new Date(r.created_at).toISOString(),reviewedBy:r.reviewed_by||undefined,reviewedAt:r.reviewed_at?new Date(r.reviewed_at).toISOString():undefined,reviewNote:r.review_note||undefined});
export async function saveArchitectureModel(user:string,org:string,input:any,source:{name:string;sha256:string}){
 await requireOrgPermission(user,org,'manageScope');if(!/^[a-f0-9]{64}$/.test(source.sha256))throw new Error('Valid source SHA-256 required');
 const m=normalizeArchitectureModel(input,{organizationId:org,userId:user,sourceName:source.name,sourceSha256:source.sha256}),digest=architectureModelDigest(m);
 const r=await pool.query(`INSERT INTO grc_architecture_models(id,organization_id,name,source_name,source_sha256,model_digest,status,model,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,[m.id,org,m.name,m.sourceName,m.sourceSha256,digest,m.status,m,user,m.createdAt]);return {...map(r.rows[0]),modelDigest:digest}
}
export async function listArchitectureModels(user:string,org:string){await requireOrgPermission(user,org,'read');const r=await pool.query('SELECT * FROM grc_architecture_models WHERE organization_id=$1 ORDER BY created_at DESC',[org]);return r.rows.map((x:any)=>({...map(x),modelDigest:x.model_digest}))}
export async function reviewArchitectureModel(user:string,org:string,id:string,status:ArchitectureReviewStatus,note=''){
 await requireOrgPermission(user,org,'review');const row=(await pool.query('SELECT * FROM grc_architecture_models WHERE id=$1 AND organization_id=$2',[id,org])).rows[0];if(!row)throw Object.assign(new Error('Architecture model not found'),{statusCode:404});
 const next=transitionArchitectureReview(map(row),status,user,note),digest=architectureModelDigest(next);if(digest!==row.model_digest)throw Object.assign(new Error('Architecture model integrity check failed'),{statusCode:409});
 const r=await pool.query('UPDATE grc_architecture_models SET status=$1,model=$2,reviewed_by=$3,reviewed_at=$4,review_note=$5 WHERE id=$6 AND organization_id=$7 RETURNING *',[next.status,next,next.reviewedBy||null,next.reviewedAt||null,next.reviewNote||null,id,org]);return {...map(r.rows[0]),modelDigest:digest}
}
