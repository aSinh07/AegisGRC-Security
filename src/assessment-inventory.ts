import crypto from 'node:crypto';
import pg from 'pg';
import {ASSESSMENT_LAYERS,assessmentCoverage,type AssessmentLayer,type LayerStatus} from './assessment-coverage.js';
import {requireOrgPermission} from './grc-organizations.js';

const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
const assetTypes=['DOMAIN','IP','HOST','SERVER','WORKSTATION','MOBILE','WEB_APP','API','CLOUD_ACCOUNT','CONTAINER','REPOSITORY','DATABASE','STORAGE','IDENTITY_PROVIDER','NETWORK_DEVICE'] as const;
export type AssetType=typeof assetTypes[number];

export async function initAssessmentInventory(){await pool.query(`
CREATE TABLE IF NOT EXISTS assessment_assets(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 scope_id uuid REFERENCES grc_scopes(id) ON DELETE SET NULL,asset_type text NOT NULL,asset_key text NOT NULL,
 name text NOT NULL,criticality text NOT NULL DEFAULT 'MEDIUM',data_classification text NOT NULL DEFAULT 'INTERNAL',
 contains_pii boolean NOT NULL DEFAULT false,owner text,status text NOT NULL DEFAULT 'ACTIVE',
 metadata jsonb NOT NULL DEFAULT '{}'::jsonb,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),UNIQUE(organization_id,asset_key));
CREATE INDEX IF NOT EXISTS assessment_assets_scope_idx ON assessment_assets(organization_id,scope_id,status);
CREATE TABLE IF NOT EXISTS assessment_layer_runs(
 id uuid PRIMARY KEY,assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
 organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 layer text NOT NULL,status text NOT NULL DEFAULT 'NOT_STARTED',required boolean NOT NULL DEFAULT true,
 engines jsonb NOT NULL DEFAULT '[]'::jsonb,evidence_count integer NOT NULL DEFAULT 0,
 failure_reasons jsonb NOT NULL DEFAULT '[]'::jsonb,started_at timestamptz,completed_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),UNIQUE(assessment_id,layer));
CREATE INDEX IF NOT EXISTS assessment_layer_runs_org_idx ON assessment_layer_runs(organization_id,assessment_id);
`)}

export async function createAssessmentAsset(userId:string,organizationId:string,input:any){
 await requireOrgPermission(userId,organizationId,'manageAssessment');
 const assetType=String(input.assetType||'').toUpperCase() as AssetType;if(!assetTypes.includes(assetType))throw new Error('Invalid asset type');
 const key=String(input.assetKey||'').trim(),name=String(input.name||'').trim();if(!key||!name)throw new Error('Asset key and name are required');
 return (await pool.query(`INSERT INTO assessment_assets(id,organization_id,scope_id,asset_type,asset_key,name,criticality,data_classification,contains_pii,owner,metadata,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,[crypto.randomUUID(),organizationId,input.scopeId||null,assetType,key,name,String(input.criticality||'MEDIUM').toUpperCase(),String(input.dataClassification||'INTERNAL').toUpperCase(),Boolean(input.containsPii),String(input.owner||'').trim()||null,input.metadata||{},userId])).rows[0]
}
export async function listAssessmentAssets(userId:string,organizationId:string){
 await requireOrgPermission(userId,organizationId,'read');return (await pool.query('SELECT * FROM assessment_assets WHERE organization_id=$1 ORDER BY created_at DESC',[organizationId])).rows
}
export async function initializeLayerCoverage(userId:string,organizationId:string,assessmentId:string,requirements:Partial<Record<AssessmentLayer,boolean>>={}){
 await requireOrgPermission(userId,organizationId,'manageAssessment');
 for(const layer of ASSESSMENT_LAYERS)await pool.query(`INSERT INTO assessment_layer_runs(id,assessment_id,organization_id,layer,required) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(assessment_id,layer) DO UPDATE SET required=EXCLUDED.required,updated_at=now()`,[crypto.randomUUID(),assessmentId,organizationId,layer,requirements[layer]!==false]);
 return assessmentLayerCoverage(userId,organizationId,assessmentId)
}
export async function recordLayerResult(userId:string,organizationId:string,assessmentId:string,layer:AssessmentLayer,input:{status:LayerStatus;engines?:string[];evidenceCount?:number;failureReasons?:string[]}){
 await requireOrgPermission(userId,organizationId,'manageAssessment');if(!ASSESSMENT_LAYERS.includes(layer))throw new Error('Invalid assessment layer');
 if(input.status==='COMPLETE'&&Number(input.evidenceCount||0)<1)throw new Error('Complete assessment layer requires persisted evidence');
 return (await pool.query(`UPDATE assessment_layer_runs SET status=$4,engines=$5,evidence_count=$6,failure_reasons=$7,
 started_at=COALESCE(started_at,now()),completed_at=CASE WHEN $4 IN ('COMPLETE','PARTIAL','FAILED','NOT_APPLICABLE') THEN now() ELSE NULL END,updated_at=now()
 WHERE assessment_id=$1 AND organization_id=$2 AND layer=$3 RETURNING *`,[assessmentId,organizationId,layer,input.status,input.engines||[],Number(input.evidenceCount||0),input.failureReasons||[]])).rows[0]
}
export async function assessmentLayerCoverage(userId:string,organizationId:string,assessmentId:string){
 await requireOrgPermission(userId,organizationId,'read');const rows=(await pool.query('SELECT layer,status,required,engines,evidence_count,failure_reasons FROM assessment_layer_runs WHERE assessment_id=$1 AND organization_id=$2 ORDER BY layer',[assessmentId,organizationId])).rows;
 return {layers:rows,summary:assessmentCoverage(rows.map(r=>({layer:r.layer,status:r.status,required:r.required,engines:r.engines||[],evidenceCount:Number(r.evidence_count),failureReasons:r.failure_reasons||[]})))}
}
