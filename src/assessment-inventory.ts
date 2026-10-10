import crypto from 'node:crypto';
import pg from 'pg';
import {ASSESSMENT_LAYERS,assessmentCoverage,type AssessmentLayer,type LayerStatus} from './assessment-coverage.js';
import {requireOrgPermission,requireAssessmentAccess} from './grc-organizations.js';

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
 if(input.scopeId){const scope=(await pool.query('SELECT 1 FROM grc_scopes WHERE id=$1 AND organization_id=$2',[input.scopeId,organizationId])).rows[0];if(!scope)throw Object.assign(new Error('Scope does not belong to this organization'),{statusCode:403});}
 if(input.containsPii!==undefined&&typeof input.containsPii!=='boolean')throw new Error('containsPii must be boolean');
 if(input.metadata!==undefined&&(typeof input.metadata!=='object'||Array.isArray(input.metadata)||input.metadata===null))throw new Error('metadata must be an object');
 return (await pool.query(`INSERT INTO assessment_assets(id,organization_id,scope_id,asset_type,asset_key,name,criticality,data_classification,contains_pii,owner,metadata,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,[crypto.randomUUID(),organizationId,input.scopeId||null,assetType,key,name,String(input.criticality||'MEDIUM').toUpperCase(),String(input.dataClassification||'INTERNAL').toUpperCase(),Boolean(input.containsPii),String(input.owner||'').trim()||null,input.metadata||{},userId])).rows[0]
}
export async function listAssessmentAssets(userId:string,organizationId:string){
 await requireOrgPermission(userId,organizationId,'read');return (await pool.query('SELECT * FROM assessment_assets WHERE organization_id=$1 ORDER BY created_at DESC',[organizationId])).rows
}
export async function initializeLayerCoverage(userId:string,organizationId:string,assessmentId:string,requirements:Partial<Record<AssessmentLayer,boolean>>={}){
 await requireOrgPermission(userId,organizationId,'manageAssessment');const access=await requireAssessmentAccess(userId,assessmentId);if(access.organization_id!==organizationId)throw Object.assign(new Error('Assessment does not belong to this organization'),{statusCode:403});
 for(const layer of ASSESSMENT_LAYERS)await pool.query(`INSERT INTO assessment_layer_runs(id,assessment_id,organization_id,layer,required) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(assessment_id,layer) DO UPDATE SET required=EXCLUDED.required,updated_at=now()`,[crypto.randomUUID(),assessmentId,organizationId,layer,requirements[layer]!==false]);
 return assessmentLayerCoverage(userId,organizationId,assessmentId)
}
export async function recordLayerResult(userId:string,organizationId:string,assessmentId:string,layer:AssessmentLayer,input:{status:LayerStatus;engines?:string[];evidenceCount?:number;failureReasons?:string[]}){
 await requireOrgPermission(userId,organizationId,'manageAssessment');const access=await requireAssessmentAccess(userId,assessmentId);if(access.organization_id!==organizationId)throw Object.assign(new Error('Assessment does not belong to this organization'),{statusCode:403});if(!ASSESSMENT_LAYERS.includes(layer))throw new Error('Invalid assessment layer');
 const validStatuses:LayerStatus[]=['NOT_STARTED','RUNNING','COMPLETE','PARTIAL','FAILED','NOT_APPLICABLE'];if(!validStatuses.includes(input.status))throw new Error('Invalid assessment layer status');
 if(['INFRASTRUCTURE','ENDPOINT','WEB','API','SOURCE_CODE'].includes(layer))throw Object.assign(new Error(layer+' coverage is evidence-derived and must use its reconciliation endpoint'),{statusCode:409});
 if(input.status==='COMPLETE'&&Number(input.evidenceCount||0)<1)throw new Error('Complete assessment layer requires persisted evidence');
 const updated=(await pool.query(`UPDATE assessment_layer_runs SET status=$4,engines=$5,evidence_count=$6,failure_reasons=$7,
 started_at=COALESCE(started_at,now()),completed_at=CASE WHEN $4 IN ('COMPLETE','PARTIAL','FAILED','NOT_APPLICABLE') THEN now() ELSE NULL END,updated_at=now()
 WHERE assessment_id=$1 AND organization_id=$2 AND layer=$3 RETURNING *`,[assessmentId,organizationId,layer,input.status,input.engines||[],Number(input.evidenceCount||0),input.failureReasons||[]])).rows[0];if(!updated)throw Object.assign(new Error('Assessment layer is not initialized'),{statusCode:409});return updated
}
export async function assessmentLayerCoverage(userId:string,organizationId:string,assessmentId:string){
 await requireOrgPermission(userId,organizationId,'read');const access=await requireAssessmentAccess(userId,assessmentId);if(access.organization_id!==organizationId)throw Object.assign(new Error('Assessment does not belong to this organization'),{statusCode:403});const rows=(await pool.query('SELECT layer,status,required,engines,evidence_count,failure_reasons FROM assessment_layer_runs WHERE assessment_id=$1 AND organization_id=$2 ORDER BY layer',[assessmentId,organizationId])).rows;
 return {layers:rows,summary:assessmentCoverage(rows.map(r=>({layer:r.layer,status:r.status,required:r.required,engines:r.engines||[],evidenceCount:Number(r.evidence_count),failureReasons:r.failure_reasons||[]})))}
}

export async function reconcileInfrastructureCoverage(userId:string,organizationId:string,assessmentId:string){
 await requireOrgPermission(userId,organizationId,'manageAssessment');const assessmentAccess=await requireAssessmentAccess(userId,assessmentId);if(assessmentAccess.organization_id!==organizationId)throw Object.assign(new Error('Assessment does not belong to this organization'),{statusCode:403});
 const access=(await pool.query('SELECT 1 FROM grc_assessment_org WHERE assessment_id=$1 AND organization_id=$2',[assessmentId,organizationId])).rows[0];if(!access)throw new Error('Assessment is not assigned to this organization');
 const ev=(await pool.query(`SELECT source,payload FROM evidence WHERE assessment_id=$1 AND source = ANY($2::text[])`,[assessmentId,['nmap','openvas']])).rows;
 const valid=(source:string)=>ev.some((x:any)=>x.source===source&&Number(x.payload?.exitCode)===0&&!x.payload?.metadata?.timedOut&&!x.payload?.metadata?.stdoutTruncated&&!x.payload?.metadata?.stderrTruncated&&String(x.payload?.stdout||'').length>0);
 const nmap=valid('nmap'),openvas=valid('openvas'),reasons:string[]=[];if(!nmap)reasons.push('Nmap successful evidence missing');if(!openvas)reasons.push('OpenVAS successful evidence missing');
 const validEvidence=(x:any)=>Number(x.payload?.exitCode)===0&&!x.payload?.metadata?.timedOut&&!x.payload?.metadata?.stdoutTruncated&&!x.payload?.metadata?.stderrTruncated&&String(x.payload?.stdout||'').length>0;const status:LayerStatus=nmap&&openvas?'COMPLETE':'PARTIAL',engines=['NMAP','OPENVAS'],count=ev.filter(validEvidence).length;
 await pool.query(`INSERT INTO assessment_layer_runs(id,assessment_id,organization_id,layer,status,required,engines,evidence_count,failure_reasons,started_at,completed_at)
 VALUES($1,$2,$3,'INFRASTRUCTURE',$4,true,$5,$6,$7,now(),CASE WHEN $4='COMPLETE' THEN now() ELSE NULL END)
 ON CONFLICT(assessment_id,layer) DO UPDATE SET status=EXCLUDED.status,required=true,engines=EXCLUDED.engines,evidence_count=EXCLUDED.evidence_count,failure_reasons=EXCLUDED.failure_reasons,started_at=COALESCE(assessment_layer_runs.started_at,now()),completed_at=EXCLUDED.completed_at,updated_at=now()`,[crypto.randomUUID(),assessmentId,organizationId,status,engines,count,reasons]);
 return {layer:'INFRASTRUCTURE',status,requiredEngines:engines,evidenceCount:count,reasons,nmap:{complete:nmap},openvas:{complete:openvas}};
}

export async function reconcileEndpointCoverage(userId:string,organizationId:string,assessmentId:string){
 await requireOrgPermission(userId,organizationId,'manageAssessment');
 const access=await requireAssessmentAccess(userId,assessmentId);if(access.organization_id!==organizationId)throw Object.assign(new Error('Assessment does not belong to this organization'),{statusCode:403});
 const ev=(await pool.query('SELECT source,payload FROM evidence WHERE assessment_id=$1 AND source=$2',[assessmentId,'wazuh'])).rows;
 const valid=ev.some((x:any)=>Number(x.payload?.exitCode)===0&&String(x.payload?.stdout||'').length>0);
 const reasons=valid?[]:['Wazuh endpoint evidence missing'];const status:LayerStatus=valid?'COMPLETE':'PARTIAL';
 await pool.query('UPDATE assessment_layer_runs SET status=$4,required=true,engines=$5,evidence_count=$6,failure_reasons=$7,started_at=COALESCE(started_at,now()),completed_at=CASE WHEN $4=\'COMPLETE\' THEN now() ELSE NULL END,updated_at=now() WHERE assessment_id=$1 AND organization_id=$2 AND layer=$3',[assessmentId,organizationId,'ENDPOINT',status,['WAZUH'],valid?ev.length:0,reasons]);
 return {layer:'ENDPOINT',status,requiredEngines:['WAZUH'],evidenceCount:valid?ev.length:0,reasons,wazuh:{complete:valid}};
}

export async function reconcileWebCoverage(userId:string,organizationId:string,assessmentId:string){
 await requireOrgPermission(userId,organizationId,'manageAssessment');const access=await requireAssessmentAccess(userId,assessmentId);if(access.organization_id!==organizationId)throw Object.assign(new Error('Assessment does not belong to this organization'),{statusCode:403});
 const ev=(await pool.query('SELECT source,payload FROM evidence WHERE assessment_id=$1 AND source = ANY($2::text[])',[assessmentId,['zap','nuclei']])).rows;
 const valid=(source:string)=>ev.some((x:any)=>x.source===source&&Number(x.payload?.exitCode)===0&&!x.payload?.metadata?.timedOut&&!x.payload?.metadata?.stdoutTruncated&&!x.payload?.metadata?.stderrTruncated&&String(x.payload?.stdout||'').length>0);
 const zap=valid('zap'),nuclei=valid('nuclei'),reasons:string[]=[];if(!zap)reasons.push('ZAP successful web evidence missing');if(!nuclei)reasons.push('Nuclei successful web evidence missing');const status:LayerStatus=zap&&nuclei?'COMPLETE':'PARTIAL';
 const updated=(await pool.query('UPDATE assessment_layer_runs SET status=$4,required=true,engines=$5,evidence_count=$6,failure_reasons=$7,started_at=COALESCE(started_at,now()),completed_at=CASE WHEN $4=\'COMPLETE\' THEN now() ELSE NULL END,updated_at=now() WHERE assessment_id=$1 AND organization_id=$2 AND layer=$3 RETURNING *',[assessmentId,organizationId,'WEB',status,['ZAP','NUCLEI'],ev.filter((x:any)=>Number(x.payload?.exitCode)===0&&String(x.payload?.stdout||'').length>0).length,reasons])).rows[0];if(!updated)throw Object.assign(new Error('WEB layer is not initialized'),{statusCode:409});
 return {layer:'WEB',status,requiredEngines:['ZAP','NUCLEI'],evidenceCount:Number(updated.evidence_count),reasons,zap:{complete:zap},nuclei:{complete:nuclei}};
}

export async function reconcileApiCoverage(userId:string,organizationId:string,assessmentId:string){
 await requireOrgPermission(userId,organizationId,'manageAssessment');const access=await requireAssessmentAccess(userId,assessmentId);if(access.organization_id!==organizationId)throw Object.assign(new Error('Assessment does not belong to this organization'),{statusCode:403});
 const ev=(await pool.query('SELECT source,payload FROM evidence WHERE assessment_id=$1 AND source = ANY($2::text[])',[assessmentId,['zap','nuclei']])).rows;
 const valid=(source:string)=>ev.some((x:any)=>x.source===source&&Number(x.payload?.exitCode)===0&&!x.payload?.metadata?.timedOut&&!x.payload?.metadata?.stdoutTruncated&&!x.payload?.metadata?.stderrTruncated&&String(x.payload?.stdout||'').length>0);
 const zap=valid('zap'),nuclei=valid('nuclei'),reasons:string[]=[];if(!zap)reasons.push('ZAP successful API evidence missing');if(!nuclei)reasons.push('Nuclei successful API evidence missing');const status:LayerStatus=zap&&nuclei?'COMPLETE':'PARTIAL';
 const count=ev.filter((x:any)=>Number(x.payload?.exitCode)===0&&!x.payload?.metadata?.timedOut&&!x.payload?.metadata?.stdoutTruncated&&!x.payload?.metadata?.stderrTruncated&&String(x.payload?.stdout||'').length>0).length;
 const updated=(await pool.query('UPDATE assessment_layer_runs SET status=$4,required=true,engines=$5,evidence_count=$6,failure_reasons=$7,started_at=COALESCE(started_at,now()),completed_at=CASE WHEN $4=\'COMPLETE\' THEN now() ELSE NULL END,updated_at=now() WHERE assessment_id=$1 AND organization_id=$2 AND layer=$3 RETURNING *',[assessmentId,organizationId,'API',status,['ZAP','NUCLEI'],count,reasons])).rows[0];if(!updated)throw Object.assign(new Error('API layer is not initialized'),{statusCode:409});
 return {layer:'API',status,requiredEngines:['ZAP','NUCLEI'],evidenceCount:count,reasons,zap:{complete:zap},nuclei:{complete:nuclei}};
}

export async function reconcileSourceCodeCoverage(userId:string,organizationId:string,assessmentId:string){
 await requireOrgPermission(userId,organizationId,'manageAssessment');const access=await requireAssessmentAccess(userId,assessmentId);if(access.organization_id!==organizationId)throw Object.assign(new Error('Assessment does not belong to this organization'),{statusCode:403});
 const ev=(await pool.query('SELECT source,payload FROM evidence WHERE assessment_id=$1 AND source=$2',[assessmentId,'semgrep'])).rows;
 const valid=ev.filter((x:any)=>Number(x.payload?.exitCode)===0&&String(x.payload?.stdout||'').length>0);const complete=valid.length>0,reasons=complete?[]:['Semgrep successful source-code evidence missing'];const status:LayerStatus=complete?'COMPLETE':'PARTIAL';
 const updated=(await pool.query('UPDATE assessment_layer_runs SET status=$4,required=true,engines=$5,evidence_count=$6,failure_reasons=$7,started_at=COALESCE(started_at,now()),completed_at=CASE WHEN $4=\'COMPLETE\' THEN now() ELSE NULL END,updated_at=now() WHERE assessment_id=$1 AND organization_id=$2 AND layer=$3 RETURNING *',[assessmentId,organizationId,'SOURCE_CODE',status,['SEMGREP'],valid.length,reasons])).rows[0];if(!updated)throw Object.assign(new Error('SOURCE_CODE layer is not initialized'),{statusCode:409});
 return {layer:'SOURCE_CODE',status,requiredEngines:['SEMGREP'],evidenceCount:valid.length,reasons,semgrep:{complete}};
}
