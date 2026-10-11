import crypto from 'node:crypto';import pg from 'pg';import {requireOrgPermission} from './grc-organizations.js';
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
const assetTypes=new Set(['FIREWALL','WAF','LOAD_BALANCER','ROUTER','SWITCH','VPN_GATEWAY','IDS_IPS','CDN','DNS','REVERSE_PROXY','SERVICE','DATA_FLOW','TRUST_BOUNDARY']);
export async function initArchitectureAssurance(){await pool.query(`
CREATE TABLE IF NOT EXISTS grc_architecture_components(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,scope_id uuid REFERENCES grc_scopes(id) ON DELETE CASCADE,
 component_key text NOT NULL,name text NOT NULL,component_type text NOT NULL,criticality text NOT NULL DEFAULT 'MEDIUM',
 internet_exposed boolean NOT NULL DEFAULT false,owner text,metadata jsonb NOT NULL DEFAULT '{}'::jsonb,status text NOT NULL DEFAULT 'ACTIVE',
 created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,component_key)
);
CREATE TABLE IF NOT EXISTS grc_architecture_edges(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,scope_id uuid REFERENCES grc_scopes(id) ON DELETE CASCADE,
 source_component_id uuid NOT NULL REFERENCES grc_architecture_components(id) ON DELETE CASCADE,target_component_id uuid NOT NULL REFERENCES grc_architecture_components(id) ON DELETE CASCADE,
 protocol text,port integer,encrypted boolean,authenticated boolean,description text NOT NULL DEFAULT '',created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS grc_firewall_reviews(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,scope_id uuid REFERENCES grc_scopes(id) ON DELETE CASCADE,
 component_id uuid NOT NULL REFERENCES grc_architecture_components(id) ON DELETE CASCADE,source_ref text,sha256 text NOT NULL,
 review_status text NOT NULL CHECK(review_status IN ('PASS','FAIL','PARTIAL','NOT_TESTED')),
 rules_total integer NOT NULL DEFAULT 0,any_any_rules integer NOT NULL DEFAULT 0,disabled_rules integer NOT NULL DEFAULT 0,stale_rules integer NOT NULL DEFAULT 0,
 shadowed_rules integer NOT NULL DEFAULT 0,expired_rules integer NOT NULL DEFAULT 0,findings jsonb NOT NULL DEFAULT '[]'::jsonb,
 reviewed_by uuid REFERENCES app_users(id) ON DELETE SET NULL,reviewed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS grc_arch_component_scope_idx ON grc_architecture_components(organization_id,scope_id,status);
CREATE INDEX IF NOT EXISTS grc_firewall_review_scope_idx ON grc_firewall_reviews(organization_id,scope_id,reviewed_at DESC);
`)}
export async function createArchitectureComponent(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageScope');const type=String(input.componentType||'').toUpperCase();if(!assetTypes.has(type))throw new Error('Unsupported architecture component type');
 const key=String(input.componentKey||'').trim().toUpperCase(),name=String(input.name||'').trim();if(!key||!name)throw new Error('Component key and name required');
 return (await pool.query(`INSERT INTO grc_architecture_components(id,organization_id,scope_id,component_key,name,component_type,criticality,internet_exposed,owner,metadata,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,[crypto.randomUUID(),org,input.scopeId||null,key,name,type,String(input.criticality||'MEDIUM').toUpperCase(),Boolean(input.internetExposed),input.owner||null,input.metadata||{},user])).rows[0]
}
export async function createArchitectureEdge(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageScope');if(input.sourceComponentId===input.targetComponentId)throw new Error('Architecture edge requires different components');
 const valid=(await pool.query('SELECT count(*) c FROM grc_architecture_components WHERE organization_id=$1 AND id=ANY($2::uuid[])',[org,[input.sourceComponentId,input.targetComponentId]])).rows[0];if(Number(valid.c)!==2)throw new Error('Architecture components not found');
 return (await pool.query(`INSERT INTO grc_architecture_edges(id,organization_id,scope_id,source_component_id,target_component_id,protocol,port,encrypted,authenticated,description,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,[crypto.randomUUID(),org,input.scopeId||null,input.sourceComponentId,input.targetComponentId,input.protocol||null,input.port||null,input.encrypted??null,input.authenticated??null,String(input.description||''),user])).rows[0]
}
export async function recordFirewallReview(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'review');const c=(await pool.query("SELECT * FROM grc_architecture_components WHERE id=$1 AND organization_id=$2 AND component_type IN ('FIREWALL','WAF','ROUTER','VPN_GATEWAY','IDS_IPS')",[input.componentId,org])).rows[0];if(!c)throw Object.assign(new Error('Firewall/security gateway component not found'),{statusCode:404});
 const sha=String(input.sha256||'').toLowerCase();if(!/^[a-f0-9]{64}$/.test(sha))throw new Error('Valid SHA-256 required for firewall report');
 const counts=['rulesTotal','anyAnyRules','disabledRules','staleRules','shadowedRules','expiredRules'].map(k=>Math.max(0,Number(input[k]||0)));
 let rs=String(input.reviewStatus||'').toUpperCase();if(!['PASS','FAIL','PARTIAL','NOT_TESTED'].includes(rs))rs=(counts.slice(1).some(x=>x>0)?'FAIL':'PARTIAL');
 return (await pool.query(`INSERT INTO grc_firewall_reviews(id,organization_id,scope_id,component_id,source_ref,sha256,review_status,rules_total,any_any_rules,disabled_rules,stale_rules,shadowed_rules,expired_rules,findings,reviewed_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,[crypto.randomUUID(),org,input.scopeId||c.scope_id,c.id,input.sourceRef||null,sha,rs,...counts,input.findings||[],user])).rows[0]
}
export async function architectureAssurance(user:string,org:string,scopeId:string){
 await requireOrgPermission(user,org,'read');const components=(await pool.query("SELECT * FROM grc_architecture_components WHERE organization_id=$1 AND scope_id=$2 AND status='ACTIVE' ORDER BY component_type,name",[org,scopeId])).rows;
 const edges=(await pool.query('SELECT * FROM grc_architecture_edges WHERE organization_id=$1 AND scope_id=$2 ORDER BY created_at',[org,scopeId])).rows;
 const reviews=(await pool.query(`SELECT DISTINCT ON(component_id) * FROM grc_firewall_reviews WHERE organization_id=$1 AND scope_id=$2 ORDER BY component_id,reviewed_at DESC`,[org,scopeId])).rows;
 const gateways=components.filter((x:any)=>['FIREWALL','WAF','ROUTER','VPN_GATEWAY','IDS_IPS'].includes(x.component_type)),reviewed=new Set(reviews.map((x:any)=>x.component_id));
 const gaps:any[]=[];for(const g of gateways)if(!reviewed.has(g.id))gaps.push({type:'FIREWALL_REVIEW_MISSING',component:g.component_key,severity:'HIGH'});
 for(const e of edges){if(e.encrypted===false)gaps.push({type:'UNENCRYPTED_FLOW',edgeId:e.id,severity:'HIGH'});if(e.authenticated===false)gaps.push({type:'UNAUTHENTICATED_FLOW',edgeId:e.id,severity:'HIGH'})}
 for(const r of reviews)if(r.review_status!=='PASS')gaps.push({type:'FIREWALL_CONTROL_GAP',componentId:r.component_id,severity:r.any_any_rules>0?'CRITICAL':'HIGH',details:{anyAny:r.any_any_rules,stale:r.stale_rules,shadowed:r.shadowed_rules,expired:r.expired_rules}});
 return {components,edges,firewallReviews:reviews,gaps,summary:{components:components.length,flows:edges.length,securityGateways:gateways.length,reviewedGateways:reviewed.size,gaps:gaps.length},assurance:'Architecture and firewall evidence is decision support. PASS requires an explicit reviewed artifact and does not establish external conformity.'}
}
