import crypto from 'node:crypto';
import pg from 'pg';

const pool=new pg.Pool({
  connectionString:process.env.DATABASE_URL,
  ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},
  max:Number(process.env.DB_POOL_MAX||30)
});

export type OrgRole='ORG_ADMIN'|'GRC_MANAGER'|'GRC_ANALYST'|'CONTROL_OWNER'|'RISK_OWNER'|'REVIEWER'|'AUDITOR'|'VIEWER';
const roles:OrgRole[]=['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST','CONTROL_OWNER','RISK_OWNER','REVIEWER','AUDITOR','VIEWER'];
const permissions={
 read:new Set<OrgRole>(roles),
 manageOrg:new Set<OrgRole>(['ORG_ADMIN']),
 manageScope:new Set<OrgRole>(['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST']),
 manageControl:new Set<OrgRole>(['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST','CONTROL_OWNER']),
 manageRisk:new Set<OrgRole>(['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST','RISK_OWNER']),
 review:new Set<OrgRole>(['GRC_MANAGER','REVIEWER','AUDITOR'])
};
export type OrgPermission=keyof typeof permissions;
export function roleAllows(role:OrgRole,permission:OrgPermission){return permissions[permission].has(role)}

export async function initOrganizations(){
 await pool.query(`
 CREATE TABLE IF NOT EXISTS grc_organizations(
   id uuid PRIMARY KEY,name text NOT NULL,industry text,status text NOT NULL DEFAULT 'ACTIVE',
   created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
   created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()
 );
 CREATE TABLE IF NOT EXISTS grc_organization_members(
   organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
   user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
   role text NOT NULL CHECK(role IN ('ORG_ADMIN','GRC_MANAGER','GRC_ANALYST','CONTROL_OWNER','RISK_OWNER','REVIEWER','AUDITOR','VIEWER')),
   status text NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','SUSPENDED')),
   created_at timestamptz NOT NULL DEFAULT now(),
   PRIMARY KEY(organization_id,user_id)
 );
 CREATE INDEX IF NOT EXISTS grc_org_members_user_idx ON grc_organization_members(user_id,status);
 CREATE TABLE IF NOT EXISTS grc_scopes(
   id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
   name text NOT NULL,description text,status text NOT NULL DEFAULT 'DRAFT',
   created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
   created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
   UNIQUE(organization_id,name)
 );
 `);
}

export async function createOrganization(userId:string,input:{name:string;industry?:string}){
 const name=String(input.name||'').trim();
 if(name.length<2||name.length>160)throw new Error('Organization name must be 2-160 characters');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const id=crypto.randomUUID();
  const org=(await client.query(`INSERT INTO grc_organizations(id,name,industry,created_by) VALUES($1,$2,$3,$4) RETURNING *`,
    [id,name,String(input.industry||'').trim()||null,userId])).rows[0];
  await client.query(`INSERT INTO grc_organization_members(organization_id,user_id,role) VALUES($1,$2,'ORG_ADMIN')`,[id,userId]);
  await client.query('COMMIT');
  return org;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function memberships(userId:string){
 return (await pool.query(`SELECT o.id,o.name,o.industry,m.role,m.status
 FROM grc_organization_members m JOIN grc_organizations o ON o.id=m.organization_id
 WHERE m.user_id=$1 AND m.status='ACTIVE' AND o.status='ACTIVE' ORDER BY o.name`,[userId])).rows;
}
export async function membership(userId:string,organizationId:string){
 return (await pool.query(`SELECT m.organization_id,m.user_id,m.role,m.status,o.name
 FROM grc_organization_members m JOIN grc_organizations o ON o.id=m.organization_id
 WHERE m.user_id=$1 AND m.organization_id=$2 AND m.status='ACTIVE' AND o.status='ACTIVE'`,[userId,organizationId])).rows[0]||null;
}
export async function requireOrgPermission(userId:string,organizationId:string,permission:OrgPermission){
 const m=await membership(userId,organizationId);
 if(!m)throw Object.assign(new Error('Organization membership required'),{statusCode:403});
 if(!roleAllows(m.role as OrgRole,permission))throw Object.assign(new Error('Insufficient organization role'),{statusCode:403});
 return m;
}
export async function createScope(userId:string,organizationId:string,input:{name:string;description?:string}){
 await requireOrgPermission(userId,organizationId,'manageScope');
 const name=String(input.name||'').trim();if(name.length<2||name.length>160)throw new Error('Scope name must be 2-160 characters');
 const id=crypto.randomUUID();
 return (await pool.query(`INSERT INTO grc_scopes(id,organization_id,name,description,created_by)
 VALUES($1,$2,$3,$4,$5) RETURNING *`,[id,organizationId,name,String(input.description||'').trim()||null,userId])).rows[0];
}
export async function listScopes(userId:string,organizationId:string){
 await requireOrgPermission(userId,organizationId,'read');
 return (await pool.query(`SELECT id,organization_id,name,description,status,created_at,updated_at FROM grc_scopes
 WHERE organization_id=$1 ORDER BY created_at DESC`,[organizationId])).rows;
}
export async function addMember(actorId:string,organizationId:string,userId:string,role:OrgRole){
 await requireOrgPermission(actorId,organizationId,'manageOrg');
 if(!roles.includes(role))throw new Error('Invalid organization role');
 if(actorId===userId&&role!=='ORG_ADMIN')throw new Error('Organization admin cannot demote self through this endpoint');
 const exists=(await pool.query('SELECT id FROM app_users WHERE id=$1',[userId])).rows[0];if(!exists)throw new Error('User not found');
 return (await pool.query(`INSERT INTO grc_organization_members(organization_id,user_id,role,status)
 VALUES($1,$2,$3,'ACTIVE') ON CONFLICT(organization_id,user_id)
 DO UPDATE SET role=EXCLUDED.role,status='ACTIVE' RETURNING organization_id,user_id,role,status`,[organizationId,userId,role])).rows[0];
}
