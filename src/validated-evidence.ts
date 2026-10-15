import pg from 'pg';
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail=(message:string)=>Object.assign(new Error(message),{statusCode:409});
export function normalizeEvidenceVersionIds(input:unknown):string[]{
 if(!Array.isArray(input)||!input.length||input.length>200||input.some(x=>typeof x!=='string'||!uuid.test(x)))throw fail('Current Evidence Vault version UUIDs required');
 const ids=input.map((x:string)=>x.toLowerCase());if(new Set(ids).size!==ids.length)throw fail('Duplicate Evidence Vault version UUIDs are not accepted');return ids;
}
/** Fail closed: tenant-owned, current, server-hashed, independently validated evidence only. */
export async function requireValidatedEvidenceVersions(db:Pick<pg.Pool,'query'>|Pick<pg.PoolClient,'query'>,org:string,input:unknown,scopeId?:string):Promise<string[]>{
 const ids=normalizeEvidenceVersionIds(input);
 const sql=`SELECT count(DISTINCT v.id)::int AS n FROM grc_evidence_versions v
 JOIN grc_evidence_requests r ON r.id=v.evidence_request_id
 JOIN grc_scope_controls sc ON sc.id=r.scope_control_id AND sc.organization_id=r.organization_id
 WHERE r.organization_id=$1 AND v.id=ANY($2::uuid[])
 AND ($3::uuid IS NULL OR sc.scope_id=$3)
 AND r.status='VALID' AND v.integrity_status='SERVER_VERIFIED'
 AND v.object_id IS NOT NULL AND v.validated_by IS NOT NULL
 AND v.submitted_by IS DISTINCT FROM v.validated_by
 AND v.validated_at IS NOT NULL AND v.valid_until>now()
 AND v.version=(SELECT max(v2.version) FROM grc_evidence_versions v2 WHERE v2.evidence_request_id=r.id)`;
 const r=await db.query(sql,[org,ids,scopeId||null]);if(Number(r.rows[0]?.n)!==ids.length)throw fail('Evidence Vault versions must be current, independently validated, server verified and tenant/scope owned');return ids;
}
