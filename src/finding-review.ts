import crypto from 'node:crypto';
import pg from 'pg';
import type {Finding} from './models.js';
import {requireAssessmentAccess,requireOrgPermission} from './grc-organizations.js';

const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
export type FindingDecision='CONFIRMED'|'FALSE_POSITIVE'|'ACCEPTED'|'REMEDIATED';
const decisions=new Set<FindingDecision>(['CONFIRMED','FALSE_POSITIVE','ACCEPTED','REMEDIATED']);

export async function initFindingReview(){
 await pool.query(`
 CREATE TABLE IF NOT EXISTS finding_reviews(
  id uuid PRIMARY KEY,finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  decision text NOT NULL CHECK(decision IN ('CONFIRMED','FALSE_POSITIVE','ACCEPTED','REMEDIATED')),
  rationale text NOT NULL,reviewer_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now()
 );
 CREATE INDEX IF NOT EXISTS finding_reviews_finding_idx ON finding_reviews(finding_id,created_at DESC);
 CREATE INDEX IF NOT EXISTS finding_reviews_assessment_idx ON finding_reviews(assessment_id,created_at DESC);
 `);
}
function statusFor(d:FindingDecision):Finding['status']{
 return d==='CONFIRMED'?'OPEN':d;
}
export async function reviewFinding(userId:string,assessmentId:string,findingId:string,input:{decision:string;rationale:string}){
 const access=await requireAssessmentAccess(userId,assessmentId);
 await requireOrgPermission(userId,access.organization_id,'findingReview');
 const decision=String(input.decision||'').toUpperCase() as FindingDecision;
 const rationale=String(input.rationale||'').trim();
 if(!decisions.has(decision))throw new Error('Decision must be CONFIRMED, FALSE_POSITIVE, ACCEPTED or REMEDIATED');
 if(rationale.length<10||rationale.length>4000)throw new Error('Review rationale must be 10-4000 characters');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const row=(await client.query('SELECT id,assessment_id,payload FROM findings WHERE id=$1 AND assessment_id=$2 FOR UPDATE',[findingId,assessmentId])).rows[0];
  if(!row)throw Object.assign(new Error('Finding not found'),{statusCode:404});
  const original=row.payload as Finding;
  const updated:Finding={...original,status:statusFor(decision)};
  await client.query('UPDATE findings SET payload=$1 WHERE id=$2',[updated,findingId]);
  const reviewId=crypto.randomUUID();
  const review=(await client.query(`INSERT INTO finding_reviews(id,finding_id,assessment_id,decision,rationale,reviewer_id)
   VALUES($1,$2,$3,$4,$5,$6) RETURNING id,finding_id,assessment_id,decision,rationale,reviewer_id,created_at`,
   [reviewId,findingId,assessmentId,decision,rationale,userId])).rows[0];
  const audit={id:crypto.randomUUID(),assessmentId,action:'FINDING_REVIEWED',actor:userId,createdAt:new Date().toISOString(),metadata:{findingId,reviewId,decision,rationale}};
  await client.query('INSERT INTO audit_events(id,assessment_id,action,created_at,payload) VALUES($1,$2,$3,$4,$5)',[audit.id,assessmentId,audit.action,audit.createdAt,audit]);
  await client.query('COMMIT');return {finding:updated,review};
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function findingReviewHistory(userId:string,assessmentId:string,findingId:string){
 await requireAssessmentAccess(userId,assessmentId);
 return (await pool.query(`SELECT r.id,r.finding_id,r.assessment_id,r.decision,r.rationale,r.created_at,u.email reviewer
 FROM finding_reviews r JOIN app_users u ON u.id=r.reviewer_id
 WHERE r.assessment_id=$1 AND r.finding_id=$2 ORDER BY r.created_at ASC`,[assessmentId,findingId])).rows;
}
