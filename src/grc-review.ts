import crypto from 'node:crypto';
import pg from 'pg';
import {signApprovedReport,verifyApprovedReportSignature} from './report-auth.js';

const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||30)});
export type ReviewStatus='SUBMITTED'|'IN_REVIEW'|'CHANGES_REQUESTED'|'APPROVED'|'REJECTED';

export async function initGrcReviews(){
  await pool.query(`CREATE TABLE IF NOT EXISTS grc_report_reviews(
    id uuid PRIMARY KEY,
    assessment_id uuid NOT NULL,
    framework text NOT NULL,
    submitted_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
    reviewer_id uuid REFERENCES app_users(id) ON DELETE SET NULL,
    status text NOT NULL DEFAULT 'SUBMITTED',
    consultant_notes text NOT NULL DEFAULT '',
    snapshot_digest text,
    approval_hash text,
    submitted_at timestamptz NOT NULL DEFAULT now(),
    reviewed_at timestamptz,
    approved_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(assessment_id,framework)
  )`);
  await pool.query('ALTER TABLE grc_report_reviews ADD COLUMN IF NOT EXISTS snapshot_digest text');
  await pool.query('CREATE INDEX IF NOT EXISTS grc_report_reviews_status_idx ON grc_report_reviews(status,updated_at DESC)');
}
export async function submitGrcReview(assessmentId:string,framework:string,userId:string,snapshotDigest:string){
  if(!/^[a-f0-9]{64}$/i.test(snapshotDigest))throw Error('Valid report snapshot digest is required');
  const id=crypto.randomUUID();
  const r=await pool.query(`INSERT INTO grc_report_reviews(id,assessment_id,framework,submitted_by,status,snapshot_digest)
    VALUES($1,$2,$3,$4,'SUBMITTED',$5)
    ON CONFLICT(assessment_id,framework) DO UPDATE SET submitted_by=EXCLUDED.submitted_by,status='SUBMITTED',snapshot_digest=EXCLUDED.snapshot_digest,reviewer_id=NULL,consultant_notes='',approval_hash=NULL,submitted_at=now(),reviewed_at=NULL,approved_at=NULL,updated_at=now()
    RETURNING *`,[id,assessmentId,framework,userId,snapshotDigest]);
  return r.rows[0];
}
export async function listGrcReviews(assessmentId?:string){
  const r=assessmentId?await pool.query('SELECT * FROM grc_report_reviews WHERE assessment_id=$1 ORDER BY updated_at DESC',[assessmentId]):await pool.query('SELECT * FROM grc_report_reviews ORDER BY updated_at DESC LIMIT 200');
  return r.rows;
}
export async function reviewGrcReport(id:string,reviewerId:string,status:ReviewStatus,notes:string){
  if(!['IN_REVIEW','CHANGES_REQUESTED','APPROVED','REJECTED'].includes(status))throw Error('Invalid GRC review status');
  if((status==='CHANGES_REQUESTED'||status==='REJECTED')&&!notes.trim())throw Error('Consultant notes are required for this decision');
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const locked=await client.query('SELECT * FROM grc_report_reviews WHERE id=$1 FOR UPDATE',[id]);
    const current=locked.rows[0];
    if(!current)throw Error('GRC review not found');
    if(current.submitted_by===reviewerId)throw Object.assign(new Error('Report submitter cannot approve or review their own submission'),{statusCode:403});
    if(current.status==='APPROVED')throw Object.assign(new Error('Approved report must be resubmitted for a new review'),{statusCode:409});
    if(status==='APPROVED'&&!current.snapshot_digest)throw Error('Report snapshot digest is required before approval');
    const approvedAt=status==='APPROVED'?new Date().toISOString():null;
    const approvalHash=status==='APPROVED'?signApprovedReport({
      reviewId:current.id,assessmentId:current.assessment_id,framework:current.framework,
      snapshotDigest:current.snapshot_digest,reviewerId,approvedAt:approvedAt!
    }):null;
    const r=await client.query(`UPDATE grc_report_reviews SET reviewer_id=$2,status=$3,consultant_notes=$4,approval_hash=$5,reviewed_at=now(),approved_at=$6,updated_at=now() WHERE id=$1 RETURNING *`,
      [id,reviewerId,status,notes.trim(),approvalHash,approvedAt]);
    await client.query('COMMIT');
    return r.rows[0];
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function verifyGrcReview(id:string,currentSnapshotDigest?:string){
  const r=await pool.query('SELECT id,assessment_id,framework,reviewer_id,status,snapshot_digest,approval_hash,approved_at FROM grc_report_reviews WHERE id=$1',[id]);
  const x=r.rows[0];
  if(!x)return {valid:false,reason:'REVIEW_NOT_FOUND'};
  if(x.status!=='APPROVED'||!x.reviewer_id||!x.snapshot_digest||!x.approval_hash||!x.approved_at)return {valid:false,reason:'NOT_APPROVED'};
  const signatureValid=verifyApprovedReportSignature({
    reviewId:x.id,assessmentId:x.assessment_id,framework:x.framework,snapshotDigest:x.snapshot_digest,
    reviewerId:x.reviewer_id,approvedAt:new Date(x.approved_at).toISOString(),signature:x.approval_hash
  });
  const snapshotCurrent=currentSnapshotDigest?currentSnapshotDigest===x.snapshot_digest:undefined;
  return {valid:signatureValid&&(snapshotCurrent!==false),signatureValid,snapshotCurrent,reviewId:x.id,assessmentId:x.assessment_id,framework:x.framework,snapshotDigest:x.snapshot_digest,approvedAt:x.approved_at};
}
