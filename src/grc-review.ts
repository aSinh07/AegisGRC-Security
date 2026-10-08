import crypto from 'node:crypto';
import pg from 'pg';

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
    approval_hash text,
    submitted_at timestamptz NOT NULL DEFAULT now(),
    reviewed_at timestamptz,
    approved_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(assessment_id,framework)
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS grc_report_reviews_status_idx ON grc_report_reviews(status,updated_at DESC)');
}
export async function submitGrcReview(assessmentId:string,framework:string,userId:string){
  const id=crypto.randomUUID();
  const r=await pool.query(`INSERT INTO grc_report_reviews(id,assessment_id,framework,submitted_by,status)
    VALUES($1,$2,$3,$4,'SUBMITTED')
    ON CONFLICT(assessment_id,framework) DO UPDATE SET submitted_by=EXCLUDED.submitted_by,status='SUBMITTED',reviewer_id=NULL,consultant_notes='',approval_hash=NULL,submitted_at=now(),reviewed_at=NULL,approved_at=NULL,updated_at=now()
    RETURNING *`,[id,assessmentId,framework,userId]);
  return r.rows[0];
}
export async function listGrcReviews(assessmentId?:string){
  const r=assessmentId?await pool.query('SELECT * FROM grc_report_reviews WHERE assessment_id=$1 ORDER BY updated_at DESC',[assessmentId]):await pool.query('SELECT * FROM grc_report_reviews ORDER BY updated_at DESC LIMIT 200');
  return r.rows;
}
export async function reviewGrcReport(id:string,reviewerId:string,status:ReviewStatus,notes:string){
  if(!['IN_REVIEW','CHANGES_REQUESTED','APPROVED','REJECTED'].includes(status))throw Error('Invalid GRC review status');
  if((status==='CHANGES_REQUESTED'||status==='REJECTED')&&!notes.trim())throw Error('Consultant notes are required for this decision');
  const approvalHash=status==='APPROVED'?crypto.createHash('sha256').update([id,reviewerId,new Date().toISOString(),notes].join('|')).digest('hex'):null;
  const r=await pool.query(`UPDATE grc_report_reviews SET reviewer_id=$2,status=$3,consultant_notes=$4,approval_hash=$5,reviewed_at=now(),approved_at=CASE WHEN $3='APPROVED' THEN now() ELSE NULL END,updated_at=now() WHERE id=$1 RETURNING *`,[id,reviewerId,status,notes.trim(),approvalHash]);
  if(!r.rows[0])throw Error('GRC review not found');
  return r.rows[0];
}
