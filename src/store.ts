import { promises as fs } from 'node:fs';import path from 'node:path';import pg from 'pg';
import type { Assessment,Evidence,Finding,AuditEvent } from './models.js';
const dir=process.env.DATA_DIR||'/tmp/aegis-data'; const url=process.env.DATABASE_URL;
const production=process.env.NODE_ENV==='production';
if(production&&!url) throw new Error('DATABASE_URL is required in production');
const pool=url?new pg.Pool({connectionString:url,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false}}):null;
async function rw<T>(name:string,f:(x:T[])=>T[]){await fs.mkdir(dir,{recursive:true});const p=path.join(dir,name);let a:T[]=[];try{a=JSON.parse(await fs.readFile(p,'utf8'))}catch{};a=f(a);await fs.writeFile(p,JSON.stringify(a,null,2));return a}
async function read<T>(name:string){try{return JSON.parse(await fs.readFile(path.join(dir,name),'utf8')) as T[]}catch{return []}}
const allowedTables={assessments:'authorized_at',evidence:'created_at',findings:'created_at',audit_events:'created_at'} as const;
async function qPayload<T>(table:keyof typeof allowedTables){if(!pool)return null;const order=allowedTables[table];const r=await pool.query(`SELECT payload FROM ${table} ORDER BY ${order} ASC`);return r.rows.map(x=>x.payload as T)}
async function upsertAssessment(x:Assessment){if(!pool)return rw<Assessment>('assessments.json',a=>[...a.filter(v=>v.id!==x.id),x]);await pool.query(`INSERT INTO assessments(id,target,authorized_at,status,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET target=EXCLUDED.target,status=EXCLUDED.status,payload=EXCLUDED.payload`,[x.id,x.target,x.authorizedAt,x.status,x]);return []}
async function insert(table:string,x:any,cols:string[],vals:any[]){if(!pool)return null;await pool.query(`INSERT INTO ${table}(${cols.join(',')}) VALUES(${cols.map((_,i)=>'$'+(i+1)).join(',')}) ON CONFLICT(id) DO NOTHING`,vals)}
export const db={
 mode:()=>pool?'postgres':'file',
 ready:async()=>{if(!pool){if(production)throw new Error('PostgreSQL is required in production');return {ok:true,mode:'file'}};await pool.query('SELECT 1');return {ok:true,mode:'postgres'}},
 assessments:async()=>pool?(await qPayload<Assessment>('assessments'))!:read<Assessment>('assessments.json'),
 evidence:async()=>pool?(await qPayload<Evidence>('evidence'))!:read<Evidence>('evidence.json'),
 findings:async()=>pool?(await qPayload<Finding>('findings'))!:read<Finding>('findings.json'),
 audits:async()=>pool?(await qPayload<AuditEvent>('audit_events'))!:read<AuditEvent>('audit.json'),
 saveAssessment:upsertAssessment,
 saveEvidence:async(x:Evidence)=>{if(!pool)return rw<Evidence>('evidence.json',a=>[...a,x]);await insert('evidence',x,['id','assessment_id','source','sha256','created_at','payload'],[x.id,x.assessmentId,x.source,x.sha256,x.createdAt,x]);return []},
 saveFindings:async(xs:Finding[])=>{if(!pool)return rw<Finding>('findings.json',a=>[...a,...xs.filter(x=>!a.some(v=>v.id===x.id))]);for(const x of xs)await insert('findings',x,['id','assessment_id','severity','source','created_at','payload'],[x.id,x.assessmentId,x.severity,x.source,x.createdAt,x]);return []},
 saveAudit:async(x:AuditEvent)=>{if(!pool)return rw<AuditEvent>('audit.json',a=>[...a,x]);await insert('audit_events',x,['id','assessment_id','action','created_at','payload'],[x.id,x.assessmentId||null,x.action,x.createdAt,x]);return []},
 saveDocument:async(x:{id:string,assessmentId:string,filename:string,mimeType:string,size:number,sha256:string,createdAt:string,content:Buffer})=>{if(!pool)throw new Error('Document vault requires PostgreSQL');await pool.query('INSERT INTO documents(id,assessment_id,filename,mime_type,size_bytes,sha256,created_at,content) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[x.id,x.assessmentId,x.filename,x.mimeType,x.size,x.sha256,x.createdAt,x.content])},
 documents:async(assessmentId:string)=>{if(!pool)return [];const r=await pool.query('SELECT id,assessment_id as "assessmentId",filename,mime_type as "mimeType",size_bytes as size,sha256,created_at as "createdAt" FROM documents WHERE assessment_id=$1 ORDER BY created_at DESC',[assessmentId]);return r.rows},
 document:async(id:string)=>{if(!pool)return null;const r=await pool.query('SELECT id,assessment_id as "assessmentId",filename,mime_type as "mimeType",size_bytes as size,sha256,created_at as "createdAt",content FROM documents WHERE id=$1',[id]);return r.rows[0]||null},
 deleteDocument:async(id:string)=>{if(!pool)return false;const r=await pool.query('DELETE FROM documents WHERE id=$1',[id]);return (r.rowCount||0)>0}
};