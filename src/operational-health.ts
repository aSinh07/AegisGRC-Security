import {pool,databasePoolCapacity} from './db-pool.js';

export async function operationalSnapshot(){
 const started=Date.now();
 const [db,scanner]=await Promise.all([
  pool.query('SELECT now() AS now'),
  pool.query(`SELECT
   count(*) FILTER (WHERE state='QUEUED')::int AS queued,
   count(*) FILTER (WHERE state='RUNNING')::int AS running,
   count(*) FILTER (WHERE state IN ('FAILED','TIMEOUT','TRUNCATED','UNAVAILABLE') AND created_at>now()-interval '1 hour')::int AS failed_last_hour
   FROM scanner_jobs`)
 ]);
 const m=process.memoryUsage();
 return {
  ok:true,
  observedAt:new Date().toISOString(),
  database:{ok:Boolean(db.rows[0]),latencyMs:Date.now()-started,pool:{...databasePoolCapacity(),total:pool.totalCount,idle:pool.idleCount,waiting:pool.waitingCount}},
  scannerQueue:scanner.rows[0]||{queued:0,running:0,failed_last_hour:0},
  process:{uptimeSeconds:Math.round(process.uptime()),rssBytes:m.rss,heapUsedBytes:m.heapUsed,heapTotalBytes:m.heapTotal}
 };
}
