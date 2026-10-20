import {monitorEventLoopDelay} from 'node:perf_hooks';
import {pool,databasePoolCapacity} from './db-pool.js';

const http={requests:0,errors:0,totalLatencyMs:0,status2xx:0,status4xx:0,status5xx:0,slowRequests:0};
const loop=monitorEventLoopDelay({resolution:20});loop.enable();
export function recordHttpObservation(status:number,latencyMs:number){
 http.requests++;http.totalLatencyMs+=Math.max(0,latencyMs);
 if(status>=500){http.status5xx++;http.errors++}else if(status>=400){http.status4xx++;http.errors++}else if(status>=200&&status<300)http.status2xx++;
 if(latencyMs>=1000)http.slowRequests++;
}
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
  http:{...http,averageLatencyMs:http.requests?Math.round(http.totalLatencyMs/http.requests):0,errorRate:http.requests?Number((http.errors/http.requests).toFixed(4)):0},eventLoop:{meanMs:Number.isFinite(loop.mean)?Number((loop.mean/1e6).toFixed(2)):0,maxMs:Number((loop.max/1e6).toFixed(2))},process:{uptimeSeconds:Math.round(process.uptime()),rssBytes:m.rss,heapUsedBytes:m.heapUsed,heapTotalBytes:m.heapTotal}
 };
}
