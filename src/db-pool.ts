import pg from 'pg';

const maxRaw=Number(process.env.DB_POOL_MAX||20);
const max=Number.isFinite(maxRaw)?Math.min(100,Math.max(2,Math.trunc(maxRaw))):20;
export const pool=new pg.Pool({
 connectionString:process.env.DATABASE_URL,
 ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},
 max,
 idleTimeoutMillis:30_000,
 connectionTimeoutMillis:10_000,
 maxLifetimeSeconds:1_800
});
pool.on('error',err=>console.error('Unexpected idle PostgreSQL client error',String(err?.message||err)));
export function databasePoolCapacity(){return {max,idleTimeoutMillis:30_000,connectionTimeoutMillis:10_000,maxLifetimeSeconds:1_800}}
