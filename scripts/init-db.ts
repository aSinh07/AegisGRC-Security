import 'dotenv/config';import { readFile } from 'node:fs/promises';import pg from 'pg';
if(!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false}});
const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
const client=await pool.connect();
try{
 await client.query('BEGIN');
 await client.query(sql);
 await client.query('COMMIT');
 console.log('AegisGRC database schema initialized transactionally');
}catch(e){
 await client.query('ROLLBACK');
 console.error('AegisGRC database schema initialization failed; transaction rolled back');
 throw e;
}finally{
 client.release();
 await pool.end();
}
