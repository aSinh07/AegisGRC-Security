import 'dotenv/config';import { readFile } from 'node:fs/promises';import pg from 'pg';
if(!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false}});
const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');await pool.query(sql);console.log('AegisGRC database schema initialized');await pool.end();
