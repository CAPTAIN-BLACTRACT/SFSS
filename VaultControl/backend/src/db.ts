import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

// The pool will handle multiple simultaneous connections
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// We'll export a helper to query the DB easily
export const query = (text: string, params?: any[]) => pool.query(text, params);

export default pool;
