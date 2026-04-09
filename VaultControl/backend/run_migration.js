const { Pool } = require('pg');
require('dotenv').config();
const fs = require('fs');
const path = require('path');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function run() {
  const file = path.join(__dirname, '../db/migrations/01_initial_schema.sql');
  const sql = fs.readFileSync(file, 'utf8');
  await pool.query(sql);
  console.log("Migration executed successfully.");
  process.exit(0);
}
run().catch(console.error);
