# Complete Backend Implementation Guide

This guide provides the necessary PostgreSQL schema and Express.js API implementation to support the full Vault Control Plane features.

## 1. Database Schema (PostgreSQL)

```sql
-- Files table
CREATE TABLE files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_name TEXT NOT NULL,
    global_status TEXT DEFAULT 'ACTIVE',
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Access Policies table
CREATE TABLE access_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID REFERENCES files(id) ON DELETE CASCADE,
    allowed_cidr TEXT,
    allowed_device_hash TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit Logs table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID REFERENCES files(id) ON DELETE CASCADE,
    request_ip TEXT,
    device_hash TEXT,
    access_granted BOOLEAN,
    denial_reason TEXT,
    attempted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

## 2. Express.js API (Complete)

Install dependencies: `npm install express pg cors body-parser multer`

```javascript
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  user: 'your_user',
  host: 'localhost',
  database: 'vault_db',
  password: 'your_password',
  port: 5432,
});

// --- FILES ---

app.get('/files', async (req, res) => {
  const result = await pool.query('SELECT * FROM files ORDER BY created_at DESC');
  res.json(result.rows);
});

app.post('/upload', upload.single('file'), async (req, res) => {
  const { name } = req.body;
  const result = await pool.query(
    'INSERT INTO files (file_name) VALUES ($1) RETURNING *',
    [name]
  );
  res.json(result.rows[0]);
});

app.delete('/files/:id', async (req, res) => {
  await pool.query('DELETE FROM files WHERE id = $1', [req.params.id]);
  res.sendStatus(204);
});

app.patch('/files/:id/revocation', async (req, res) => {
  const { is_revoked } = req.body;
  await pool.query(
    'UPDATE files SET is_revoked = $1, global_status = $2 WHERE id = $3',
    [is_revoked, is_revoked ? 'REVOKED' : 'ACTIVE', req.params.id]
  );
  res.json({ success: true });
});

// --- POLICIES ---

app.get('/files/:id/policies', async (req, res) => {
  const result = await pool.query('SELECT * FROM access_policies WHERE file_id = $1', [req.params.id]);
  res.json(result.rows);
});

app.post('/files/:id/policies', async (req, res) => {
  const { allowed_cidr, allowed_device_hash } = req.body;
  await pool.query(
    'INSERT INTO access_policies (file_id, allowed_cidr, allowed_device_hash) VALUES ($1, $2, $3)',
    [req.params.id, allowed_cidr, allowed_device_hash]
  );
  res.sendStatus(201);
});

app.delete('/policies/:id', async (req, res) => {
  await pool.query('DELETE FROM access_policies WHERE id = $1', [req.params.id]);
  res.sendStatus(204);
});

// --- AUDIT LOGS ---

app.get('/audit-logs', async (req, res) => {
  const result = await pool.query(`
    SELECT a.*, f.file_name 
    FROM audit_logs a 
    JOIN files f ON a.file_id = f.id 
    ORDER BY a.attempted_at DESC
  `);
  res.json(result.rows);
});

app.get('/files/:id/audit', async (req, res) => {
  const result = await pool.query('SELECT * FROM audit_logs WHERE file_id = $1 ORDER BY attempted_at DESC', [req.params.id]);
  res.json(result.rows);
});

app.listen(5000, () => console.log('Vault API running on port 5000'));
```
