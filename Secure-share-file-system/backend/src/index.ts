import express, { Request, Response } from 'express';
import cors from 'cors';
import { query } from './db';

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// 1. List all files in the vault
app.get('/files', async (req: Request, res: Response) => {
  try {
    const result = await query('SELECT * FROM Files_Vault ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 2. Revoke or Activate access to a file
app.patch('/files/:id/status', async (req: Request, res: Response) => {
  const { id } = req.params;
  const { status } = req.body; // 'ACTIVE' or 'REVOKED'

  try {
    const result = await query(
      'UPDATE Files_Vault SET global_status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 3. Add a new Access Policy (CIDR/Device Hash)
app.post('/files/:id/policies', async (req: Request, res: Response) => {
  const { id } = req.params;
  const { allowed_cidr, allowed_device_hash } = req.body;

  try {
    const result = await query(
      'INSERT INTO Access_Policies (file_id, allowed_cidr, allowed_device_hash) VALUES ($1, $2, $3) RETURNING *',
      [id, allowed_cidr, allowed_device_hash]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 4. Get audit logs for a specific file
app.get('/files/:id/audit', async (req: Request, res: Response) => {
  const { id } = req.params;

  try {
    const result = await query(
      'SELECT * FROM Audit_Ledger WHERE file_id = $1 ORDER BY attempted_at DESC',
      [id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(port, () => {
  console.log(`Dashboard API running on http://localhost:${port}`);
});
