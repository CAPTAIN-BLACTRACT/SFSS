import express, { Request, Response } from 'express';
import cors from 'cors';
import { query } from './db';

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

import multer from 'multer';
const upload = multer({ dest: 'uploads/' });

import fs from 'fs';
import crypto from 'crypto';
import path from 'path';

// 0. Upload a new asset
app.post('/upload', upload.single('file'), async (req: Request, res: Response) => {
  const { name } = req.body;
  const fileName = name || (req.file ? req.file.originalname : 'unknown');
  
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
     // Generate real 256-bit AES DEK
     const aesKey = crypto.randomBytes(32);
     const nonce = crypto.randomBytes(12);
     
     // Generate dummy hash
     const fileHash = crypto.createHash('sha256').update(fs.readFileSync(req.file.path)).digest('hex');

     // Cross-Platform AES-256-GCM Encryption Mapping (Node to Rust)
     const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce);
     const plaintext = fs.readFileSync(req.file.path);
     const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
     const authTag = cipher.getAuthTag(); // Rust expects the 16-byte tag appended at the very end
     
     // Final physical binary layout: [12-byte Nonce] + [Ciphertext] + [16-byte MAC Auth Tag]
     const physicalFileBlob = Buffer.concat([nonce, ciphertext, authTag]);

     // Write the actual .enc file directly to the secure_agent folder so it can access it instantly
     const targetPath = path.join(__dirname, '../../../secure_agent', fileName.replace('.txt', '') + '.enc');
     fs.writeFileSync(targetPath, physicalFileBlob);
     
     // Convert raw Node buffer to Postgres BYTEA hex format
     const pgDekHex = '\\x' + aesKey.toString('hex');
     
     const result = await query(
       'INSERT INTO Files_Vault (file_name, wrapped_dek, global_status, file_hash) VALUES ($1, $2, $3, $4) RETURNING *',
       [fileName, pgDekHex, 'ACTIVE', fileHash]
     );
     
     res.status(201).json(result.rows[0]);
  } catch(err) {
     console.error(err);
     res.status(500).json({ error: 'Internal server error' });
  }
});

// 1. List all files in the vault
app.get('/files', async (req: Request, res: Response) => {
  try {
    const result = await query(`
      SELECT f.*, (SELECT COUNT(*) FROM Access_Policies p WHERE p.file_id = f.id) as policy_count 
      FROM Files_Vault f 
      ORDER BY f.created_at DESC
    `);
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

// 5. Delete File
app.delete('/files/:id', async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    await query('DELETE FROM Access_Policies WHERE file_id = $1', [id]);
    await query('DELETE FROM Audit_Ledger WHERE file_id = $1', [id]);
    // Active Sessions gets cleaned up by CASCADE delete on DB level
    await query('DELETE FROM Files_Vault WHERE id = $1', [id]);
    res.status(200).json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 6. Get active sessions
app.get('/files/:id/active_sessions', async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    const result = await query(
      'SELECT * FROM Active_Sessions WHERE file_id = $1 ORDER BY connected_at DESC',
      [id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 7. Revoke an active session by deleting its corresponding explicit device policy
app.delete('/files/:id/sessions/:deviceHash', async (req: Request, res: Response) => {
  const { id, deviceHash } = req.params;
  try {
    await query(
      'DELETE FROM Access_Policies WHERE file_id = $1 AND allowed_device_hash = $2',
      [id, deviceHash]
    );
    res.status(200).json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 6. Get all policies for a file
app.get('/files/:id/policies', async (req: Request, res: Response) => {
  try {
    const result = await query('SELECT * FROM Access_Policies WHERE file_id = $1', [req.params.id]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 7. Delete a specific policy
app.delete('/policies/:id', async (req: Request, res: Response) => {
  try {
    await query('DELETE FROM Access_Policies WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 8. Get ALL audit logs
app.get('/audit-logs', async (req: Request, res: Response) => {
  try {
    const result = await query('SELECT a.*, f.file_name FROM Audit_Ledger a LEFT JOIN Files_Vault f ON a.file_id = f.id ORDER BY a.attempted_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 9. Mock Active Sessions (Zero-Trust Architecture is inherently Stateless)
app.get('/files/:id/active_sessions', async (req: Request, res: Response) => {
  res.json([]);
});

app.listen(port, () => {
  console.log(`Dashboard API running on http://localhost:${port}`);
});
