"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const db_1 = require("./db");
const app = (0, express_1.default)();
const port = process.env.PORT || 5000;
app.use((0, cors_1.default)());
app.use(express_1.default.json());
// 1. List all files in the vault
app.get('/files', async (req, res) => {
    try {
        const result = await (0, db_1.query)('SELECT * FROM Files_Vault ORDER BY created_at DESC');
        res.json(result.rows);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// 2. Revoke or Activate access to a file
app.patch('/files/:id/status', async (req, res) => {
    const { id } = req.params;
    const { status } = req.body; // 'ACTIVE' or 'REVOKED'
    try {
        const result = await (0, db_1.query)('UPDATE Files_Vault SET global_status = $1 WHERE id = $2 RETURNING *', [status, id]);
        res.json(result.rows[0]);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// 3. Add a new Access Policy (CIDR/Device Hash)
app.post('/files/:id/policies', async (req, res) => {
    const { id } = req.params;
    const { allowed_cidr, allowed_device_hash } = req.body;
    try {
        const result = await (0, db_1.query)('INSERT INTO Access_Policies (file_id, allowed_cidr, allowed_device_hash) VALUES ($1, $2, $3) RETURNING *', [id, allowed_cidr, allowed_device_hash]);
        res.status(201).json(result.rows[0]);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// 4. Get audit logs for a specific file
app.get('/files/:id/audit', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await (0, db_1.query)('SELECT * FROM Audit_Ledger WHERE file_id = $1 ORDER BY attempted_at DESC', [id]);
        res.json(result.rows);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.listen(port, () => {
    console.log(`Dashboard API running on http://localhost:${port}`);
});
//# sourceMappingURL=index.js.map