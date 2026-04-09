import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { X, Plus, ShieldOff, ShieldCheck, Trash2, Save } from 'lucide-react';

interface Policy {
  id: string;
  allowed_cidr: string;
  allowed_device_hash: string;
}

interface ActiveSession {
  id: string;
  device_hash: string;
  ip_address: string;
  connected_at: string;
}

interface AuditLog {
  id: string;
  request_ip: string;
  device_hash: string;
  access_granted: boolean;
  denial_reason: string;
  attempted_at: string;
}

interface FileEntry {
  id: string;
  file_name: string;
  global_status: string;
}

interface AccessControlProps {
  file: FileEntry;
  onClose: () => void;
  onUpdate: () => void;
  apiBase: string;
}

const AccessControlModal: React.FC<AccessControlProps> = ({ file, onClose, onUpdate, apiBase }) => {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [sessions, setSessions] = useState<ActiveSession[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [newCidr, setNewCidr] = useState('');
  const [newDevice, setNewDevice] = useState('');
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    fetchPolicies();
  }, [file.id]);

  const fetchPolicies = async () => {
    try {
      const resP = await axios.get(`${apiBase}/files/${file.id}/policies`);
      setPolicies(resP.data);
      const resS = await axios.get(`${apiBase}/files/${file.id}/active_sessions`);
      setSessions(resS.data);
      const resL = await axios.get(`${apiBase}/files/${file.id}/audit`);
      setLogs(resL.data);
    } catch (err) {
      console.error("Error fetching data", err);
    }
  };

  const addPolicy = async () => {
    if (!newCidr && !newDevice) return;
    setIsSaving(true);
    try {
      await axios.post(`${apiBase}/files/${file.id}/policies`, { 
        allowed_cidr: newCidr, 
        allowed_device_hash: newDevice 
      });
      setNewCidr('');
      setNewDevice('');
      fetchPolicies();
    } catch (err) {
      console.error("Error adding policy", err);
    } finally {
      setIsSaving(false);
    }
  };

  const removePolicy = async (policyId: string) => {
    try {
      await axios.delete(`${apiBase}/policies/${policyId}`);
      fetchPolicies();
    } catch (err) {
      console.error("Error removing policy", err);
    }
  };

  const revokeSession = async (deviceHash: string) => {
    try {
      await axios.delete(`${apiBase}/files/${file.id}/sessions/${deviceHash}`);
      fetchPolicies();
    } catch (err) {
      console.error("Error revoking session", err);
    }
  };

  const toggleRevocation = async () => {
    try {
      const newStatus = file.global_status === 'ACTIVE' ? 'REVOKED' : 'ACTIVE';
      await axios.patch(`${apiBase}/files/${file.id}/status`, { 
        status: newStatus 
      });
      onUpdate();
    } catch (err) {
      console.error("Error updating revocation status", err);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()} style={{ maxWidth: '900px', width: '90%' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3>Access Control: {file.file_name}</h3>
          <button className="btn btn-ghost" onClick={onClose}><X size={20} /></button>
        </div>

        <div className="card" style={{ marginBottom: '20px', border: file.global_status === 'REVOKED' ? '1px solid var(--danger)' : '1px solid var(--success)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h4 style={{ color: file.global_status === 'REVOKED' ? 'var(--danger)' : 'var(--success)' }}>
                {file.global_status === 'REVOKED' ? 'Access Revoked' : 'Access Active'}
              </h4>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                {file.global_status === 'REVOKED' ? 'All access to this file is currently blocked.' : 'Access is allowed based on policies below.'}
              </p>
            </div>
            <button 
              className={`btn ${file.global_status === 'REVOKED' ? 'btn-primary' : ''}`}
              style={{ backgroundColor: file.global_status === 'REVOKED' ? 'var(--success)' : 'var(--danger)', color: 'white' }}
              onClick={toggleRevocation}
            >
              {file.global_status === 'REVOKED' ? <ShieldCheck size={18} /> : <ShieldOff size={18} />}
              {file.global_status === 'REVOKED' ? 'Restore Access' : 'Revoke All'}
            </button>
          </div>
        </div>

        <div style={{ marginBottom: '20px' }}>
          <h4 style={{ marginBottom: '12px' }}>Network & Device Rules</h4>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
            <input 
              placeholder="CIDR (e.g. 192.168.1.0/24)" 
              value={newCidr}
              onChange={e => setNewCidr(e.target.value)}
              style={{ flex: 1 }}
            />
            <input 
              placeholder="Device Hash" 
              value={newDevice}
              onChange={e => setNewDevice(e.target.value)}
              style={{ flex: 1 }}
            />
            <button className="btn btn-primary" onClick={addPolicy} disabled={isSaving}>
              {isSaving ? '...' : <Plus size={18} />}
            </button>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {policies.map(p => (
              <div key={p.id} className="card" style={{ padding: '8px 12px', display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px' }}>
                <span>{p.allowed_cidr || 'Any IP'} | {p.allowed_device_hash || 'Any Device'}</span>
                <Trash2 
                  size={14} 
                  color="var(--danger)" 
                  style={{ cursor: 'pointer' }} 
                  onClick={() => removePolicy(p.id)}
                />
              </div>
            ))}
            {policies.length === 0 && <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>No specific rules defined.</p>}
          </div>
        </div>

        <div style={{ marginBottom: '20px' }}>
          <h4 style={{ marginBottom: '12px' }}>Active Sessions (Real-Time)</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {sessions.map(s => (
              <div key={s.id} className="card" style={{ padding: '8px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', fontSize: '13px', borderLeft: '3px solid var(--success)', gap: '16px' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <strong style={{ wordBreak: 'break-all' }}>{s.device_hash}</strong> ({s.ip_address})<br/>
                  <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Since: {new Date(s.connected_at).toLocaleString()}</span>
                </div>
                <button className="btn btn-ghost" style={{ color: 'var(--danger)', fontSize: '12px', padding: '4px 8px', whiteSpace: 'nowrap' }} onClick={() => revokeSession(s.device_hash)}>
                  Revoke Device
                </button>
              </div>
            ))}
            {sessions.length === 0 && <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>No devices currently connected.</p>}
          </div>
        </div>

        <div style={{ marginBottom: '20px', maxHeight: '150px', overflowY: 'auto', border: '1px solid var(--border)', borderRadius: '8px', padding: '8px' }}>
          <h4 style={{ marginBottom: '8px', fontSize: '13px' }}>Audit Ledger</h4>
          <table style={{ fontSize: '11px', width: '100%' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--text-muted)' }}>
                <th>Time</th><th>IP</th><th>Device Hash</th><th>Status</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(l => (
                <tr key={l.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td>{new Date(l.attempted_at).toLocaleString()}</td>
                  <td>{l.request_ip}</td>
                  <td style={{ maxWidth: '100px', overflow: 'hidden', textOverflow: 'ellipsis' }} title={l.device_hash}>{l.device_hash}</td>
                  <td style={{ color: l.access_granted ? 'var(--success)' : 'var(--danger)' }}>
                    {l.access_granted ? 'GRANTED' : `DENIED: ${l.denial_reason || 'Unknown'}`}
                  </td>
                </tr>
              ))}
              {logs.length === 0 && <tr><td colSpan={4} style={{ textAlign: 'center' }}>No audit history found.</td></tr>}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button className="btn btn-primary" onClick={onClose}>
            <Save size={18} />
            Save Changes
          </button>
        </div>
      </div>
    </div>
  );
};

export default AccessControlModal;
