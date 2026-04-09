import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Plus, Shield, ShieldAlert, History, Edit, RefreshCw, Trash2, Eye } from 'lucide-react';
import AccessControlModal from './AccessControlModal';
import UploadModal from './UploadModal';

interface FileEntry {
  id: string;
  file_name: string;
  // is_revoked is removed, use global_status instead
  created_at: string;
  global_status: string;
  policy_count?: number;
}

const Dashboard: React.FC<{ apiBase: string }> = ({ apiBase }) => {
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [selectedFile, setSelectedFile] = useState<FileEntry | null>(null);
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [stats, setStats] = useState({ total: 0, active: 0, revoked: 0, recentLogs: 0 });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const res = await axios.get(`${apiBase}/files`);
      const filesData = res.data;
      setFiles(filesData);
      
      const active = filesData.filter((f: any) => f.global_status !== 'REVOKED').length;
      const revoked = filesData.length - active;
      
      setStats({
        total: filesData.length,
        active,
        revoked,
        recentLogs: 0 // Fetch real stats from an endpoint in production
      });
    } catch (err) {
      console.error("Error fetching dashboard data", err);
    }
  };

  const deleteFile = async (id: string) => {
    if (!confirm("Are you sure? This will permanently delete the file and its policies.")) return;
    try {
      await axios.delete(`${apiBase}/files/${id}`);
      fetchData();
    } catch (err) {
      console.error("Error deleting file", err);
    }
  };

  return (
    <div style={{ padding: '32px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '32px' }}>
        <div>
          <h2 style={{ fontSize: '24px', marginBottom: '8px' }}>Security Dashboard</h2>
          <p style={{ color: 'var(--text-muted)' }}>Overview of your secured assets and global security posture.</p>
        </div>
        <button className="btn btn-primary" onClick={() => setIsUploadOpen(true)}>
          <Plus size={20} />
          Secure New File
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '24px', marginBottom: '32px' }}>
        <div className="card">
          <p style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '8px', fontWeight: 'bold', textTransform: 'uppercase' }}>Total Files</p>
          <h3 style={{ fontSize: '28px' }}>{stats.total}</h3>
        </div>
        <div className="card" style={{ borderLeft: '4px solid var(--success)' }}>
          <p style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '8px', fontWeight: 'bold', textTransform: 'uppercase' }}>Active Files</p>
          <h3 style={{ fontSize: '28px', color: 'var(--success)' }}>{stats.active}</h3>
        </div>
        <div className="card" style={{ borderLeft: '4px solid var(--danger)' }}>
          <p style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '8px', fontWeight: 'bold', textTransform: 'uppercase' }}>Revoked Files</p>
          <h3 style={{ fontSize: '28px', color: 'var(--danger)' }}>{stats.revoked}</h3>
        </div>
        <div className="card">
          <p style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '8px', fontWeight: 'bold', textTransform: 'uppercase' }}>Recent Activity</p>
          <h3 style={{ fontSize: '28px' }}>{stats.recentLogs}</h3>
        </div>
      </div>

      <div className="table-container">
        <div style={{ padding: '20px', borderBottom: '1px solid var(--border)', fontWeight: 'bold' }}>
          File Vault
        </div>
        <table>
          <thead>
            <tr>
              <th>File Name</th>
              <th>File ID</th>
              <th>Granted Access</th>
              <th>Status</th>
              <th>Created At</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {files.map(file => (
              <tr key={file.id}>
                <td style={{ fontWeight: '500' }}>{file.file_name}</td>
                <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{file.id}</td>
                <td>
                  <span style={{ fontWeight: 'bold' }}>{file.policy_count || 0}</span> IPs/Devices
                </td>
                <td>
                  <span className={`badge ${file.global_status === 'REVOKED' ? 'badge-revoked' : 'badge-active'}`}>
                    {file.global_status === 'REVOKED' ? 'Revoked' : 'Active'}
                  </span>
                </td>
                <td style={{ color: 'var(--text-muted)' }}>{new Date(file.created_at).toLocaleDateString()}</td>
                <td style={{ textAlign: 'right' }}>
                  <div style={{ display: 'inline-flex', gap: '8px' }}>
                    <button className="btn btn-ghost" onClick={() => setSelectedFile(file)} title="Edit Access">
                      <Edit size={16} />
                    </button>
                    <button className="btn btn-ghost" onClick={() => deleteFile(file.id)} title="Delete" style={{ color: 'var(--danger)' }}>
                      <Trash2 size={16} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {files.length === 0 && (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  No files secured in vault yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {selectedFile && (
        <AccessControlModal 
          file={selectedFile} 
          onClose={() => setSelectedFile(null)} 
          onUpdate={fetchData} 
          apiBase={apiBase} 
        />
      )}

      {isUploadOpen && (
        <UploadModal 
          onClose={() => setIsUploadOpen(false)} 
          onSuccess={fetchData} 
          apiBase={apiBase} 
        />
      )}
    </div>
  );
};

export default Dashboard;
