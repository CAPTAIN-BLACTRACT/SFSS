import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

// Interfaces for our data
interface FileEntry {
  id: string;
  file_name: string;
  global_status: string;
  created_at: string;
}

interface AuditEntry {
  id: string;
  request_ip: string;
  device_hash: string;
  access_granted: boolean;
  denial_reason: string;
  attempted_at: string;
}

const API_BASE = 'http://localhost:5000';

function App() {
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [selectedFile, setSelectedFile] = useState<FileEntry | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);
  
  // Refs for the form inputs
  const cidrRef = useRef<HTMLInputElement>(null);
  const deviceRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchFiles();
  }, []);

  // When a file is selected, fetch its audit logs
  useEffect(() => {
    if (selectedFile) {
      fetchAuditLogs(selectedFile.id);
    }
  }, [selectedFile]);

  const fetchFiles = async () => {
    try {
      const res = await axios.get(`${API_BASE}/files`);
      setFiles(res.data);
    } catch (err) {
      console.error("Error fetching files", err);
    }
  };

  const fetchAuditLogs = async (id: string) => {
    try {
      const res = await axios.get(`${API_BASE}/files/${id}/audit`);
      setAuditLogs(res.data);
    } catch (err) {
      console.error("Error fetching audit logs", err);
    }
  };

  const toggleStatus = async (id: string, currentStatus: string) => {
    const newStatus = currentStatus === 'ACTIVE' ? 'REVOKED' : 'ACTIVE';
    try {
      await axios.patch(`${API_BASE}/files/${id}/status`, { status: newStatus });
      fetchFiles(); // Refresh list
    } catch (err) {
      console.error("Error updating status", err);
    }
  };

  const addPolicy = async () => {
    if (!selectedFile) return;
    const allowed_cidr = cidrRef.current?.value;
    const allowed_device_hash = deviceRef.current?.value;

    if (!allowed_cidr || !allowed_device_hash) {
      alert("Please fill both CIDR and Device Hash");
      return;
    }

    try {
      await axios.post(`${API_BASE}/files/${selectedFile.id}/policies`, { 
        allowed_cidr, 
        allowed_device_hash 
      });
      alert("Policy added successfully!");
      if (cidrRef.current) cidrRef.current.value = "";
      if (deviceRef.current) deviceRef.current.value = "";
    } catch (err) {
      console.error("Error adding policy", err);
    }
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      <h1>The Vault Control Plane</h1>
      <p>Manage your encrypted assets and access policies.</p>
      
      <div style={{ display: 'flex', gap: '30px', marginTop: '30px' }}>
        {/* Left Panel: File List */}
        <div style={{ width: '400px', borderRight: '1px solid #ccc', paddingRight: '20px' }}>
          <h3>Secured Assets</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {files.map(file => (
              <div key={file.id} style={{ 
                padding: '15px', 
                border: selectedFile?.id === file.id ? '2px solid #007bff' : '1px solid #ddd',
                borderRadius: '8px',
                cursor: 'pointer',
                backgroundColor: selectedFile?.id === file.id ? '#f0f7ff' : '#fff'
              }} onClick={() => setSelectedFile(file)}>
                <div style={{ fontWeight: 'bold' }}>{file.file_name}</div>
                <div style={{ fontSize: '12px', color: '#666' }}>{file.id}</div>
                <div style={{ marginTop: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ 
                    color: file.global_status === 'ACTIVE' ? '#28a745' : '#dc3545',
                    fontSize: '12px',
                    fontWeight: 'bold',
                    padding: '2px 8px',
                    backgroundColor: file.global_status === 'ACTIVE' ? '#e6f4ea' : '#fbe9eb',
                    borderRadius: '4px'
                  }}>
                    {file.global_status}
                  </span>
                  <button onClick={(e) => { e.stopPropagation(); toggleStatus(file.id, file.global_status); }}>
                    Toggle Status
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Panel: Selected File Details */}
        <div style={{ flex: 1 }}>
          {selectedFile ? (
            <div>
              <h2>{selectedFile.file_name} <span style={{ color: '#666', fontSize: '14px' }}>(Details)</span></h2>
              
              <div style={{ backgroundColor: '#f8f9fa', padding: '20px', borderRadius: '8px' }}>
                <h4>New Access Policy</h4>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <input ref={cidrRef} placeholder="Allowed CIDR (e.g. 192.168.1.0/24)" style={{ flex: 1, padding: '8px' }} />
                  <input ref={deviceRef} placeholder="Device Hash (e.g. SMBIOS UUID)" style={{ flex: 1, padding: '8px' }} />
                  <button onClick={addPolicy} style={{ padding: '8px 20px', backgroundColor: '#007bff', color: 'white', border: 'none', borderRadius: '4px' }}>
                    Authorize
                  </button>
                </div>
              </div>

              <div style={{ marginTop: '30px' }}>
                <h4>Access Audit Ledger</h4>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #ddd' }}>
                      <th style={{ padding: '10px' }}>Timestamp</th>
                      <th style={{ padding: '10px' }}>Requester IP</th>
                      <th style={{ padding: '10px' }}>Outcome</th>
                      <th style={{ padding: '10px' }}>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.length > 0 ? auditLogs.map(log => (
                      <tr key={log.id} style={{ borderBottom: '1px solid #eee' }}>
                        <td style={{ padding: '10px', fontSize: '14px' }}>{new Date(log.attempted_at).toLocaleString()}</td>
                        <td style={{ padding: '10px', fontSize: '14px' }}>{log.request_ip}</td>
                        <td style={{ padding: '10px' }}>
                          <span style={{ 
                            color: log.access_granted ? '#28a745' : '#dc3545',
                            fontWeight: 'bold'
                          }}>
                            {log.access_granted ? 'GRANTED' : 'DENIED'}
                          </span>
                        </td>
                        <td style={{ padding: '10px', fontSize: '14px', color: '#666' }}>{log.denial_reason || '-'}</td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan={4} style={{ padding: '20px', textAlign: 'center', color: '#999' }}>No access attempts recorded for this file yet.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div style={{ textAlign: 'center', marginTop: '100px', color: '#999' }}>
              <h3>No file selected</h3>
              <p>Select an asset from the list to manage its access control and view activity logs.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
