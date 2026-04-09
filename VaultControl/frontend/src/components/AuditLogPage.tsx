import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Filter, Download, Search } from 'lucide-react';

interface AuditEntry {
  id: string;
  file_name?: string;
  request_ip: string;
  device_hash: string;
  access_granted: boolean;
  denial_reason: string;
  attempted_at: string;
}

const AuditLogPage: React.FC<{ apiBase: string }> = ({ apiBase }) => {
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    try {
      const res = await axios.get(`${apiBase}/audit-logs`);
      setLogs(res.data);
    } catch (err) {
      console.error("Error fetching audit logs", err);
    }
  };

  const filteredLogs = logs.filter(log => {
    const statusMatch = filterStatus === 'ALL' || 
      (filterStatus === 'GRANTED' && log.access_granted) || 
      (filterStatus === 'DENIED' && !log.access_granted);
    
    const searchMatch = log.request_ip.includes(searchTerm) || 
      (log.file_name?.toLowerCase().includes(searchTerm.toLowerCase()));

    return statusMatch && searchMatch;
  });

  return (
    <div style={{ padding: '32px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '32px' }}>
        <div>
          <h2 style={{ fontSize: '24px', marginBottom: '8px' }}>Audit Ledger</h2>
          <p style={{ color: 'var(--text-muted)' }}>Real-time immutable history of all file access attempts.</p>
        </div>
        <button className="btn btn-ghost" onClick={() => window.print()}>
          <Download size={18} />
          Export PDF
        </button>
      </div>

      <div className="card" style={{ marginBottom: '24px', display: 'flex', gap: '16px', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1 }}>
          <Search size={18} color="var(--text-muted)" />
          <input 
            placeholder="Search by IP or Filename..." 
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            style={{ border: 'none', width: '100%', padding: '0' }}
          />
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <Filter size={18} color="var(--text-muted)" />
          <select 
            className="btn" 
            style={{ border: '1px solid var(--border)', background: 'white' }}
            value={filterStatus}
            onChange={e => setFilterStatus(e.target.value)}
          >
            <option value="ALL">All Outcomes</option>
            <option value="GRANTED">Granted Only</option>
            <option value="DENIED">Denied Only</option>
          </select>
          <input type="date" className="btn" style={{ border: '1px solid var(--border)', background: 'white' }} />
        </div>
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Asset</th>
              <th>Requester IP</th>
              <th>Outcome</th>
              <th>Denial Reason / Device</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.map(log => (
              <tr key={log.id}>
                <td style={{ color: 'var(--text-muted)' }}>{new Date(log.attempted_at).toLocaleString()}</td>
                <td style={{ fontWeight: '500' }}>{log.file_name || 'Asset-'+log.id.split('-')[0]}</td>
                <td>{log.request_ip}</td>
                <td>
                  <span className={`badge ${log.access_granted ? 'badge-active' : 'badge-revoked'}`}>
                    {log.access_granted ? 'Approved' : 'Denied'}
                  </span>
                </td>
                <td style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                  {log.access_granted ? (
                    <span style={{ fontSize: '11px' }}>Device: {log.device_hash.substring(0, 12)}...</span>
                  ) : (
                    <span style={{ color: 'var(--danger)' }}>{log.denial_reason}</span>
                  )}
                </td>
              </tr>
            ))}
            {filteredLogs.length === 0 && (
              <tr>
                <td colSpan={5} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  No logs found matching filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AuditLogPage;
