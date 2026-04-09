import React from 'react';

interface AuditEntry {
  id: string;
  request_ip: string;
  device_hash: string;
  access_granted: boolean;
  denial_reason: string;
  attempted_at: string;
}

interface AuditLogProps {
  logs: AuditEntry[];
  fileName: string;
}

const AuditLog: React.FC<AuditLogProps> = ({ logs, fileName }) => {
  return (
    <div style={{ marginTop: '30px' }}>
      <h4>Access Audit Ledger for: {fileName}</h4>
      <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
        <thead>
          <tr style={{ borderBottom: '2px solid #ddd' }}>
            <th style={{ padding: '10px' }}>Timestamp</th>
            <th style={{ padding: '10px' }}>Requester IP</th>
            <th style={{ padding: '10px' }}>Device</th>
            <th style={{ padding: '10px' }}>Outcome</th>
            <th style={{ padding: '10px' }}>Reason</th>
          </tr>
        </thead>
        <tbody>
          {logs.length > 0 ? logs.map(log => (
            <tr key={log.id} style={{ borderBottom: '1px solid #eee' }}>
              <td style={{ padding: '10px', fontSize: '14px' }}>{new Date(log.attempted_at).toLocaleString()}</td>
              <td style={{ padding: '10px', fontSize: '14px' }}>{log.request_ip}</td>
              <td style={{ padding: '10px', fontSize: '12px', color: '#888' }}>{log.device_hash.substring(0, 15)}...</td>
              <td style={{ padding: '10px' }}>
                <span style={{ 
                  color: log.access_granted ? '#28a745' : '#dc3545',
                  fontWeight: 'bold',
                  padding: '2px 8px',
                  backgroundColor: log.access_granted ? '#e6f4ea' : '#fbe9eb',
                  borderRadius: '4px',
                  fontSize: '12px'
                }}>
                  {log.access_granted ? 'GRANTED' : 'DENIED'}
                </span>
              </td>
              <td style={{ padding: '10px', fontSize: '14px', color: '#666' }}>{log.denial_reason || '-'}</td>
            </tr>
          )) : (
            <tr>
              <td colSpan={5} style={{ padding: '20px', textAlign: 'center', color: '#999' }}>No access attempts recorded for this file yet.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
};

export default AuditLog;
