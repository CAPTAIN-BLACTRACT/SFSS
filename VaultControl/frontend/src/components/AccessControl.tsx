import React, { useRef } from 'react';
import axios from 'axios';

interface FileEntry {
  id: string;
  file_name: string;
  global_status: string;
  is_revoked: boolean;
  created_at: string;
}

interface AccessControlProps {
  selectedFile: FileEntry;
  onUpdate: () => void;
  apiBase: string;
}

const AccessControl: React.FC<AccessControlProps> = ({ selectedFile, onUpdate, apiBase }) => {
  const cidrRef = useRef<HTMLInputElement>(null);
  const deviceRef = useRef<HTMLInputElement>(null);

  const addPolicy = async () => {
    const allowed_cidr = cidrRef.current?.value;
    const allowed_device_hash = deviceRef.current?.value;

    if (!allowed_cidr || !allowed_device_hash) {
      alert("Please fill both CIDR and Device Hash");
      return;
    }

    try {
      await axios.post(`${apiBase}/files/${selectedFile.id}/policies`, { 
        allowed_cidr, 
        allowed_device_hash 
      });
      alert("Policy added successfully!");
      if (cidrRef.current) cidrRef.current.value = "";
      if (deviceRef.current) deviceRef.current.value = "";
      onUpdate();
    } catch (err) {
      console.error("Error adding policy", err);
    }
  };

  const toggleRevocation = async () => {
    const newRevocationState = !selectedFile.is_revoked;
    try {
      await axios.patch(`${apiBase}/files/${selectedFile.id}/revocation`, { 
        is_revoked: newRevocationState 
      });
      onUpdate();
    } catch (err) {
      console.error("Error updating revocation status", err);
    }
  };

  return (
    <div style={{ backgroundColor: '#f8f9fa', padding: '20px', borderRadius: '8px', marginBottom: '20px' }}>
      <h3>Access Control for: {selectedFile.file_name}</h3>
      
      <div style={{ marginBottom: '20px' }}>
        <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold' }}>Revoke All Access</label>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <button 
            onClick={toggleRevocation} 
            style={{ 
              padding: '10px 20px', 
              backgroundColor: selectedFile.is_revoked ? '#28a745' : '#dc3545', 
              color: 'white', 
              border: 'none', 
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: 'bold'
            }}
          >
            {selectedFile.is_revoked ? 'Grant Access' : 'Revoke Access'}
          </button>
          <span style={{ color: '#666' }}>
            Current Status: <strong>{selectedFile.is_revoked ? 'REVOKED' : 'ACTIVE'}</strong>
          </span>
        </div>
      </div>

      <div style={{ borderTop: '1px solid #ddd', paddingTop: '20px' }}>
        <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold' }}>Add Specific Access Policy</label>
        <div style={{ display: 'flex', gap: '10px' }}>
          <div style={{ flex: 1 }}>
            <input 
              ref={cidrRef} 
              placeholder="Allowed CIDR (e.g. 192.168.1.0/24)" 
              style={{ width: '100%', padding: '10px', boxSizing: 'border-box' }} 
            />
          </div>
          <div style={{ flex: 1 }}>
            <input 
              ref={deviceRef} 
              placeholder="Device Hash (e.g. SMBIOS UUID)" 
              style={{ width: '100%', padding: '10px', boxSizing: 'border-box' }} 
            />
          </div>
          <button 
            onClick={addPolicy} 
            style={{ 
              padding: '10px 25px', 
              backgroundColor: '#007bff', 
              color: 'white', 
              border: 'none', 
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: 'bold'
            }}
          >
            Authorize IP/Device
          </button>
        </div>
      </div>
    </div>
  );
};

export default AccessControl;
