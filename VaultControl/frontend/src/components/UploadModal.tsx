import React, { useState } from 'react';
import axios from 'axios';
import { X, Upload, ShieldCheck, Loader2 } from 'lucide-react';

interface UploadModalProps {
  onClose: () => void;
  onSuccess: () => void;
  apiBase: string;
}

const UploadModal: React.FC<UploadModalProps> = ({ onClose, onSuccess, apiBase }) => {
  const [file, setFile] = useState<File | null>(null);
  const [fileName, setFileName] = useState('');
  const [status, setStatus] = useState<'idle' | 'encrypting' | 'uploading' | 'success'>('idle');

  const handleUpload = async () => {
    if (!file) return;
    
    setStatus('encrypting');
    // Simulate encryption
    await new Promise(r => setTimeout(r, 1500));
    
    setStatus('uploading');
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('name', fileName || file.name);
      
      await axios.post(`${apiBase}/upload`, formData);
      
      setStatus('success');
      await new Promise(r => setTimeout(r, 1000));
      onSuccess();
      onClose();
    } catch (err) {
      console.error("Upload error", err);
      setStatus('idle');
      alert("Upload failed. Make sure backend is running.");
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
          <h3>Secure New Asset</h3>
          <button className="btn btn-ghost" onClick={onClose}><X size={20} /></button>
        </div>

        {status === 'idle' ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div 
              style={{ 
                border: '2px dashed var(--border)', 
                borderRadius: '8px', 
                padding: '40px', 
                textAlign: 'center',
                cursor: 'pointer'
              }}
              onClick={() => document.getElementById('fileInput')?.click()}
            >
              <Upload size={32} color="var(--text-muted)" style={{ marginBottom: '12px' }} />
              <p style={{ fontSize: '14px', color: 'var(--text-muted)' }}>
                {file ? file.name : 'Click to select or drag and drop file'}
              </p>
              <input 
                id="fileInput"
                type="file" 
                style={{ display: 'none' }} 
                onChange={e => {
                  const f = e.target.files?.[0];
                  if (f) {
                    setFile(f);
                    setFileName(f.name);
                  }
                }}
              />
            </div>

            <input 
              placeholder="Custom File Name (Optional)" 
              value={fileName}
              onChange={e => setFileName(e.target.value)}
            />

            <button 
              className="btn btn-primary" 
              onClick={handleUpload}
              disabled={!file}
              style={{ justifyContent: 'center', padding: '12px' }}
            >
              Encrypt & Upload
            </button>
          </div>
        ) : (
          <div style={{ padding: '40px', textAlign: 'center' }}>
            {status === 'encrypting' && (
              <>
                <Loader2 size={40} className="animate-spin" color="var(--primary)" style={{ marginBottom: '16px' }} />
                <h4>Encrypting File...</h4>
                <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Applying AES-256-GCM encryption layers</p>
              </>
            )}
            {status === 'uploading' && (
              <>
                <Loader2 size={40} className="animate-spin" color="var(--primary)" style={{ marginBottom: '16px' }} />
                <h4>Securing in Vault...</h4>
              </>
            )}
            {status === 'success' && (
              <>
                <ShieldCheck size={40} color="var(--success)" style={{ marginBottom: '16px' }} />
                <h4 style={{ color: 'var(--success)' }}>File Secured!</h4>
                <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Asset is now protected by active policies</p>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default UploadModal;
