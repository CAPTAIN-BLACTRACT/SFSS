-- Users table for dashboard login
CREATE TABLE IF NOT EXISTS Users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Files_Vault: Stores file metadata and the wrapped DEK (Data Encryption Key)
CREATE TABLE IF NOT EXISTS Files_Vault (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_name TEXT NOT NULL,
    file_hash TEXT UNIQUE NOT NULL, -- SHA-256 hash of the original file
    wrapped_dek BYTEA NOT NULL, -- The DEK encrypted by KMS
    owner_id UUID REFERENCES Users(id),
    global_status TEXT DEFAULT 'ACTIVE', -- 'ACTIVE', 'REVOKED'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Access_Policies: Defines where and on what hardware the file can be opened
CREATE TABLE IF NOT EXISTS Access_Policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID NOT NULL REFERENCES Files_Vault(id) ON DELETE CASCADE,
    allowed_cidr CIDR NOT NULL, -- E.g., '192.168.1.0/24'
    allowed_device_hash TEXT NOT NULL, -- CPUID/SMBIOS fingerprint hash
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit_Ledger: Tracks every successful and failed access attempt
CREATE TABLE IF NOT EXISTS Audit_Ledger (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID NOT NULL REFERENCES Files_Vault(id) ON DELETE CASCADE,
    request_ip INET NOT NULL,
    device_hash TEXT,
    access_granted BOOLEAN NOT NULL,
    denial_reason TEXT,
    attempted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
