# Zero-Trust Key Management Server (KMS)

This is a high-security, zero-trust KMS built in Rust using Axum and SQLx. It acts as a strict bouncer for self-destructing file-sharing applications.

## Features
- **mTLS Enforcement**: All client connections must present a valid certificate (Zero-Trust).
- **Network-Level Security**: Access policies enforce CIDR-based IP restriction.
- **Device Fingerprinting**: Requests are validated against unique `device_hash`.
- **Global Revocation**: Files can be revoked instantly at the database level.
- **Double Encryption**: DEKs are encrypted at rest with a Master Key and re-wrapped with an ephemeral key for delivery.

## Tech Stack
- **Rust (2021)**: Axum 0.7, Tokio, SQLx 0.7.
- **Cryptography**: ChaCha20Poly1305 (AEAD) for high-performance authenticated encryption.
- **Database**: PostgreSQL with UUIDs and INET types.

## Database Schema
```sql
CREATE TYPE file_status AS ENUM ('ACTIVE', 'REVOKED');

CREATE TABLE Files_Vault (
    file_id UUID PRIMARY KEY,
    dek_blob BYTEA NOT NULL,
    global_status file_status NOT NULL DEFAULT 'ACTIVE'
);

CREATE TABLE Access_Policies (
    policy_id UUID PRIMARY KEY,
    file_id UUID NOT NULL REFERENCES Files_Vault(file_id),
    allowed_cidr INET NOT NULL,
    allowed_device_hash VARCHAR(64) NOT NULL
);
```

## Running the Server

1. **Setup Database**:
   Ensure PostgreSQL is running and the schema is applied.

2. **Generate Certificates**:
   Place `server.crt`, `server.key`, and `ca.crt` in the `certs/` directory.
   Ensure mTLS is enabled on the server config.

3. **Set Environment Variables**:
   ```bash
   export DATABASE_URL=postgres://user:password@localhost/kms_db
   export KMS_MASTER_KEY=$(openssl rand -base64 32)
   ```

4. **Start the Server**:
   ```bash
   cargo run
   ```

## Key Retrieval Workflow
1. Client establishes mTLS connection.
2. Client sends `POST /v1/keys/retrieve` with `file_id` and `device_hash`.
3. KMS validates:
   - File status is `ACTIVE`.
   - `device_hash` matches policy.
   - Client IP is within `allowed_cidr`.
4. KMS unwraps `dek_blob` with Master Key.
5. KMS wraps DEK with an ephemeral key.
6. KMS returns wrapped DEK and nonce.
