use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sqlx::Type;
use ipnetwork::IpNetwork;

#[derive(Debug, Serialize, Deserialize, Type, PartialEq)]
#[sqlx(type_name = "file_status")]
pub enum FileStatus {
    ACTIVE,
    REVOKED,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct FileVault {
    pub file_id: Uuid,
    pub dek_blob: Vec<u8>,
    pub global_status: FileStatus,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AccessPolicy {
    pub policy_id: Uuid,
    pub file_id: Uuid,
    pub allowed_cidr: IpNetwork,
    pub allowed_device_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct KeyRequest {
    pub file_id: Uuid,
    pub device_hash: String,
    pub ephemeral_pub_key: String, // Client's public key (base64) for wrapping
}

#[derive(Debug, Serialize)]
pub struct KeyResponse {
    pub wrapped_dek: String, // Base64 encoded
    pub nonce: String,       // Base64 encoded
}
