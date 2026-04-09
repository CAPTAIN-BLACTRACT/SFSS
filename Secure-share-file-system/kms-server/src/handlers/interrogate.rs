use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    body::Bytes,
};
use sqlx::PgPool;
use std::net::SocketAddr;
use uuid::Uuid;
use prost::Message;

use crate::crypto::chacha::wrap_dek;
use crate::db::vault::retrieve_key;
use crate::proto::secure_vault::{KeyRequest, KeyResponse};

async fn log_audit(pool: &PgPool, file_id: Uuid, ip: std::net::IpAddr, device_hash: &str, granted: bool, reason: &str) {
    let reason_opt = if reason.is_empty() { None } else { Some(reason) };
    let _ = sqlx::query!(
        r#"
        INSERT INTO Audit_Ledger (file_id, request_ip, device_hash, access_granted, denial_reason)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        file_id,
        ip as std::net::IpAddr,
        device_hash,
        granted,
        reason_opt
    )
    .execute(pool)
    .await;
}

pub async fn handle_interrogation(
    State(pool): State<PgPool>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    bytes: Bytes,
) -> impl IntoResponse {
    let client_ip = addr.ip();

    // 1. Decode Protobuf Request
    let request = match KeyRequest::decode(&*bytes) {
        Ok(req) => req,
        Err(e) => {
            println!("[ERROR] Failed to decode protobuf request: {}", e);
            let response = KeyResponse {
                wrapped_dek: vec![],
                is_approved: false,
                error_message: "Invalid protobuf payload".to_string(),
            };
            return (StatusCode::BAD_REQUEST, response.encode_to_vec()).into_response();
        }
    };

    let file_id = match Uuid::parse_str(&request.file_id) {
        Ok(id) => id,
        Err(_) => {
            let response = KeyResponse {
                wrapped_dek: vec![],
                is_approved: false,
                error_message: "Invalid file_id UUID format".to_string(),
            };
            return (StatusCode::BAD_REQUEST, response.encode_to_vec()).into_response();
        }
    };

    // 2. Fetch Policy from Database
    let policies_result = sqlx::query!(
        r#"
        SELECT allowed_cidr as "allowed_cidr: ipnetwork::IpNetwork", allowed_device_hash
        FROM Access_Policies
        WHERE file_id = $1
        "#,
        file_id
    )
    .fetch_all(&pool)
    .await;

    let policies = match policies_result {
        Ok(p) => {
            if p.is_empty() {
                log_audit(&pool, file_id, client_ip, &request.device_hash, false, "No access policy defined").await;
                let response = KeyResponse {
                    wrapped_dek: vec![],
                    is_approved: false,
                    error_message: "No access policy defined for this file".to_string(),
                };
                return (StatusCode::FORBIDDEN, response.encode_to_vec()).into_response();
            }
            p
        }
        Err(e) => {
            let response = KeyResponse {
                wrapped_dek: vec![],
                is_approved: false,
                error_message: format!("Database error fetching policy: {}", e),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, response.encode_to_vec()).into_response();
        }
    };

    let mut is_authorized = false;
    let mut last_error = "No valid policy matched".to_string();

    for policy in policies {
        if policy.allowed_cidr.contains(client_ip) {
            let clean_hash = policy.allowed_device_hash.trim();
            // Empty hash means wildcard (Any Device allowed on this IP)
            if clean_hash.is_empty() || request.device_hash == clean_hash {
                is_authorized = true;
                break;
            } else {
                last_error = "Invalid device hash".to_string();
            }
        } else {
            last_error = "IP address not allowed".to_string();
        }
    }

    if !is_authorized {
        println!("[SECURITY] Blocked request from IP {} due to policy mismatch: {}", client_ip, last_error);
        log_audit(&pool, file_id, client_ip, &request.device_hash, false, &last_error).await;
        let response = KeyResponse {
            wrapped_dek: vec![],
            is_approved: false,
            error_message: last_error,
        };
        return (StatusCode::FORBIDDEN, response.encode_to_vec()).into_response();
    }

    // 5. Retrieve Key
    let dek_blob = match retrieve_key(&pool, file_id).await {
        Ok(Some(blob)) => blob,
        Ok(None) => {
            let response = KeyResponse {
                wrapped_dek: vec![],
                is_approved: false,
                error_message: "File not found".to_string(),
            };
            return (StatusCode::NOT_FOUND, response.encode_to_vec()).into_response();
        }
        Err(e) => {
            log_audit(&pool, file_id, client_ip, &request.device_hash, false, &e).await;
            let response = KeyResponse {
                wrapped_dek: vec![],
                is_approved: false,
                error_message: e,
            };
            return (StatusCode::FORBIDDEN, response.encode_to_vec()).into_response();
        }
    };

    let wrapped_payload = match wrap_dek(&dek_blob, &request.agent_public_key) {
        Ok(payload) => payload,
        Err(e) => {
            let response = KeyResponse {
                wrapped_dek: vec![],
                is_approved: false,
                error_message: e,
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, response.encode_to_vec()).into_response();
        }
    };

    // Here we encode the wrapped payload (ephemeral key + nonce + ciphertext) 
    // into the single wrapped_dek bytes field. We could send it as JSON bytes,
    // or as a tightly packed format. We will use JSON serialization within the bytes for now,
    // as WrappedPayload implements Serialize.
    let wrapped_dek_bytes = serde_json::to_vec(&wrapped_payload).unwrap();

    // Log successful grant
    log_audit(&pool, file_id, client_ip, &request.device_hash, true, "").await;

    let response = KeyResponse {
        wrapped_dek: wrapped_dek_bytes,
        is_approved: true,
        error_message: String::new(),
    };

    (StatusCode::OK, response.encode_to_vec()).into_response()
}
