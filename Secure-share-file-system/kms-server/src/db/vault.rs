use sqlx::PgPool;
use uuid::Uuid;

#[derive(sqlx::Type, Debug, PartialEq)]
#[sqlx(type_name = "file_status", rename_all = "UPPERCASE")]
pub enum FileStatus {
    ACTIVE,
    REVOKED,
}

pub async fn retrieve_key(pool: &PgPool, file_id: Uuid) -> Result<Option<Vec<u8>>, String> {
    let result = sqlx::query!(
        r#"
        SELECT wrapped_dek, global_status
        FROM Files_Vault
        WHERE id = $1
        "#,
        file_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Database error: {}", e))?;

    match result {
        Some(row) => {
            // Because we didn't specify the enum type cast strictly in PG,
            // we manually check the string
            if row.global_status == Some("REVOKED".to_string()) {
                Err("File access has been REVOKED".to_string())
            } else {
                Ok(Some(row.wrapped_dek))
            }
        }
        None => Ok(None),
    }
}
