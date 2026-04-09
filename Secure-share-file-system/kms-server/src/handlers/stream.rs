use axum::{
    extract::{ConnectInfo, Path, State},
    response::sse::{Event, Sse},
};
use sqlx::PgPool;
use std::net::SocketAddr;
use uuid::Uuid;
use tokio::time::{sleep, Duration};
use futures::stream::Stream;

pub async fn handle_stream(
    Path((file_id, device_hash)): Path<(Uuid, String)>,
    State(pool): State<PgPool>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let ip = addr.ip();

    let stream = async_stream::stream! {
        println!("[STREAM] Agent {} connected to file {}", device_hash, file_id);

        let _ = sqlx::query!(
            r#"
            INSERT INTO Active_Sessions (file_id, device_hash, ip_address)
            VALUES ($1, $2, $3)
            ON CONFLICT (file_id, device_hash) DO UPDATE SET connected_at = CURRENT_TIMESTAMP, ip_address = $3
            "#,
            file_id,
            device_hash,
            ip as std::net::IpAddr
        )
        .execute(&pool)
        .await;

        loop {
            sleep(Duration::from_secs(2)).await;

            let file_status = sqlx::query!(
                "SELECT global_status FROM Files_Vault WHERE id = $1",
                file_id
            )
            .fetch_optional(&pool)
            .await;

            let mut should_revoke = false;
            match file_status {
                Ok(Some(row)) => {
                    if row.global_status == Some("REVOKED".to_string()) {
                        should_revoke = true;
                    }
                }
                _ => should_revoke = true,
            }

            if !should_revoke {
                let policy_exists = sqlx::query!(
                    "SELECT id FROM Access_Policies WHERE file_id = $1 AND allowed_device_hash = $2",
                    file_id,
                    device_hash
                )
                .fetch_optional(&pool)
                .await;

                match policy_exists {
                    Ok(Some(_)) => {} 
                    _ => should_revoke = true, 
                }
            }

            if should_revoke {
                println!("[STREAM] Revoking access for agent {} on file {}", device_hash, file_id);
                yield Ok(Event::default().data("REVOKE"));
                break;
            } else {
                yield Ok(Event::default().data("PING"));
            }
        }

        let _ = sqlx::query!(
            "DELETE FROM Active_Sessions WHERE file_id = $1 AND device_hash = $2",
            file_id,
            device_hash
        )
        .execute(&pool)
        .await;

        println!("[STREAM] Agent {} disconnected from file {}", device_hash, file_id);
    };

    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::new())
}
