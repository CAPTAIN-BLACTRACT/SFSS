use axum::{routing::post, Router};
use axum_server::tls_rustls::RustlsConfig;
use rustls::{server::WebPkiClientVerifier, RootCertStore};
use sqlx::postgres::PgPoolOptions;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;

use std::sync::Arc;

mod crypto;
mod db;
mod handlers;
mod models;
mod proto;

use crate::handlers::interrogate::handle_interrogation;
use crate::handlers::stream::handle_stream;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to Postgres database");

    // Notice we've dropped the :file_id param since it's now in the Protobuf payload
    let app = Router::new()
        .route("/api/v1/interrogate", post(handle_interrogation))
        .route("/api/v1/stream/:file_id/:device_hash", axum::routing::get(handle_stream))
        .with_state(pool);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    println!("KMS Zero-Trust Server starting on {} with mTLS", addr);

    // Load CA Cert for client verification
    let mut root_cert_store = RootCertStore::empty();
    let ca_cert_file = File::open("certs/ca.crt").expect("Failed to open ca.crt");
    let mut ca_reader = BufReader::new(ca_cert_file);
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        root_cert_store.add(cert.unwrap()).unwrap();
    }

    // Require valid client certs
    let client_verifier = WebPkiClientVerifier::builder(root_cert_store.into())
        .build()
        .unwrap();

    // Load Server's own cert and private key
    let mut server_certs = vec![];
    let server_cert_file = File::open("certs/server.crt").expect("Failed to open server.crt");
    for cert in rustls_pemfile::certs(&mut BufReader::new(server_cert_file)) {
        server_certs.push(cert.unwrap());
    }

    let server_key_file = File::open("certs/server.key").expect("Failed to open server.key");
    let server_key = rustls_pemfile::private_key(&mut BufReader::new(server_key_file))
        .unwrap()
        .unwrap();

    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .unwrap();

    let tls_config = RustlsConfig::from_config(Arc::new(server_config));

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
