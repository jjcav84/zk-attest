//! zk-attest — Zero-knowledge attestation platform on Hedera.
//!
//! Architecture:
//! - `POST /api/issue` — issuer signs a private value commitment (simulated authority)
//! - `POST /api/attest` — user generates a Groth16 proof + submits to HCS + mints HTS NFT
//! - `POST /api/verify` — verifies a proof + checks HCS audit trail
//! - `GET /api/health` — health check
//! - `GET /api/stats` — metrics for Hedera milestone tracking
//! - `GET /api/energy/{proof_id}` — attestation energy score (FMD physics model)
//!
//! Each attestation generates 3 Hedera transactions:
//!   1. HCS message (proof + public signals logged to consensus)
//!   2. HTS NFT mint (attestation tokenized as transferable credential)
//!   3. HCS message (energy score + verification result logged)
//!
//! This drives the 50K monthly transaction target for Milestone 4.

pub mod attestation_energy;
pub mod issuer;
pub mod prover;
pub mod hedera;
pub mod routes;
pub mod state;
pub mod types;

use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let state = Arc::new(state::AppState::new());
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any) // TODO: restrict to production frontend origin
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE]);
    let app = routes::router(state.clone()).layer(cors);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("zk-attest backend listening on http://{}", addr);
    tracing::info!("Hedera network: {}", std::env::var("HEDERA_NETWORK").unwrap_or_else(|_| "testnet".to_string()));

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
