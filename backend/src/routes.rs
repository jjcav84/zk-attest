//! HTTP routes — the API surface for the zk-attest backend.

use std::sync::Arc;
use axum::{routing::{get, post}, Json, Router, extract::Path};
use crate::state::AppState;
use crate::types::*;
use crate::attestation_energy::{AttestationPotential, AttestationType};

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/issue", post(issue))
        .route("/api/attest", post(attest))
        .route("/api/verify", post(verify))
        .route("/api/stats", get(stats))
        .route("/api/energy/:proof_id", get(energy))
        .fallback_service(tower_http::services::ServeFile::new("frontend/index.html"))
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    let config = crate::hedera::HederaConfig::default();
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        hedera_connected: config.enabled,
    })
}

async fn issue(
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, (axum::http::StatusCode, String)> {
    crate::issuer::issue(&req)
        .map(Json)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn attest(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, (axum::http::StatusCode, String)> {
    // 1. Generate ZK proof
    let proof_result = crate::prover::generate_proof(&req)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 2. Compute attestation energy (FMD physics model)
    let attestation_type = AttestationType::from_u64(req.attestation_type)
        .unwrap_or(AttestationType::Age);
    let mut potential = AttestationPotential::default();
    potential.proof_latency_ms = proof_result.latency_ms;
    potential.attestation_age_secs = 0.0; // fresh
    let energy = potential.energy(attestation_type, req.threshold, req.issuer_trust);

    // 3. Submit to Hedera (HCS + HTS)
    let hedera_config = crate::hedera::HederaConfig::default();
    let hedera_result = crate::hedera::submit_attestation(
        &hedera_config,
        &proof_result.proof,
        &proof_result.public_signals,
        &proof_result.proof_id,
        &energy,
    )
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 4. Record metrics
    let user_id = format!("user-{}", req.private_value);
    state.record_attestation(&user_id, energy.energy);
    state.record_hcs(); // proof log
    state.record_hts_mint(); // NFT
    state.record_hcs(); // energy log

    tracing::info!(
        "attestation created: id={}, type={}, energy={:.2}, negentropy={:.1} bits, hcs_seq={}, nft={}",
        proof_result.proof_id,
        attestation_type.label(),
        energy.energy,
        energy.negentropy_bits,
        hedera_result.hcs_sequence,
        hedera_result.nft_serial,
    );

    Ok(Json(AttestResponse {
        proof_id: proof_result.proof_id,
        proof: proof_result.proof,
        public_signals: proof_result.public_signals,
        hcs_sequence: Some(hedera_result.hcs_sequence),
        nft_serial: Some(hedera_result.nft_serial),
        energy,
        hedera_submitted: !hedera_result.simulated,
    }))
}

async fn verify(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (axum::http::StatusCode, String)> {
    // 1. Local snarkjs verification
    let verified = crate::prover::verify_local(&req.proof, &req.public_signals)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 2. Decode attestation type and threshold from public signals
    // Public signals: [attestation_type, threshold, issuer_pubkey_hash, current_year]
    let attestation_type = req.public_signals.first().and_then(|s| s.parse::<u64>().ok());
    let threshold = req.public_signals.get(1).and_then(|s| s.parse::<u64>().ok());

    // 3. Submit verification result to HCS
    let config = crate::hedera::HederaConfig::default();
    let hcs_verify_sequence = crate::hedera::submit_verification(&config, &req.proof_id, verified)
        .await
        .ok()
        .flatten();

    if verified {
        state.record_verification();
        state.record_hcs();
    }

    tracing::info!(
        "proof verified: id={}, verified={}, type={:?}, threshold={:?}",
        req.proof_id, verified, attestation_type, threshold
    );

    Ok(Json(VerifyResponse {
        verified,
        hcs_verify_sequence,
        attestation_type,
        threshold,
    }))
}

async fn stats(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Json<StatsResponse> {
    let (attestations, verified, hcs, mints, txs, users, last, avg_energy) = state.stats();

    Json(StatsResponse {
        total_attestations: attestations,
        total_verified: verified,
        total_hcs_messages: hcs,
        total_hts_mints: mints,
        total_hedera_transactions: txs,
        unique_users: users,
        last_attestation_at: last,
        avg_energy,
    })
}

async fn energy(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Path(_proof_id): Path<String>,
) -> Json<serde_json::Value> {
    // Return the energy model parameters and last computed energy
    let (_, _, _, _, _, _, _, avg_energy) = state.stats();
    Json(serde_json::json!({
        "avg_energy": avg_energy,
        "model": "FMD Route Energy (adapted)",
        "formula": "energy = confidence * sqrt(depth_ratio * timing_factor) * latency_decay * (1 - cost_penalty)",
        "negentropy_formula": "N = constraint_count * log2(threshold)",
        "origin": "orkid fmd-physics route_energy.rs",
    }))
}
