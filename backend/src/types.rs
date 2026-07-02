//! Shared types for the zk-attest API.

use serde::{Deserialize, Serialize};

/// Attestation type enum (matches circuit).
pub use crate::attestation_energy::AttestationType;

/// Request to issue a signed attestation credential.
#[derive(Debug, Deserialize)]
pub struct IssueRequest {
    /// The private value to attest (birth_year, income, credential_id).
    pub private_value: u64,
    /// Attestation type: 0=age, 1=income, 2=credential.
    pub attestation_type: u64,
}

/// Response from the issuer.
#[derive(Debug, Serialize)]
pub struct IssueResponse {
    pub issuer_pubkey: String,
    pub issuer_signature: String,
    pub signature_nonce: String,
    pub private_value: u64,
    pub attestation_type: u64,
    /// Issuer trust score (0..1) — affects attestation energy.
    pub issuer_trust: f64,
}

/// Request to create an attestation (generate proof + submit to Hedera).
#[derive(Debug, Deserialize)]
pub struct AttestRequest {
    pub private_value: u64,
    pub attestation_type: u64,
    pub issuer_pubkey: String,
    pub issuer_signature: String,
    pub signature_nonce: String,
    pub threshold: u64,
    pub issuer_trust: f64,
}

/// Response containing the attestation result.
#[derive(Debug, Serialize)]
pub struct AttestResponse {
    pub proof_id: String,
    pub proof: serde_json::Value,
    pub public_signals: Vec<String>,
    /// HCS topic message sequence number.
    pub hcs_sequence: Option<u64>,
    /// HTS NFT serial number (the tokenized attestation).
    pub nft_serial: Option<u64>,
    /// Attestation energy score (FMD physics model).
    pub energy: crate::attestation_energy::AttestationEnergyResult,
    /// Whether Hedera submission succeeded.
    pub hedera_submitted: bool,
}

/// Request to verify an attestation.
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub proof: serde_json::Value,
    pub public_signals: Vec<String>,
    pub proof_id: String,
}

/// Verification response.
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
    /// HCS message confirming verification.
    pub hcs_verify_sequence: Option<u64>,
    /// Attestation type decoded from public signals.
    pub attestation_type: Option<u64>,
    /// Threshold decoded from public signals.
    pub threshold: Option<u64>,
}

/// Health check.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub hedera_connected: bool,
}

/// Metrics for Hedera milestone tracking.
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_attestations: u64,
    pub total_verified: u64,
    pub total_hcs_messages: u64,
    pub total_hts_mints: u64,
    pub total_hedera_transactions: u64,
    pub unique_users: u64,
    pub last_attestation_at: Option<String>,
    /// Average attestation energy across all attestations.
    pub avg_energy: f64,
}
