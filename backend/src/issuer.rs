//! Simulated issuer — represents a credential authority that signs
//! private value commitments for ZK attestations.
//!
//! In production: government digital ID, Polygon ID, or OIDC provider.
//! For demo: simplified algebraic signature.

use anyhow::Result;
use crate::types::{IssueRequest, IssueResponse};

const ISSUER_PUBKEY_HASH: u64 = 12345;

/// Trust scores for different attestation types (affects energy calculation).
const TRUST_AGE: f64 = 0.95;        // Government ID
const TRUST_INCOME: f64 = 0.80;     // Bank statement
const TRUST_CREDENTIAL: f64 = 0.90; // Issued credential

pub fn issue(req: &IssueRequest) -> Result<IssueResponse> {
    let randomness: u64 = rand::random::<u32>() as u64;
    let signature = req.private_value + ISSUER_PUBKEY_HASH * randomness;

    let issuer_trust = match req.attestation_type {
        0 => TRUST_AGE,
        1 => TRUST_INCOME,
        2 => TRUST_CREDENTIAL,
        _ => 0.5,
    };

    Ok(IssueResponse {
        issuer_pubkey_hash: ISSUER_PUBKEY_HASH.to_string(),
        issuer_signature: signature.to_string(),
        signature_randomness: randomness.to_string(),
        private_value: req.private_value,
        attestation_type: req.attestation_type,
        issuer_trust,
    })
}
