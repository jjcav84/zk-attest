//! Issuer — represents a credential authority that signs private value
//! commitments using a Poseidon-based Schnorr-like signature.
//!
//! Signature scheme:
//! - Issuer secret key: sk (random field element, known only to issuer)
//! - Issuer public key: pk = Poseidon(sk) (public input to circuit)
//! - To sign message m (private_value):
//!   1. Choose random nonce r
//!   2. Compute challenge h = Poseidon(pk, m, r)
//!   3. Compute signature sig = sk + h (mod p)
//! - Circuit verifies: Poseidon(sig - h) === pk (since sig - h = sk)
//!
//! Security: forging requires a preimage attack on Poseidon over BN254.

use anyhow::Result;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use pso_poseidon::{Poseidon, PoseidonHasher};
use rand::Rng;

use crate::types::{IssueRequest, IssueResponse};

/// Issuer secret key (demo: hardcoded). In production this would be in an HSM.
const ISSUER_SK_HEX: &str = "0x0000000000000000000000000000000000000000000000000000000000000002";

/// Trust scores for different attestation types (affects energy calculation).
const TRUST_AGE: f64 = 0.95;        // Government ID
const TRUST_INCOME: f64 = 0.80;     // Bank statement
const TRUST_CREDENTIAL: f64 = 0.90; // Issued credential

fn fr_from_hex(hex: &str) -> Fr {
    let bytes = hex.strip_prefix("0x").unwrap_or(hex);
    let big_int = BigUint::parse_bytes(bytes.as_bytes(), 16).expect("invalid hex");
    Fr::from_le_bytes_mod_order(&big_int.to_bytes_le())
}

fn fr_to_string(fr: &Fr) -> String {
    let big_int: BigUint = fr.into_bigint().into();
    big_int.to_str_radix(10)
}

/// Issue a Poseidon-based signature on the user's private value.
pub fn issue(req: &IssueRequest) -> Result<IssueResponse> {
    let sk = fr_from_hex(ISSUER_SK_HEX);

    // Compute pk = Poseidon(sk)
    let mut poseidon1 = Poseidon::<Fr>::new_circom(1).expect("failed to init Poseidon(1)");
    let pk = poseidon1.hash(&[sk]).expect("failed to hash sk");

    // Message = private_value as field element
    let message = Fr::from(req.private_value);

    // Random nonce
    let nonce_bytes: [u8; 32] = rand::thread_rng().gen();
    let nonce = Fr::from_le_bytes_mod_order(&nonce_bytes);

    // Challenge: h = Poseidon(pk, m, r)
    let mut poseidon3 = Poseidon::<Fr>::new_circom(3).expect("failed to init Poseidon(3)");
    let h = poseidon3
        .hash(&[pk, message, nonce])
        .expect("failed to compute challenge hash");

    // Signature: sig = sk + h (mod p)
    let sig = sk + h;

    let issuer_trust = match req.attestation_type {
        0 => TRUST_AGE,
        1 => TRUST_INCOME,
        2 => TRUST_CREDENTIAL,
        _ => 0.5,
    };

    Ok(IssueResponse {
        issuer_pubkey: fr_to_string(&pk),
        issuer_signature: fr_to_string(&sig),
        signature_nonce: fr_to_string(&nonce),
        private_value: req.private_value,
        attestation_type: req.attestation_type,
        issuer_trust,
    })
}
