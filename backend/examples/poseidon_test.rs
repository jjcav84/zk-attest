use ark_bn254::Fr;
use ark_ff::PrimeField;
use pso_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;

fn fr_from_hex(hex: &str) -> Fr {
    let bytes = hex.strip_prefix("0x").unwrap_or(hex);
    let big_int = BigUint::parse_bytes(bytes.as_bytes(), 16).expect("invalid hex");
    Fr::from_le_bytes_mod_order(&big_int.to_bytes_le())
}

fn fr_to_string(fr: &Fr) -> String {
    let big_int: BigUint = fr.into_bigint().into();
    big_int.to_str_radix(10)
}

fn main() {
    // zk-attest uses sk=0x2
    let sk = fr_from_hex("0x0000000000000000000000000000000000000000000000000000000000000002");

    let mut poseidon1 = Poseidon::<Fr>::new_circom(1).expect("failed to init Poseidon(1)");
    let pk = poseidon1.hash(&[sk]).expect("failed to hash sk");

    // Test: income attestation (type=1), private_value=75000, threshold=50000
    let message = Fr::from(75000u64);
    let nonce = Fr::from(67890u64);

    let mut poseidon3 = Poseidon::<Fr>::new_circom(3).expect("failed to init Poseidon(3)");
    let h = poseidon3.hash(&[pk, message, nonce]).expect("failed to compute challenge");
    let sig = sk + h;

    // Verify
    let recovered_sk = sig - h;
    let computed_pk = poseidon1.hash(&[recovered_sk]).expect("failed to verify");
    println!("Verification: Poseidon(sig-h) === pk? {}", computed_pk == pk);

    let current_year = 2026u64;
    println!("\n=== Circom input JSON (income attestation) ===");
    println!("{{");
    println!("  \"attestation_type\": \"1\",");
    println!("  \"threshold\": \"50000\",");
    println!("  \"issuer_pubkey\": \"{}\",", fr_to_string(&pk));
    println!("  \"current_year\": \"{}\",", current_year);
    println!("  \"private_value\": \"75000\",");
    println!("  \"issuer_signature\": \"{}\",", fr_to_string(&sig));
    println!("  \"signature_nonce\": \"{}\"", fr_to_string(&nonce));
    println!("}}");
}
