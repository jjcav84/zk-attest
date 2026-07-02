//! Proof generation — orchestrates snarkjs via subprocess to generate
//! Groth16 proofs from the compiled circom attestation circuit.

use std::path::PathBuf;
use std::process::Command;
use anyhow::{anyhow, Result};
use serde_json::json;
use uuid::Uuid;
use crate::types::AttestRequest;

const BUILD_DIR: &str = "build";
const WASM_FILE: &str = "attest_js/attest.wasm";
const ZKEY_FILE: &str = "attest_final.zkey";

pub struct ProofResult {
    pub proof: serde_json::Value,
    pub public_signals: Vec<String>,
    pub proof_id: String,
    pub latency_ms: u64,
}

/// Generate a Groth16 proof of attestation.
pub fn generate_proof(req: &AttestRequest) -> Result<ProofResult> {
    let proof_id = Uuid::new_v4().to_string();
    let tmp_dir = std::env::temp_dir().join(format!("zk-attest-{}", proof_id));
    std::fs::create_dir_all(&tmp_dir)?;

    let current_year = chrono::Utc::now().format("%Y").to_string().parse::<u64>()?;
    let start = std::time::Instant::now();

    let inputs = json!({
        "attestation_type": req.attestation_type.to_string(),
        "threshold": req.threshold.to_string(),
        "issuer_pubkey": req.issuer_pubkey,
        "current_year": current_year.to_string(),
        "private_value": req.private_value.to_string(),
        "issuer_signature": req.issuer_signature,
        "signature_nonce": req.signature_nonce,
    });
    let input_path = tmp_dir.join("input.json");
    std::fs::write(&input_path, inputs.to_string())?;

    let build_dir = find_build_dir()?;
    let wasm_path = build_dir.join(WASM_FILE);
    let witness_path = tmp_dir.join("witness.wtns");
    let gen_witness_js = build_dir.join("attest_js/generate_witness.js");

    let witness_output = Command::new("node")
        .arg(&gen_witness_js)
        .arg(&wasm_path)
        .arg(&input_path)
        .arg(&witness_path)
        .output()?;

    if !witness_output.status.success() {
        let err = String::from_utf8_lossy(&witness_output.stderr);
        return Err(anyhow!("witness generation failed: {}", err));
    }

    let zkey_path = build_dir.join(ZKEY_FILE);
    let proof_path = tmp_dir.join("proof.json");
    let public_path = tmp_dir.join("public.json");

    let prove_output = Command::new("snarkjs")
        .arg("groth16")
        .arg("prove")
        .arg(&zkey_path)
        .arg(&witness_path)
        .arg(&proof_path)
        .arg(&public_path)
        .output()?;

    if !prove_output.status.success() {
        let err = String::from_utf8_lossy(&prove_output.stderr);
        return Err(anyhow!("proof generation failed: {}", err));
    }

    let latency_ms = start.elapsed().as_millis() as u64;

    let proof: serde_json::Value = serde_json::from_slice(&std::fs::read(&proof_path)?)?;
    let public_raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&public_path)?)?;

    let public_signals: Vec<String> = public_raw
        .as_array()
        .ok_or_else(|| anyhow!("public signals must be an array"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| v.as_u64().map(|n| n.to_string()))
                .ok_or_else(|| anyhow!("public signal must be a string or integer"))
        })
        .collect::<Result<Vec<_>>>()?;

    let _ = std::fs::remove_dir_all(&tmp_dir);

    Ok(ProofResult { proof, public_signals, proof_id, latency_ms })
}

fn find_build_dir() -> Result<PathBuf> {
    let mut cwd = std::env::current_dir()?;
    for _ in 0..5 {
        let candidate = cwd.join(BUILD_DIR);
        if candidate.join(ZKEY_FILE).exists() {
            return Ok(candidate);
        }
        if !cwd.pop() { break; }
    }
    Err(anyhow!("could not find build/ directory with compiled circuit artifacts"))
}

/// Local snarkjs verification of a proof.
pub async fn verify_local(proof: &serde_json::Value, public_signals: &[String]) -> Result<bool> {
    let tmp = std::env::temp_dir().join(format!("zk-attest-verify-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp)?;

    let proof_path = tmp.join("proof.json");
    let public_path = tmp.join("public.json");

    std::fs::write(&proof_path, serde_json::to_string(proof)?)?;
    std::fs::write(&public_path, serde_json::to_string(public_signals)?)?;

    let vk_path = find_vk()?;

    let output = tokio::process::Command::new("snarkjs")
        .arg("groth16")
        .arg("verify")
        .arg(&vk_path)
        .arg(&public_path)
        .arg(&proof_path)
        .output()
        .await?;

    let _ = std::fs::remove_dir_all(&tmp);

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains("OK!"))
}

fn find_vk() -> Result<PathBuf> {
    let mut cwd = std::env::current_dir()?;
    for _ in 0..5 {
        let candidate = cwd.join("build/verification_key.json");
        if candidate.exists() {
            return Ok(candidate);
        }
        if !cwd.pop() { break; }
    }
    Err(anyhow!("verification_key.json not found"))
}
