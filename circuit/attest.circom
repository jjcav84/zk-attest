// zk-attest: Zero-knowledge attestation circuit
//
// Proves an attestation claim without revealing the underlying private data.
// Supports three attestation types:
//   0 = Age attestation:      proves age >= threshold
//   1 = Income attestation:   proves annual income >= threshold
//   2 = Credential attestation: proves possession of a valid credential
//
// Signature scheme: Poseidon-based Schnorr-like signature
// - Issuer secret key: sk (random field element, known only to issuer)
// - Issuer public key: pk = Poseidon(sk) (public input)
// - Signature on message m: choose random r, compute h = Poseidon(pk, m, r),
//   then sig = sk + h
// - Verification: Poseidon(sig - h) === pk (since sig - h = sk)
//
// Public inputs:  attestation_type, threshold, issuer_pubkey, current_year
// Private inputs: private_value, issuer_signature, signature_nonce

pragma circom 2.2.3;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/gates.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

template Attest() {
    // Public inputs
    signal input attestation_type;     // 0=age, 1=income, 2=credential
    signal input threshold;            // minimum value to prove
    signal input issuer_pubkey;        // pk = Poseidon(sk)
    signal input current_year;         // for age computation

    // Private inputs
    signal input private_value;        // birth_year / income / credential_id
    signal input issuer_signature;     // sig = sk + h
    signal input signature_nonce;      // r (random nonce)

    // --- Constraint 1: Poseidon signature verification ---
    // h = Poseidon(pk, m, r) = Poseidon(issuer_pubkey, private_value, signature_nonce)
    component hashChallenge = Poseidon(3);
    hashChallenge.inputs[0] <== issuer_pubkey;
    hashChallenge.inputs[1] <== private_value;
    hashChallenge.inputs[2] <== signature_nonce;

    // sig - h = sk (recoverable only by issuer who knows sk)
    signal recovered_sk;
    recovered_sk <== issuer_signature - hashChallenge.out;

    // Poseidon(sk) === pk
    component hashPk = Poseidon(1);
    hashPk.inputs[0] <== recovered_sk;
    hashPk.out === issuer_pubkey;

    // --- Constraint 2: Attestation-specific logic ---
    // Age: diff_age = current_year - threshold - private_value (must be >= 0)
    signal diff_age;
    diff_age <== current_year - threshold - private_value;

    // Income: diff_income = private_value - threshold (must be >= 0)
    signal diff_income;
    diff_income <== private_value - threshold;

    // Credential: diff_cred = private_value - threshold (must be === 0)
    signal diff_cred;
    diff_cred <== private_value - threshold;

    // Select the relevant difference based on attestation_type
    component eq_age = IsEqual();
    eq_age.in[0] <== attestation_type;
    eq_age.in[1] <== 0;

    component eq_income = IsEqual();
    eq_income.in[0] <== attestation_type;
    eq_income.in[1] <== 1;

    component eq_cred = IsEqual();
    eq_cred.in[0] <== attestation_type;
    eq_cred.in[1] <== 2;

    signal is_age;
    signal is_income;
    signal is_cred;
    is_age <== eq_age.out;
    is_income <== eq_income.out;
    is_cred <== eq_cred.out;

    // Enforce exactly one type is selected
    signal type_sum;
    type_sum <== is_age + is_income + is_cred;
    type_sum === 1;

    // Selected difference
    signal term_age;
    signal term_income;
    signal term_cred;
    term_age <== is_age * diff_age;
    term_income <== is_income * diff_income;
    term_cred <== is_cred * diff_cred;

    signal selected_diff;
    selected_diff <== term_age + term_income + term_cred;

    // For age and income: selected_diff >= 0 (16-bit range check)
    // For credential: selected_diff === 0 (credential ID must match exactly)
    component n2b = Num2Bits(16);
    n2b.in <== selected_diff;

    // For credential type, also enforce selected_diff === 0
    signal cred_check;
    cred_check <== is_cred * selected_diff;
    cred_check === 0;
}

component main { public [attestation_type, threshold, issuer_pubkey, current_year] } = Attest();
