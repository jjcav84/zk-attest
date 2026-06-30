// zk-attest: Zero-knowledge attestation circuit
//
// Proves an attestation claim without revealing the underlying private data.
// Supports three attestation types:
//   0 = Age attestation:      proves age >= threshold
//   1 = Income attestation:   proves annual income >= threshold
//   2 = Credential attestation: proves possession of a valid credential
//
// Public inputs:  attestation_type, threshold, issuer_pubkey_hash, current_year
// Private inputs: private_value, issuer_signature, signature_randomness
//
// The private_value is:
//   - birth_year for age attestation (type 0)
//   - annual_income for income attestation (type 1)
//   - credential_id for credential attestation (type 2)
//
// The circuit constrains:
//   1. The signature is valid: sig = private_value + pubkey * randomness
//   2. For age: current_year - private_value >= threshold
//   3. For income: private_value >= threshold
//   4. For credential: private_value === threshold (credential ID match)

pragma circom 2.2.3;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/gates.circom";

template Attest() {
    // Public inputs
    signal input attestation_type;     // 0=age, 1=income, 2=credential
    signal input threshold;            // minimum value to prove
    signal input issuer_pubkey_hash;   // issuer's public key hash
    signal input current_year;         // for age computation

    // Private inputs
    signal input private_value;        // birth_year / income / credential_id
    signal input issuer_signature;     // issuer's signature
    signal input signature_randomness; // randomness in signature

    // --- Constraint 1: Signature verification (simplified) ---
    // In production: Poseidon(private_value, issuer_pubkey_hash, randomness)
    signal expected_sig;
    expected_sig <== private_value + issuer_pubkey_hash * signature_randomness;
    expected_sig === issuer_signature;

    // --- Constraint 2: Attestation-specific logic ---
    // We use conditional constraints via the IsEqual trick:
    // compute the difference for each type, then select the right one.

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
    // type 0: use diff_age, type 1: use diff_income, type 2: use diff_cred
    // Use IsEqual to compute indicator signals (quadratic constraints)

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

    // Selected difference — use intermediate signals for each product
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
    // We enforce both: range check AND zero check for credential

    component n2b = Num2Bits(16);
    n2b.in <== selected_diff;

    // For credential type, also enforce selected_diff === 0
    // is_cred * selected_diff === 0
    signal cred_check;
    cred_check <== is_cred * selected_diff;
    cred_check === 0;
}

component main { public [attestation_type, threshold, issuer_pubkey_hash, current_year] } = Attest();
