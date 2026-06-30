# zk-attest

**Zero-knowledge attestation platform on Hedera — prove without revealing.**

zk-attest lets users prove attributes about themselves (age, income, credential possession) using Groth16 zero-knowledge proofs, without revealing the underlying private data. Each attestation is logged to Hedera Consensus Service (HCS) for an immutable audit trail and minted as an HTS NFT — a transferable, verifiable credential.

Attestations are scored using an **attestation energy model** adapted from the [orkid FMD physics engine](https://github.com/jjcav84/orkid) — the same thermodynamic framework that scores arbitrage routes in production MEV extraction.

## Why this matters

Every age-gated website, income-verified service, and credential-checked platform today collects raw PII — birthdates, salary, ID numbers. This creates:

- **PII liability**: GDPR exposure, breach risk, compliance overhead
- **Data honeypots**: Centralized stores of sensitive data attract attackers
- **Privacy erosion**: Users surrender personal data for trivial verifications

zk-attest eliminates this. Users prove `age >= 18` or `income >= 50000` with a ZK proof. The verifier learns **only** the boolean result — never the underlying value.

## Architecture

| Layer | Technology |
|-------|-----------|
| Circuit | circom 2.2.3 (Groth16, BN128, 27 non-linear constraints) |
| Backend | Rust (axum, tokio, hiero-sdk 0.45) |
| Hedera | HCS (audit log) + HTS (NFT minting) + Mirror Nodes (verification) |
| Frontend | Vanilla HTML/JS (zero dependencies) |
| Energy model | FMD route energy formula (adapted from orkid fmd-physics) |

## The circuit

`circuit/attest.circom` supports three attestation types in a single circuit:

| Type | Private input | Public output | Privacy guarantee |
|------|--------------|---------------|-------------------|
| 0 (Age) | birth_year | `age >= threshold` | Birth year never revealed |
| 1 (Income) | annual_income | `income >= threshold` | Income never revealed |
| 2 (Credential) | credential_id | `credential_id === expected` | Credential ID never revealed |

**Public signals**: `[attestation_type, threshold, issuer_pubkey_hash, current_year]`
**Private signals**: `[private_value, issuer_signature, signature_randomness]`

The circuit constrains:
1. **Signature verification**: `sig = private_value + pubkey_hash * randomness`
2. **Attestation logic**: type-dependent range check (age: `current_year - birth_year >= threshold`, income: `income >= threshold`, credential: exact match)
3. **Type selection**: exactly one attestation type is active (IsEqual constraints)

## Hedera integration

Each attestation generates **3+ Hedera transactions**:

| Transaction | Service | Purpose |
|------------|---------|---------|
| 1 | HCS | Proof + public signals logged to consensus topic |
| 2 | HTS | NFT minted (attestation tokenized as transferable credential) |
| 3 | HCS | Energy score + verification result logged |
| 4 | HCS | Verification confirmation (on verify) |

### Hedera services used

- **HTS (Hedera Token Service)**: Mint NFTs representing attestations. Each NFT's metadata contains the proof ID, attestation type, and energy score. NFTs are transferable — users can present them to third-party verifiers.
- **HCS (Hedera Consensus Service)**: Immutable, timestamped, ordered log of all attestation proofs and verification events. Creates a tamper-proof audit trail accessible via Mirror Nodes.
- **Mirror Nodes**: Third-party verifiers query HCS topic messages to independently verify attestation history without trusting the issuer.

### Configuration

```bash
# Testnet (simulated mode without credentials)
export HEDERA_NETWORK=testnet

# Mainnet (real transactions)
export HEDERA_NETWORK=mainnet
export HEDERA_OPERATOR_ID=0.0.xxxx
export HEDERA_OPERATOR_KEY=302e0201...
export HEDERA_TOPIC_ID=0.0.xxxx   # optional, auto-created
export HEDERA_TOKEN_ID=0.0.xxxx   # optional, auto-created
```

## Attestation energy model (FMD physics)

The attestation energy model is adapted from the **route energy formula** in the orkid FMD (Financial Molecular Dynamics) physics engine — a production MEV detection system that treats market inefficiency as thermodynamic negentropy.

### The thermodynamic framing

In the orkid framework:
- **Markets** are thermodynamic systems with entropy (disorder) and negentropy (order)
- **Arbitrage opportunities** are low-entropy pockets — mispricings that searchers extract as profit
- **Route energy** scores arbitrage paths by how much negentropy they extract

In zk-attest:
- **Private data** is a high-entropy state (chaotic, unverifiable)
- **A ZK proof** is a negentropy extraction — converting private chaos into structured, verifiable order
- **Attestation energy** scores proofs by how much negentropy they extract

### The formula

**FMD route energy** (orkid `fmd-physics/src/route_energy.rs`):
```
energy = net_bps * sqrt(depth_ratio * timing_factor) * latency_decay * (1 - gas_penalty)
```

**Attestation energy** (adapted):
```
energy = confidence * sqrt(depth_ratio * timing_factor) * latency_decay * (1 - cost_penalty)
```

Where:
- **confidence** = `base_depth(attestation_type) * issuer_trust` — analogous to pool TVL
- **depth_ratio** = `confidence / log10(threshold)` — higher threshold = harder to prove = more negentropy
- **timing_factor** = `exp(-age / half_life)` — recency decay (1-hour half-life)
- **latency_decay** = `1 / (1 + total_latency_ms * 0.0001)` — proof generation speed
- **cost_penalty** = `(hcs_cost + hts_cost) * hbar_price * normalization` — Hedera transaction cost

### Negentropy extraction

Each ZK proof extracts negentropy (information) from private data:

```
N = constraint_count * log2(threshold)
```

For a 27-constraint circuit proving age >= 18: `N = 27 * log2(18) ≈ 112.6 bits`

This is the Shannon entropy reduction — the amount of uncertainty eliminated by the proof.

### Committor function

Adapted from the TPS (Transition Path Sampling) committor in the FMD engine, which predicts the probability of reaching a profitable state:

```
committor = (depth_ratio / (1 + depth_ratio)) * timing_factor * (1 - cost_penalty * 0.5)
```

This estimates the probability that an attestation is valid and uncontested — a "rare event" prediction for attestation quality.

## Transaction volume model (Milestone 4 target: 50K monthly transactions)

Each attestation generates **3 Hedera transactions** (HCS + HTS + HCS). Each verification adds **1 more**.

| Scenario | Attestations/month | Verifications/month | Hedera txs/month |
|----------|-------------------|--------------------|--------------------|
| Age-gated e-commerce | 8,000 | 8,000 | 56,000 |
| Income verification (fintech KYC) | 5,000 | 5,000 | 30,000 |
| Credential checks (gig platforms) | 3,000 | 3,000 | 18,000 |
| **Total (conservative)** | **16,000** | **16,000** | **104,000** |

**50K monthly transactions** is achievable with ~8,300 attestations/month — well within a single age-gated e-commerce deployment.

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check + Hedera connection status |
| `/api/issue` | POST | Issue signed credential (simulated authority) |
| `/api/attest` | POST | Generate ZK proof + submit to HCS/HTS |
| `/api/verify` | POST | Verify a proof + log to HCS |
| `/api/stats` | GET | Metrics for milestone tracking |
| `/api/energy/:id` | GET | Attestation energy score (FMD model) |

## Quick start

```bash
# 1. Install circom + snarkjs
curl -Ls https://github.com/iden3/circom/releases/latest/download/circom-linux-amd64 -o /usr/local/bin/circom
npm install -g snarkjs

# 2. Compile circuit + trusted setup
cd circuit && npm install circomlib
circom attest.circom --r1cs --wasm --sym -o ../build
cd ../build
snarkjs powersoftau new bn128 8 pot0_0000.ptau
snarkjs powersoftau contribute pot0_0000.ptau pot0_0001.ptau --name="zk-attest" -e="entropy"
snarkjs powersoftau prepare phase2 pot0_0001.ptau pot0_final.ptau
snarkjs groth16 setup attest.r1cs pot0_final.ptau attest_0000.zkey
snarkjs zkey contribute attest_0000.zkey attest_final.zkey --name="zk-attest" -e="entropy"
snarkjs zkey export verificationkey attest_final.zkey verification_key.json

# 3. Run backend
cd .. && cargo run

# 4. Open frontend
open http://localhost:3000
```

## Build & test

```bash
cargo build
cargo test --bin zk-attest-backend
```

## Project structure

```
zk-attest/
├── circuit/
│   ├── attest.circom          # Multi-attestation ZK circuit
│   └── package.json           # circomlib dependency
├── build/                     # Compiled circuit artifacts (gitignored)
├── backend/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs            # axum server entry
│       ├── routes.rs          # HTTP API
│       ├── types.rs           # API types
│       ├── state.rs           # Metrics tracking
│       ├── issuer.rs          # Credential issuance (simulated authority)
│       ├── prover.rs          # snarkjs proof generation + verification
│       ├── hedera.rs          # HCS + HTS integration
│       └── attestation_energy.rs  # FMD physics energy model
├── frontend/
│   └── index.html             # Zero-dependency web UI
├── Cargo.toml                 # Workspace
└── README.md
```

## Production upgrades

- **Poseidon signatures**: Replace simplified algebraic signature with Poseidon hash + EdDSA on BabyJubJub (native ZK-friendly)
- **Real Hedera integration**: Wire `hiero-sdk` for live HCS/HTS transactions (code structure ready)
- **Issuer marketplace**: Multiple credential authorities with on-chain reputation
- **Revocation**: HCS-based revocation registry
- **Batch verification**: Verify multiple proofs in a single HCS message

## License

MIT
