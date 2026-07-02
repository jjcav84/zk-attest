//! Application state — tracks metrics for Hedera milestone tracking.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::collections::HashSet;

pub struct AppState {
    pub attestations: AtomicU64,
    pub verified: AtomicU64,
    pub hcs_messages: AtomicU64,
    pub hts_mints: AtomicU64,
    pub hedera_txs: AtomicU64,
    pub unique_users: RwLock<HashSet<String>>,
    pub last_attestation_at: RwLock<Option<String>>,
    pub energy_sum: RwLock<f64>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            attestations: AtomicU64::new(0),
            verified: AtomicU64::new(0),
            hcs_messages: AtomicU64::new(0),
            hts_mints: AtomicU64::new(0),
            hedera_txs: AtomicU64::new(0),
            unique_users: RwLock::new(HashSet::new()),
            last_attestation_at: RwLock::new(None),
            energy_sum: RwLock::new(0.0),
        }
    }

    pub fn record_attestation(&self, user_id: &str, energy: f64) {
        self.attestations.fetch_add(1, Ordering::Relaxed);
        {
            let mut users = self.unique_users.write().expect("unique_users lock poisoned");
            users.insert(user_id.to_string());
        }
        {
            let mut ts = self.last_attestation_at.write().expect("last_attestation_at lock poisoned");
            *ts = Some(chrono::Utc::now().to_rfc3339());
        }
        {
            let mut sum = self.energy_sum.write().expect("energy_sum lock poisoned");
            *sum += energy;
        }
    }

    pub fn record_hcs(&self) {
        self.hcs_messages.fetch_add(1, Ordering::Relaxed);
        self.hedera_txs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_hts_mint(&self) {
        self.hts_mints.fetch_add(1, Ordering::Relaxed);
        self.hedera_txs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_verification(&self) {
        self.verified.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stats(&self) -> (u64, u64, u64, u64, u64, u64, Option<String>, f64) {
        let users = self.unique_users.read().expect("unique_users read lock poisoned").len() as u64;
        let last = self.last_attestation_at.read().expect("last_attestation_at read lock poisoned").clone();
        let avg = {
            let count = self.attestations.load(Ordering::Relaxed);
            if count == 0 { 0.0 }
            else {
                let sum = *self.energy_sum.read().expect("energy_sum read lock poisoned");
                sum / count as f64
            }
        };
        (
            self.attestations.load(Ordering::Relaxed),
            self.verified.load(Ordering::Relaxed),
            self.hcs_messages.load(Ordering::Relaxed),
            self.hts_mints.load(Ordering::Relaxed),
            self.hedera_txs.load(Ordering::Relaxed),
            users,
            last,
            avg,
        )
    }
}
