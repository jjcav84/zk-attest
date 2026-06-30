//! Application state — tracks metrics for Hedera milestone tracking.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::collections::HashSet;

pub struct AppState {
    pub attestations: AtomicU64,
    pub verified: AtomicU64,
    pub hcs_messages: AtomicU64,
    pub hts_mints: AtomicU64,
    pub hedera_txs: AtomicU64,
    pub unique_users: Mutex<HashSet<String>>,
    pub last_attestation_at: Mutex<Option<String>>,
    pub energy_sum: Mutex<f64>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            attestations: AtomicU64::new(0),
            verified: AtomicU64::new(0),
            hcs_messages: AtomicU64::new(0),
            hts_mints: AtomicU64::new(0),
            hedera_txs: AtomicU64::new(0),
            unique_users: Mutex::new(HashSet::new()),
            last_attestation_at: Mutex::new(None),
            energy_sum: Mutex::new(0.0),
        }
    }

    pub fn record_attestation(&self, user_id: &str, energy: f64) {
        self.attestations.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut users) = self.unique_users.lock() {
            users.insert(user_id.to_string());
        }
        if let Ok(mut ts) = self.last_attestation_at.lock() {
            *ts = Some(chrono::Utc::now().to_rfc3339());
        }
        if let Ok(mut sum) = self.energy_sum.lock() {
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
        let users = self.unique_users.lock().map(|u| u.len() as u64).unwrap_or(0);
        let last = self.last_attestation_at.lock().ok().and_then(|t| t.clone());
        let avg = {
            let count = self.attestations.load(Ordering::Relaxed);
            if count == 0 { 0.0 }
            else {
                let sum = self.energy_sum.lock().map(|s| *s).unwrap_or(0.0);
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
