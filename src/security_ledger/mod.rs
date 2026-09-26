// SecurityLedger: Append-only tamper-evident audit log
// Week 1 Task 2: Core implementation

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write, BufRead, BufReader};
use std::path::Path;
use std::sync::Mutex;
use crate::types::Principal;

pub mod schema;
pub use schema::{SecurityEvent, EventType, Severity};

/// SecurityLedger: Append-only JSON Lines log with hash chain
pub struct SecurityLedger {
    file_path: String,
    writer: Mutex<BufWriter<File>>,
    index: Mutex<Vec<[u8; 32]>>,  // Hash index for verification
    last_hash: Mutex<[u8; 32]>,    // Last entry hash
    ledger_index: Mutex<u64>,      // Current entry count
}

impl SecurityLedger {
    /// Create or open existing ledger
    pub fn open(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        let writer = BufWriter::new(file);

        // Load existing entries to reconstruct state
        let (index, last_hash, ledger_index) = Self::load_existing(path)?;

        Ok(SecurityLedger {
            file_path: path.to_string(),
            writer: Mutex::new(writer),
            index: Mutex::new(index),
            last_hash: Mutex::new(last_hash),
            ledger_index: Mutex::new(ledger_index),
        })
    }

    /// Load existing entries from disk
    fn load_existing(path: &str) -> std::io::Result<(Vec<[u8; 32]>, [u8; 32], u64)> {
        let mut index = Vec::new();
        let mut last_hash = [0u8; 32];
        let mut ledger_index = 0u64;

        if Path::new(path).exists() {
            let file = File::open(path)?;
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line?;
                if !line.trim().is_empty() {
                    if let Ok(event) = serde_json::from_str::<SecurityEvent>(&line) {
                        last_hash = event.current_entry_hash;
                        index.push(last_hash);
                        ledger_index += 1;
                    }
                }
            }
        } else {
            // First entry: prev_hash is zero
            last_hash = [0u8; 32];
        }

        Ok((index, last_hash, ledger_index))
    }

    /// Append a new event (append-only)
    pub fn append_event(
        &self,
        event_type: EventType,
        principal: Principal,
        severity: Severity,
        run_id: &str,
        boot_id: &str,
        epoch_id: &str,
        details: HashMap<String, String>,
    ) -> std::io::Result<u64> {
        let mut ledger_idx = self.ledger_index.lock().unwrap();
        let mut last = self.last_hash.lock().unwrap();

        // Create event with zero hash initially
        let mut event = SecurityEvent::new(
            *ledger_idx,
            event_type,
            principal,
            severity,
            run_id.to_string(),
            boot_id.to_string(),
            epoch_id.to_string(),
            *last,  // prev_hash
            [0u8; 32],  // current_hash (to be calculated)
            details,
        );

        // Calculate hash
        event.current_entry_hash = Self::hash_event(&event);

        // Serialize to JSON
        let json = serde_json::to_string(&event)?;

        // Write to file (atomic append)
        let mut writer = self.writer.lock().unwrap();
        writeln!(writer, "{}", json)?;
        writer.flush()?;

        // Update state
        *last = event.current_entry_hash;
        self.index.lock().unwrap().push(event.current_entry_hash);
        *ledger_idx += 1;

        Ok(*ledger_idx - 1)  // Return index of this entry
    }

    /// Calculate hash for event (SHA-256)
    fn hash_event(event: &SecurityEvent) -> [u8; 32] {
        // Serialize without current_entry_hash for hashing
        let json = serde_json::json!({
            "ledger_index": event.ledger_index,
            "timestamp_ns": event.timestamp_ns,
            "event_type": event.event_type,
            "severity": event.severity,
            "principal": event.principal,
            "run_id": event.run_id,
            "boot_id": event.boot_id,
            "epoch_id": event.epoch_id,
            "prev_entry_hash": Self::hash_to_hex(&event.prev_entry_hash),
            "details": event.details,
        });

        let mut hasher = Sha256::new();
        hasher.update(json.to_string());

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Convert hash bytes to hex string
    fn hash_to_hex(hash: &[u8; 32]) -> String {
        hex::encode(hash)
    }

    /// Verify hash chain integrity
    pub fn verify_chain(&self) -> Result<bool, String> {
        let file = File::open(&self.file_path)
            .map_err(|e| format!("Failed to open ledger: {}", e))?;

        let reader = BufReader::new(file);
        let mut prev_hash = [0u8; 32];

        for (idx, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| format!("Read error at line {}: {}", idx, e))?;
            if line.trim().is_empty() {
                continue;
            }

            let mut event = serde_json::from_str::<SecurityEvent>(&line)
                .map_err(|e| format!("Parse error at line {}: {}", idx, e))?;

            // Verify prev_hash matches
            if event.prev_entry_hash != prev_hash {
                return Err(format!(
                    "Hash chain broken at entry {}: expected prev={}, got {}",
                    idx,
                    hex::encode(prev_hash),
                    hex::encode(event.prev_entry_hash)
                ));
            }

            // Calculate and verify current hash
            let calculated = Self::hash_event(&event);
            if event.current_entry_hash != calculated {
                return Err(format!(
                    "Entry hash mismatch at {}: expected={}, got={}",
                    idx,
                    hex::encode(calculated),
                    hex::encode(event.current_entry_hash)
                ));
            }

            prev_hash = event.current_entry_hash;
        }

        Ok(true)
    }

    /// Get event count
    pub fn count(&self) -> u64 {
        *self.ledger_index.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_ledger_create() {
        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
        assert_eq!(ledger.count(), 0);
    }

    #[test]
    fn test_ledger_append() {
        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

        let mut details = HashMap::new();
        details.insert("action".to_string(), "TEST".to_string());

        let idx = ledger.append_event(
            EventType::SupervisorStart,
            Principal::Supervisor,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            details,
        ).unwrap();

        assert_eq!(idx, 0);
        assert_eq!(ledger.count(), 1);
    }

    #[test]
    fn test_ledger_verify_chain() {
        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

        let mut details = HashMap::new();
        details.insert("test".to_string(), "value".to_string());

        ledger.append_event(
            EventType::SupervisorStart,
            Principal::Supervisor,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            details,
        ).unwrap();

        assert!(ledger.verify_chain().is_ok());
    }
}
