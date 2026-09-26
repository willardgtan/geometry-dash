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
pub mod auth_trail;

pub use schema::{SecurityEvent, EventType, Severity};
pub use auth_trail::{AuthenticationEvent, AuthenticationEventType, AuthenticationAuditTrail, AuthenticationStatistics};

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
    /// Includes classification metadata for data lineage integrity
    fn hash_event(event: &SecurityEvent) -> [u8; 32] {
        // Serialize without current_entry_hash for hashing
        let mut json_obj = serde_json::json!({
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

        // Add optional classification fields if present
        if let Some(ref level) = event.classification_level {
            json_obj["classification_level"] = serde_json::to_value(level).unwrap_or_default();
        }
        if let Some(ref parent) = event.declassification_parent {
            json_obj["declassification_parent"] = serde_json::json!(parent);
        }
        if let Some(ref lineage) = event.data_lineage {
            json_obj["data_lineage"] = serde_json::json!(lineage);
        }

        let mut hasher = Sha256::new();
        hasher.update(json_obj.to_string());

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

    /// Compute Merkle root hash over all events in ledger
    /// Used for evidence bundle manifest to prove completeness and ordering
    pub fn compute_event_root_hash(&self) -> std::io::Result<[u8; 32]> {
        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);
        let mut hashes = Vec::new();

        // Collect hash of each event in order
        for line in reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                if let Ok(event) = serde_json::from_str::<SecurityEvent>(&line) {
                    hashes.push(event.current_entry_hash);
                }
            }
        }

        // Compute Merkle root from event hashes
        Ok(Self::merkle_root(&hashes))
    }

    /// Compute Merkle root from list of hashes
    /// Empty tree returns zero hash; single hash returns that hash;
    /// multiple hashes are paired and hashed recursively up to root
    fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
        if hashes.is_empty() {
            // Empty tree: return zero hash
            return [0u8; 32];
        }

        if hashes.len() == 1 {
            // Single node: return that hash
            return hashes[0];
        }

        let mut tree = hashes.to_vec();

        while tree.len() > 1 {
            let mut next_level = Vec::new();

            // Process pairs of nodes
            for chunk in tree.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);

                if chunk.len() == 2 {
                    // Pair: hash both
                    hasher.update(&chunk[1]);
                } else {
                    // Odd node: hash with itself (right-tree padding)
                    hasher.update(&chunk[0]);
                }

                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                next_level.push(hash);
            }

            tree = next_level;
        }

        tree[0]
    }

    /// Verify event chain integrity against expected Merkle root
    /// Returns true if computed root matches expected root
    pub fn verify_event_chain_with_proof(&self, expected_root: [u8; 32]) -> std::io::Result<bool> {
        let computed = self.compute_event_root_hash()?;
        Ok(computed == expected_root)
    }

    /// Append a classified event with data lineage metadata
    /// Used for events that track declassification operations
    ///
    /// Preconditions:
    /// - classification_level is set (Some value required)
    /// - If declassified, declassification_parent and data_lineage are set
    ///
    /// Postconditions:
    /// - Event appended with hash chain intact
    /// - Lineage chain recorded in ledger for audit trail
    pub fn append_classified_event(
        &self,
        event_type: EventType,
        principal: Principal,
        severity: Severity,
        run_id: &str,
        boot_id: &str,
        epoch_id: &str,
        classification_level: crate::principals::ClassificationLevel,
        declassification_parent: Option<String>,
        data_lineage: Option<Vec<String>>,
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

        // Set classification metadata
        event.set_classification(classification_level);
        if let Some(parent) = declassification_parent {
            if let Some(lineage) = data_lineage {
                event.set_declassification_lineage(parent, lineage);
            }
        }

        // Calculate hash (includes classification fields)
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

    /// Get complete lineage chain for a declassification event
    /// Searches ledger for events with matching declassification_parent
    ///
    /// Returns:
    /// - Some(Vec<SecurityEvent>) if events with matching parent found
    /// - None if no matching lineage found
    pub fn get_lineage(&self, declassification_parent: &str) -> std::io::Result<Option<Vec<SecurityEvent>>> {
        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);
        let mut lineage_events = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                if let Ok(event) = serde_json::from_str::<SecurityEvent>(&line) {
                    // Check if this event is part of the lineage chain
                    if let Some(ref parent) = event.declassification_parent {
                        if parent == declassification_parent {
                            lineage_events.push(event);
                        }
                    }
                }
            }
        }

        if lineage_events.is_empty() {
            Ok(None)
        } else {
            // Sort by ledger_index to maintain temporal order
            lineage_events.sort_by_key(|e| e.ledger_index);
            Ok(Some(lineage_events))
        }
    }

    /// Get all classified events for a principal
    /// Returns events where principal matches and classification_level is set
    pub fn get_principal_classified_events(
        &self,
        principal: Principal,
    ) -> std::io::Result<Vec<SecurityEvent>> {
        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                if let Ok(event) = serde_json::from_str::<SecurityEvent>(&line) {
                    if event.principal == principal && event.classification_level.is_some() {
                        events.push(event);
                    }
                }
            }
        }

        Ok(events)
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

    #[test]
    fn test_merkle_root_empty() {
        let hashes: Vec<[u8; 32]> = vec![];
        let root = SecurityLedger::merkle_root(&hashes);
        assert_eq!(root, [0u8; 32]);  // Empty tree is zero hash
    }

    #[test]
    fn test_merkle_root_single() {
        let hash = [0xAAu8; 32];
        let hashes = vec![hash];
        let root = SecurityLedger::merkle_root(&hashes);
        assert_eq!(root, hash);  // Single node returns itself
    }

    #[test]
    fn test_merkle_root_pair() {
        let hash1 = [0xAAu8; 32];
        let hash2 = [0xBBu8; 32];
        let hashes = vec![hash1, hash2];
        let root = SecurityLedger::merkle_root(&hashes);

        // Root should be deterministic
        let root2 = SecurityLedger::merkle_root(&hashes);
        assert_eq!(root, root2);

        // Should not be zero or either input
        assert_ne!(root, [0u8; 32]);
        assert_ne!(root, hash1);
        assert_ne!(root, hash2);
    }

    #[test]
    fn test_merkle_root_consistency() {
        let hashes = vec![
            [0xAAu8; 32],
            [0xBBu8; 32],
            [0xCCu8; 32],
            [0xDDu8; 32],
        ];

        let root1 = SecurityLedger::merkle_root(&hashes);
        let root2 = SecurityLedger::merkle_root(&hashes);

        // Merkle root should be deterministic
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_event_root_hash_empty_ledger() {
        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

        let root = ledger.compute_event_root_hash().unwrap();
        assert_eq!(root, [0u8; 32]);  // Empty ledger has zero root
    }

    #[test]
    fn test_event_root_hash_consistency() {
        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

        let mut details = HashMap::new();
        details.insert("test".to_string(), "value1".to_string());

        ledger.append_event(
            EventType::SupervisorStart,
            Principal::Supervisor,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            details.clone(),
        ).unwrap();

        ledger.append_event(
            EventType::PolicyDecision,
            Principal::Policy,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            details,
        ).unwrap();

        // Root should be consistent across calls
        let root1 = ledger.compute_event_root_hash().unwrap();
        let root2 = ledger.compute_event_root_hash().unwrap();

        assert_eq!(root1, root2);
        assert_ne!(root1, [0u8; 32]);  // Should not be zero (we have events)
    }

    #[test]
    fn test_verify_event_chain_with_proof_valid() {
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

        // Compute root and verify
        let root = ledger.compute_event_root_hash().unwrap();
        let verified = ledger.verify_event_chain_with_proof(root).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_verify_event_chain_with_proof_invalid() {
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

        // Try to verify with wrong root
        let wrong_root = [0xFFu8; 32];
        let verified = ledger.verify_event_chain_with_proof(wrong_root).unwrap();
        assert!(!verified);
    }

    #[test]
    fn test_append_classified_event() {
        use crate::principals::ClassificationLevel;

        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

        let mut details = HashMap::new();
        details.insert("field".to_string(), "sensitive_data".to_string());

        // Append a classified event
        let idx = ledger.append_classified_event(
            EventType::ArtifactDeclassified,
            Principal::Policy,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            ClassificationLevel::SensitiveReward,
            None,
            None,
            details,
        ).unwrap();

        assert_eq!(idx, 0);
        assert_eq!(ledger.count(), 1);
    }

    #[test]
    fn test_append_classified_event_with_lineage() {
        use crate::principals::ClassificationLevel;

        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

        let mut details = HashMap::new();
        details.insert("field".to_string(), "declassified_data".to_string());

        let lineage = vec!["parent-001".to_string(), "parent-002".to_string()];

        // Append a declassified event with lineage
        let idx = ledger.append_classified_event(
            EventType::ArtifactDeclassified,
            Principal::Audit,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            ClassificationLevel::PrivilegedTelemetry,
            Some("decl-001".to_string()),
            Some(lineage.clone()),
            details,
        ).unwrap();

        assert_eq!(idx, 0);
        assert_eq!(ledger.count(), 1);

        // Verify event can be read back with classification
        let file = std::fs::File::open(temp.path()).unwrap();
        let reader = std::io::BufReader::new(file);
        if let Some(first_line) = reader.lines().next() {
            let event: SecurityEvent = serde_json::from_str(&first_line.unwrap()).unwrap();
            assert!(event.is_declassified());
            assert_eq!(event.get_lineage(), Some(&lineage));
        }
    }

    #[test]
    fn test_get_lineage() {
        use crate::principals::ClassificationLevel;

        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

        let lineage1 = vec!["orig-001".to_string()];
        let lineage2 = vec!["orig-001".to_string(), "decl-001".to_string()];

        // Add two events with same parent
        ledger.append_classified_event(
            EventType::ArtifactDeclassified,
            Principal::Audit,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            ClassificationLevel::SensitiveReward,
            Some("parent-001".to_string()),
            Some(lineage1),
            HashMap::new(),
        ).unwrap();

        ledger.append_classified_event(
            EventType::ArtifactDeclassified,
            Principal::Audit,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            ClassificationLevel::SensitiveReward,
            Some("parent-001".to_string()),
            Some(lineage2),
            HashMap::new(),
        ).unwrap();

        // Retrieve lineage
        let result = ledger.get_lineage("parent-001").unwrap();
        assert!(result.is_some());
        let events = result.unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].ledger_index, 0);
        assert_eq!(events[1].ledger_index, 1);
    }

    #[test]
    fn test_get_lineage_not_found() {
        use crate::principals::ClassificationLevel;

        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

        // Add an event with a parent
        ledger.append_classified_event(
            EventType::ArtifactDeclassified,
            Principal::Audit,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            ClassificationLevel::SensitiveReward,
            Some("parent-001".to_string()),
            Some(vec!["orig".to_string()]),
            HashMap::new(),
        ).unwrap();

        // Try to get lineage for non-existent parent
        let result = ledger.get_lineage("parent-999").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_principal_classified_events() {
        use crate::principals::ClassificationLevel;

        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

        // Add event for Policy principal
        ledger.append_classified_event(
            EventType::ActionApproved,
            Principal::Policy,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            ClassificationLevel::Unrestricted,
            None,
            None,
            HashMap::new(),
        ).unwrap();

        // Add regular event for Audit principal (no classification)
        let mut details = HashMap::new();
        details.insert("action".to_string(), "audit".to_string());
        ledger.append_event(
            EventType::ActionExecuted,
            Principal::Audit,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            details,
        ).unwrap();

        // Add classified event for Audit principal
        ledger.append_classified_event(
            EventType::ArtifactDeclassified,
            Principal::Audit,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            ClassificationLevel::SensitiveReward,
            None,
            None,
            HashMap::new(),
        ).unwrap();

        // Get classified events for Audit
        let events = ledger.get_principal_classified_events(Principal::Audit).unwrap();
        assert_eq!(events.len(), 1);  // Only the classified one
        assert_eq!(events[0].ledger_index, 2);

        // Get classified events for Policy
        let policy_events = ledger.get_principal_classified_events(Principal::Policy).unwrap();
        assert_eq!(policy_events.len(), 1);
        assert_eq!(policy_events[0].ledger_index, 0);
    }

    #[test]
    fn test_classified_events_preserve_hash_chain() {
        use crate::principals::ClassificationLevel;

        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

        // Add regular event
        ledger.append_event(
            EventType::SupervisorStart,
            Principal::Supervisor,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            HashMap::new(),
        ).unwrap();

        // Add classified event
        ledger.append_classified_event(
            EventType::ArtifactDeclassified,
            Principal::Audit,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            ClassificationLevel::SensitiveReward,
            None,
            None,
            HashMap::new(),
        ).unwrap();

        // Verify hash chain still works
        assert!(ledger.verify_chain().is_ok());
    }
}
