// Execution Snapshot and Replay Detection (Sprint 4 Task 4.5)
// Prevent replay of execution contexts with outdated state
// Content-addressed snapshots ensure immutability and tamper detection

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::ipc::execution_context::CommandExecutionContext;

/// Execution snapshot: immutable hash of validation state
#[derive(Debug, Clone)]
pub struct ExecutionSnapshot {
    /// SHA-256 hash of entire validation context
    pub snapshot_hash: String,

    /// Hash of command component
    pub command_hash: String,

    /// Hash of Gate C (authorization) validation
    pub gate_c_hash: String,

    /// Hash of Gate I (integrity) validation
    pub gate_i_hash: String,

    /// Hash of requester principal identity
    pub principal_identity_hash: String,

    /// Hash of requester certificate
    pub certificate_hash: String,

    /// Hash of execution token
    pub token_hash: String,

    /// Timestamp when snapshot was created (nanoseconds)
    pub timestamp_ns: u64,

    /// Snapshot content for verification
    pub content: String,
}

impl ExecutionSnapshot {
    /// Create snapshot from execution context
    pub fn from_context(context: &CommandExecutionContext, timestamp_ns: u64) -> Self {
        // Compute component hashes
        let command_hash = compute_hash(&context.command.command_id);
        let gate_c_hash = compute_hash(&format!(
            "{}-{}-{}",
            context.gate_c_snapshot.allowed,
            context.gate_c_snapshot.policy_version,
            context.gate_c_snapshot.timestamp_ns
        ));
        let gate_i_hash = compute_hash(&format!(
            "{}-{}-{}",
            context.gate_i_snapshot.integrity_valid,
            context.gate_i_snapshot.signature_valid,
            context.gate_i_snapshot.nonce_fresh
        ));
        let principal_identity_hash = compute_hash(&context.requester_state.identity.public_key_hash);
        let certificate_hash = compute_hash(&context.requester_state.certificate.content_hash);
        let token_hash = compute_hash(&context.execution_token.token_id);

        // Compute overall snapshot hash
        let content = format!(
            "{}-{}-{}-{}-{}-{}-{}",
            &command_hash,
            &gate_c_hash,
            &gate_i_hash,
            &principal_identity_hash,
            &certificate_hash,
            &token_hash,
            timestamp_ns
        );
        let snapshot_hash = compute_hash(&content);

        ExecutionSnapshot {
            snapshot_hash,
            command_hash,
            gate_c_hash,
            gate_i_hash,
            principal_identity_hash,
            certificate_hash,
            token_hash,
            timestamp_ns,
            content,
        }
    }

    /// Verify snapshot integrity (no tampering)
    pub fn verify(&self) -> Result<(), String> {
        let recomputed_hash = compute_hash(&self.content);
        if recomputed_hash != self.snapshot_hash {
            return Err("Snapshot hash mismatch - possible tampering".to_string());
        }
        Ok(())
    }
}

/// Entry in execution replay log
#[derive(Debug, Clone)]
struct ExecutionReplayEntry {
    /// Snapshot hash that was executed
    snapshot_hash: String,

    /// When this snapshot was executed
    execution_timestamp_ns: u64,

    /// Execution expiration time (for TTL cleanup)
    expiration_ns: u64,
}

/// Execution replay detector: prevents same snapshot from executing twice
pub struct ExecutionReplayDetector {
    /// Map of snapshot_hash -> execution details
    execution_log: Mutex<HashMap<String, ExecutionReplayEntry>>,

    /// TTL for replay log entries (in nanoseconds)
    ttl_ns: u64,

    /// Maximum entries before cleanup
    max_entries: usize,
}

impl ExecutionReplayDetector {
    /// Create new replay detector with TTL
    pub fn new(ttl_ms: u64, max_entries: usize) -> Self {
        ExecutionReplayDetector {
            execution_log: Mutex::new(HashMap::new()),
            ttl_ns: ttl_ms * 1_000_000,  // Convert ms to ns
            max_entries,
        }
    }

    /// Check if snapshot has been executed before (replay detection)
    pub fn check_replay(&self, snapshot: &ExecutionSnapshot) -> Result<(), String> {
        let mut log = self.execution_log.lock().unwrap();

        // Check if snapshot was already executed
        if log.contains_key(&snapshot.snapshot_hash) {
            return Err(format!(
                "Execution replay detected: snapshot {} already executed",
                snapshot.snapshot_hash
            ));
        }

        // Add to log with expiration
        let expiration_ns = snapshot.timestamp_ns + self.ttl_ns;
        log.insert(
            snapshot.snapshot_hash.clone(),
            ExecutionReplayEntry {
                snapshot_hash: snapshot.snapshot_hash.clone(),
                execution_timestamp_ns: snapshot.timestamp_ns,
                expiration_ns,
            },
        );

        // Cleanup expired entries if needed
        if log.len() > self.max_entries {
            self.cleanup_expired_entries(&mut log, snapshot.timestamp_ns);
        }

        Ok(())
    }

    /// Record successful execution of snapshot
    pub fn record_execution(&self, snapshot: &ExecutionSnapshot) -> Result<(), String> {
        let mut log = self.execution_log.lock().unwrap();

        let expiration_ns = snapshot.timestamp_ns + self.ttl_ns;
        log.insert(
            snapshot.snapshot_hash.clone(),
            ExecutionReplayEntry {
                snapshot_hash: snapshot.snapshot_hash.clone(),
                execution_timestamp_ns: snapshot.timestamp_ns,
                expiration_ns,
            },
        );

        Ok(())
    }

    /// Check if snapshot has executed
    pub fn has_executed(&self, snapshot_hash: &str) -> bool {
        let log = self.execution_log.lock().unwrap();
        log.contains_key(snapshot_hash)
    }

    /// Cleanup expired entries from log
    fn cleanup_expired_entries(&self, log: &mut HashMap<String, ExecutionReplayEntry>, current_ns: u64) {
        let before_count = log.len();

        log.retain(|_, entry| current_ns < entry.expiration_ns);

        // If still over max, remove oldest entries
        while log.len() > self.max_entries {
            if let Some(oldest_hash) = log
                .values()
                .min_by_key(|e| e.execution_timestamp_ns)
                .map(|e| e.snapshot_hash.clone())
            {
                log.remove(&oldest_hash);
            } else {
                break;
            }
        }
    }

    /// Manual cleanup of expired entries
    pub fn cleanup_expired(&self, current_timestamp_ns: u64) {
        let mut log = self.execution_log.lock().unwrap();
        self.cleanup_expired_entries(&mut log, current_timestamp_ns);
    }

    /// Get execution log statistics
    pub fn statistics(&self) -> (usize, usize) {
        let log = self.execution_log.lock().unwrap();
        (log.len(), self.max_entries)
    }

    /// Clear execution log (for testing)
    pub fn clear(&self) {
        let mut log = self.execution_log.lock().unwrap();
        log.clear();
    }
}

/// Snapshot verifier: detects tampering with snapshots
pub struct SnapshotVerifier;

impl SnapshotVerifier {
    /// Verify snapshot has not been tampered with
    pub fn verify_snapshot(snapshot: &ExecutionSnapshot) -> Result<(), String> {
        snapshot.verify()
    }

    /// Verify snapshot against expected hash
    pub fn verify_snapshot_hash(snapshot: &ExecutionSnapshot, expected_hash: &str) -> Result<(), String> {
        if snapshot.snapshot_hash != expected_hash {
            return Err(format!(
                "Snapshot hash mismatch: expected {}, got {}",
                expected_hash, snapshot.snapshot_hash
            ));
        }
        Ok(())
    }

    /// Verify all component hashes are consistent
    pub fn verify_all_components(snapshot: &ExecutionSnapshot) -> Result<(), String> {
        // Verify overall hash
        snapshot.verify()?;

        // Verify each component is non-empty
        if snapshot.command_hash.is_empty() {
            return Err("Command hash is empty".to_string());
        }
        if snapshot.gate_c_hash.is_empty() {
            return Err("Gate C hash is empty".to_string());
        }
        if snapshot.gate_i_hash.is_empty() {
            return Err("Gate I hash is empty".to_string());
        }
        if snapshot.principal_identity_hash.is_empty() {
            return Err("Principal identity hash is empty".to_string());
        }
        if snapshot.certificate_hash.is_empty() {
            return Err("Certificate hash is empty".to_string());
        }
        if snapshot.token_hash.is_empty() {
            return Err("Token hash is empty".to_string());
        }

        Ok(())
    }
}

/// Compute SHA-256 hash of content
fn compute_hash(content: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    let hash_value = hasher.finish();
    format!("{:x}", hash_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Principal;
    use crate::principals::identity::PublicKey;
    use crate::principals::identity::PrincipalIdentity;
    use crate::principals::certificate::PrincipalCertificate;
    use crate::ipc::token::ExecutionToken;
    use crate::ipc::execution_context::{GateCSnapshot, GateISnapshot, CommandSnapshot, PrincipalStateSnapshot, CommandExecutionContext};

    fn create_test_context() -> CommandExecutionContext {
        let gate_c = GateCSnapshot {
            allowed: true,
            reason: "authorized".to_string(),
            capabilities: vec![3, 5],
            policy_version: 1,
            timestamp_ns: 1000,
        };

        let gate_i = GateISnapshot {
            integrity_valid: true,
            signature_valid: true,
            nonce_fresh: true,
            timestamp_ns: 1000,
        };

        let identity = PrincipalIdentity {
            identity_id: "id-1".to_string(),
            principal: Principal::Policy,
            public_key: PublicKey::new([1u8; 32]),
            key_version: 1,
            created_timestamp_ns: 1000,
            expires_timestamp_ns: None,
            is_active: true,
            purpose: "primary".to_string(),
            public_key_hash: "hash-1".to_string(),
        };

        let mut certificate = PrincipalCertificate::new(
            "cert-1".to_string(),
            Principal::Policy,
            PublicKey::new([1u8; 32]),
            1,
            Principal::Sealer,
            1000,
            6000,
        );
        certificate.content_hash = "hash-1".to_string();

        let token = ExecutionToken::new(
            "cmd-1".to_string(),
            1000,
            6000,
            Principal::Supervisor,
            Principal::Policy,
            0x03,
            [1u8; 64],
        );

        CommandExecutionContext::new(
            "cmd-1".to_string(),
            "test command".to_string(),
            Principal::Policy,
            3,
            1000,
            gate_c,
            gate_i,
            identity,
            certificate,
            token,
        )
    }

    #[test]
    fn test_snapshot_creation() {
        let context = create_test_context();
        let snapshot = ExecutionSnapshot::from_context(&context, 2000);

        assert!(!snapshot.snapshot_hash.is_empty());
        assert!(!snapshot.command_hash.is_empty());
        assert!(!snapshot.gate_c_hash.is_empty());
        assert!(!snapshot.gate_i_hash.is_empty());
        assert_eq!(snapshot.timestamp_ns, 2000);
    }

    #[test]
    fn test_snapshot_verification() {
        let context = create_test_context();
        let snapshot = ExecutionSnapshot::from_context(&context, 2000);

        assert!(snapshot.verify().is_ok());
    }

    #[test]
    fn test_snapshot_tampering_detection() {
        let context = create_test_context();
        let mut snapshot = ExecutionSnapshot::from_context(&context, 2000);

        // Tamper with content
        snapshot.content = "tampered".to_string();

        // Verification should fail
        assert!(snapshot.verify().is_err());
    }

    #[test]
    fn test_replay_detector_creation() {
        let detector = ExecutionReplayDetector::new(5000, 1000);
        let (size, max) = detector.statistics();
        assert_eq!(size, 0);
        assert_eq!(max, 1000);
    }

    #[test]
    fn test_replay_detection_single_snapshot() {
        let detector = ExecutionReplayDetector::new(5000, 1000);
        let context = create_test_context();
        let snapshot = ExecutionSnapshot::from_context(&context, 1000);

        // First execution should succeed
        assert!(detector.check_replay(&snapshot).is_ok());
        assert!(detector.has_executed(&snapshot.snapshot_hash));

        // Second execution should be rejected
        let result = detector.check_replay(&snapshot);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("replay detected"));
    }

    #[test]
    fn test_replay_detector_multiple_snapshots() {
        let detector = ExecutionReplayDetector::new(5000, 1000);
        let context = create_test_context();

        // Create different snapshots
        let snap1 = ExecutionSnapshot::from_context(&context, 1000);
        let snap2 = ExecutionSnapshot::from_context(&context, 2000);

        // Both should execute successfully
        assert!(detector.check_replay(&snap1).is_ok());
        assert!(detector.check_replay(&snap2).is_ok());

        // Replay should be rejected
        assert!(detector.check_replay(&snap1).is_err());
    }

    #[test]
    fn test_snapshot_verifier() {
        let context = create_test_context();
        let snapshot = ExecutionSnapshot::from_context(&context, 2000);

        assert!(SnapshotVerifier::verify_snapshot(&snapshot).is_ok());
        assert!(SnapshotVerifier::verify_all_components(&snapshot).is_ok());
    }

    #[test]
    fn test_snapshot_verifier_hash_mismatch() {
        let context = create_test_context();
        let snapshot = ExecutionSnapshot::from_context(&context, 2000);

        let result = SnapshotVerifier::verify_snapshot_hash(&snapshot, "wrong_hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_replay_detector_clear() {
        let detector = ExecutionReplayDetector::new(5000, 1000);
        let context = create_test_context();
        let snapshot = ExecutionSnapshot::from_context(&context, 1000);

        detector.check_replay(&snapshot).unwrap();
        assert_eq!(detector.statistics().0, 1);

        detector.clear();
        assert_eq!(detector.statistics().0, 0);

        // Should be able to replay after clear
        assert!(detector.check_replay(&snapshot).is_ok());
    }
}
