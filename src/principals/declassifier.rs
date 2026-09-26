// Declassifier Principal: Data Classification Management (Sprint 2 Task 2.1)
// Responsible for managing data classifications and declassification policies
// Implements SEC-C01 Privileged Data Boundary Enforcement

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::types::Principal;
use crate::security_ledger::SecurityLedger;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use uuid::Uuid;

/// Data classification level for privileged data boundary enforcement
/// Defines the sensitivity level of data and controls which principals can access it
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum ClassificationLevel {
    /// Unrestricted data readable by all principals (policy-safe)
    Unrestricted,
    /// Sensitive reward/outcome data (reward-sensitive principals only)
    SensitiveReward,
    /// Privileged telemetry (physics probes, internal metrics)
    PrivilegedTelemetry,
    /// Internal system state (sealer/audit only)
    Internal,
}

impl std::fmt::Display for ClassificationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClassificationLevel::Unrestricted => write!(f, "unrestricted"),
            ClassificationLevel::SensitiveReward => write!(f, "sensitive-reward"),
            ClassificationLevel::PrivilegedTelemetry => write!(f, "privileged-telemetry"),
            ClassificationLevel::Internal => write!(f, "internal"),
        }
    }
}

/// Classification label applied to a specific field or value
/// Binds a classification level to a named data field for access control enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationLabel {
    /// Field or resource name being classified
    pub field_name: String,
    /// Classification level assigned to this field
    pub level: ClassificationLevel,
    /// Principal that applied this classification
    pub applied_by: Principal,
    /// Timestamp when classification was applied (nanoseconds since UNIX_EPOCH)
    pub applied_timestamp_ns: u64,
    /// Justification for this classification
    pub justification: String,
}

impl ClassificationLabel {
    /// Create a new classification label
    pub fn new(
        field_name: String,
        level: ClassificationLevel,
        applied_by: Principal,
        applied_timestamp_ns: u64,
        justification: String,
    ) -> Self {
        ClassificationLabel {
            field_name,
            level,
            applied_by,
            applied_timestamp_ns,
            justification,
        }
    }
}

/// Versioned declassification policy that controls reduction of classification
/// Requires approval chain and tracks effective/expiry dates for enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclassificationPolicy {
    /// Unique policy identifier (UUID)
    pub policy_id: String,
    /// Version number for tracking policy evolution
    pub version: u32,
    /// Field name this policy applies to
    pub field_name: String,
    /// Minimum classification that can be reduced
    pub source_level: ClassificationLevel,
    /// Target classification after declassification
    pub target_level: ClassificationLevel,
    /// Optional transformation function (e.g., "hash_sha256", "aggregate_mean")
    pub transformation: Option<String>,
    /// Principals that approved this policy (requires at least 2)
    pub approved_by: Vec<Principal>,
    /// Timestamp when policy becomes effective (nanoseconds since UNIX_EPOCH)
    pub effective_timestamp_ns: u64,
    /// Optional timestamp when policy expires (None = no expiration)
    pub expires_timestamp_ns: Option<u64>,
}

impl DeclassificationPolicy {
    /// Create a new declassification policy
    pub fn new(
        policy_id: String,
        version: u32,
        field_name: String,
        source_level: ClassificationLevel,
        target_level: ClassificationLevel,
        transformation: Option<String>,
        approved_by: Vec<Principal>,
        effective_timestamp_ns: u64,
        expires_timestamp_ns: Option<u64>,
    ) -> Self {
        DeclassificationPolicy {
            policy_id,
            version,
            field_name,
            source_level,
            target_level,
            transformation,
            approved_by,
            effective_timestamp_ns,
            expires_timestamp_ns,
        }
    }

    /// Check if this policy is currently valid (effective and not expired)
    pub fn is_valid(&self, current_time_ns: u64) -> bool {
        current_time_ns >= self.effective_timestamp_ns &&
            (self.expires_timestamp_ns.is_none() ||
             current_time_ns < self.expires_timestamp_ns.unwrap())
    }

    /// Check if principal is in approval chain
    pub fn is_approved_by(&self, principal: Principal) -> bool {
        self.approved_by.contains(&principal)
    }
}

/// Audit record documenting each declassification operation
/// Creates immutable trail of all data reductions with lineage tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclassificationRecord {
    /// Unique record identifier (UUID)
    pub record_id: String,
    /// Field name that was declassified
    pub field_name: String,
    /// SHA-256 hash of original (classified) value
    pub original_value_hash: [u8; 32],
    /// SHA-256 hash of declassified value
    pub declassified_value_hash: [u8; 32],
    /// Policy ID applied for this declassification
    pub policy_id: String,
    /// Principal that performed the declassification
    pub applied_by: Principal,
    /// Timestamp when declassification occurred (nanoseconds since UNIX_EPOCH)
    pub timestamp_ns: u64,
    /// Lineage chain showing parent records (for multi-level transformations)
    pub lineage: Vec<String>,
}

impl DeclassificationRecord {
    /// Create a new declassification record
    pub fn new(
        record_id: String,
        field_name: String,
        original_value_hash: [u8; 32],
        declassified_value_hash: [u8; 32],
        policy_id: String,
        applied_by: Principal,
        timestamp_ns: u64,
        lineage: Vec<String>,
    ) -> Self {
        DeclassificationRecord {
            record_id,
            field_name,
            original_value_hash,
            declassified_value_hash,
            policy_id,
            applied_by,
            timestamp_ns,
            lineage,
        }
    }
}

/// Classification system registry
/// Manages all active classification labels, declassification policies, and audit records
pub struct ClassificationRegistry {
    /// Field name -> active classification label
    labels: Arc<Mutex<HashMap<String, ClassificationLabel>>>,

    /// Policy ID -> versioned declassification policy
    policies: Arc<Mutex<HashMap<String, DeclassificationPolicy>>>,

    /// Immutable audit ledger of declassifications performed
    declassification_records: Arc<Mutex<Vec<DeclassificationRecord>>>,

    /// Security ledger reference for integration
    ledger: Arc<SecurityLedger>,
}

impl ClassificationRegistry {
    /// Create a new classification registry
    pub fn new(ledger: Arc<SecurityLedger>) -> Self {
        ClassificationRegistry {
            labels: Arc::new(Mutex::new(HashMap::new())),
            policies: Arc::new(Mutex::new(HashMap::new())),
            declassification_records: Arc::new(Mutex::new(Vec::new())),
            ledger,
        }
    }

    /// Apply a classification label to a field
    pub fn apply_classification(
        &self,
        field_name: String,
        level: ClassificationLevel,
        applied_by: Principal,
        applied_timestamp_ns: u64,
        justification: String,
    ) -> ClassificationLabel {
        let label = ClassificationLabel::new(
            field_name.clone(),
            level,
            applied_by,
            applied_timestamp_ns,
            justification,
        );

        {
            let mut labels = self.labels.lock().unwrap();
            labels.insert(field_name, label.clone());
        }

        label
    }

    /// Retrieve a classification label for a field
    pub fn get_label(&self, field_name: &str) -> Option<ClassificationLabel> {
        self.labels.lock().unwrap().get(field_name).cloned()
    }

    /// List all active classification labels
    pub fn list_labels(&self) -> Vec<ClassificationLabel> {
        self.labels.lock().unwrap().values().cloned().collect()
    }

    /// Register a new declassification policy
    pub fn register_policy(
        &self,
        policy_id: String,
        version: u32,
        field_name: String,
        source_level: ClassificationLevel,
        target_level: ClassificationLevel,
        transformation: Option<String>,
        approved_by: Vec<Principal>,
        effective_timestamp_ns: u64,
        expires_timestamp_ns: Option<u64>,
    ) -> Result<DeclassificationPolicy, String> {
        // Validate policy
        if approved_by.len() < 2 {
            return Err("Policy requires at least 2 approvals".to_string());
        }

        if source_level as u8 <= target_level as u8 {
            return Err("Source level must be more restrictive than target level".to_string());
        }

        let policy = DeclassificationPolicy::new(
            policy_id.clone(),
            version,
            field_name,
            source_level,
            target_level,
            transformation,
            approved_by,
            effective_timestamp_ns,
            expires_timestamp_ns,
        );

        {
            let mut policies = self.policies.lock().unwrap();
            policies.insert(policy_id, policy.clone());
        }

        Ok(policy)
    }

    /// Retrieve a declassification policy
    pub fn get_policy(&self, policy_id: &str) -> Option<DeclassificationPolicy> {
        self.policies.lock().unwrap().get(policy_id).cloned()
    }

    /// List all declassification policies
    pub fn list_policies(&self) -> Vec<DeclassificationPolicy> {
        self.policies.lock().unwrap().values().cloned().collect()
    }

    /// Create a declassification record (audit trail)
    pub fn record_declassification(
        &self,
        field_name: String,
        original_value_hash: [u8; 32],
        declassified_value_hash: [u8; 32],
        policy_id: String,
        applied_by: Principal,
        timestamp_ns: u64,
        lineage: Vec<String>,
    ) -> DeclassificationRecord {
        let record = DeclassificationRecord::new(
            Uuid::new_v4().to_string(),
            field_name,
            original_value_hash,
            declassified_value_hash,
            policy_id,
            applied_by,
            timestamp_ns,
            lineage,
        );

        {
            let mut records = self.declassification_records.lock().unwrap();
            records.push(record.clone());
        }

        record
    }

    /// Retrieve declassification history
    pub fn get_declassification_history(&self) -> Vec<DeclassificationRecord> {
        self.declassification_records.lock().unwrap().clone()
    }

    /// Get declassification records for a specific field
    pub fn get_field_declassifications(&self, field_name: &str) -> Vec<DeclassificationRecord> {
        self.declassification_records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.field_name == field_name)
            .cloned()
            .collect()
    }

    /// Get statistics about classification and declassification
    pub fn statistics(&self) -> (usize, usize, usize) {
        (
            self.labels.lock().unwrap().len(),
            self.policies.lock().unwrap().len(),
            self.declassification_records.lock().unwrap().len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper function to compute SHA-256 hash
    fn compute_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    #[test]
    fn test_classification_level_types() {
        // Verify all 4 classification levels exist and are distinct
        assert_eq!(ClassificationLevel::Unrestricted.to_string(), "unrestricted");
        assert_eq!(ClassificationLevel::SensitiveReward.to_string(), "sensitive-reward");
        assert_eq!(ClassificationLevel::PrivilegedTelemetry.to_string(), "privileged-telemetry");
        assert_eq!(ClassificationLevel::Internal.to_string(), "internal");

        // Verify they're all different
        assert_ne!(ClassificationLevel::Unrestricted, ClassificationLevel::SensitiveReward);
        assert_ne!(ClassificationLevel::SensitiveReward, ClassificationLevel::PrivilegedTelemetry);
        assert_ne!(ClassificationLevel::PrivilegedTelemetry, ClassificationLevel::Internal);
    }

    #[test]
    fn test_classification_label_creation() {
        let label = ClassificationLabel::new(
            "physics_probe".to_string(),
            ClassificationLevel::PrivilegedTelemetry,
            Principal::Developer,
            1000,
            "Contains sensitive physics measurements".to_string(),
        );

        assert_eq!(label.field_name, "physics_probe");
        assert_eq!(label.level, ClassificationLevel::PrivilegedTelemetry);
        assert_eq!(label.applied_by, Principal::Developer);
        assert_eq!(label.applied_timestamp_ns, 1000);
        assert_eq!(label.justification, "Contains sensitive physics measurements");
    }

    #[test]
    fn test_declassification_policy_validity() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Create a valid policy
        let policy = DeclassificationPolicy::new(
            "policy-001".to_string(),
            1,
            "reward_value".to_string(),
            ClassificationLevel::SensitiveReward,
            ClassificationLevel::Unrestricted,
            Some("hash_sha256".to_string()),
            vec![Principal::Audit, Principal::Policy],
            now - 1000,  // Effective in past
            Some(now + 1000),  // Expires in future
        );

        // Policy should be valid at current time
        assert!(policy.is_valid(now));

        // Policy should not be valid before effective time
        assert!(!policy.is_valid(now - 2000));

        // Policy should not be valid after expiration
        assert!(!policy.is_valid(now + 2000));
    }

    #[test]
    fn test_declassification_policy_approval_chain() {
        let policy = DeclassificationPolicy::new(
            "policy-002".to_string(),
            1,
            "field".to_string(),
            ClassificationLevel::PrivilegedTelemetry,
            ClassificationLevel::Unrestricted,
            None,
            vec![Principal::Audit, Principal::Sealer],
            1000,
            None,
        );

        assert!(policy.is_approved_by(Principal::Audit));
        assert!(policy.is_approved_by(Principal::Sealer));
        assert!(!policy.is_approved_by(Principal::Policy));
    }

    #[test]
    fn test_declassification_record_creation() {
        let original = b"sensitive_value";
        let declassified = b"hashed_value";

        let record = DeclassificationRecord::new(
            "record-001".to_string(),
            "field_name".to_string(),
            compute_hash(original),
            compute_hash(declassified),
            "policy-001".to_string(),
            Principal::Audit,
            1000,
            vec![],
        );

        assert_eq!(record.record_id, "record-001");
        assert_eq!(record.field_name, "field_name");
        assert_eq!(record.policy_id, "policy-001");
        assert_eq!(record.applied_by, Principal::Audit);
        assert_eq!(record.timestamp_ns, 1000);
        assert!(record.lineage.is_empty());
    }

    #[test]
    fn test_declassification_record_lineage() {
        let record = DeclassificationRecord::new(
            "record-002".to_string(),
            "field".to_string(),
            compute_hash(b"value1"),
            compute_hash(b"value2"),
            "policy-001".to_string(),
            Principal::Declassifier,
            1000,
            vec!["record-001".to_string(), "record-000".to_string()],
        );

        assert_eq!(record.lineage.len(), 2);
        assert_eq!(record.lineage[0], "record-001");
        assert_eq!(record.lineage[1], "record-000");
    }

    #[test]
    fn test_classification_registry_apply_label() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );
        let registry = ClassificationRegistry::new(ledger);

        let label = registry.apply_classification(
            "physics_data".to_string(),
            ClassificationLevel::PrivilegedTelemetry,
            Principal::Developer,
            1000,
            "Physics probe output".to_string(),
        );

        assert_eq!(label.field_name, "physics_data");
        assert_eq!(label.level, ClassificationLevel::PrivilegedTelemetry);

        // Verify retrieval
        let retrieved = registry.get_label("physics_data").unwrap();
        assert_eq!(retrieved.field_name, "physics_data");
    }

    #[test]
    fn test_classification_registry_policy_registration() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );
        let registry = ClassificationRegistry::new(ledger);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Register a valid policy
        let result = registry.register_policy(
            "policy-003".to_string(),
            1,
            "reward".to_string(),
            ClassificationLevel::SensitiveReward,
            ClassificationLevel::Unrestricted,
            Some("aggregate_mean".to_string()),
            vec![Principal::Audit, Principal::Policy],
            now,
            None,
        );

        assert!(result.is_ok());
        let policy = result.unwrap();
        assert_eq!(policy.policy_id, "policy-003");
        assert_eq!(policy.version, 1);

        // Verify retrieval
        let retrieved = registry.get_policy("policy-003").unwrap();
        assert_eq!(retrieved.field_name, "reward");
    }

    #[test]
    fn test_classification_registry_policy_validation() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );
        let registry = ClassificationRegistry::new(ledger);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Test: require at least 2 approvals
        let result = registry.register_policy(
            "policy-bad-1".to_string(),
            1,
            "field".to_string(),
            ClassificationLevel::SensitiveReward,
            ClassificationLevel::Unrestricted,
            None,
            vec![Principal::Audit],  // Only 1 approval
            now,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("2 approvals"));

        // Test: source must be more restrictive than target
        let result = registry.register_policy(
            "policy-bad-2".to_string(),
            1,
            "field".to_string(),
            ClassificationLevel::Unrestricted,  // Less restrictive
            ClassificationLevel::Internal,      // More restrictive
            None,
            vec![Principal::Audit, Principal::Policy],
            now,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_classification_registry_record_declassification() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );
        let registry = ClassificationRegistry::new(ledger);

        let original = b"sensitive_reward_value";
        let declassified = b"hashed_reward";

        let record = registry.record_declassification(
            "reward".to_string(),
            compute_hash(original),
            compute_hash(declassified),
            "policy-001".to_string(),
            Principal::Declassifier,
            1000,
            vec![],
        );

        assert_eq!(record.field_name, "reward");
        assert_eq!(record.policy_id, "policy-001");

        // Verify history
        let history = registry.get_declassification_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].record_id, record.record_id);
    }

    #[test]
    fn test_classification_registry_statistics() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );
        let registry = ClassificationRegistry::new(ledger);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Add some classifications and records
        registry.apply_classification(
            "field1".to_string(),
            ClassificationLevel::PrivilegedTelemetry,
            Principal::Developer,
            now,
            "Test".to_string(),
        );

        registry.apply_classification(
            "field2".to_string(),
            ClassificationLevel::SensitiveReward,
            Principal::Developer,
            now,
            "Test".to_string(),
        );

        let _ = registry.register_policy(
            "policy-1".to_string(),
            1,
            "field1".to_string(),
            ClassificationLevel::PrivilegedTelemetry,
            ClassificationLevel::Unrestricted,
            None,
            vec![Principal::Audit, Principal::Policy],
            now,
            None,
        );

        registry.record_declassification(
            "field1".to_string(),
            compute_hash(b"value1"),
            compute_hash(b"value2"),
            "policy-1".to_string(),
            Principal::Audit,
            now,
            vec![],
        );

        let (labels, policies, records) = registry.statistics();
        assert_eq!(labels, 2);
        assert_eq!(policies, 1);
        assert_eq!(records, 1);
    }
}
