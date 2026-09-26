// Evidence Manifest: Artifact registry and sealing proof
// Sprint 1, Task 1.1: Evidence Manifest Structure (SEC-C02)

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use crate::types::Principal;

/// Type of artifact in evidence bundle
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArtifactType {
    SecurityLedger,
    PolicySnapshot,
    ConfigSnapshot,
    ExperimentManifest,
    RewardLog,
    TransitionLog,
    AuditLog,
    EvaluatorReport,
    PhysicsProbeData,
    CustomMetadata,
}

impl ArtifactType {
    /// Human-readable description of artifact type
    pub fn description(&self) -> &'static str {
        match self {
            ArtifactType::SecurityLedger => "Append-only security event log with hash chain",
            ArtifactType::PolicySnapshot => "Frozen policy/model state at run start",
            ArtifactType::ConfigSnapshot => "Configuration parameters frozen before run",
            ArtifactType::ExperimentManifest => "Experiment definition with seeds and stopping rules",
            ArtifactType::RewardLog => "Declassified reward/outcome records",
            ArtifactType::TransitionLog => "Learner state transitions (policy-safe only)",
            ArtifactType::AuditLog => "Privileged telemetry and audit events",
            ArtifactType::EvaluatorReport => "Gate evaluator decision and evidence summary",
            ArtifactType::PhysicsProbeData => "Privileged physics/geometry telemetry",
            ArtifactType::CustomMetadata => "Run-specific metadata or custom artifact",
        }
    }
}

/// Reference to a single artifact in evidence bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// Filename or logical ID of artifact (relative to evidence directory)
    pub artifact_id: String,

    /// Type of artifact
    pub artifact_type: ArtifactType,

    /// SHA-256 hash of artifact file
    pub file_hash: [u8; 32],

    /// Size in bytes
    pub size_bytes: u64,

    /// Principal that created/wrote the artifact
    pub created_by: Principal,

    /// Timestamp when artifact was created (nanoseconds since UNIX_EPOCH)
    pub created_timestamp_ns: u64,

    /// Human-readable description
    pub description: String,
}

impl ArtifactRef {
    /// Create a new artifact reference
    pub fn new(
        artifact_id: String,
        artifact_type: ArtifactType,
        file_hash: [u8; 32],
        size_bytes: u64,
        created_by: Principal,
        description: String,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let created_timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        ArtifactRef {
            artifact_id,
            artifact_type,
            file_hash,
            size_bytes,
            created_by,
            created_timestamp_ns,
            description,
        }
    }
}

/// Complete evidence bundle manifest
/// Signed and sealed by SealerPrincipal; verified by Gate I auditor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceManifest {
    /// Unique identifier for this evidence bundle (UUID)
    pub bundle_id: String,

    /// Run ID from episode controller
    pub run_id: String,

    /// Boot ID (identifies host/environment)
    pub boot_id: String,

    /// Epoch ID (identifies training/evaluation epoch)
    pub epoch_id: String,

    /// When manifest was created (before sealing)
    pub created_timestamp_ns: u64,

    /// When manifest was sealed (signature applied)
    pub sealed_timestamp_ns: u64,

    /// All artifacts included in evidence bundle
    pub artifacts: Vec<ArtifactRef>,

    /// SHA-256 hash of policy/model snapshot at run start
    pub policy_snapshot_hash: [u8; 32],

    /// SHA-256 hash of configuration snapshot
    pub config_snapshot_hash: [u8; 32],

    /// Merkle root hash of all events in SecurityLedger
    pub event_root_hash: [u8; 32],

    /// Principal that signed/sealed the manifest
    pub sealer_principal: Principal,

    /// Ed25519 signature over manifest (created by SealerPrincipal via HSM)
    pub seal_signature: [u8; 64],

    /// When seal was applied (trusted timestamp)
    pub seal_timestamp_ns: u64,

    /// Optional: Git commit hash of source code used (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_commit_hash: Option<String>,

    /// Optional: References Gate I decision that accepted this evidence
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_decision_id: Option<String>,
}

impl EvidenceManifest {
    /// Create new unsigned manifest (before sealing)
    pub fn new(
        bundle_id: String,
        run_id: String,
        boot_id: String,
        epoch_id: String,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        EvidenceManifest {
            bundle_id,
            run_id,
            boot_id,
            epoch_id,
            created_timestamp_ns: timestamp_ns,
            sealed_timestamp_ns: 0,
            artifacts: Vec::new(),
            policy_snapshot_hash: [0u8; 32],
            config_snapshot_hash: [0u8; 32],
            event_root_hash: [0u8; 32],
            sealer_principal: Principal::Supervisor,
            seal_signature: [0u8; 64],
            seal_timestamp_ns: 0,
            source_commit_hash: None,
            gate_decision_id: None,
        }
    }

    /// Add artifact to manifest
    pub fn add_artifact(&mut self, artifact: ArtifactRef) {
        self.artifacts.push(artifact);
    }

    /// Get count of artifacts in manifest
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }

    /// Calculate hash of manifest (for signing)
    /// Excludes seal_signature and sealed_timestamp_ns to create deterministic hash
    pub fn calculate_hash(&self) -> [u8; 32] {
        // Create copy with signature zeroed for hashing
        let mut unsigned = self.clone();
        unsigned.seal_signature = [0u8; 64];
        unsigned.sealed_timestamp_ns = 0;

        let json = serde_json::to_string(&unsigned)
            .expect("manifest serialization should not fail");

        let mut hasher = Sha256::new();
        hasher.update(json);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify manifest hash is consistent (for integrity checking)
    pub fn verify_hash(&self, expected_hash: [u8; 32]) -> bool {
        self.calculate_hash() == expected_hash
    }

    /// Get total size of all artifacts (bytes)
    pub fn total_artifact_size(&self) -> u64 {
        self.artifacts.iter().map(|a| a.size_bytes).sum()
    }

    /// Get artifact by ID
    pub fn get_artifact(&self, artifact_id: &str) -> Option<&ArtifactRef> {
        self.artifacts.iter().find(|a| a.artifact_id == artifact_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_ref_creation() {
        let artifact = ArtifactRef::new(
            "test.txt".to_string(),
            ArtifactType::CustomMetadata,
            [0xAAu8; 32],
            1024,
            Principal::Audit,
            "Test artifact".to_string(),
        );

        assert_eq!(artifact.artifact_id, "test.txt");
        assert_eq!(artifact.artifact_type, ArtifactType::CustomMetadata);
        assert_eq!(artifact.size_bytes, 1024);
        assert!(artifact.created_timestamp_ns > 0);
    }

    #[test]
    fn test_manifest_creation() {
        let manifest = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );

        assert_eq!(manifest.bundle_id, "bundle-001");
        assert_eq!(manifest.run_id, "run-001");
        assert_eq!(manifest.boot_id, "boot-001");
        assert_eq!(manifest.epoch_id, "epoch-001");
        assert_eq!(manifest.artifact_count(), 0);
        assert_eq!(manifest.seal_signature, [0u8; 64]);
    }

    #[test]
    fn test_manifest_add_artifact() {
        let mut manifest = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );

        let artifact = ArtifactRef::new(
            "ledger.jsonl".to_string(),
            ArtifactType::SecurityLedger,
            [0xBBu8; 32],
            5000,
            Principal::Audit,
            "Security ledger".to_string(),
        );

        manifest.add_artifact(artifact);
        assert_eq!(manifest.artifact_count(), 1);
        assert!(manifest.get_artifact("ledger.jsonl").is_some());
    }

    #[test]
    fn test_manifest_hash_consistency() {
        let mut manifest = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );

        let artifact = ArtifactRef::new(
            "test.txt".to_string(),
            ArtifactType::CustomMetadata,
            [0xCCu8; 32],
            512,
            Principal::Audit,
            "Test".to_string(),
        );

        manifest.add_artifact(artifact);
        manifest.policy_snapshot_hash = [0xDDu8; 32];
        manifest.config_snapshot_hash = [0xEEu8; 32];
        manifest.event_root_hash = [0xFFu8; 32];

        // Hash should be consistent across multiple calls
        let hash1 = manifest.calculate_hash();
        let hash2 = manifest.calculate_hash();

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]); // Should not be zero hash
    }

    #[test]
    fn test_manifest_hash_changes_with_content() {
        let mut manifest1 = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );
        manifest1.policy_snapshot_hash = [0xAAu8; 32];

        let mut manifest2 = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );
        manifest2.policy_snapshot_hash = [0xBBu8; 32];

        let hash1 = manifest1.calculate_hash();
        let hash2 = manifest2.calculate_hash();

        // Different content should produce different hash
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_manifest_serialization() {
        let mut manifest = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );

        let artifact = ArtifactRef::new(
            "test.bin".to_string(),
            ArtifactType::PhysicsProbeData,
            [0x99u8; 32],
            1024,
            Principal::Developer,
            "Physics data".to_string(),
        );

        manifest.add_artifact(artifact);
        manifest.seal_signature = [0x77u8; 64];

        // Serialize to JSON
        let json = serde_json::to_string(&manifest).unwrap();

        // Deserialize back
        let deserialized: EvidenceManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.bundle_id, manifest.bundle_id);
        assert_eq!(deserialized.artifact_count(), 1);
        assert_eq!(deserialized.seal_signature, [0x77u8; 64]);
    }

    #[test]
    fn test_artifact_type_descriptions() {
        assert!(!ArtifactType::SecurityLedger.description().is_empty());
        assert!(!ArtifactType::PolicySnapshot.description().is_empty());
        assert!(!ArtifactType::EvaluatorReport.description().is_empty());
    }

    #[test]
    fn test_manifest_total_artifact_size() {
        let mut manifest = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );

        for i in 0..3 {
            let artifact = ArtifactRef::new(
                format!("file{}.bin", i),
                ArtifactType::CustomMetadata,
                [i as u8; 32],
                1000 * (i + 1) as u64,
                Principal::Audit,
                format!("File {}", i),
            );
            manifest.add_artifact(artifact);
        }

        // Total: 1000 + 2000 + 3000 = 6000
        assert_eq!(manifest.total_artifact_size(), 6000);
    }
}
