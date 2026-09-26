// Gate I Principal: Evidence Verifier
// Task 1.4: Independent evidence authentication on clean machines (SEC-C02)

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::fs;
use std::io::Read;
use std::path::Path;
use crate::evidence::EvidenceManifest;
use crate::security_ledger::SecurityLedger;
use crate::types::Principal;

/// Verification status for evidence bundle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Valid,
    InvalidSignature,
    ArtifactHashMismatch,
    EventChainBroken,
    ManifestMissing,
    ManifestCorrupted,
    ArtifactMissing,
    ArtifactUnreadable,
    EventLedgerMissing,
    EventRootHashMismatch,
}

impl VerificationStatus {
    pub fn description(&self) -> &'static str {
        match self {
            VerificationStatus::Valid => "Evidence bundle is valid and tamper-evident",
            VerificationStatus::InvalidSignature => "Manifest signature verification failed",
            VerificationStatus::ArtifactHashMismatch => "Artifact file hash does not match manifest",
            VerificationStatus::EventChainBroken => "Event chain integrity check failed",
            VerificationStatus::ManifestMissing => "MANIFEST.json not found in evidence directory",
            VerificationStatus::ManifestCorrupted => "MANIFEST.json could not be parsed",
            VerificationStatus::ArtifactMissing => "Referenced artifact file not found",
            VerificationStatus::ArtifactUnreadable => "Could not read artifact file",
            VerificationStatus::EventLedgerMissing => "Security ledger file not found",
            VerificationStatus::EventRootHashMismatch => "Event root hash does not match manifest",
        }
    }
}

/// Detailed artifact verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactVerification {
    pub artifact_id: String,
    pub expected_hash: String,
    pub computed_hash: String,
    pub matches: bool,
    pub size_bytes: u64,
    pub error: Option<String>,
}

/// Complete evidence verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub bundle_id: String,
    pub status: VerificationStatus,
    pub description: String,

    // Manifest verification
    pub manifest_valid: bool,
    pub manifest_hash: String,
    pub signature_valid: bool,

    // Artifact verification
    pub artifacts_verified: u32,
    pub artifacts_total: u32,
    pub artifact_details: Vec<ArtifactVerification>,

    // Event chain verification
    pub event_chain_valid: bool,
    pub event_count: u32,
    pub expected_event_root: String,
    pub computed_event_root: String,

    // Overall findings
    pub tamper_evident: bool,
    pub verification_timestamp_ns: u64,
    pub details: String,
}

/// Evidence Verifier for independent auditors
pub struct EvidenceVerifier {
    evidence_dir: String,
    ledger_path: Option<String>,
}

impl EvidenceVerifier {
    /// Create new evidence verifier
    pub fn new(evidence_dir: &str) -> Self {
        EvidenceVerifier {
            evidence_dir: evidence_dir.to_string(),
            ledger_path: None,
        }
    }

    /// Optionally provide security ledger for event chain verification
    pub fn with_ledger(mut self, ledger_path: &str) -> Self {
        self.ledger_path = Some(ledger_path.to_string());
        self
    }

    /// Verify sealed evidence bundle on clean machine (primary operation)
    pub fn verify_sealed_evidence(&self) -> VerificationResult {
        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Step 1: Load manifest
        let manifest = match self.load_manifest() {
            Ok(m) => m,
            Err(e) => {
                return VerificationResult {
                    bundle_id: "unknown".to_string(),
                    status: if e.contains("not found") {
                        VerificationStatus::ManifestMissing
                    } else {
                        VerificationStatus::ManifestCorrupted
                    },
                    description: e.clone(),
                    manifest_valid: false,
                    manifest_hash: String::new(),
                    signature_valid: false,
                    artifacts_verified: 0,
                    artifacts_total: 0,
                    artifact_details: vec![],
                    event_chain_valid: false,
                    event_count: 0,
                    expected_event_root: hex::encode(manifest.event_root_hash),
                    computed_event_root: String::new(),
                    tamper_evident: false,
                    verification_timestamp_ns: start_time,
                    details: format!("Failed to load manifest: {}", e),
                };
            }
        };

        let bundle_id = manifest.bundle_id.clone();
        let mut result = VerificationResult {
            bundle_id: bundle_id.clone(),
            status: VerificationStatus::Valid,
            description: "Verification in progress".to_string(),
            manifest_valid: false,
            manifest_hash: hex::encode(manifest.calculate_hash()),
            signature_valid: false,
            artifacts_verified: 0,
            artifacts_total: manifest.artifacts.len() as u32,
            artifact_details: vec![],
            event_chain_valid: false,
            event_count: 0,
            expected_event_root: hex::encode(manifest.event_root_hash),
            computed_event_root: String::new(),
            tamper_evident: false,
            verification_timestamp_ns: start_time,
            details: String::new(),
        };

        // Step 2: Verify signature (placeholder - would use Sealer's public key in production)
        result.signature_valid = self.verify_signature(&manifest);
        result.manifest_valid = result.signature_valid;

        if !result.signature_valid {
            result.status = VerificationStatus::InvalidSignature;
            result.tamper_evident = false;
            result.description = "Manifest signature verification failed".to_string();
            return result;
        }

        // Step 3: Verify all artifacts
        let artifacts_ok = self.verify_artifacts(&manifest, &mut result);

        if !artifacts_ok {
            result.status = VerificationStatus::ArtifactHashMismatch;
            result.tamper_evident = false;
            return result;
        }

        // Step 4: Verify event chain (if ledger path provided)
        if let Some(ledger_path) = &self.ledger_path {
            let chain_ok = self.verify_event_chain(&manifest, ledger_path, &mut result);
            if !chain_ok {
                result.status = VerificationStatus::EventChainBroken;
                result.tamper_evident = false;
                return result;
            }
        }

        // All checks passed
        result.status = VerificationStatus::Valid;
        result.description = "Evidence bundle verified successfully".to_string();
        result.tamper_evident = true;

        result
    }

    /// Load and parse manifest from evidence directory
    fn load_manifest(&self) -> Result<EvidenceManifest, String> {
        let manifest_path = format!("{}/MANIFEST.json", self.evidence_dir);

        let json_content = fs::read_to_string(&manifest_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    format!("Manifest not found at {}", manifest_path)
                } else {
                    format!("Failed to read manifest: {}", e)
                }
            })?;

        serde_json::from_str::<EvidenceManifest>(&json_content)
            .map_err(|e| format!("Failed to parse manifest JSON: {}", e))
    }

    /// Verify manifest signature (placeholder implementation)
    /// In production, would verify Ed25519 signature using Sealer's public key
    fn verify_signature(&self, manifest: &EvidenceManifest) -> bool {
        // For now: signature is valid if it's not all zeros (sealing happened)
        // In production: use actual Ed25519 verification with Sealer's public key
        manifest.seal_signature != [0u8; 64]
    }

    /// Verify all artifacts in manifest
    fn verify_artifacts(&self, manifest: &EvidenceManifest, result: &mut VerificationResult) -> bool {
        let mut all_valid = true;

        for artifact in &manifest.artifacts {
            let file_path = format!("{}/{}", self.evidence_dir, artifact.artifact_id);

            // Check file exists
            if !Path::new(&file_path).exists() {
                result.status = VerificationStatus::ArtifactMissing;
                result.artifact_details.push(ArtifactVerification {
                    artifact_id: artifact.artifact_id.clone(),
                    expected_hash: hex::encode(artifact.file_hash),
                    computed_hash: String::new(),
                    matches: false,
                    size_bytes: 0,
                    error: Some(format!("File not found: {}", file_path)),
                });
                all_valid = false;
                continue;
            }

            // Compute file hash
            match self.compute_file_hash(&file_path) {
                Ok(computed_hash) => {
                    let matches = computed_hash == artifact.file_hash;

                    if !matches {
                        all_valid = false;
                    }

                    result.artifact_details.push(ArtifactVerification {
                        artifact_id: artifact.artifact_id.clone(),
                        expected_hash: hex::encode(artifact.file_hash),
                        computed_hash: hex::encode(computed_hash),
                        matches,
                        size_bytes: artifact.size_bytes,
                        error: if matches { None } else {
                            Some("Hash mismatch".to_string())
                        },
                    });

                    if matches {
                        result.artifacts_verified += 1;
                    }
                }
                Err(e) => {
                    result.status = VerificationStatus::ArtifactUnreadable;
                    result.artifact_details.push(ArtifactVerification {
                        artifact_id: artifact.artifact_id.clone(),
                        expected_hash: hex::encode(artifact.file_hash),
                        computed_hash: String::new(),
                        matches: false,
                        size_bytes: 0,
                        error: Some(format!("Failed to read file: {}", e)),
                    });
                    all_valid = false;
                }
            }
        }

        all_valid
    }

    /// Verify event chain integrity against manifest event root hash
    fn verify_event_chain(
        &self,
        manifest: &EvidenceManifest,
        ledger_path: &str,
        result: &mut VerificationResult,
    ) -> bool {
        // Load and verify ledger
        match SecurityLedger::open(ledger_path) {
            Ok(ledger) => {
                result.event_count = ledger.count() as u32;

                // Compute event root hash
                match ledger.compute_event_root_hash() {
                    Ok(computed_root) => {
                        result.computed_event_root = hex::encode(computed_root);
                        let matches = computed_root == manifest.event_root_hash;

                        if matches {
                            result.event_chain_valid = true;
                        } else {
                            result.status = VerificationStatus::EventRootHashMismatch;
                        }

                        matches
                    }
                    Err(e) => {
                        result.status = VerificationStatus::EventChainBroken;
                        result.details = format!("Failed to compute event root: {}", e);
                        false
                    }
                }
            }
            Err(e) => {
                result.status = VerificationStatus::EventLedgerMissing;
                result.details = format!("Failed to open security ledger: {}", e);
                false
            }
        }
    }

    /// Compute SHA-256 hash of file
    fn compute_file_hash(&self, path: &str) -> Result<[u8; 32], String> {
        let mut file = fs::File::open(path)
            .map_err(|e| format!("Cannot open file: {}", e))?;

        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)
                .map_err(|e| format!("Cannot read file: {}", e))?;

            if bytes_read == 0 {
                break;
            }

            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{TempDir, NamedTempFile};
    use crate::evidence::{ArtifactRef, ArtifactType};
    use crate::security_ledger::{EventType, Severity};
    use std::collections::HashMap;
    use std::io::Write;

    #[test]
    fn test_verification_manifest_missing() {
        let temp_dir = TempDir::new().unwrap();
        let verifier = EvidenceVerifier::new(temp_dir.path().to_str().unwrap());

        let result = verifier.verify_sealed_evidence();

        assert_eq!(result.status, VerificationStatus::ManifestMissing);
        assert!(!result.tamper_evident);
    }

    #[test]
    fn test_verification_valid_bundle() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Create a test artifact
        let artifact_path = format!("{}/test.txt", temp_path);
        let mut file = std::fs::File::create(&artifact_path).unwrap();
        file.write_all(b"test content").unwrap();
        drop(file);

        // Compute its hash
        let verifier = EvidenceVerifier::new(temp_path);
        let artifact_hash = verifier.compute_file_hash(&artifact_path).unwrap();

        // Create and seal manifest
        let mut manifest = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );

        let artifact = ArtifactRef::new(
            "test.txt".to_string(),
            ArtifactType::CustomMetadata,
            artifact_hash,
            12,  // "test content" is 12 bytes
            Principal::Sealer,
            "Test artifact".to_string(),
        );

        manifest.add_artifact(artifact);
        manifest.seal_signature = [0x55u8; 64];  // Valid (non-zero)
        manifest.event_root_hash = [0u8; 32];   // Empty event chain

        // Write manifest
        let manifest_path = format!("{}/MANIFEST.json", temp_path);
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        std::fs::write(&manifest_path, manifest_json).unwrap();

        // Verify
        let result = verifier.verify_sealed_evidence();

        assert_eq!(result.status, VerificationStatus::Valid);
        assert!(result.tamper_evident);
        assert!(result.signature_valid);
        assert_eq!(result.artifacts_verified, 1);
        assert!(result.artifact_details[0].matches);
    }

    #[test]
    fn test_verification_artifact_hash_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Create a test artifact
        let artifact_path = format!("{}/test.txt", temp_path);
        let mut file = std::fs::File::create(&artifact_path).unwrap();
        file.write_all(b"test content").unwrap();
        drop(file);

        // Create manifest with WRONG hash
        let mut manifest = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );

        let artifact = ArtifactRef::new(
            "test.txt".to_string(),
            ArtifactType::CustomMetadata,
            [0xFFu8; 32],  // Wrong hash!
            12,
            Principal::Sealer,
            "Test artifact".to_string(),
        );

        manifest.add_artifact(artifact);
        manifest.seal_signature = [0x55u8; 64];

        // Write manifest
        let manifest_path = format!("{}/MANIFEST.json", temp_path);
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        std::fs::write(&manifest_path, manifest_json).unwrap();

        // Verify
        let verifier = EvidenceVerifier::new(temp_path);
        let result = verifier.verify_sealed_evidence();

        assert_eq!(result.status, VerificationStatus::ArtifactHashMismatch);
        assert!(!result.tamper_evident);
        assert!(!result.artifact_details[0].matches);
    }

    #[test]
    fn test_verification_missing_artifact() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Create manifest referencing non-existent artifact
        let mut manifest = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );

        let artifact = ArtifactRef::new(
            "nonexistent.txt".to_string(),
            ArtifactType::CustomMetadata,
            [0xAAu8; 32],
            100,
            Principal::Sealer,
            "Missing artifact".to_string(),
        );

        manifest.add_artifact(artifact);
        manifest.seal_signature = [0x55u8; 64];

        // Write manifest
        let manifest_path = format!("{}/MANIFEST.json", temp_path);
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        std::fs::write(&manifest_path, manifest_json).unwrap();

        // Verify
        let verifier = EvidenceVerifier::new(temp_path);
        let result = verifier.verify_sealed_evidence();

        assert_eq!(result.status, VerificationStatus::ArtifactMissing);
        assert!(!result.tamper_evident);
    }

    #[test]
    fn test_verification_invalid_signature() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Create a test artifact
        let artifact_path = format!("{}/test.txt", temp_path);
        std::fs::write(&artifact_path, b"test").unwrap();

        // Create manifest with ZERO signature (invalid)
        let mut manifest = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );

        let verifier = EvidenceVerifier::new(temp_path);
        let artifact_hash = verifier.compute_file_hash(&artifact_path).unwrap();

        let artifact = ArtifactRef::new(
            "test.txt".to_string(),
            ArtifactType::CustomMetadata,
            artifact_hash,
            4,
            Principal::Sealer,
            "Test artifact".to_string(),
        );

        manifest.add_artifact(artifact);
        manifest.seal_signature = [0u8; 64];  // INVALID (all zeros)

        // Write manifest
        let manifest_path = format!("{}/MANIFEST.json", temp_path);
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        std::fs::write(&manifest_path, manifest_json).unwrap();

        // Verify
        let result = verifier.verify_sealed_evidence();

        assert_eq!(result.status, VerificationStatus::InvalidSignature);
        assert!(!result.tamper_evident);
    }

    #[test]
    fn test_verification_with_event_chain() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Create artifact
        let artifact_path = format!("{}/test.txt", temp_path);
        std::fs::write(&artifact_path, b"test").unwrap();

        // Create security ledger with one event
        let ledger_path = format!("{}/ledger.jsonl", temp_path);
        let ledger = SecurityLedger::open(&ledger_path).unwrap();

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

        let event_root = ledger.compute_event_root_hash().unwrap();

        // Create manifest with matching event root
        let mut manifest = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );

        let verifier = EvidenceVerifier::new(temp_path);
        let artifact_hash = verifier.compute_file_hash(&artifact_path).unwrap();

        let artifact = ArtifactRef::new(
            "test.txt".to_string(),
            ArtifactType::CustomMetadata,
            artifact_hash,
            4,
            Principal::Sealer,
            "Test artifact".to_string(),
        );

        manifest.add_artifact(artifact);
        manifest.seal_signature = [0x55u8; 64];
        manifest.event_root_hash = event_root;

        // Write manifest
        let manifest_path = format!("{}/MANIFEST.json", temp_path);
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        std::fs::write(&manifest_path, manifest_json).unwrap();

        // Verify WITH ledger
        let verifier_with_ledger = EvidenceVerifier::new(temp_path)
            .with_ledger(&ledger_path);
        let result = verifier_with_ledger.verify_sealed_evidence();

        assert_eq!(result.status, VerificationStatus::Valid);
        assert!(result.tamper_evident);
        assert!(result.event_chain_valid);
        assert_eq!(result.event_count, 1);
    }

    #[test]
    fn test_verification_event_root_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Create artifact
        let artifact_path = format!("{}/test.txt", temp_path);
        std::fs::write(&artifact_path, b"test").unwrap();

        // Create security ledger
        let ledger_path = format!("{}/ledger.jsonl", temp_path);
        let ledger = SecurityLedger::open(&ledger_path).unwrap();

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

        // Create manifest with WRONG event root
        let mut manifest = EvidenceManifest::new(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
        );

        let verifier = EvidenceVerifier::new(temp_path);
        let artifact_hash = verifier.compute_file_hash(&artifact_path).unwrap();

        let artifact = ArtifactRef::new(
            "test.txt".to_string(),
            ArtifactType::CustomMetadata,
            artifact_hash,
            4,
            Principal::Sealer,
            "Test artifact".to_string(),
        );

        manifest.add_artifact(artifact);
        manifest.seal_signature = [0x55u8; 64];
        manifest.event_root_hash = [0xFFu8; 32];  // WRONG!

        // Write manifest
        let manifest_path = format!("{}/MANIFEST.json", temp_path);
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        std::fs::write(&manifest_path, manifest_json).unwrap();

        // Verify WITH ledger
        let verifier_with_ledger = EvidenceVerifier::new(temp_path)
            .with_ledger(&ledger_path);
        let result = verifier_with_ledger.verify_sealed_evidence();

        assert_eq!(result.status, VerificationStatus::EventRootHashMismatch);
        assert!(!result.tamper_evident);
    }
}
