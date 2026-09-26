# Sprint 1: Evidence Authenticity & Sealing
**Duration:** Week 1 (2-3 sprint days, ~40-60 hours)  
**Objective:** Implement cryptographic evidence sealing to resolve SEC-C02 CRITICAL finding  
**Owner:** SealerPrincipal integration team  
**Blocking Gate:** Gate I (evidence audit)

---

## Overview

SEC-C02 requires evidence bundles to be authenticated by a sealing authority separate from control/learner processes. The SecurityLedger currently provides hash-chain integrity but lacks:
- Cryptographic signing of final evidence
- Immutability enforcement (read-only directories)
- Evidence bundle manifest with artifact registry
- Tamper-evident event streams

This sprint implements a complete evidence sealing pipeline that allows independent auditors to verify evidence authenticity on a clean machine without trusting the run directory.

---

## Architecture

### New Components

```
┌─────────────────────────────────────────────────────────┐
│                   Evidence Bundle                        │
│  ┌──────────────────────────────────────────────────┐   │
│  │ EvidenceManifest                                 │   │
│  │  - bundle_id: String (UUID)                      │   │
│  │  - run_id: String                                │   │
│  │  - epoch_id: String                              │   │
│  │  - created_timestamp_ns: u64                     │   │
│  │  - sealed_timestamp_ns: u64                      │   │
│  │  - artifacts: Vec<ArtifactRef>                   │   │
│  │  - policy_snapshot_hash: [u8; 32]               │   │
│  │  - config_snapshot_hash: [u8; 32]               │   │
│  │  - event_root_hash: [u8; 32]                    │   │
│  │  - sealer_principal: Principal                  │   │
│  │  - seal_signature: [u8; 64] (Ed25519)          │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │ ArtifactRef (for each artifact)                  │   │
│  │  - artifact_id: String (filename or path)        │   │
│  │  - artifact_type: ArtifactType enum              │   │
│  │  - file_hash: [u8; 32] (SHA-256)                │   │
│  │  - size_bytes: u64                               │   │
│  │  - created_by: Principal                         │   │
│  │  - created_timestamp_ns: u64                     │   │
│  │  - description: String                           │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │ SecurityLedger (append-only events)              │   │
│  │  - Event hash chain (existing)                   │   │
│  │  - Event root hash (Merkle root of all events)  │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │ Seal Proof                                       │   │
│  │  - manifest_hash: [u8; 32]                       │   │
│  │  - sealed_by: Principal (Sealer)                 │   │
│  │  - sealed_timestamp_ns: u64 (TSA or trusted)    │   │
│  │  - signature: [u8; 64] (Ed25519 from HSM)       │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

```
Run Execution
    │
    ├─> Policy Agent creates actions
    │   └─> Logged to SecurityLedger (append-only)
    │
    ├─> Actuator executes actions
    │   └─> Logged to SecurityLedger
    │
    ├─> Audit agent correlates events
    │   └─> Logged to SecurityLedger
    │
    ├─> Declassifier generates rewards
    │   └─> Logged to SecurityLedger
    │
    └─> Run completion
        │
        ├─> Compute event root hash (Merkle tree of all events)
        │
        ├─> Collect all artifacts (SecurityLedger, policies, config, etc.)
        │
        ├─> Create EvidenceManifest with all artifact hashes
        │
        ├─> SealerPrincipal.seal_evidence():
        │   ├─> Load manifest
        │   ├─> Verify all artifact hashes match
        │   ├─> Sign manifest with HSM key
        │   └─> Create sealed evidence directory (read-only)
        │
        └─> Gate I Reviewer:
            ├─> Receive sealed evidence bundle
            ├─> Load EvidenceManifest
            ├─> Verify manifest signature with Sealer's public key
            ├─> Verify all artifact hashes in manifest
            ├─> Verify event chain integrity
            └─> Authorize publication
```

---

## Implementation Tasks

### Task 1.1: Evidence Manifest Structure
**Size:** 3-4 hours  
**Owner:** TBD  

**Create** `src/evidence/manifest.rs`:

```rust
use serde::{Deserialize, Serialize};
use crate::types::Principal;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub artifact_id: String,           // filename or logical ID
    pub artifact_type: ArtifactType,
    pub file_hash: [u8; 32],          // SHA-256
    pub size_bytes: u64,
    pub created_by: Principal,
    pub created_timestamp_ns: u64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceManifest {
    pub bundle_id: String,             // UUID unique per evidence run
    pub run_id: String,
    pub boot_id: String,
    pub epoch_id: String,
    pub created_timestamp_ns: u64,
    pub sealed_timestamp_ns: u64,      // Set when sealed
    
    pub artifacts: Vec<ArtifactRef>,   // All evidence artifacts
    
    pub policy_snapshot_hash: [u8; 32],
    pub config_snapshot_hash: [u8; 32],
    pub event_root_hash: [u8; 32],     // Merkle root of event chain
    
    pub sealer_principal: Principal,   // Principal that sealed
    pub seal_signature: [u8; 64],      // Ed25519 signature over manifest
    pub seal_timestamp_ns: u64,        // When seal was applied (TSA or trusted source)
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_commit_hash: Option<String>,  // Git commit (if applicable)
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_decision_id: Option<String>,   // References Gate I decision
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
    
    /// Calculate manifest hash (for signing)
    pub fn calculate_hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        
        // Serialize manifest with signature as zero
        let mut unsigned = self.clone();
        unsigned.seal_signature = [0u8; 64];
        unsigned.sealed_timestamp_ns = 0;
        
        let json = serde_json::to_string(&unsigned).expect("serialization failed");
        let mut hasher = Sha256::new();
        hasher.update(json);
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}
```

**Tasks:**
- [ ] Create struct definitions
- [ ] Implement `new()` constructor
- [ ] Implement `add_artifact()`
- [ ] Implement `calculate_hash()` for signing
- [ ] Add unit tests for serialization/deserialization
- [ ] Document ArtifactType enum with examples

**Acceptance:**
- Compiles without warnings
- Unit tests pass (serialization round-trip, hash consistency)

---

### Task 1.2: Event Root Hash (Merkle Tree)
**Size:** 4-5 hours  
**Owner:** TBD  

**Modify** `src/security_ledger/mod.rs`:

Add Merkle tree computation for event chain:

```rust
/// Compute Merkle root hash over all events in ledger
pub fn compute_event_root_hash(&self) -> std::io::Result<[u8; 32]> {
    use sha2::{Sha256, Digest};
    
    let file = File::open(&self.file_path)?;
    let reader = BufReader::new(file);
    let mut hashes = Vec::new();
    
    // Collect hash of each event
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            if let Ok(event) = serde_json::from_str::<SecurityEvent>(&line) {
                hashes.push(event.current_entry_hash);
            }
        }
    }
    
    // Compute Merkle root from event hashes
    Self::merkle_root(&hashes)
}

/// Compute Merkle root from list of hashes
fn merkle_root(hashes: &[[u8; 32]]) -> std::io::Result<[u8; 32]> {
    use sha2::{Sha256, Digest};
    
    if hashes.is_empty() {
        // Empty tree: return zero hash
        return Ok([0u8; 32]);
    }
    
    let mut tree = hashes.to_vec();
    
    while tree.len() > 1 {
        let mut next_level = Vec::new();
        
        // Process pairs of nodes
        for chunk in tree.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            
            if chunk.len() == 2 {
                hasher.update(&chunk[1]);
            } else {
                // Odd node: hash with itself
                hasher.update(&chunk[0]);
            }
            
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            next_level.push(hash);
        }
        
        tree = next_level;
    }
    
    Ok(tree[0])
}

/// Verify event chain integrity with Merkle proof
pub fn verify_event_chain_with_proof(&self, expected_root: [u8; 32]) -> std::io::Result<bool> {
    let computed = self.compute_event_root_hash()?;
    Ok(computed == expected_root)
}
```

**Tasks:**
- [ ] Implement `compute_event_root_hash()`
- [ ] Implement `merkle_root()` helper
- [ ] Implement `verify_event_chain_with_proof()`
- [ ] Add unit tests for Merkle tree correctness
- [ ] Test with 1, 2, 4, 8, 16+ event chains (verify proof structure)

**Acceptance:**
- Merkle tree correctly computes root hash
- Root hash is reproducible across runs
- Verification catches tampered ledger files

---

### Task 1.3: SealerPrincipal Evidence Sealing Operation
**Size:** 5-6 hours  
**Owner:** TBD  

**Modify** `src/principals/sealer.rs`:

Extend SealerPrincipal with evidence sealing contract:

```rust
use crate::evidence::manifest::{EvidenceManifest, ArtifactRef, ArtifactType};
use crate::ipc::{UniversalMessage, UniversalMessageHeader, MESSAGE_TYPE_REQUEST};
use crate::hsm::HsmClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealEvidenceRequest {
    pub run_id: String,
    pub boot_id: String,
    pub epoch_id: String,
    pub evidence_dir: String,        // Path to evidence directory
    pub artifacts: Vec<ArtifactRef>,
    pub policy_snapshot_hash: [u8; 32],
    pub config_snapshot_hash: [u8; 32],
    pub event_root_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealEvidenceResponse {
    pub bundle_id: String,
    pub manifest_hash: [u8; 32],
    pub seal_signature: [u8; 64],
    pub sealed_timestamp_ns: u64,
    pub result: SealResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SealResult {
    Success,
    VerificationFailed(String),
    SigningFailed(String),
    FileSystemError(String),
}

impl SealerPrincipal {
    /// Seal an evidence bundle with cryptographic signature
    pub async fn seal_evidence(
        &mut self,
        request: SealEvidenceRequest,
        hsm: &dyn HsmClient,
    ) -> Result<SealEvidenceResponse, String> {
        // Step 1: Verify all artifact hashes match files on disk
        for artifact in &request.artifacts {
            let file_hash = Self::compute_file_hash(&request.evidence_dir, &artifact.artifact_id)
                .map_err(|e| format!("Failed to hash artifact {}: {}", artifact.artifact_id, e))?;
            
            if file_hash != artifact.file_hash {
                return Ok(SealEvidenceResponse {
                    bundle_id: String::new(),
                    manifest_hash: [0u8; 32],
                    seal_signature: [0u8; 64],
                    sealed_timestamp_ns: 0,
                    result: SealResult::VerificationFailed(format!(
                        "Artifact {} hash mismatch: expected {}, got {}",
                        artifact.artifact_id,
                        hex::encode(artifact.file_hash),
                        hex::encode(file_hash)
                    )),
                });
            }
        }
        
        // Step 2: Create manifest
        let bundle_id = uuid::Uuid::new_v4().to_string();
        let mut manifest = EvidenceManifest::new(
            bundle_id.clone(),
            request.run_id.clone(),
            request.boot_id.clone(),
            request.epoch_id.clone(),
        );
        
        manifest.artifacts = request.artifacts;
        manifest.policy_snapshot_hash = request.policy_snapshot_hash;
        manifest.config_snapshot_hash = request.config_snapshot_hash;
        manifest.event_root_hash = request.event_root_hash;
        manifest.sealer_principal = Principal::Sealer;
        
        // Step 3: Sign manifest with HSM
        let manifest_hash = manifest.calculate_hash();
        
        let signature = hsm.sign(&manifest_hash)
            .map_err(|e| format!("HSM signing failed: {}", e))?;
        
        manifest.seal_signature = signature;
        
        use std::time::{SystemTime, UNIX_EPOCH};
        manifest.sealed_timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        
        // Step 4: Write manifest to evidence directory
        let manifest_path = format!("{}/MANIFEST.json", request.evidence_dir);
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| format!("Manifest serialization failed: {}", e))?;
        
        std::fs::write(&manifest_path, manifest_json)
            .map_err(|e| format!("Failed to write manifest: {}", e))?;
        
        // Step 5: Make evidence directory read-only (if supported on platform)
        #[cfg(unix)]
        {
            use std::fs;
            use std::os::unix::fs::PermissionsExt;
            
            let perms = fs::Permissions::from_mode(0o555);  // r-xr-xr-x
            let _ = fs::set_permissions(&request.evidence_dir, perms);
        }
        
        // Record in consistency report
        self.state.last_consistency_check = Some(ConsistencyReport {
            checked_at: manifest.sealed_timestamp_ns,
            artifacts_verified: request.artifacts.len() as u32,
            bundle_id: bundle_id.clone(),
            seal_valid: true,
            violations: Vec::new(),
        });
        
        Ok(SealEvidenceResponse {
            bundle_id,
            manifest_hash,
            seal_signature: signature,
            sealed_timestamp_ns: manifest.sealed_timestamp_ns,
            result: SealResult::Success,
        })
    }
    
    /// Compute SHA-256 hash of artifact file
    fn compute_file_hash(evidence_dir: &str, artifact_id: &str) -> std::io::Result<[u8; 32]> {
        use sha2::{Sha256, Digest};
        use std::fs::File;
        use std::io::Read;
        
        let path = format!("{}/{}", evidence_dir, artifact_id);
        let mut file = File::open(&path)?;
        let mut hasher = Sha256::new();
        
        let mut buffer = [0u8; 8192];
        loop {
            let bytes_read = file.read(&mut buffer)?;
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
```

**Tasks:**
- [ ] Define SealEvidenceRequest and SealEvidenceResponse structs
- [ ] Implement `seal_evidence()` operation
- [ ] Implement artifact hash verification
- [ ] Implement manifest creation and signing (via HSM)
- [ ] Implement manifest serialization to disk
- [ ] Implement read-only directory enforcement (Unix/Windows)
- [ ] Add error handling for all failure modes
- [ ] Add unit tests (mock HSM, test failures)

**Acceptance:**
- `seal_evidence()` creates EvidenceManifest with correct hash
- Manifest is signed with HSM key
- All artifacts are verified before sealing
- Evidence directory is marked read-only (or documented why not on platform)
- Error cases handled gracefully (bad artifact hash, HSM error, etc.)

---

### Task 1.4: Gate I Verifier (Evidence Authentication)
**Size:** 4-5 hours  
**Owner:** TBD  

**Create** `src/evidence/verifier.rs`:

```rust
use crate::evidence::manifest::EvidenceManifest;
use sha2::{Sha256, Digest};

#[derive(Debug, Clone)]
pub struct EvidenceVerifier {
    sealer_public_key: [u8; 32],  // Ed25519 public key from Sealer principal
}

#[derive(Debug, Clone, PartialEq)]
pub enum VerificationResult {
    Valid,
    InvalidSignature,
    ManifestHashMismatch,
    ArtifactHashMismatch(String),
    EventChainBroken,
    ManifestFileNotFound,
    ConfigurationMissing,
}

impl EvidenceVerifier {
    pub fn new(sealer_public_key: [u8; 32]) -> Self {
        EvidenceVerifier { sealer_public_key }
    }
    
    /// Verify sealed evidence on a clean machine (Gate I reviewer)
    pub fn verify_sealed_evidence(
        &self,
        evidence_dir: &str,
    ) -> Result<(bool, VerificationResult), String> {
        // Step 1: Load manifest
        let manifest_path = format!("{}/MANIFEST.json", evidence_dir);
        let manifest_json = std::fs::read_to_string(&manifest_path)
            .map_err(|_| VerificationResult::ManifestFileNotFound)?;
        
        let manifest: EvidenceManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| format!("Manifest parse error: {}", e))?;
        
        // Step 2: Verify manifest signature
        if !self.verify_signature(&manifest) {
            return Ok((false, VerificationResult::InvalidSignature));
        }
        
        // Step 3: Verify all artifact hashes
        for artifact in &manifest.artifacts {
            let file_hash = Self::compute_file_hash(evidence_dir, &artifact.artifact_id)
                .map_err(|e| format!("Failed to hash artifact: {}", e))?;
            
            if file_hash != artifact.file_hash {
                return Ok((
                    false,
                    VerificationResult::ArtifactHashMismatch(artifact.artifact_id.clone()),
                ));
            }
        }
        
        // Step 4: Verify event chain (if SecurityLedger is in artifacts)
        if let Some(ledger_artifact) = manifest.artifacts.iter()
            .find(|a| a.artifact_id.contains("security_ledger")) {
            
            // Verify event root hash matches
            // (Would need to re-read and verify ledger structure)
            // For now, just verify it exists
            let ledger_path = format!("{}/{}", evidence_dir, ledger_artifact.artifact_id);
            if !std::path::Path::new(&ledger_path).exists() {
                return Ok((false, VerificationResult::EventChainBroken));
            }
        }
        
        Ok((true, VerificationResult::Valid))
    }
    
    /// Verify Ed25519 signature on manifest
    fn verify_signature(&self, manifest: &EvidenceManifest) -> bool {
        use ed25519_dalek::PublicKey;
        
        // Calculate manifest hash (unsigned)
        let manifest_hash = manifest.calculate_hash();
        
        // Verify signature with public key
        let public_key = PublicKey::from_bytes(&self.sealer_public_key)
            .ok()
            .and_then(|pk| {
                let sig = ed25519_dalek::Signature::from_bytes(&manifest.seal_signature)
                    .ok()?;
                pk.verify_strict(&manifest_hash, &sig).ok()?;
                Some(true)
            });
        
        public_key.is_some()
    }
    
    fn compute_file_hash(evidence_dir: &str, artifact_id: &str) -> std::io::Result<[u8; 32]> {
        use std::fs::File;
        use std::io::Read;
        
        let path = format!("{}/{}", evidence_dir, artifact_id);
        let mut file = File::open(&path)?;
        let mut hasher = Sha256::new();
        
        let mut buffer = [0u8; 8192];
        loop {
            let bytes_read = file.read(&mut buffer)?;
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
```

**Tasks:**
- [ ] Define EvidenceVerifier structure
- [ ] Implement `verify_sealed_evidence()` operation
- [ ] Implement signature verification with ed25519-dalek
- [ ] Implement artifact hash verification
- [ ] Implement event chain verification
- [ ] Add comprehensive error reporting
- [ ] Add unit tests (valid manifest, tampered artifacts, invalid signature)

**Acceptance:**
- Verifier can independently verify sealed evidence on a clean machine
- Detects artifact tampering
- Detects signature forgery
- Provides clear verification result (Valid, InvalidSignature, etc.)

---

### Task 1.5: Integration Test Suite
**Size:** 6-8 hours  
**Owner:** TBD  

**Create** `tests/evidence_sealing_test.rs`:

```rust
use geometry_dash::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_seal_evidence_basic() {
    // Create temporary evidence directory with fake artifacts
    let temp_dir = TempDir::new().unwrap();
    let ledger_path = temp_dir.path().join("security_ledger.jsonl");
    
    // Create fake artifact
    let artifact_content = b"test artifact data";
    fs::write(temp_dir.path().join("test_artifact.bin"), artifact_content).unwrap();
    
    // Compute artifact hash
    let artifact_hash = compute_sha256(artifact_content);
    
    // Create seal request
    let request = SealEvidenceRequest {
        run_id: "run-001".to_string(),
        boot_id: "boot-001".to_string(),
        epoch_id: "epoch-001".to_string(),
        evidence_dir: temp_dir.path().to_str().unwrap().to_string(),
        artifacts: vec![
            ArtifactRef {
                artifact_id: "test_artifact.bin".to_string(),
                artifact_type: ArtifactType::CustomMetadata,
                file_hash: artifact_hash,
                size_bytes: artifact_content.len() as u64,
                created_by: Principal::Audit,
                created_timestamp_ns: 0,
                description: "Test artifact".to_string(),
            },
        ],
        policy_snapshot_hash: [0u8; 32],
        config_snapshot_hash: [0u8; 32],
        event_root_hash: [0u8; 32],
    };
    
    // Seal evidence
    let mut sealer = SealerPrincipal::new();
    let hsm = FilesystemHsmClient::new("/tmp/test_hsm").unwrap();
    
    let response = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(sealer.seal_evidence(request, &hsm))
        .unwrap();
    
    // Verify response
    assert_eq!(response.result, SealResult::Success);
    assert!(!response.bundle_id.is_empty());
    assert!(response.seal_signature != [0u8; 64]);
    
    // Verify manifest was created
    let manifest_path = temp_dir.path().join("MANIFEST.json");
    assert!(manifest_path.exists());
    
    let manifest_content = fs::read_to_string(&manifest_path).unwrap();
    let manifest: EvidenceManifest = serde_json::from_str(&manifest_content).unwrap();
    
    assert_eq!(manifest.bundle_id, response.bundle_id);
    assert_eq!(manifest.sealer_principal, Principal::Sealer);
    assert_eq!(manifest.artifacts.len(), 1);
}

#[test]
fn test_seal_evidence_artifact_tampering_detected() {
    // Similar setup, but modify artifact after sealing
    let temp_dir = TempDir::new().unwrap();
    let artifact_path = temp_dir.path().join("test_artifact.bin");
    
    let artifact_content = b"original content";
    fs::write(&artifact_path, artifact_content).unwrap();
    let original_hash = compute_sha256(artifact_content);
    
    // Seal evidence
    let request = SealEvidenceRequest {
        run_id: "run-002".to_string(),
        boot_id: "boot-002".to_string(),
        epoch_id: "epoch-002".to_string(),
        evidence_dir: temp_dir.path().to_str().unwrap().to_string(),
        artifacts: vec![
            ArtifactRef {
                artifact_id: "test_artifact.bin".to_string(),
                artifact_type: ArtifactType::CustomMetadata,
                file_hash: original_hash,
                size_bytes: artifact_content.len() as u64,
                created_by: Principal::Audit,
                created_timestamp_ns: 0,
                description: "Test artifact".to_string(),
            },
        ],
        policy_snapshot_hash: [0u8; 32],
        config_snapshot_hash: [0u8; 32],
        event_root_hash: [0u8; 32],
    };
    
    let mut sealer = SealerPrincipal::new();
    let hsm = FilesystemHsmClient::new("/tmp/test_hsm").unwrap();
    let _response = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(sealer.seal_evidence(request, &hsm))
        .unwrap();
    
    // Now tamper with artifact
    fs::write(&artifact_path, b"tampered content").unwrap();
    
    // Try to verify - should fail
    let manifest_path = temp_dir.path().join("MANIFEST.json");
    let manifest_content = fs::read_to_string(&manifest_path).unwrap();
    let manifest: EvidenceManifest = serde_json::from_str(&manifest_content).unwrap();
    
    let sealer_public_key = [0u8; 32]; // Would be real key in practice
    let verifier = EvidenceVerifier::new(sealer_public_key);
    
    let (valid, result) = verifier.verify_sealed_evidence(temp_dir.path().to_str().unwrap())
        .unwrap();
    
    assert!(!valid);
    assert_eq!(result, VerificationResult::ArtifactHashMismatch(
        "test_artifact.bin".to_string()
    ));
}

#[test]
fn test_verify_evidence_signature() {
    // Test signature verification with real manifest
    // ...
}

#[test]
fn test_event_root_hash_consistency() {
    // Create SecurityLedger with multiple events
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp_file.path().to_str().unwrap()).unwrap();
    
    // Add events
    let mut details = std::collections::HashMap::new();
    details.insert("test".to_string(), "value".to_string());
    
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
        details.clone(),
    ).unwrap();
    
    // Compute event root hash
    let root1 = ledger.compute_event_root_hash().unwrap();
    let root2 = ledger.compute_event_root_hash().unwrap();
    
    // Should be consistent
    assert_eq!(root1, root2);
    
    // Should not be zero hash (we have events)
    assert_ne!(root1, [0u8; 32]);
}

fn compute_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
```

**Tasks:**
- [ ] Create test file structure
- [ ] Implement `test_seal_evidence_basic()`
- [ ] Implement `test_seal_evidence_artifact_tampering_detected()`
- [ ] Implement `test_verify_evidence_signature()`
- [ ] Implement `test_event_root_hash_consistency()`
- [ ] Add tests for read-only enforcement
- [ ] Add tests for all error conditions (bad artifact hash, HSM error, etc.)
- [ ] Add integration test with full workflow (seal + verify on clean machine)

**Acceptance:**
- All tests pass
- >85% code coverage for sealing/verification logic
- Detects all major tampering scenarios

---

### Task 1.6: Documentation & Contracts
**Size:** 3-4 hours  
**Owner:** TBD  

**Create** `EVIDENCE_SEALING_CONTRACT.md`:

```markdown
# Evidence Sealing Contract (IF-XXX)

## Purpose
Cryptographically seal evidence bundles with tamper-detection and authenticity verification for Gate I audit.

## Message Types

### SealEvidenceRequest (IF-XXX-REQUEST)
- Caller: Control/Evaluator Agent
- Callee: SealerPrincipal
- Operation: Seal evidence bundle with HSM signature
- Fields: run_id, boot_id, epoch_id, evidence_dir, artifacts, hashes
- Data Classification: PRIVILEGED (contains evidence metadata)
- Timeout: 30s
- Retry: IDEMPOTENT (same inputs always produce same sealed bundle)
- Persistence: Evidence directory marked read-only after seal

### SealEvidenceResponse (IF-XXX-RESPONSE)
- bundle_id: UUID (unique per evidence run)
- manifest_hash: SHA-256 hash of manifest (what was signed)
- seal_signature: Ed25519 signature from HSM
- sealed_timestamp_ns: Trusted timestamp of seal operation
- result: SealResult enum (Success, VerificationFailed, SigningFailed, etc.)

## Verification Flow (Gate I)

1. Receive sealed evidence directory
2. Load MANIFEST.json from directory
3. Verify Ed25519 signature with Sealer's public key
4. Re-compute all artifact hashes; compare with manifest
5. Verify event chain integrity (Merkle root hash)
6. Return VerificationResult (Valid, InvalidSignature, ArtifactHashMismatch, etc.)

## Requirements Met

- REQ-SEC-002: Evidence authenticated by separate sealing authority ✅
- REQ-SEC-005: Final evidence tamper-evident and authenticated ✅
- REQ-DATA-004: Accepted evidence writes crash-consistent (manifest atomic) ✅
- REQ-EVID-001: Evidence bundle includes seal and decision ✅

## Failure Modes

- **Artifact Hash Mismatch**: File modified after manifest creation → VerificationFailed
- **Bad Signature**: Manifest modified or key rotated → InvalidSignature
- **Event Chain Broken**: Ledger truncated or reordered → EventChainBroken
- **HSM Unavailable**: Cannot sign → SigningFailed
- **Disk Full**: Cannot write manifest → FileSystemError
```

**Tasks:**
- [ ] Document SealEvidenceRequest/Response contracts
- [ ] Document verification flow for Gate I
- [ ] Document error handling and failure modes
- [ ] List requirements satisfied
- [ ] Add examples (request/response JSON)

---

## Dependencies & Prerequisites

### External Libraries to Add to Cargo.toml
```toml
[dependencies]
sha2 = "0.10"
hex = "0.4"
uuid = { version = "1.0", features = ["v4", "serde"] }
ed25519-dalek = "2.0"
tokio = { version = "1.0", features = ["full"] }
```

### HSM Client Requirements
- FilesystemHsmClient must support `sign(&[u8; 32]) -> [u8; 64]` operation
- Must use Ed25519 signing algorithm
- Must be available before seal_evidence() call

### Prior Completion
- SealerPrincipal principal implementation (from Week 2)
- SecurityLedger implementation (from Week 1)
- HSM client implementation (from Week 1)

---

## Success Criteria

- [ ] All 4 tasks completed and integrated
- [ ] All unit tests passing (>85% coverage)
- [ ] All integration tests passing (seal + verify workflow)
- [ ] No compiler warnings
- [ ] Documentation complete and examples work
- [ ] Evidence sealing adds <100ms latency to run completion
- [ ] Gate I verifier can verify evidence on a clean machine without run access

---

## Deployment Notes

- **Development Mode:** Filesystem HSM acceptable; uses local keys
- **Evidence Mode:** Requires hardware HSM or equivalent key protection
- **Evidence Directory:** Must be mounted read-only after seal (or documented exception on Windows)
- **Public Key Distribution:** Sealer's public key must be provisioned to Gate I auditors out-of-band

---

## Rollback Plan

If sealing implementation is defective:
1. Disable SealerPrincipal.seal_evidence() call in orchestrator
2. Revert to unsigned SecurityLedger (hash chain only)
3. Document that Gate I evidence is not authenticated (temporary)
4. Fix sealing in parallel sprint
5. Re-seal all affected evidence runs

---

## Success Metrics

- Evidence bundle size: < 10MB for typical 1-hour run (exclude large artifacts)
- Seal operation latency: < 100ms (excluding HSM network latency)
- Manifest JSON size: < 1MB
- Verification latency: < 5s on clean machine
- False positive rate on tampering detection: 0%
