# Evidence Sealing System: Formal Contracts & Specifications

**Version:** 1.0  
**Component:** SealerPrincipal, EvidenceVerifier  
**Specification Level:** SEC-C02 Remediation

## Contract: SealerPrincipal::seal_evidence()

### Preconditions (MUST all be true)

1. **Artifact Files Exist**: For each ArtifactRef in `artifacts`, the file at `evidence_dir/artifact_id` must exist
2. **Artifact Hashes Valid**: For each artifact, `file_hash` matches SHA-256(file contents)
3. **Evidence Directory Writable**: `evidence_dir` must be writable by Sealer process
4. **No Existing Manifest**: `evidence_dir/MANIFEST.json` should not exist (or will be overwritten)
5. **SealerPrincipal Initialized**: Must have signing key loaded via `initialize()`
6. **Bundle ID Unique**: `bundle_id` is globally unique (UUID recommended)
7. **Identifiers Non-Empty**: `run_id`, `boot_id`, `epoch_id` are non-empty strings

### Invariants (MUST remain true throughout)

1. **Hash Consistency**: Manifest artifact hashes = SHA-256(artifact file contents)
2. **Signature Non-Zero**: Seal signature is never all-zero bytes (indicates unsigned)
3. **Timestamps Monotonic**: `sealed_timestamp_ns >= created_timestamp_ns`
4. **Sealer Identity**: `sealer_principal` is always Principal::Sealer
5. **Manifest Well-Formed**: MANIFEST.json is valid JSON serializable

### Postconditions (GUARANTEED if operation succeeds)

1. **Manifest Created**: `MANIFEST.json` exists in `evidence_dir` with valid JSON
2. **Manifest Signed**: `seal_signature` field is non-zero (represents Ed25519 signature)
3. **All Artifacts Listed**: Every artifact parameter appears in manifest with matching metadata
4. **Directory Read-Only** (Unix): `evidence_dir` permissions set to 0o555 (best-effort on Windows)
5. **Sealing Timestamp**: `sealed_timestamp_ns` is current time in nanoseconds
6. **Total Size Accurate**: `result.total_artifact_size = sum(artifact.size_bytes)`
7. **Manifest Hash Computed**: `result.manifest_hash` matches manifest content hash
8. **Success Flag Set**: `result.success == true`

### Error Conditions (MUST return Err)

1. **Artifact Not Found**
   - Condition: File referenced in `artifacts` doesn't exist
   - Error: `"Failed to hash artifact X: No such file or directory"`
   - Guarantees: Manifest NOT created, no state changes

2. **Artifact Hash Mismatch**
   - Condition: Computed SHA-256 ≠ provided artifact.file_hash
   - Error: `"Artifact X hash mismatch: expected Y, got Z"`
   - Guarantees: Manifest NOT created, no state changes
   - Resolution: Recompute artifact hashes or investigate file corruption

3. **File I/O Failure**
   - Condition: Cannot read artifact or write manifest
   - Error: `"Failed to write manifest: <OS error>"`
   - Guarantees: Partial write cleanup attempted, directory state undefined
   - Resolution: Check disk space, permissions, path validity

4. **Serialization Failure**
   - Condition: Manifest or artifact data not JSON-serializable
   - Error: `"Manifest serialization failed: <serde error>"`
   - Guarantees: Manifest NOT written
   - Resolution: Check for non-UTF8 strings, numeric overflow

### Security Properties

1. **Artifact Binding**: Manifest cryptographically commits to exact artifact contents via hash
2. **Tampering Detection**: Any artifact modification → hash mismatch on verification
3. **Complete Record**: Manifest includes all artifact metadata for accountability
4. **Immutability Enforcement**: Read-only directory prevents post-hoc modifications (Unix)
5. **Non-Repudiation**: Sealer signature proves sealing identity (with proper key security)

## Contract: EvidenceVerifier::verify_sealed_evidence()

### Preconditions (Assumed true)

1. **Evidence Directory Exists**: `evidence_dir` parameter points to valid directory
2. **Verifier Constructed**: EvidenceVerifier initialized with `new(evidence_dir)`
3. **Optional Ledger Path**: If provided, `ledger_path` points to valid SecurityLedger file

### Invariants (Maintained throughout verification)

1. **No Modifications**: Verifier is read-only; evidence files not modified
2. **Deterministic Results**: Same evidence → identical verification results
3. **Partial Verification OK**: Can verify artifacts without ledger
4. **Graceful Failures**: Each check fails independently; others continue

### Postconditions (ALWAYS produces valid VerificationResult)

1. **Result Always Valid**: Returns well-formed VerificationResult (no panics/crashes)
2. **Status Set**: `status` field is set to one of VerificationStatus enum values
3. **Description Populated**: `description` explains the result in English
4. **Timestamp Set**: `verification_timestamp_ns` records verification time
5. **Tamper Evidence Flag**: `tamper_evident` is true IFF status == Valid AND all checks passed

### Verification Algorithm Guarantees

#### Step 1: Load Manifest

**Postconditions:**
- If MANIFEST.json exists and is valid JSON → manifest loaded successfully
- If MANIFEST.json missing → status = ManifestMissing, result returned immediately
- If MANIFEST.json corrupted → status = ManifestCorrupted, result returned immediately

#### Step 2: Verify Signature

**Current Implementation (Placeholder):**
- Signature considered valid if `seal_signature != [0u8; 64]`
- This is a placeholder; production uses Ed25519 verification with Sealer public key

**Postconditions:**
- `signature_valid = true` if signature appears valid
- `manifest_valid = signature_valid` (requires valid signature)
- If signature invalid → status = InvalidSignature, result returned

#### Step 3: Verify Artifacts

**For each artifact in manifest:**

1. **File Exists Check**
   - If file missing → artifact_details entry with error, `matches=false`
   - Continue checking other artifacts
   - Final status = ArtifactMissing if ANY file missing

2. **Hash Verification**
   - Compute SHA-256 of actual file
   - Compare against manifest hash
   - Record in artifact_details: expected_hash, computed_hash, matches flag
   - Increment `artifacts_verified` counter if matches

3. **Size Recording**
   - Record actual file size in artifact_details
   - Compare against manifest (informational only)

**Postconditions:**
- `artifacts_verified` = count of artifacts with matching hashes
- `artifact_details` contains entry for EACH artifact with full diagnostic
- If ANY artifact mismatches → status = ArtifactHashMismatch
- If ANY artifact unreadable → status = ArtifactUnreadable

#### Step 4: Verify Event Chain (Optional)

**Only executed if ledger_path provided via `with_ledger()`**

1. **Load Ledger**
   - If ledger file missing → status = EventLedgerMissing, return
   - If ledger unreadable → status = EventChainBroken, return

2. **Compute Event Root**
   - Call `ledger.compute_event_root_hash()`
   - Get count of events from ledger

3. **Compare Hashes**
   - Computed root vs manifest `event_root_hash`
   - If mismatch → status = EventRootHashMismatch
   - If match → `event_chain_valid = true`

**Postconditions:**
- `event_count` populated from ledger
- `computed_event_root` hex-encoded result
- `expected_event_root` hex-encoded from manifest
- `event_chain_valid = true` if hashes match

#### Step 5: Determine Final Status

**Status Resolution Order (first matching condition wins):**

1. If `!signature_valid` → status = InvalidSignature
2. Else if any artifact missing → status = ArtifactMissing
3. Else if any artifact hash mismatches → status = ArtifactHashMismatch
4. Else if any artifact unreadable → status = ArtifactUnreadable
5. Else if ledger provided AND event chain broken → status = EventChainBroken
6. Else if ledger provided AND root hash mismatches → status = EventRootHashMismatch
7. Else → status = Valid

**Final Flag:**
- `tamper_evident = true` IFF `status == Valid`

### Security Properties

1. **Read-Only Verification**: No state changes, safe to run multiple times
2. **Comprehensive Checking**: Verifies signature + artifacts + event chain
3. **Detailed Diagnostics**: Per-artifact error reporting for forensics
4. **Tamper Detection**: Detects 5 independent attack vectors:
   - Artifact modification (hash mismatch)
   - Artifact replacement (hash mismatch)
   - Manifest deletion (missing)
   - Manifest corruption (parse error)
   - Event chain tampering (root hash mismatch)
5. **Clean-Machine Friendly**: No privileged access required for verification

## Artifact Verification Contract

### ArtifactRef Structure Guarantees

```rust
pub struct ArtifactRef {
    pub artifact_id: String,              // Filename relative to evidence_dir
    pub artifact_type: ArtifactType,      // Semantic type
    pub file_hash: [u8; 32],              // SHA-256 of file contents
    pub size_bytes: u64,                  // File size in bytes
    pub created_by: Principal,            // Principal that created artifact
    pub created_timestamp_ns: u64,        // Creation time (nanoseconds since UNIX_EPOCH)
    pub description: String,              // Human-readable description
}
```

### Hash Verification Invariants

1. **Hash Format**: Always 32 bytes (256 bits), suitable for SHA-256
2. **Hash Determinism**: SHA-256(file) always produces same hash
3. **Hash Completeness**: Hash covers entire file content
4. **Hash Mismatch = Tampering**: Any byte change → different hash
5. **Size Tracking**: `size_bytes` recorded at sealing time for reference

### Timestamp Semantics

1. **created_timestamp_ns**: Artifact creation time (set by sealer)
2. **sealed_timestamp_ns** (manifest): When manifest was created (≥ artifact time)
3. **verification_timestamp_ns**: When verification was performed

## EvidenceManifest Structure Guarantees

```rust
pub struct EvidenceManifest {
    pub bundle_id: String,                    // Unique bundle ID
    pub run_id: String,                       // Training/eval run
    pub boot_id: String,                      // Host/environment
    pub epoch_id: String,                     // Training epoch
    pub created_timestamp_ns: u64,            // When manifest created
    pub sealed_timestamp_ns: u64,             // When sealed (signature applied)
    pub artifacts: Vec<ArtifactRef>,          // All artifacts in bundle
    pub policy_snapshot_hash: [u8; 32],       // Frozen policy hash
    pub config_snapshot_hash: [u8; 32],       // Frozen config hash
    pub event_root_hash: [u8; 32],            // Merkle root of events
    pub sealer_principal: Principal,          // Who sealed (always Sealer)
    pub seal_signature: [u8; 64],             // Ed25519 signature
    pub seal_timestamp_ns: u64,               // When signature applied
    pub source_commit_hash: Option<String>,   // Git commit (if applicable)
    pub gate_decision_id: Option<String>,     // Gate I decision (if applicable)
}
```

### Manifest Integrity Invariants

1. **Non-Empty Artifacts**: Must contain ≥1 artifact
2. **Unique Artifact IDs**: All artifacts have unique `artifact_id`
3. **Consistent Timestamps**: `sealed_timestamp_ns >= created_timestamp_ns`
4. **Valid Hashes**: All hash fields are exactly 32 bytes
5. **Serializable**: Must be JSON-serializable without errors
6. **Hash Chain**: Each artifact hash is independent SHA-256 of file

## Merkle Tree (Event Chain) Contract

### compute_event_root_hash() Guarantees

**Input:** List of event hashes from SecurityLedger

**Postconditions:**

1. **Deterministic Output**: Same event sequence → same root hash
2. **Empty Tree**: 0 events → zero hash `[0u8; 32]`
3. **Single Event**: 1 event → that event's hash returned
4. **Multiple Events**: n events → Merkle root hash computed
5. **Well-Formed Tree**: Odd nodes padded (hashed with themselves)

### Event Chain Verification

**Invariant:** If ledger unchanged, `compute_event_root_hash()` is idempotent

**Tampering Detection:**
- Append new event → root hash changes
- Modify existing event → hash chain breaks
- Delete events → root hash changes

## Test Coverage & Validation

### Unit Tests
- Individual component tests (SecurityLedger, EvidenceManifest, EvidenceVerifier)
- Hash computation consistency
- Signature placeholder verification
- Artifact metadata handling

### Integration Tests
- End-to-end sealing and verification workflow
- Multiple artifacts simultaneously
- Event chain integration
- 5 tamper detection scenarios:
  1. Artifact modification
  2. Manifest deletion
  3. Manifest corruption
  4. Artifact addition (extra files OK)
  5. Event chain tampering

### Success Criteria
- All unit tests pass
- All integration tests pass
- Tamper detection works for known attack vectors
- Verification results consistent across runs
- No data loss or corruption in sealing

## Compliance

- **SEC-C02 Remediation**: Evidence must be cryptographically authenticated
  - ✓ Artifacts bound via SHA-256 hashing
  - ✓ Manifest signed (placeholder; real sig with HSM)
  - ✓ Event chain verified via Merkle root
  - ✓ Tamper detection enabled

- **Gate I Integration**: Independent verification on clean machines
  - ✓ EvidenceVerifier operates without privileged access
  - ✓ Detailed diagnostic results for auditors
  - ✓ Supports optional event chain verification
  - ✓ Clear tamper/no-tamper decision

## Implementation Notes

### Known Limitations (Current)

1. **Placeholder Signature**: Signature verification checks non-zero bytes, not actual Ed25519
   - Fix: Integrate HSM and actual public key verification
   
2. **No Confidentiality**: Evidence bundles not encrypted
   - Fix: Add AES-256-GCM encryption layer
   
3. **Time-of-Check-Time-of-Use (TOCTOU)**:
   - Read-only enforcement best-effort only (Unix)
   - Fix: File locking or immutable filesystem

4. **Ledger Authenticity**: SecurityLedger itself assumed authentic
   - Fix: Verify ledger hash chain

### Future Enhancements

1. Ed25519 signature verification with public key
2. AES-256-GCM encryption for confidentiality
3. Timestamping authority integration
4. Blockchain attestation
5. Redundant Sealer signatures (Byzantine tolerance)
