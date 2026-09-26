# Evidence Sealing: Deployment & Operations Guide

**Version:** 1.0  
**Status:** Ready for Sprint 1 Integration  
**Target Audience:** DevOps, System Architects, Security Engineers

## Deployment Checklist

### Pre-Deployment (Before Production)

- [ ] **Code Review**: Evidence sealing implementation reviewed
- [ ] **Security Audit**: Ed25519 signing integrated with HSM
- [ ] **Performance Tested**: Sealing performance acceptable for expected bundle sizes
- [ ] **Integration Tested**: Sealing integrated with run infrastructure
- [ ] **Documentation**: All runbooks and troubleshooting guides prepared
- [ ] **Access Control**: Sealer principal access restricted to authorized users
- [ ] **Key Management**: HSM keys generated, backed up, access controlled
- [ ] **Disaster Recovery**: Evidence bundle backup and recovery procedures defined

### Deployment Steps

1. **Code Deployment**
   ```bash
   # Build sealing system
   cargo build --release --features sealing
   
   # Run full test suite
   cargo test evidence_sealing_integration --release
   
   # Deploy binary
   cp target/release/libgeometry_dash.so /usr/local/lib/
   ```

2. **HSM Setup** (if using real HSM)
   ```bash
   # Initialize HSM (see HSM provider docs)
   # Generate Ed25519 keypair for Sealer
   # Store public key in auditable registry
   # Configure access controls
   ```

3. **Directory Setup**
   ```bash
   # Create evidence storage directory
   mkdir -p /evidence/bundles
   chmod 755 /evidence/bundles
   
   # Create read-only directory for archival
   mkdir -p /evidence/archive
   chmod 555 /evidence/archive  # Will be set dynamically
   ```

4. **Configuration**
   ```bash
   # Create sealing configuration
   cat > /etc/geometry-dash/sealing.conf << EOF
   # Evidence Sealing Configuration
   EVIDENCE_DIR=/evidence/bundles
   ARCHIVE_DIR=/evidence/archive
   HSM_CONFIG=/etc/geometry-dash/hsm.conf
   ENABLE_VERIFICATION=true
   MAX_BUNDLE_SIZE=10737418240  # 10GB
   EOF
   ```

5. **Integration Testing**
   ```bash
   # Create test run with evidence sealing
   # Verify manifest creation
   # Verify read-only enforcement
   # Verify signature presence
   ```

## Operational Procedures

### Sealing a Run's Evidence

**Scenario:** After training run completes, seal evidence for Gate I review.

**Steps:**

1. Gather artifacts:
   ```rust
   let artifacts = vec![
       collect_artifact("output.log", ArtifactType::CustomMetadata),
       collect_artifact("policy.pkl", ArtifactType::PolicySnapshot),
       collect_artifact("config.json", ArtifactType::ConfigSnapshot),
       collect_artifact("ledger.jsonl", ArtifactType::SecurityLedger),
   ];
   ```

2. Compute root hashes:
   ```rust
   let policy_hash = compute_file_hash("snapshots/policy.pkl");
   let config_hash = compute_file_hash("snapshots/config.json");
   let event_root = ledger.compute_event_root_hash()?;
   ```

3. Invoke sealing:
   ```rust
   let result = sealer.seal_evidence(
       bundle_id,
       run_id,
       boot_id,
       epoch_id,
       evidence_dir,
       artifacts,
       policy_hash,
       config_hash,
       event_root,
   )?;
   ```

4. Verify sealing succeeded:
   ```rust
   assert!(result.success);
   assert_ne!(result.seal_signature, [0u8; 64]);
   println!("Bundle {}: {} bytes sealed", result.bundle_id, result.total_artifact_size);
   ```

5. Archive:
   ```bash
   # Archive sealed bundle
   tar -czf /evidence/archive/bundle-001.tar.gz /evidence/bundles/bundle-001/
   
   # Verify manifest in archive
   tar -tzf /evidence/archive/bundle-001.tar.gz | grep MANIFEST.json
   ```

### Verifying Evidence (Gate I Auditor)

**Scenario:** Auditor wants to verify evidence authenticity on clean machine.

**Steps:**

1. Obtain evidence bundle (from secure archive, not original host)
2. Extract to clean machine:
   ```bash
   mkdir -p /mnt/evidence/bundle-001
   tar -xzf /evidence/archive/bundle-001.tar.gz -C /mnt/evidence/bundle-001/
   ```

3. Run verification:
   ```rust
   let verifier = EvidenceVerifier::new("/mnt/evidence/bundle-001")
       .with_ledger("/mnt/evidence/bundle-001/ledger.jsonl");
   
   let result = verifier.verify_sealed_evidence();
   ```

4. Interpret results:
   ```rust
   match result.status {
       VerificationStatus::Valid => {
           println!("✓ Evidence verified - accepted for Gate I review");
           println!("  - {} artifacts verified", result.artifacts_verified);
           println!("  - Event chain: {} events", result.event_count);
       },
       VerificationStatus::ArtifactHashMismatch => {
           println!("✗ Tampering detected: artifact hash mismatch");
           for detail in result.artifact_details {
               if !detail.matches {
                   println!("  - {}: expected {}, got {}",
                       detail.artifact_id, detail.expected_hash, detail.computed_hash);
               }
           }
       },
       VerificationStatus::EventRootHashMismatch => {
           println!("✗ Event chain tampering detected");
           println!("  - Expected: {}", result.expected_event_root);
           println!("  - Computed: {}", result.computed_event_root);
       },
       _ => println!("✗ Verification failed: {}", result.description),
   }
   ```

5. Record verification:
   ```bash
   # Log verification result
   echo "Bundle: ${BUNDLE_ID}" >> /var/log/evidence_verification.log
   echo "Status: ${RESULT_STATUS}" >> /var/log/evidence_verification.log
   echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> /var/log/evidence_verification.log
   ```

## Troubleshooting

### Problem: Artifact Hash Mismatch During Sealing

**Symptoms:**
```
Error: Artifact output.log hash mismatch: expected abcd1234..., got efgh5678...
```

**Causes:**
1. File modified between hash computation and sealing
2. Incorrect artifact hash provided
3. File corruption on disk

**Resolution:**
1. Verify artifact file integrity:
   ```bash
   # Recompute hash manually
   sha256sum /evidence/run-001/output.log
   
   # Compare against provided hash
   ```

2. If mismatch, investigate:
   - Check file modification times
   - Verify no background processes modifying files
   - Run filesystem integrity check: `fsck`, `btrfs check`, etc.

3. Recompute hashes and retry sealing

### Problem: Evidence Directory Not Becoming Read-Only

**Symptoms:**
```
Warning: Failed to set read-only permissions (Windows?)
Evidence directory still writable after sealing
```

**Cause:** Running on Windows (read-only enforcement Unix-only)

**Resolution:**
1. Expected behavior on Windows - use external enforcement:
   ```powershell
   # On Windows, use NTFS permissions instead
   icacls C:\evidence\bundle-001 /inheritance:r
   icacls C:\evidence\bundle-001 /grant:r "SYSTEM:(OI)(CI)R"
   ```

2. Alternative: Use immutable filesystem (btrfs, XFS):
   ```bash
   # Make directory immutable (Linux ext4+)
   sudo chattr +i /evidence/bundle-001
   
   # Verify immutability
   lsattr /evidence/bundle-001
   # Should show immutable flag
   ```

### Problem: Verification Shows Signature Invalid

**Symptoms:**
```
VerificationStatus: InvalidSignature
Description: Manifest signature verification failed
```

**Cause:**
1. Manifest not properly sealed (development environment)
2. Manifest corrupted/tampered
3. Production: Ed25519 signature verification with public key failed

**Resolution (Development):**
- This is expected when using placeholder signature
- Check that `seal_signature != [0u8; 64]`

**Resolution (Production):**
- Verify Sealer HSM is working: Check HSM logs
- Verify manifest wasn't modified: Check file timestamps
- Verify auditor has correct Sealer public key
- Escalate to security team if consistent failures

### Problem: Event Chain Verification Failing

**Symptoms:**
```
VerificationStatus: EventRootHashMismatch
Expected: abcd1234...
Computed: efgh5678...
```

**Cause:**
1. Security ledger modified after sealing (tampering)
2. Ledger file corrupted
3. Different ledger file provided to verifier

**Resolution:**
1. Verify ledger path is correct:
   ```bash
   ls -lh /path/to/ledger.jsonl
   ```

2. Check ledger integrity:
   ```rust
   let ledger = SecurityLedger::open("/path/to/ledger.jsonl")?;
   let chain_valid = ledger.verify_chain().is_ok();
   ```

3. If ledger valid but hash mismatches:
   - **This indicates tampering** - escalate to security
   - Do NOT accept evidence
   - Preserve ledger for forensic analysis

### Problem: Read-Only Directory Bypassed

**Symptoms:**
```
Successfully modified file in supposedly read-only evidence directory
rm: cannot remove 'artifact.txt': Read-only file system
# But: echo content > /path/to/file succeeds
```

**Cause:** File permissions vs directory permissions

**Explanation:**
- Directory `chmod 555` (r-xr-xr-x) prevents:
  - Creating new files
  - Deleting files
  - Renaming files

- Directory `chmod 555` does NOT prevent:
  - Modifying existing files (if file permissions allow)

**Resolution:**
1. Also set file permissions to read-only:
   ```bash
   chmod 444 /evidence/bundle-001/*
   ```

2. Or use filesystem immutability:
   ```bash
   chattr +i /evidence/bundle-001/*
   ```

3. Or use ACLs with write-protection

## Monitoring & Alerts

### Metrics to Track

1. **Sealing Performance:**
   - Time to seal bundle (target: <1s per GB)
   - Total artifact size per bundle (trend)
   - Sealing success rate (target: 99.9%)

2. **Verification Performance:**
   - Time to verify bundle (target: <1s per GB)
   - Verification success rate (target: 100% for non-tampered)

3. **Tampering Alerts:**
   - Count of tamper detections
   - Types of tampering (artifact vs event)
   - Affected bundles

### Alert Thresholds

| Metric | Threshold | Action |
|--------|-----------|--------|
| Sealing Failures | >1% | Investigate HSM, disk space |
| Hash Mismatches | >0 | Investigate immediately (tampering suspected) |
| Ledger Verification Failures | >0 | Investigate immediately (critical) |
| Signature Invalid (Prod) | Any | Escalate to security team |

### Log Locations

- **Sealing Operations**: `/var/log/geometry-dash/sealing.log`
- **Verification Results**: `/var/log/geometry-dash/verification.log`
- **Security Events**: `/var/log/geometry-dash/security.log`
- **HSM Operations**: `/var/log/hsm/operations.log` (HSM-specific)

### Recommended Monitoring Setup

```bash
# Monitor sealing success rate
grep "seal_evidence.*success=true" /var/log/geometry-dash/sealing.log | wc -l
grep "seal_evidence" /var/log/geometry-dash/sealing.log | wc -l

# Monitor tamper detections
grep "ArtifactHashMismatch\|EventRootHashMismatch" /var/log/geometry-dash/verification.log

# Monitor error conditions
grep "ERROR\|CRITICAL" /var/log/geometry-dash/sealing.log
```

## Performance Tuning

### Artifact Hash Computation

**Bottleneck:** Reading large files for SHA-256

**Optimization:**
```rust
// Use 8KB buffers (good balance for I/O)
let mut buffer = [0u8; 8192];

// Consider parallel hashing if many small artifacts
use rayon::prelude::*;
let artifact_hashes: Vec<_> = artifacts
    .par_iter()
    .map(|a| (a.id.clone(), compute_file_hash(&a.path)))
    .collect();
```

### Event Chain Verification

**Bottleneck:** Merkle tree computation

**Optimization:**
```rust
// For n events with m artifacts:
// Merkle tree: O(n log n) time, O(n) space
// Can be cached if ledger not modified

// Parallelization limited due to hash chain dependency
// Use hardware acceleration if available:
// - SHA-256 with AES-NI (Intel SHA extensions)
// - RISC-V accelerators
```

### Verification on Clean Machine

**Recommendation:**
- Verify on machine with >100MB/s disk I/O
- Allocate 1GB RAM minimum
- Use SSD if bundle >1GB

**Typical Times:**
- 100MB bundle: 0.5-1s
- 1GB bundle: 5-10s
- 10GB bundle: 50-100s

## Backup & Recovery

### Evidence Bundle Backup Strategy

1. **Immediate Backup (after sealing):**
   ```bash
   # Copy to secure storage immediately
   rsync -av /evidence/bundles/bundle-001/ /backup/evidence/bundle-001/
   
   # Verify backup
   diff -r /evidence/bundles/bundle-001/ /backup/evidence/bundle-001/
   ```

2. **Long-Term Archival:**
   ```bash
   # Compress and archive
   tar -czf /archive/evidence-2024-01.tar.gz \
       /backup/evidence/bundle-00{1..100}/
   
   # Verify integrity
   tar -tzf /archive/evidence-2024-01.tar.gz > /dev/null
   ```

3. **Geographic Distribution:**
   ```bash
   # Replicate to secondary site
   aws s3 sync /archive/evidence/ s3://evidence-backup/2024-01/
   ```

### Recovery Procedures

**If evidence bundle lost:**
1. Restore from backup: `rsync -av /backup/evidence/bundle-001 /evidence/bundles/`
2. Verify integrity: `EvidenceVerifier::new(...).verify_sealed_evidence()`
3. If integrity check passes, evidence is recoverable

**If ledger lost:**
1. Restore from backup
2. Verify ledger hash chain: `ledger.verify_chain()?`
3. Re-seal evidence with recovered ledger

**If manifest lost:**
1. Cannot recover without manifest
2. Event chain remains verifiable if ledger intact
3. Manually reconstruct manifest from artifacts and ledger

## Security Considerations

### Key Management

1. **HSM Protection**: Ed25519 private key must never leave HSM
2. **Access Control**: Only authorized Sealer processes can sign
3. **Key Rotation**: Rotate keys periodically (e.g., annually)
4. **Key Backup**: Backup key material in secure HSM backup facility

### Audit Trail

1. **Every sealing**: Log bundle ID, artifacts, and seal timestamp
2. **Every verification**: Log verification result and auditor ID
3. **Tamper detections**: Immediate security alert
4. **Key operations**: Log all HSM operations

### Threat Model

**In Scope:**
- Artifact tampering detection
- Event chain tampering detection
- Manifest integrity verification

**Out of Scope:**
- Confidentiality (use encryption layer)
- Availability (use redundancy)
- Key compromise (use HSM + access control)
- Time-based attacks (use timestamping authority)

## Contact & Escalation

- **Operational Issues**: DevOps Team
- **Security Incidents**: Security Team
- **Performance Issues**: Architecture Team
- **HSM Issues**: HSM Vendor Support

## Related Documentation

- [Evidence Sealing Guide](./EVIDENCE_SEALING_GUIDE.md)
- [Sealing Contracts & Specs](./SEALING_CONTRACTS.md)
- [HSM Integration Guide](./HSM_INTEGRATION.md) (future)
- [Security Ledger Documentation](../src/security_ledger/README.md)
