# SecurityLedger Design (Week 1 Task 2)

**Status:** Design phase – Week 1  
**Owner:** QA Engineer + Audit Engineer  
**Timeline:** Week 1 (design + implementation), Week 1-14 (append-only logging throughout)  
**Target LOC:** 400–600 (implementation)  

---

## Executive Summary

The **SecurityLedger** is the tamper-evident, append-only log of all security-relevant events in Phase 2. It:
1. Records every action by every principal (start, stop, request, decision, error)
2. Is cryptographically hash-chained (Merkle tree) for tamper detection
3. Survives principal crashes and system reboots
4. Serves as evidence for Gate I audit (Week 13-14)
5. Powers forensic analysis of any security incident

SecurityLedger is foundational; all modules depend on it (Week 1 blocker).

---

## Requirements (From Phase 1)

**REQ-AUDIT-001 through REQ-AUDIT-015:** SecurityLedger must:
- Append-only: No modification, deletion, or reordering of past events
- Hash-chained: Each entry includes hash of previous entry (Merkle chain)
- Monotonic timestamps: ts[n] < ts[n+1] always (REQ-EVIDENCE-004)
- Tamper-detectable: Any modification breaks hash chain (detected at Gate I)
- Recoverable: Survive crashes; restart by replaying from disk
- Auditable: All fields queryable for forensic analysis
- Efficient: Write latency <100ms per event (REQ-PERF-005)

---

## Design

### 1. Data Format

**Storage Format: JSON Lines**
- One JSON event per line
- Newline-delimited (NDJSON)
- File: `/var/log/geometry-dash/security_ledger.jsonl`
- Permissions: 0600 (readable only by Supervisor, other principals read via IF-011)

**Event Schema (v1.0):**
```json
{
  "ledger_index": 12345,
  "timestamp_ns": 1695226800123456789,
  "event_type": "ACTION_REQUESTED",
  "severity": "INFO",
  "principal": "PRN-POLICY",
  "run_id": "550e8400-e29b-41d4-a716-446655440000",
  "boot_id": "abcdef01-2345-6789-abcd-ef0123456789",
  "epoch_id": "epoch-1695226800-a1b2c3d4",
  "prev_entry_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "current_entry_hash": "f4c1d55a9001c229f9b9cf3e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e",
  "interface_id": 2,
  "message_id": 456,
  "details": {
    "action": "DECLASSIFY",
    "artifact_id": "artifact-789",
    "requestor": "PRN-DECLASSIFIER",
    "status": "APPROVED",
    "reason": "User declassification request approved"
  }
}
```

**Event Types:**
- `SUPERVISOR_START` — Supervisor boots
- `PRINCIPAL_START` — Principal process starts
- `PRINCIPAL_READY` — Principal reports ready
- `PRINCIPAL_CRASH` — Principal process detected dead
- `PRINCIPAL_RESTART` — Supervisor attempts restart
- `PRINCIPAL_SHUTDOWN` — Principal graceful shutdown
- `ACTION_REQUESTED` — Principal requests action
- `ACTION_APPROVED` — Authorization granted
- `ACTION_DENIED` — Authorization denied
- `ACTION_EXECUTED` — Action taken
- `ARTIFACT_SEALED` — Evidence sealed
- `ARTIFACT_DECLASSIFIED` — Classification changed
- `SIGNATURE_VERIFIED` — Message signature valid
- `SIGNATURE_FAILED` — Message signature invalid
- `NONCE_ACCEPTED` — Nonce cache accepted message
- `NONCE_REJECTED` — Duplicate nonce detected
- `TIMESTAMP_STALE` — Message timestamp too old
- `CONFIG_LOADED` — Configuration initialized
- `CONFIG_IMMUTABLE` — Config marked immutable
- `LOCKDOWN_ENTERED` — System entered LOCKDOWN state
- `RECOVERY_ATTEMPTED` — Recovery procedure started
- `ERROR` — Unclassified error
- `SECURITY_ISSUE` — Potential exploit detected

**Severity Levels:**
- `DEBUG` — Low-level tracing (disabled in production)
- `INFO` — Normal operations
- `WARN` — Potential issues (requires investigation)
- `ERROR` — Operation failed (principal may be compromised)
- `CRITICAL` — Exploit detected, system integrity at risk (LOCKDOWN)

---

### 2. Hash Chain (Merkle)

**Per-Entry Hash:**
```rust
fn hash_entry(entry: &SecurityEvent) -> [u8; 32] {
    let json = serde_json::to_string(entry).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&json);
    hasher.finalize().into()
}
```

**Chain Verification (Week 1 Task 2.3):**
```rust
fn verify_chain(ledger: &[SecurityEvent]) -> Result<(), String> {
    for (i, entry) in ledger.iter().enumerate() {
        if i == 0 {
            // First entry: prev_hash should be zero hash
            assert_eq!(entry.prev_entry_hash, [0u8; 32]);
        } else {
            let prev_entry = &ledger[i - 1];
            let expected_prev_hash = hash_entry(prev_entry);
            if entry.prev_entry_hash != expected_prev_hash {
                return Err(format!("Chain broken at index {}", i));
            }
        }
        // Verify current entry hash
        let calculated_hash = hash_entry(entry);
        if entry.current_entry_hash != calculated_hash {
            return Err(format!("Entry hash mismatch at index {}", i));
        }
    }
    Ok(())
}
```

**Tamper Detection at Gate I:**
- Security Auditor loads entire ledger
- Verifies hash chain from entry 0 to final entry
- If any break detected: CRITICAL finding, abort Gate I approval
- Report which entries were modified/deleted

---

### 3. API (IF-011 Audit Logging Interface)

**Write (Append-Only):**
```rust
pub fn append_event(
    event_type: EventType,
    principal: Principal,
    severity: Severity,
    details: HashMap<String, String>,
) -> Result<u64, Error> {
    // Called by Supervisor, any principal
    // Returns ledger_index (monotonic)
    // Writes to /var/log/geometry-dash/security_ledger.jsonl
}
```

**Read (For Audit & Forensics):**
```rust
pub fn get_events(
    filter: EventFilter,
) -> Result<Vec<SecurityEvent>, Error> {
    // Query by:
    // - Time range (start_ns, end_ns)
    // - Event type (EventType enum)
    // - Principal (PRN-* enum)
    // - Severity (>= given level)
    // Returns immutable snapshot
}

pub fn verify_chain() -> Result<bool, String> {
    // Verify entire hash chain
    // Returns Ok(true) if valid, Err(reason) if tampered
}

pub fn get_statistics() -> Statistics {
    // Return count of events by type, principal, severity
}
```

**Recovery (After Crash):**
```rust
pub fn load_from_disk() -> Result<SecurityLedger, Error> {
    // Load all events from /var/log/geometry-dash/security_ledger.jsonl
    // Verify hash chain during load
    // Return in-memory ledger
}
```

---

### 4. Storage & Performance

**File Organization:**
```
/var/log/geometry-dash/
  ├── security_ledger.jsonl (current, append-only)
  ├── security_ledger.jsonl.1 (rotated, if size >100MB)
  ├── security_ledger.jsonl.2 (older rotation)
  └── ledger_index.txt (current index for recovery)
```

**Rotation (REQ-PERF-006):**
- Rotate when ledger >100MB
- Compress old rotations with gzip
- Keep last 10 rotations (1GB total)
- Oldest rotations archived to immutable storage (Week 7-8 WORM)

**Write Performance Target:**
- Append latency: <100ms per event (REQ-PERF-005)
- Throughput: 1,000+ events/second sustained
- Memory overhead: <10MB for in-memory index

**Caching Strategy:**
- In-memory hash index: [ledger_index] → event_hash
- Lazy verification: Hash chain verified at query time or Gate I
- Write-through: Immediate disk flush (via fsync)

---

### 5. Integration with Provenance Schema

**Artifact Linking (REQ-EVIDENCE-005):**
Every artifact references its genesis event in SecurityLedger:
```json
{
  "artifact_id": "artifact-001",
  "artifact_type": "OBSERVATION",
  "source_evidence_id": null,  // or reference to SecEvent
  "ledger_index": 45,           // Points to SecurityEvent at index 45
  "witness_principal": "PRN-AUDIT",
  "witness_signature": "..."    // Signature over all 17 provenance fields
}
```

**Audit Trail Example:**
1. Event #45: `ARTIFACT_CREATED` (PRN-AUDIT produces observation)
2. Event #46: `ACTION_REQUESTED` (declassification request)
3. Event #47: `ACTION_APPROVED` (PRN-DECLASSIFIER approves)
4. Event #48: `ARTIFACT_DECLASSIFIED` (PRN-DECLASSIFIER creates new artifact)
5. Event #49: `ARTIFACT_SEALED` (PRN-SEALER seals all artifacts)

Full audit chain reconstructable from SecurityLedger.

---

## Week 1 Task Breakdown

### Task 2.1: Schema & API Design (1 day)
- Finalize JSON event schema (all fields, types, constraints)
- Design Rust struct `SecurityEvent` with serde serialization
- Design public API: `append_event()`, `get_events()`, `verify_chain()`
- Define event types and severity levels exhaustively

**Deliverable:** `src/security_ledger/schema.rs` (300+ LOC, fully documented)

### Task 2.2: Implementation (2 days)
- Implement append-only write to disk
- Implement in-memory index for fast queries
- Implement hash chain generation per entry
- Implement rotation logic (100MB threshold)
- Handle concurrent writes (mutex-protected)

**Deliverable:** `src/security_ledger/lib.rs` (400–500 LOC)

### Task 2.3: Hash Chain Verification (1 day)
- Implement `verify_chain()` function
- Test on large ledgers (10k+ entries)
- Benchmark verification time
- Document tamper-detection guarantees

**Deliverable:** `src/security_ledger/verify.rs` (100–150 LOC)

### Task 2.4: Unit Tests (1 day)
- Test append (single, concurrent, rapid fire)
- Test query (by type, principal, severity, time range)
- Test hash chain generation & verification
- Test rotation logic
- Test recovery from disk

**Deliverable:** `tests/unit/security_ledger_test.rs` (600+ LOC, 25+ test cases)

### Task 2.5: Integration Tests (1 day)
- Test SecurityLedger + Supervisor together
- Test SecurityLedger + all principals logging events
- Test multi-principal concurrent appends
- Test crash recovery scenario

**Deliverable:** `tests/integration/ledger_integration_test.rs` (400+ LOC, 10+ test cases)

---

## Success Criteria (Week 1 End)

- [ ] SecurityLedger binary compiles (no warnings)
- [ ] Append latency <100ms (measured)
- [ ] Throughput ≥1,000 events/sec sustained
- [ ] Hash chain verification works on 10k+ event logs
- [ ] Rotation works correctly (100MB threshold)
- [ ] Recovery from disk reconstructs full ledger
- [ ] All unit + integration tests pass (100% coverage)
- [ ] Schema matches Phase 1 audit requirements
- [ ] Documentation: API contract fully specified

---

## Integration Points

| Module | Interface | Week | Notes |
|--------|-----------|------|-------|
| Supervisor | IF-011 (audit log) | 1 | Supervisor writes all events |
| Policy | IF-011 (audit log) | 2 | Policy logs decisions |
| Actuator | IF-011 (audit log) | 3 | Actuator logs executions |
| Audit | IF-016 (forensics) | 9 | Auditor queries ledger for forensics |
| Sealer | IF-011 (audit log) | 5 | Sealer logs sealing events |
| Gate I | IF-017 (verification) | 13 | Gate I auditor verifies hash chain |

---

## Known Risks

| Risk | Mitigation | Owner |
|------|-----------|-------|
| Disk full (ledger grows unbounded) | Rotation policy (100MB threshold) | QA Eng |
| Ledger deleted/corrupted | WORM enforcement post-Gate C | Systems Eng |
| Performance regression with size | Rotation + indexing strategy | QA Eng |
| Hash chain breaks on edit | No API to modify past events | Design by contract |
| Concurrent write conflicts | Mutex-protected append | Implementation |

---

## Document Control

| Version | Date | Status |
|---------|------|--------|
| 1.0 | 2026-09-26 | Week 1 design |

**Next Update:** Week 2 (after Task 2.1–2.5 completion)
