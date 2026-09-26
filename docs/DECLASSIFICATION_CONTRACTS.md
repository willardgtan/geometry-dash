# Declassification Contracts and Specifications (SEC-C01)

## Document Overview

This document provides formal specifications and contracts for all declassification operations in the SEC-C01 Privileged Data Boundary system. Each operation includes pre/postconditions, invariants, and error handling requirements.

**Version:** 1.0  
**Sprint:** 2  
**Tasks Covered:** 2.1-2.5  

---

## Table of Contents

1. [Classification Operations](#classification-operations)
2. [Access Control Operations](#access-control-operations)
3. [Declassification Operations](#declassification-operations)
4. [Lineage Operations](#lineage-operations)
5. [IPC Message Operations](#ipc-message-operations)
6. [System Invariants](#system-invariants)
7. [Error Handling](#error-handling)

---

## Classification Operations

### Operation: apply_classification()

**Purpose:** Label a field with a classification level and justification

**Signature:**
```rust
pub fn apply_classification(
    &self,
    field_name: String,
    level: ClassificationLevel,
    principal: Principal,
    justification: String,
) -> Result<ClassificationLabel, String>
```

**Preconditions:**
- `field_name` is non-empty string
- `level` is valid ClassificationLevel (0-3)
- `principal` is valid Principal
- `justification` is non-empty string
- Field not already classified (if strict uniqueness enforced)

**Postconditions:**
- New ClassificationLabel created with unique `label_id`
- Label stored in registry
- Timestamp set to current time
- All metadata preserved
- Registry.statistics.label_count incremented by 1

**Invariants:**
- Each label has unique label_id
- label_id remains constant throughout label lifetime
- applied_timestamp_ns is monotonically increasing
- applied_by is immutable once set
- Classification level cannot be changed (new classification required)

**Error Cases:**
- Empty field_name → `"Field name cannot be empty"`
- Invalid level → `"Invalid classification level"`
- Registry overflow → `"Maximum labels exceeded"`

**Example Success:**
```
Input: field_name="physics_probe", level=PrivilegedTelemetry, 
       principal=Audit, justification="..."
Output: ClassificationLabel {
  label_id: "label-001",
  field_name: "physics_probe",
  level: PrivilegedTelemetry,
  applied_by: Audit,
  applied_timestamp_ns: 1234567890000,
  justification: "..."
}
```

---

### Operation: get_label()

**Purpose:** Retrieve classification metadata for a field

**Signature:**
```rust
pub fn get_label(&self, field_name: &str) -> Result<Option<ClassificationLabel>, String>
```

**Preconditions:**
- `field_name` is valid string reference
- Registry is initialized

**Postconditions:**
- Returns Some(label) if field classified
- Returns None if field not classified
- Label returned is exact copy (immutable)
- No state changes

**Invariants:**
- Same field always returns same label (idempotent)
- Returned label is read-only (cannot modify via return)

**Error Cases:**
- Registry not accessible → `"Registry access failed"`
- Corrupted label data → `"Label deserialization failed"`

---

## Access Control Operations

### Operation: can_read()

**Purpose:** Check if principal is authorized to read at given classification level

**Signature:**
```rust
pub fn can_read(
    &self,
    principal: Principal,
    level: ClassificationLevel,
) -> Result<bool, String>
```

**Preconditions:**
- `principal` is valid Principal
- `level` is valid ClassificationLevel
- Access control engine initialized
- Principal clearances populated

**Postconditions:**
- Returns true if principal clearances include `level`
- Returns false if principal lacks clearance
- No state changes
- No logging (lightweight check)

**Invariants:**
- Same (principal, level) always returns same result
- Unrestricted is readable by all principals

**Error Cases:**
- Principal not found → returns false (graceful)
- Invalid level → `"Invalid classification level"`

**Logic:**
```
if principal not in clearance map:
    return false if level != Unrestricted
    return true if level == Unrestricted
else:
    return level in principal_clearances[principal]
```

---

### Operation: check_read()

**Purpose:** Check read authorization AND log access attempt

**Signature:**
```rust
pub fn check_read(
    &self,
    principal: Principal,
    level: ClassificationLevel,
) -> Result<(), String>
```

**Preconditions:**
- Same as `can_read()`
- Access log is accessible

**Postconditions:**
- If authorized: returns Ok(())
- If not authorized: returns Err("Access denied")
- Access attempt logged with timestamp
- AccessAttempt recorded (principal, level, allowed, timestamp)

**Invariants:**
- Every call creates audit record (non-repudiation)
- Log entries immutable after creation
- Log is append-only

**Side Effects:**
- Appends to access_log: AccessAttempt {
  - principal: input principal
  - level: input level
  - allowed: authorization result
  - timestamp_ns: current nanosecond timestamp
}

---

### Operation: check_declassify()

**Purpose:** Check declassification authorization AND log attempt

**Signature:**
```rust
pub fn check_declassify(
    &self,
    principal: Principal,
    policy: &DeclassificationPolicy,
) -> Result<(), String>
```

**Preconditions:**
- `principal` is valid Principal
- `policy` is valid DeclassificationPolicy
- Principal has declassification capability
- Current time is within policy effective window

**Postconditions:**
- If authorized: returns Ok(())
- If not authorized: returns Err with detailed reason
- Access attempt logged

**Authorization Rules:**
```
1. Principal must be in policy.approved_by list (policy author)
   OR principal has explicit declassify clearance
2. Current timestamp must be >= policy.effective_timestamp_ns
3. Current timestamp must be < policy.expires_timestamp_ns (if set)
4. Principal must have read authorization for source_level
5. Policy must not be revoked (optional)
```

**Error Messages:**
- Not in approvers: `"Principal not authorized for this policy"`
- Policy not effective: `"Policy not yet effective (activates at ...)"`
- Policy expired: `"Policy expired (expired at ...)"`
- Lacks source clearance: `"Principal cannot read source level"`

---

## Declassification Operations

### Operation: register_policy()

**Purpose:** Register a new declassification policy with multi-party approval

**Signature:**
```rust
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
) -> Result<DeclassificationPolicy, String>
```

**Preconditions:**
- `policy_id` is unique and non-empty
- `field_name` is non-empty
- `source_level` ≠ `target_level`
- `target_level` < `source_level` (strictly less sensitive)
- `approved_by.len() >= 2` (minimum threshold)
- `transformation` is valid enum value or None
- `effective_timestamp_ns` <= `expires_timestamp_ns` (if set)
- All approvers are distinct

**Postconditions:**
- New DeclassificationPolicy created
- Policy stored in engine's policy map
- policy_id is immutable identifier
- Policy is immediately usable if effective_timestamp_ns <= now

**Invariants:**
- Each policy_id is unique
- Policy object is immutable (no mutation after creation)
- approved_by list is immutable
- source_level always > target_level (semantic invariant)
- Effective timestamp ≤ expiration timestamp

**Validation:**
```
source_level hierarchy:
  Internal (3) > PrivilegedTelemetry (2) > SensitiveReward (1) > Unrestricted (0)

Therefore:
  Internal → PrivilegedTelemetry ✓
  PrivilegedTelemetry → SensitiveReward ✓
  PrivilegedTelemetry → Internal ✗ (not downward)
  SensitiveReward → SensitiveReward ✗ (same level)
```

**Error Cases:**
- `approved_by.len() < 2`: `"Policy requires minimum 2 approvals"`
- `source_level <= target_level`: `"Source must be more sensitive than target"`
- Invalid transformation: `"Unknown transformation: ..."`
- Invalid timestamps: `"Effective time must precede expiration"`
- Duplicate policy_id: `"Policy ID already exists"`

---

### Operation: declassify()

**Purpose:** Apply declassification policy to transform sensitive value

**Signature:**
```rust
pub fn declassify(
    &self,
    principal: Principal,
    policy_id: &str,
    original_value: &[u8],
    source_level: ClassificationLevel,
    parent_records: Vec<String>,
) -> Result<(Vec<u8>, DeclassificationRecord), String>
```

**Preconditions:**
- `principal` is valid and authorized (checked via access_control)
- `policy_id` exists and is registered
- Policy is currently effective (not expired)
- `source_level` matches `policy.source_level`
- `original_value` is not empty
- `parent_records` contains valid record IDs (for lineage)
- Principal has read clearance for source_level

**Postconditions:**
- Returns transformed value and DeclassificationRecord
- Record created with unique record_id
- Original and result hashed (SHA-256)
- Lineage chain preserved in record
- Record appended to immutable declassification_ledger

**Invariants:**
- Transformation is deterministic (same input → same output)
- Original value hash never equals declassified hash (unless passthrough)
- record_id is globally unique
- Lineage chain order preserved
- Record timestamp monotonically increasing

**Transformation Rules:**

**hash_sha256:**
```
Input: arbitrary bytes
Output: SHA-256(input) = 32 bytes
Properties:
  - Irreversible
  - Deterministic
  - Suitable for reward signals
  - Suitable for telemetry
```

**passthrough:**
```
Input: arbitrary bytes
Output: same bytes
Properties:
  - Reversible (original recoverable)
  - Suitable only for low-sensitivity data
  - Should not be used for PrivilegedTelemetry
```

**Error Cases:**
- Policy not found: `"Policy {} not found"`
- Source level mismatch: `"Expected source level {...}, got {...}"`
- Authorization failed: `"Not authorized to declassify"`
- Policy expired: `"Policy expired at ..."`
- Empty value: `"Original value cannot be empty"`

**Success Example:**
```
Input:
  principal: Audit
  policy_id: "reward_hash"
  original_value: b"0.95"
  source_level: PrivilegedTelemetry
  parent_records: ["label-001"]

Processing:
  1. Verify Audit authorized for PrivilegedTelemetry → OK
  2. Get policy reward_hash → OK
  3. Check source_level matches → PrivilegedTelemetry == PrivilegedTelemetry ✓
  4. Apply hash_sha256(b"0.95") → 32-byte hash
  5. Compute SHA-256 of original → [u8; 32]
  6. Create record with lineage

Output:
  (
    [hash bytes],
    DeclassificationRecord {
      record_id: "decl-001",
      field_name: "reward_value",
      original_value_hash: [...],
      declassified_value_hash: [...],
      policy_id: "reward_hash",
      applied_by: Audit,
      timestamp_ns: 1234567890000,
      lineage: ["label-001"]
    }
  )
```

---

## Lineage Operations

### Operation: append_classified_event()

**Purpose:** Log declassification operation to SecurityLedger with lineage

**Signature:**
```rust
pub fn append_classified_event(
    &self,
    event_type: EventType,
    principal: Principal,
    severity: Severity,
    run_id: &str,
    boot_id: &str,
    epoch_id: &str,
    classification_level: ClassificationLevel,
    declassification_parent: Option<String>,
    data_lineage: Option<Vec<String>>,
    details: HashMap<String, String>,
) -> std::io::Result<u64>
```

**Preconditions:**
- All parameters valid
- SecurityLedger file accessible
- Event not already appended (idempotency via caller)
- Ledger hash chain consistent

**Postconditions:**
- Event appended to ledger file
- Hash chain extended (prev_hash set correctly)
- Returns ledger index of appended event
- Ledger count incremented
- All metadata stored

**Invariants:**
- prev_entry_hash of new event matches last_hash of ledger
- current_entry_hash computed from all fields including classification
- Hash chain remains valid and continuous
- Events ordered by ledger_index
- Classification metadata immutable after append

**Classification Metadata Storage:**
```json
{
  "ledger_index": 42,
  "event_type": "ARTIFACT_DECLASSIFIED",
  "principal": "PRN-AUDIT",
  "classification_level": "SENSITIVE_REWARD",
  "declassification_parent": "decl-001",
  "data_lineage": ["original-label", "decl-001"],
  "prev_entry_hash": "...",
  "current_entry_hash": "..."
}
```

---

### Operation: get_lineage()

**Purpose:** Retrieve complete lineage chain for a declassification operation

**Signature:**
```rust
pub fn get_lineage(
    &self,
    declassification_parent: &str,
) -> std::io::Result<Option<Vec<SecurityEvent>>>
```

**Preconditions:**
- `declassification_parent` is valid string
- Ledger file readable
- Ledger hash chain verified (optional)

**Postconditions:**
- Returns Some(Vec<SecurityEvent>) if matching parent found
- Events sorted by ledger_index (temporal order)
- Returns None if no matching parent
- No state changes
- Read-only operation

**Invariants:**
- Same parent always returns same events (idempotent)
- Events returned in chronological order
- Each event's classification_level correct

**Example:**
```
Query: get_lineage("decl-001")

Result: Some(vec![
  SecurityEvent {
    ledger_index: 10,
    event_type: ArtifactDeclassified,
    principal: Audit,
    classification_level: Some(SensitiveReward),
    declassification_parent: Some("decl-001"),
    data_lineage: Some(["original-label", "decl-001"]),
    ...
  }
])
```

---

## IPC Message Operations

### Operation: set_classification()

**Purpose:** Mark IPC message with classification level

**Signature:**
```rust
pub fn set_classification(&mut self, level: ClassificationLevel)
```

**Preconditions:**
- Header is mutable
- `level` is valid ClassificationLevel

**Postconditions:**
- classification_level set to Some(level)
- Header modification tracked
- No validation yet (validation at send/receive)

**Invariants:**
- classification_level immutable after set (should not change)
- Setting same level twice is idempotent

---

### Operation: authorize_receiver()

**Purpose:** Validate if receiver principal has required clearance

**Signature:**
```rust
pub fn authorize_receiver(
    &self,
    principal_clearances: &[(u8, Vec<ClassificationLevel>)],
) -> bool
```

**Preconditions:**
- Header has receiver_principal set
- `principal_clearances` is valid clearance list

**Postconditions:**
- Returns true if receiver authorized
- Returns false if not authorized
- No state changes
- No logging (caller logs if needed)

**Authorization Rules:**
```
1. If required_clearance is None:
     return true (unclassified message)

2. If required_clearance is Some(level):
     if receiver_principal in principal_clearances:
       return level in receiver_clearances
     else:
       return false
```

**Example:**
```
Message: required_clearance = SensitiveReward
Receiver: principal = 2

Clearances:
  1: [Unrestricted]
  2: [Unrestricted, SensitiveReward]
  3: [all levels]

authorize_receiver(&clearances):
  Find principal 2 → [Unrestricted, SensitiveReward]
  Check SensitiveReward in list → true ✓
  Return true
```

---

## System Invariants

### Global Invariants

1. **Non-Repudiation**
   - Every classification, declassification, and access decision is logged
   - Logs are append-only and immutable
   - No way to undo or erase operations

2. **Causality**
   - Declassification lineage forms directed acyclic graph (DAG)
   - Parent records precede child records in time
   - Cycles impossible

3. **Monotonic Declassification**
   - Data only becomes less sensitive
   - source_level > target_level always
   - Cannot classify more restrictive than original

4. **Hash Chain Integrity**
   - SecurityLedger forms continuous hash chain
   - Each event's hash depends on all predecessors
   - Modification of any event breaks chain

5. **Principal Isolation**
   - Principals cannot exceed their clearance level
   - Clearances immutable per principal
   - No privilege escalation

6. **Policy Approval**
   - Every declassification policy requires ≥2 approvals
   - Approval is immutable (recorded with policy)
   - Revocation requires new policy (explicit action)

7. **Idempotency**
   - Read operations have no side effects
   - Multiple identical operations safe
   - Replay-safe (nonce in IPC layer)

### Data Structure Invariants

**ClassificationLabel:**
- label_id unique within registry
- applied_timestamp_ns ≤ all lineage descendants
- justification non-empty

**DeclassificationPolicy:**
- source_level > target_level (strict)
- approved_by.len() ≥ 2
- effective_timestamp_ns ≤ expires_timestamp_ns (if set)
- policy_id unique within engine

**DeclassificationRecord:**
- record_id unique globally
- lineage forms DAG (no cycles)
- original_value_hash ≠ declassified_value_hash (unless passthrough)
- timestamp_ns monotonically increasing

**AccessAttempt:**
- timestamp_ns set at logging time
- allowed field accurately reflects authorization result
- immutable after creation

---

## Error Handling

### Error Classification

**Authorization Errors** (recoverable by user action):
- Principal lacks clearance
- Policy not approved
- Policy expired
- No matching field classification

**Validation Errors** (typically development time):
- Invalid classification level
- Mismatched source level
- Invalid transformation name
- Policy pre-conditions violated

**System Errors** (requires investigation):
- Ledger file not accessible
- Hash chain broken
- Corrupted records
- Race condition (concurrent modification)

### Error Recovery Strategies

**Authorization Denied:**
```rust
match engine.declassify(...) {
    Ok((value, record)) => send_declassified_value(value),
    Err(e) if e.contains("authorized") => {
        log_authorization_failure(&e);
        return Err(IpcError::AuthenticationFailed(e));
    },
    Err(e) => {
        log_internal_error(&e);
        return Err(IpcError::SerializationError(e));
    },
}
```

**Expired Policy:**
```rust
if let Err(e) = check_declassify(...) {
    if e.contains("expired") {
        // Try to register new policy
        register_policy(...)?;
        // Retry declassification
        declassify(...)?;
    }
}
```

**Ledger Corruption:**
```rust
match ledger.verify_chain() {
    Ok(true) => { /* OK */ },
    Ok(false) => {
        log_critical_error("Hash chain broken");
        return Err("Ledger integrity failure");
    },
    Err(e) => {
        log_critical_error(&format!("Ledger read error: {}", e));
        // Initiate recovery procedure
    },
}
```

---

## Testing Requirements

### Unit Test Coverage

Each operation must have tests for:
1. **Happy Path:** Normal operation with valid inputs
2. **Boundary Cases:** Edge cases (empty, max size, etc.)
3. **Error Cases:** Each documented error condition
4. **Invariants:** Verify invariants hold after operation

### Integration Test Coverage

End-to-end tests for:
1. Complete classification → declassification → lineage flow
2. Multi-level declassification chains
3. Cross-component interactions
4. Error propagation and recovery
5. Concurrent operations (thread safety)

### Security Test Coverage

1. Authorization bypass attempts
2. Lineage tampering detection
3. Hash chain verification
4. Replay attack prevention (nonce)
5. Privilege escalation attempts

---

## References

- **Standard Definitions:** Common Criteria, NIST FIPS 140-2
- **Hash Functions:** SHA-256 (FIPS 180-4)
- **Authorization Model:** Capability-based security
- **Audit Trail:** Write-once, read-many (WORM) principle

---

**Document Version:** 1.0  
**Last Updated:** 2026-09-26  
**Classification:** Internal
