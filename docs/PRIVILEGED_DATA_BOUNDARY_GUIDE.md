# Privileged Data Boundary Implementation Guide (SEC-C01)

## Executive Summary

This guide documents the implementation of SEC-C01 remediation: a multi-layered system for enforcing privileged data boundaries across the Geometry Dash security infrastructure. The system prevents sensitive telemetry (physics probes, rewards) from flowing into policy-safe contexts through classification, access control, and controlled declassification workflows.

**Status:** ✅ Sprint 2 Complete  
**Commits:** e934657 (Task 2.4), 2535b8f (Task 2.5), 1ad66b8 (Task 2.6)  
**Remediation Target:** SEC-C01 (Privileged Data Boundary)  
**Remaining Work:** HSM integration for production signing (Sprint 3+)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Classification System](#classification-system)
3. [Access Control Engine](#access-control-engine)
4. [Declassification Engine](#declassification-engine)
5. [Data Lineage Tracking](#data-lineage-tracking)
6. [IPC Message Classification](#ipc-message-classification)
7. [API Reference](#api-reference)
8. [Operational Procedures](#operational-procedures)
9. [Troubleshooting](#troubleshooting)
10. [Performance Characteristics](#performance-characteristics)

---

## Architecture Overview

### High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Privileged Data Boundary System              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐      ┌──────────────────┐                │
│  │  Source System   │      │  Classification  │                │
│  │  (Physics, Env)  │─────→│    Registry      │                │
│  └──────────────────┘      │                  │                │
│                             │  • Labels       │                │
│                             │  • Metadata     │                │
│                             │  • Audit Trail  │                │
│                             └────────┬────────┘                │
│                                      │                         │
│                             ┌────────▼──────────┐              │
│                             │  Access Control   │              │
│                             │  Engine           │              │
│                             │                   │              │
│                             │ • Clearances      │              │
│                             │ • Authorization   │              │
│                             │ • Audit Logging   │              │
│                             └────────┬──────────┘              │
│                                      │                         │
│                          ┌───────────┴──────────┐              │
│                          ▼                      ▼              │
│                   ┌─────────────┐      ┌──────────────────┐    │
│                   │ Denied      │      │Declassification  │    │
│                   │ Access      │      │Engine            │    │
│                   │ (Audit Log) │      │                  │    │
│                   └─────────────┘      │ • Policy Mgmt    │    │
│                                        │ • Transformation │    │
│                                        │ • Record Creation│    │
│                                        └────────┬─────────┘    │
│                                                 │              │
│                                        ┌────────▼──────────┐   │
│                                        │  SecurityLedger   │   │
│                                        │  (Classified)     │   │
│                                        │                   │   │
│                                        │ • Event Log       │   │
│                                        │ • Lineage Chain   │   │
│                                        │ • Hash Chain      │   │
│                                        └────────┬──────────┘   │
│                                                 │              │
│                          ┌──────────────────────┴──────────┐   │
│                          ▼                                 ▼   │
│                   ┌───────────────┐          ┌──────────────┐ │
│                   │ IPC Messages  │          │ Policy/      │ │
│                   │ (Classified)  │          │ Learner      │ │
│                   │               │          │ (Safe)       │ │
│                   │ • Classification         └──────────────┘ │
│                   │ • Clearance               (No privileged   │
│                   │ • Authorization           telemetry)      │
│                   └───────────────┘                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Core Components

**1. Classification System**
- Applies labels to sensitive fields
- Tracks metadata (principal, timestamp, justification)
- Provides registry for label lookup and audit
- 4-level hierarchy: Unrestricted, SensitiveReward, PrivilegedTelemetry, Internal

**2. Access Control Engine**
- Enforces per-principal clearance levels
- Maintains principal-to-clearance mapping
- Logs all access attempts (allow and deny)
- Validates declassification authorization

**3. Declassification Engine**
- Manages declassification policies
- Applies transformations (hash_sha256, passthrough)
- Creates immutable audit records
- Tracks lineage chain with parent references

**4. Data Lineage System**
- Integrates with SecurityLedger
- Records all declassification operations
- Maintains chain of custody
- Enables complete audit trail reconstruction

**5. IPC Message Classification**
- Adds classification metadata to messages
- Enforces receiver clearance validation
- Marks declassified payloads
- Prevents unauthorized principal access

---

## Classification System

### Overview

The classification system assigns sensitivity levels to data fields and tracks all classification decisions in an immutable audit trail.

### Classification Levels

| Level | Name | Description | Usage |
|-------|------|-------------|-------|
| 0 | Unrestricted | No sensitivity constraints | Default for all unclassified data |
| 1 | SensitiveReward | Contains reward signal information | Reward values, signals (Learner cleared) |
| 2 | PrivilegedTelemetry | Physics probes, environment state | High-frequency telemetry (Audit only) |
| 3 | Internal | Implementation secrets, keys | System internals (Developer/Audit only) |

### API Reference

#### ClassificationLabel

```rust
pub struct ClassificationLabel {
    pub label_id: String,              // Unique identifier
    pub field_name: String,            // Field being classified
    pub level: ClassificationLevel,    // Classification level
    pub applied_by: Principal,         // Principal that applied label
    pub applied_timestamp_ns: u64,    // When label was applied (ns since epoch)
    pub justification: String,         // Why this classification
}
```

#### ClassificationRegistry

```rust
// Apply classification to a field
pub fn apply_classification(
    &self,
    field_name: String,
    level: ClassificationLevel,
    principal: Principal,
    justification: String,
) -> Result<ClassificationLabel, String>

// Get label for a field
pub fn get_label(&self, field_name: &str) -> Result<Option<ClassificationLabel>, String>

// List all labels
pub fn list_labels(&self) -> Vec<ClassificationLabel>

// Get audit trail
pub fn statistics(&self) -> (usize, u64)  // (label_count, total_record_count)
```

### Example Usage

```rust
use geometry_dash::{ClassificationRegistry, ClassificationLevel, Principal};
use std::sync::Arc;

let registry = ClassificationRegistry::new(Arc::new(ledger));

// Classify physics probe data
let label = registry.apply_classification(
    "physics_probe_x".to_string(),
    ClassificationLevel::PrivilegedTelemetry,
    Principal::Audit,
    "Real-time physics probe data requires containment".to_string(),
)?;

println!("Classified field: {} (level: {:?})", label.field_name, label.level);

// Retrieve label
let retrieved = registry.get_label("physics_probe_x")?;
```

---

## Access Control Engine

### Overview

The access control engine enforces per-principal clearance levels and logs all access attempts for audit purposes.

### Clearance Levels by Principal

| Principal | Clearance Levels | Notes |
|-----------|------------------|-------|
| Policy | [Unrestricted] | Policy-safe context, no privileged access |
| Learner | [Unrestricted, SensitiveReward] | ML training requires reward signals |
| Audit | All 4 levels | Auditors need full visibility |
| Actuator | [Unrestricted] | Actions based on policy only |
| Developer | All 4 levels | Debugging and introspection |
| Supervisor | [Unrestricted] | System management only |
| Sealer | All 4 levels | Evidence verification |
| Evaluator | [Unrestricted, SensitiveReward] | Policy evaluation requires reward |
| Declassifier | [Unrestricted, SensitiveReward, PrivilegedTelemetry] | Data reduction operations |

### API Reference

```rust
pub struct AccessControlEngine {
    principal_clearances: HashMap<Principal, Vec<ClassificationLevel>>,
    declassifier_roles: HashMap<String, Vec<Principal>>,
    access_log: Arc<Mutex<Vec<AccessAttempt>>>,
}

impl AccessControlEngine {
    // Check if principal can read at this level
    pub fn can_read(
        &self,
        principal: Principal,
        level: ClassificationLevel,
    ) -> Result<bool, String>

    // Check if principal can declassify
    pub fn can_declassify(
        &self,
        principal: Principal,
        policy: &DeclassificationPolicy,
    ) -> Result<bool, String>

    // Log and check read access
    pub fn check_read(
        &self,
        principal: Principal,
        level: ClassificationLevel,
    ) -> Result<(), String>

    // Log and check declassify access
    pub fn check_declassify(
        &self,
        principal: Principal,
        policy: &DeclassificationPolicy,
    ) -> Result<(), String>

    // Access log queries
    pub fn denied_attempts(&self) -> Vec<AccessAttempt>
    pub fn allowed_attempts(&self) -> Vec<AccessAttempt>
}
```

### Example Usage

```rust
let access_control = AccessControlEngine::new();

// Check read authorization
match access_control.check_read(
    Principal::Learner,
    ClassificationLevel::SensitiveReward,
) {
    Ok(()) => println!("Access granted"),
    Err(e) => println!("Access denied: {}", e),
}

// Check declassification authorization
match access_control.check_declassify(Principal::Audit, &policy) {
    Ok(()) => println!("Declassification authorized"),
    Err(e) => println!("Declassification denied: {}", e),
}
```

---

## Declassification Engine

### Overview

The declassification engine manages policies for data reduction and applies transformations to sensitive fields while maintaining complete audit trails.

### Policy Structure

```rust
pub struct DeclassificationPolicy {
    pub policy_id: String,
    pub version: u32,
    pub field_name: String,
    pub source_level: ClassificationLevel,      // e.g., PrivilegedTelemetry
    pub target_level: ClassificationLevel,      // e.g., SensitiveReward
    pub transformation: Option<String>,         // "hash_sha256" or "passthrough"
    pub approved_by: Vec<Principal>,           // Min 2 approvals required
    pub effective_timestamp_ns: u64,
    pub expires_timestamp_ns: Option<u64>,
}

pub struct DeclassificationRecord {
    pub record_id: String,
    pub field_name: String,
    pub original_value_hash: [u8; 32],         // SHA-256 of original
    pub declassified_value_hash: [u8; 32],     // SHA-256 of result
    pub policy_id: String,
    pub applied_by: Principal,
    pub timestamp_ns: u64,
    pub lineage: Vec<String>,                  // Parent record IDs
}
```

### Supported Transformations

**hash_sha256**: Cryptographically irreversible hash
- Input: Arbitrary bytes
- Output: 32-byte SHA-256 hash
- Use case: Reward signals (only need to know they were reduced)

**passthrough**: Direct value (requires higher security)
- Input: Arbitrary bytes
- Output: Same bytes
- Use case: Metadata that needs original value but within a policy-safe context

### API Reference

```rust
pub impl DeclassificationEngine {
    // Register a policy (requires 2+ approvals)
    pub fn register_policy(
        &self,
        policy_id: String,
        version: u32,
        field_name: String,
        source_level: ClassificationLevel,
        target_level: ClassificationLevel,
        transformation: Option<String>,
        approved_by: Vec<Principal>,          // Min 2
        effective_timestamp_ns: u64,
        expires_timestamp_ns: Option<u64>,
    ) -> Result<DeclassificationPolicy, String>

    // Apply declassification
    pub fn declassify(
        &self,
        principal: Principal,
        policy_id: &str,
        original_value: &[u8],
        source_level: ClassificationLevel,
        parent_records: Vec<String>,          // Lineage
    ) -> Result<(Vec<u8>, DeclassificationRecord), String>

    // Retrieve policy
    pub fn get_policy(&self, policy_id: &str) -> Result<Option<DeclassificationPolicy>, String>

    // History queries
    pub fn get_declassification_history(
        &self,
        principal: Principal,
    ) -> Result<Vec<DeclassificationRecord>, String>

    pub fn get_field_declassifications(
        &self,
        field_name: &str,
    ) -> Result<Vec<DeclassificationRecord>, String>
}
```

### Example Usage

```rust
// Create engine
let access_control = AccessControlEngine::new();
let engine = DeclassificationEngine::new(access_control);

// Register policy
let policy = engine.register_policy(
    "reward_hash_policy".to_string(),
    1,
    "reward_value".to_string(),
    ClassificationLevel::PrivilegedTelemetry,
    ClassificationLevel::SensitiveReward,
    Some("hash_sha256".to_string()),
    vec![Principal::Audit, Principal::Learner],  // 2 approvals
    now_ns,
    None,  // No expiration
)?;

// Apply declassification
let (hashed_value, record) = engine.declassify(
    Principal::Audit,
    "reward_hash_policy",
    b"0.95",
    ClassificationLevel::PrivilegedTelemetry,
    vec!["original_label_id".to_string()],  // Lineage
)?;

println!("Original: {:?}", b"0.95");
println!("Declassified (hash): {}", hex::encode(hashed_value));
println!("Record ID: {}", record.record_id);
```

---

## Data Lineage Tracking

### Overview

The data lineage system tracks the complete history of all declassification operations, enabling auditors to trace sensitive data through its reduction and transformation.

### SecurityLedger Enhancements

The SecurityLedger now stores classification metadata for all events:

```rust
pub struct SecurityEvent {
    // ... existing fields ...
    
    pub classification_level: Option<ClassificationLevel>,
    pub declassification_parent: Option<String>,  // Parent record ID
    pub data_lineage: Option<Vec<String>>,        // Full chain
}
```

### API Reference

```rust
pub impl SecurityLedger {
    // Append event with classification metadata
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

    // Retrieve lineage chain for a parent ID
    pub fn get_lineage(
        &self,
        declassification_parent: &str,
    ) -> std::io::Result<Option<Vec<SecurityEvent>>>

    // Get all classified events for a principal
    pub fn get_principal_classified_events(
        &self,
        principal: Principal,
    ) -> std::io::Result<Vec<SecurityEvent>>
}
```

### Lineage Chain Structure

```
Original Data (Internal, PrivilegedTelemetry)
           │
           ├─→ [Declassification 1] 
           │   Label: "physics_probe_original"
           │   Policy: "probe_to_reward"
           │   Result: Physics probe hash
           │
           └─→ [Declassification 2]
               Parent: Declassification 1
               Policy: "intermediate_reduction"
               Result: Aggregated statistical summary
               
Event Log Entry:
{
  "ledger_index": 42,
  "event_type": "ARTIFACT_DECLASSIFIED",
  "principal": "PRN-AUDIT",
  "classification_level": "SENSITIVE_REWARD",
  "declassification_parent": "decl-001",
  "data_lineage": [
    "original-label",
    "decl-001",
    "decl-002"
  ],
  "timestamp_ns": 1234567890000
}
```

### Example Usage

```rust
// Log a declassification to the ledger
ledger.append_classified_event(
    EventType::ArtifactDeclassified,
    Principal::Audit,
    Severity::Info,
    run_id,
    boot_id,
    epoch_id,
    ClassificationLevel::SensitiveReward,
    Some("decl-001".to_string()),
    Some(vec![
        "original-label".to_string(),
        "decl-001".to_string(),
    ]),
    HashMap::new(),
)?;

// Retrieve complete lineage
let lineage = ledger.get_lineage("decl-001")?;
if let Some(events) = lineage {
    for event in events {
        println!("Lineage event: {} (index: {})", 
                 event.event_type, 
                 event.ledger_index);
    }
}
```

---

## IPC Message Classification

### Overview

The IPC layer enforces classification boundaries at the message transport level, preventing classified payloads from reaching unauthorized principals.

### Message Header Extensions

```rust
pub struct UniversalMessageHeader {
    // ... existing fields ...
    
    pub classification_level: Option<ClassificationLevel>,
    pub required_clearance: Option<ClassificationLevel>,
    pub declassification_approved: Option<bool>,
}
```

### API Reference

```rust
pub impl UniversalMessageHeader {
    // Set payload classification
    pub fn set_classification(&mut self, level: ClassificationLevel)

    // Set minimum clearance to process message
    pub fn set_required_clearance(&mut self, level: ClassificationLevel)

    // Mark as declassified
    pub fn mark_declassified(&mut self)

    // Validate receiver authorization
    pub fn authorize_receiver(
        &self,
        principal_clearances: &[(u8, Vec<ClassificationLevel>)],
    ) -> bool
}
```

### Example Usage

```rust
// Create classified message
let mut header = UniversalMessageHeader::new(
    IF_DECLASSIFIER,
    MESSAGE_TYPE_REQUEST,
    Principal::Audit as u8,
    Principal::Learner as u8,
    FLAG_REQUIRES_AUTH,
);

// Set classification metadata
header.set_classification(ClassificationLevel::SensitiveReward);
header.set_required_clearance(ClassificationLevel::SensitiveReward);
header.mark_declassified();

// Validate receiver authorization
let clearances = vec![
    (Principal::Learner as u8, vec![
        ClassificationLevel::Unrestricted,
        ClassificationLevel::SensitiveReward,
    ]),
];

if header.authorize_receiver(&clearances) {
    // Safe to send
    let msg = UniversalMessage {
        header,
        payload: declassified_data,
    };
} else {
    // Receiver lacks clearance
    return Err("Unauthorized receiver");
}
```

---

## Operational Procedures

### 1. Classifying New Fields

**Pre-requisites:**
- Identified field contains sensitive data
- Classification level determined
- Justification documented

**Steps:**
1. Get ClassificationRegistry reference
2. Call `apply_classification()` with field details
3. Store returned label ID for lineage tracking
4. Log classification decision to SecurityLedger

**Example:**

```rust
let label = registry.apply_classification(
    "episode_reward".to_string(),
    ClassificationLevel::PrivilegedTelemetry,
    Principal::Audit,
    "Episodic return signals require containment".to_string(),
)?;

// Log to ledger
ledger.append_event(
    EventType::ConfigLoaded,
    Principal::Audit,
    Severity::Info,
    run_id, boot_id, epoch_id,
    {
        let mut details = HashMap::new();
        details.insert("classification".to_string(), "applied".to_string());
        details.insert("field".to_string(), label.field_name);
        details.insert("level".to_string(), format!("{:?}", label.level));
        details
    },
)?;
```

### 2. Creating Declassification Policies

**Pre-requisites:**
- Source classification level known
- Target classification level appropriate
- Transformation method selected
- 2+ approvers identified

**Steps:**
1. Design policy (source → target + transformation)
2. Get approval from min 2 principals
3. Call `register_policy()` with approval list
4. Verify policy accepted

**Example:**

```rust
let policy = engine.register_policy(
    "probe_to_summary".to_string(),
    1,  // version
    "physics_probe_x".to_string(),
    ClassificationLevel::PrivilegedTelemetry,
    ClassificationLevel::SensitiveReward,
    Some("hash_sha256".to_string()),
    vec![Principal::Audit, Principal::Learner],  // 2 approvals
    now_ns,
    Some(now_ns + 90 * 24 * 3600 * 1_000_000_000),  // 90-day expiry
)?;
```

### 3. Performing Declassification

**Pre-requisites:**
- Declassification policy exists and is active
- Principal has declassification authorization
- Original value and source classification available
- Lineage parent IDs documented

**Steps:**
1. Verify authorization (access control engine)
2. Call `declassify()` with value and lineage
3. Receive transformed value and record
4. Log operation to SecurityLedger
5. Send declassified value via classified IPC message

**Example:**

```rust
// Step 1: Declassify
let (hashed, record) = engine.declassify(
    Principal::Audit,
    "probe_to_summary",
    original_value,
    ClassificationLevel::PrivilegedTelemetry,
    vec![original_label.label_id],
)?;

// Step 2: Log to ledger
ledger.append_classified_event(
    EventType::ArtifactDeclassified,
    Principal::Audit,
    Severity::Info,
    run_id, boot_id, epoch_id,
    ClassificationLevel::SensitiveReward,
    Some(record.record_id.clone()),
    Some(vec![original_label.label_id]),
    HashMap::new(),
)?;

// Step 3: Send via classified IPC
let mut header = UniversalMessageHeader::new(
    IF_TO_LEARNER, MESSAGE_TYPE_REQUEST,
    Principal::Audit as u8,
    Principal::Learner as u8,
    FLAG_REQUIRES_AUTH,
);
header.set_classification(ClassificationLevel::SensitiveReward);
header.set_required_clearance(ClassificationLevel::SensitiveReward);
header.mark_declassified();

let msg = UniversalMessage { header, payload: hashed };
```

### 4. Auditing Declassification Chain

**Procedure:**
1. Identify target declassification parent ID
2. Query ledger for lineage
3. Iterate through lineage events
4. Verify each transformation step
5. Check all operations are authorized

**Example:**

```rust
// Retrieve complete lineage
let events = ledger.get_lineage("decl-001")?.unwrap();

for event in events {
    println!("Event {}: {:?}", event.ledger_index, event.event_type);
    if let Some(lineage) = event.get_lineage() {
        println!("  Lineage chain: {:?}", lineage);
    }
    if event.is_declassified() {
        println!("  Status: Declassified");
    }
}
```

---

## Troubleshooting

### Issue: "Access Denied" on Declassification

**Symptom:** `declassify()` returns "not authorized to declassify"

**Root Causes:**
1. Principal lacks declassification clearance (not in policy approvers)
2. Policy not registered or not found
3. Policy expired or not yet effective

**Resolution:**
1. Check principal clearances: `access_control.principal_clearances.get(&principal)`
2. Verify policy exists: `engine.get_policy(policy_id)`
3. Check timestamps: `policy.is_valid(now_ns)`
4. Register new policy with appropriate approvals if needed

### Issue: Insufficient Clearance on IPC Reception

**Symptom:** `authorize_receiver()` returns false on valid message

**Root Causes:**
1. Receiver principal not in clearance list
2. Receiver's clearance doesn't include required level
3. Message clearance requirement too high for receiver

**Resolution:**
1. Verify receiver principal in `principal_clearances` list
2. Check clearance levels contain required level
3. Review message `required_clearance` setting
4. Adjust policy target level if declassification too restrictive

### Issue: Lineage Chain Broken

**Symptom:** `get_lineage()` returns None or incomplete chain

**Root Causes:**
1. Parent ID doesn't match any declassification record
2. Event wasn't logged to ledger
3. Ledger file corrupted or truncated

**Resolution:**
1. Verify parent ID: `engine.get_declassification_history(principal)`
2. Confirm ledger append succeeded (check return value)
3. Run `ledger.verify_chain()` to check integrity
4. If corrupted, restore from backup

### Issue: Performance Degradation

**Symptom:** Declassification operations slow down over time

**Root Causes:**
1. Ledger file growing large (many events)
2. Hash chain computation expensive on large ledgers
3. Access log growing unbounded

**Resolution:**
1. Monitor ledger size: `ledger.count()` events
2. Consider archiving old ledger segments
3. Implement periodic cleanup: `access_control.log.clear()` (with caution)
4. Cache frequently accessed policies

### Issue: Policy Validation Failures

**Symptom:** `register_policy()` returns errors

**Root Causes:**
1. Fewer than 2 approvals provided
2. Source/target levels invalid
3. Transformation name invalid
4. Timestamp values inconsistent

**Resolution:**
1. Ensure `approved_by.len() >= 2`
2. Validate levels are from ClassificationLevel enum
3. Use "hash_sha256" or "passthrough" for transformation
4. Ensure `effective_timestamp_ns <= expires_timestamp_ns`

---

## Performance Characteristics

### Declassification Operations

| Operation | Complexity | Time (est.) |
|-----------|-----------|------------|
| `apply_classification()` | O(1) | <1ms |
| `can_read()` | O(n) | <1ms (n=principals) |
| `can_declassify()` | O(n) | <1ms (n=approvals) |
| `declassify()` | O(m) | <1ms (m=lineage length) |
| Hash transformation | O(size) | 1-10μs per KB |
| Passthrough transformation | O(1) | <1μs |
| `get_lineage()` | O(events) | <100ms |

### Storage Requirements

| Component | Per-Operation Storage |
|-----------|----------------------|
| Label | ~200 bytes |
| Policy | ~500 bytes |
| Record | ~300 bytes |
| Ledger event | ~1 KB |
| Access log entry | ~100 bytes |

### Scalability

- **Concurrent Operations:** Thread-safe via Arc<Mutex<>>
- **Ledger Growth:** Linear; ~1 GB per 1M events
- **Principal Count:** O(n) lookup, n typically ~10
- **Policy Count:** O(1) via HashMap

---

## Integration with Existing Systems

### SecurityLedger Integration

Classified events integrate seamlessly with existing SecurityLedger:

```rust
// Regular event
ledger.append_event(EventType::ActionExecuted, ...)?;

// Classified event
ledger.append_classified_event(
    EventType::ArtifactDeclassified,
    Principal::Audit,
    Severity::Info,
    ...,
    ClassificationLevel::SensitiveReward,
    Some("parent-id"),
    Some(lineage),
    ...
)?;

// Both appear in same ledger, hash chain preserved
```

### IPC Integration

Classification flows naturally through message transport:

```rust
// Create request with sensitive data
let mut msg = UniversalMessage::new(...);
msg.header.set_classification(ClassificationLevel::PrivilegedTelemetry);
msg.header.set_required_clearance(ClassificationLevel::PrivilegedTelemetry);

// IPC layer checks authorization on send/receive
if msg.header.authorize_receiver(&principal_clearances) {
    send_message(msg)?;
} else {
    return Err("Unauthorized receiver");
}
```

---

## Future Enhancements

### Short-Term (Sprint 3)
1. **HSM Signing:** Real Ed25519 signatures via HSM client
2. **Policy Expiration Enforcement:** Automatic policy invalidation
3. **Batch Declassification:** Process multiple fields in one operation
4. **Policy Versioning:** Support policy updates with version tracking

### Long-Term (Sprint 4+)
1. **Encryption:** AES-256-GCM for declassified value confidentiality
2. **Byzantine Tolerance:** Multiple Sealer signatures for evidence
3. **Timestamping Authority:** External timestamp verification
4. **Dynamic Clearance:** Time-based and event-based clearance changes
5. **Differential Privacy:** Noise injection for reward aggregation

---

## References

- SEC-C01 Remediation Requirement
- Sprint 2 Implementation Status: 6/6 tasks complete
- Related: DECLASSIFICATION_CONTRACTS.md (formal specifications)
- Related: DATA_LINEAGE_DEPLOYMENT.md (operational procedures)
- Evidence Sealing Guide: EVIDENCE_SEALING_GUIDE.md (SEC-C02)

---

**Document Version:** 1.0  
**Last Updated:** 2026-09-26  
**Author:** Claude Haiku 4.5  
**Classification:** Internal (Documentation)
