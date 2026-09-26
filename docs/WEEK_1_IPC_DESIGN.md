# Inter-Process Communication (IPC) Design (Week 1 Task 3)

**Status:** Design phase – Week 1  
**Owner:** Systems Engineers + Lead Architect  
**Timeline:** Week 1 (design + implementation)  
**Target LOC:** 800–1,200 (implementation)  

---

## Executive Summary

**IPC** implements the 22 critical interfaces (IF-001 through IF-022) that enable principals to communicate securely:
1. Named pipes (FIFOs) as transport
2. Message authentication (Ed25519 signatures)
3. Nonce caching for replay detection
4. Peer credential validation (SO_PEERCRED)
5. Timeout handling with fail-safe defaults

IPC is the communication backbone; all principal interactions depend on it (Week 1 blocker).

---

## Architecture

### 1. Interface Definitions (From Phase 1 Catalog)

**Example: IF-002 (Policy → Audit Logging)**
```
Initiator: PRN-POLICY
Recipient: PRN-AUDIT
Direction: One-way (request only)
Message Type: OBSERVATION (artifact structure)
Authentication: Ed25519 signature (CRITICAL)
Purpose: Policy logs observation to SecurityLedger
Frequency: 10–100 requests/second
Timeout: 100ms (fail-safe: retry 3x, then log ERROR)
```

**Example: IF-004 (Declassifier Decision)**
```
Initiator: PRN-DECLASSIFIER
Recipient: PRN-POLICY
Direction: Two-way (request + response)
Message Type: DECLASSIFICATION_REQUEST
Authentication: Nonce + signature (CRITICAL)
Purpose: Declassifier approves/denies declassification
Frequency: 1–10 requests/minute
Timeout: 5s (fail-safe: DENY on timeout)
Idempotent: Yes (same request_id → same response)
```

**All 22 Interfaces:**
- IF-001: Supervisor → Policy (startup)
- IF-002: Policy → Audit (observe)
- IF-003: Policy → Actuator (execute action)
- IF-004: Declassifier → Policy (declassify decision)
- IF-005: Actuator → Policy (action complete)
- IF-006: Learner → Audit (learning query)
- IF-007: Evaluator → Audit (evaluation query)
- IF-008: Sealer → Audit (seal evidence)
- IF-009: Sealer → Policy (update seal status)
- IF-010: Developer → Supervisor (introspection)
- IF-011: All → Audit (log to SecurityLedger)
- IF-012: Policy → Declassifier (declassify request)
- IF-013: Actuator → Supervisor (heartbeat)
- IF-014: Supervisor → All (broadcast shutdown)
- IF-015: All → HSM (sign request)
- IF-016: Audit → Auditor (forensic query)
- IF-017: Auditor → Supervisor (Gate I verification)
- IF-018: All → SecurityLedger (verify chain)
- IF-019: Sealer → All (broadcast seal complete)
- IF-020: Policy → Developer (introspection query)
- IF-021: Evaluator → Declassifier (evaluation result)
- IF-022: Learner → Sealer (model update)

---

### 2. Named Pipes (FIFO) Transport

**Naming Convention:**
```
/var/run/geometry-dash/if{number:03d}-{sender}-to-{receiver}
```

**Example Pipes for IF-002 (Policy → Audit):**
- `/var/run/geometry-dash/if002-policy-to-audit` (request)
- `/var/run/geometry-dash/if002-audit-to-policy` (response)

**Permissions:**
- Owner: root
- Mode: 0600 (readable/writable only by Supervisor and principals)
- Supervisor creates all pipes at startup

**Reliability Guarantees:**
- Atomic write: Messages ≤4KB written atomically on Linux
- Ordering: Messages delivered in order (FIFO)
- No duplication: OS kernel prevents duplicate reads
- Timeout: Non-blocking read with timeout (using select/poll)

---

### 3. Message Format (Universal Header)

**Rust Struct:**
```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UniversalMessageHeader {
    pub interface_id: u32,           // IF-001 through IF-022
    pub protocol_version: u8,         // v1
    pub message_type: u8,             // 0=REQUEST, 1=RESPONSE, 2=EVENT, 3=ERROR
    pub flags: u32,                   // Bit flags (see below)
    pub sender_principal: u8,         // PRN enum (0-8)
    pub receiver_principal: u8,       // PRN enum (0-8)
    pub message_id: u64,              // Unique per interface (incremental)
    pub request_id: u64,              // For matching requests ↔ responses
    pub nonce: [u8; 32],              // 256-bit random (replay detection)
    pub timestamp_ns: u64,            // Monotonic ns (REQ-EVIDENCE-004)
    pub witness_principal: u8,        // Signer (usually = sender_principal)
    pub witness_signature: [u8; 64],  // Ed25519 signature over serialized message
    pub source_evidence_id: Option<String>,  // Artifact ID if applicable
    pub sequence_number: u64,         // For ordering within interface
}

pub struct UniversalMessage {
    pub header: UniversalMessageHeader,
    pub payload: Vec<u8>,             // Interface-specific data
}

// Message flags (bit 0-31)
pub const FLAG_REQUIRES_AUTH: u32 = 0x01;      // Signature mandatory
pub const FLAG_REQUIRES_NONCE: u32 = 0x02;     // Nonce cache check
pub const FLAG_REQUIRES_RESPONSE: u32 = 0x04;  // Expect response
pub const FLAG_IDEMPOTENT: u32 = 0x08;         // Safe to retry
pub const FLAG_PRIORITY_HIGH: u32 = 0x10;      // Expedite processing
pub const FLAG_CRITICAL: u32 = 0x20;           // Audit-critical (log at CRITICAL)
```

**JSON Serialization Example:**
```json
{
  "header": {
    "interface_id": 2,
    "protocol_version": 1,
    "message_type": 0,
    "flags": 3,
    "sender_principal": 1,
    "receiver_principal": 3,
    "message_id": 456,
    "request_id": 456,
    "nonce": "a1b2c3d4e5f6...",
    "timestamp_ns": 1695226800123456789,
    "witness_principal": 1,
    "witness_signature": "e3b0c44298fc...",
    "source_evidence_id": "artifact-001",
    "sequence_number": 45
  },
  "payload": "..."
}
```

**Serialization (Week 1 Task 3.1):**
- JSON for easy debugging
- Size limit: 1MB per message (enforced)
- Null-termination: `\0` marks end of message in FIFO

---

### 4. Authentication & Authorization

**Signature Verification (REQ-AUTHN-001):**
1. Extract message (excluding signature field)
2. Hash with SHA-256
3. Verify Ed25519 signature using sender's public key
4. Log result to SecurityLedger

**Public Key Management:**
- Keys frozen in config (Week 0)
- One per principal
- Loaded at startup, no runtime changes
- Config immutable post-Gate C (Week 11)

**Authorization (REQ-AUTHZ-001):**
- Supervisor maintains capability matrix
- Each principal has list of allowed interfaces (IF-001, IF-003, IF-011, etc)
- IPC layer checks: `if capabilities[sender][interface_id] != ALLOW { DENY }`
- Denial logged as CRITICAL

---

### 5. Nonce Caching (Replay Detection)

**Cache Structure:**
```rust
pub struct NonceCache {
    cache: HashMap<[u8; 32], NonceEntry>,
    ttl: Duration,  // max_message_age_ns + 5s (from config)
}

struct NonceEntry {
    timestamp_ns: u64,
    interface_id: u32,
    message_id: u64,
    sender_principal: u8,
}
```

**Detection (REQ-CRYPTO-005):**
1. Receive message with nonce
2. Query cache: `cache.get(nonce)`
3. If found + timestamp_ns < entry.timestamp_ns + ttl: REJECT (NONCE_REJECTED)
4. If not found: ACCEPT, add to cache
5. Expire old entries (TTL-based eviction)

**Size Limits:**
- Max cache entries: 100,000
- Eviction policy: LRU (least recently used)
- Memory per entry: ~60 bytes → 6MB max

---

### 6. Peer Credential Validation

**Unix Domain Sockets (Bonus: Week 1 Task 3.3)**
- Alternative transport for same message format
- Uses `SO_PEERCRED` to verify sender UID/GID
- More efficient than named pipes (bidirectional)
- Fallback: Named pipes if socket unavailable

**Validation:**
```rust
fn verify_peer_cred(fd: i32, expected_uid: u32) -> Result<(), String> {
    let cred = get_peer_credentials(fd)?;
    if cred.uid != expected_uid {
        return Err(format!("UID mismatch: {} != {}", cred.uid, expected_uid));
    }
    Ok(())
}
```

---

### 7. Timeout & Fail-Safe Handling

**Read Timeout (REQ-RELIABILITY-001):**
```rust
fn read_with_timeout(
    fd: i32,
    timeout_ms: u64,
) -> Result<UniversalMessage, IpcError> {
    let mut fds = [pollfd { fd, events: POLLIN, revents: 0 }];
    match poll(&mut fds, timeout_ms as i32) {
        -1 => Err(IpcError::PollError),
        0 => Err(IpcError::Timeout),  // ← Triggers fail-safe
        _ => read_message(fd),
    }
}
```

**Fail-Safe Actions:**
- IF-003 (execute action): RELEASE action (execute immediately)
- IF-004 (declassify): DENY (don't declassify on timeout)
- IF-011 (audit log): Retry 3x, then drop event (log ERROR)
- IF-014 (shutdown): Force shutdown (SIGKILL) after 1s timeout

---

## Week 1 Task Breakdown

### Task 3.1: Message Format & Serialization (1 day)
- Define UniversalMessageHeader struct
- Implement JSON serialization (serde)
- Define payload types for each interface
- Create message validation function

**Deliverable:** `src/ipc/message.rs` (300–400 LOC)

### Task 3.2: Named Pipes Transport (1.5 days)
- Implement FIFO creation (Supervisor)
- Implement write/read functions
- Implement timeout handling (select/poll)
- Test atomic writes

**Deliverable:** `src/ipc/pipes.rs` (400–500 LOC)

### Task 3.3: Authentication & Nonce Cache (1.5 days)
- Implement signature verification (Ed25519)
- Implement nonce cache (HashMap + TTL)
- Implement replay detection
- Implement capability matrix check

**Deliverable:** `src/ipc/auth.rs` (300–400 LOC)

### Task 3.4: Peer Credential Validation (0.5 day)
- Implement SO_PEERCRED validation
- Bonus: Unix domain socket transport
- Test UID/GID matching

**Deliverable:** `src/ipc/credentials.rs` (150–200 LOC)

### Task 3.5: Unit Tests (1 day)
- Test message serialization (JSON)
- Test pipe creation and cleanup
- Test timeout detection
- Test nonce cache (insert, lookup, expiry)
- Test signature verification (valid, forged, missing)

**Deliverable:** `tests/unit/ipc_test.rs` (600+ LOC, 30+ test cases)

### Task 3.6: Integration Tests (1 day)
- Test IPC with 2+ mock principals
- Test message flow (request → response)
- Test replay attack detection
- Test timeout recovery

**Deliverable:** `tests/integration/ipc_integration_test.rs` (400+ LOC, 10+ test cases)

---

## Success Criteria (Week 1 End)

- [ ] IPC library compiles (no warnings)
- [ ] Message round-trip latency <10ms (measured)
- [ ] Throughput ≥1,000 messages/sec sustained
- [ ] Signature verification works on all 22 interfaces
- [ ] Nonce cache prevents 100% of replay attacks
- [ ] Timeout detection works <100ms
- [ ] Peer credential validation works on Unix sockets
- [ ] All unit + integration tests pass (100% coverage)
- [ ] API stable (no breaking changes to UniversalMessage)

---

## Integration Points

| Module | Interface | Week | Notes |
|--------|-----------|------|-------|
| Supervisor | IF-001, IF-014 | 1 | Startup, shutdown signals |
| SecurityLedger | IF-011 | 1 | Audit logging |
| Policy | IF-002–004 | 2 | Decision-making |
| Actuator | IF-005, IF-013 | 3 | Action execution |
| All | IF-015 (HSM sign) | 1.5 | Message signing |

---

## Known Risks

| Risk | Mitigation | Owner |
|------|-----------|-------|
| Named pipe fills up (message loss) | Size limits + error handling | Systems Eng |
| Signature verification overhead | Batch verification | Crypto Eng |
| Nonce cache collision | 256-bit random (< 1e-77 probability) | Design |
| Socket descriptor exhaustion | Ulimit config, cleanup on crash | Ops |
| Message ordering violation | IPC layer enforces ordering | Implementation |

---

## Document Control

| Version | Date | Status |
|---------|------|--------|
| 1.0 | 2026-09-26 | Week 1 design |

**Next Update:** Week 2 (after Task 3.1–3.6 completion)
