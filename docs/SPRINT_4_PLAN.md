# Sprint 4 Plan: SEC-C04 Actuator TOCTOU Prevention

**Status**: Planning  
**Timeline**: Week 4 (1 week, 5 days intensive)  
**Focus**: Eliminating Time-of-Check/Time-of-Use vulnerabilities in Actuator command execution  
**Architecture Phase**: Phase 2 - Privileged Data Boundary Protection  

---

## Executive Summary

Sprint 4 implements cryptographic token-based execution to eliminate TOCTOU (Time-of-Check/Time-of-Use) vulnerabilities in the Actuator principal's command execution pipeline. The system prevents command revocation after validation, ensures atomic validation-to-execution transitions, and enables forensic tracking of all state changes that affect authorization decisions.

---

## Security Problem: TOCTOU in Command Execution

### Current Vulnerability

In Actuator's `execute_command()` flow (src/principals/actuator.rs:287-348):

```rust
1. Gate C validation (line 290): Is this command allowed?
2. Gate I validation (line 291): Is this message authentic?
3. Decision (line 295):       if success { perform_action() }
4. Action execution (line 297): Actually do the thing
```

**The Window**: Between steps 2 and 4, the state can change:
- Policy revokes the command capability
- Requester's identity is compromised and revoked
- Certificate expires
- Capability matrix is updated
- Network policy changes
- Requester is deactivated

**Consequence**: The system validated a safe state, but executes in an unsafe state.

### Attack Scenarios

| Scenario | Impact | Severity |
|----------|--------|----------|
| **Revocation After Check** | Actuator executes revoked command | CRITICAL |
| **Capability Downgrade** | Actuator escalates to revoked privilege level | CRITICAL |
| **Identity Revocation** | Actuator acts on behalf of compromised principal | CRITICAL |
| **Certificate Expiration** | Actuator executes with expired credentials | HIGH |
| **Policy Change** | Actuator operates under outdated policy | HIGH |
| **Race Condition** | Two commands execute with inconsistent auth state | HIGH |

---

## Sprint 4 Task Structure (7 Tasks)

### Task 4.1: Execution Token System
**Goal**: Issue signed tokens that bind validation decisions to execution identity  
**Owner**: Crypto Engineer  
**Estimated**: 2 days

**Deliverables**:
- `ExecutionToken` struct: token_id, command_id, validation_timestamp, issuer_principal, validator_principal, required_flags, signature, expires_ns
- `ExecutionTokenIssuer`: Issues tokens after gate validation
- `ExecutionTokenVerifier`: Validates tokens at execution time
- Token lifecycle: PENDING → ACTIVE → CONSUMED → EXPIRED
- Signature verification (Ed25519 from Validator principal)

**Key Components**:
```rust
pub struct ExecutionToken {
    pub token_id: String,
    pub command_id: String,
    pub validation_timestamp_ns: u64,
    pub expiration_ns: u64,
    pub issuer_principal: Principal,
    pub validator_principal: Principal,  // Who performed the validation
    pub required_flags: u32,              // What gates were checked
    pub signature: [u8; 64],              // Validator's Ed25519 signature
    pub status: TokenStatus,              // PENDING, ACTIVE, CONSUMED, EXPIRED, REVOKED
}

pub enum TokenStatus {
    Pending,      // Issued, not yet activated
    Active,       // Ready for execution
    Consumed,     // Used for execution
    Expired,      // TTL exceeded
    Revoked,      // Explicitly revoked (capability downgrade)
}
```

**Integration Points**:
- Consumes ExecutionTokens from gate validation
- Consumed by Actuator execution engine
- Tracked in SecurityLedger as EXECUTION_TOKEN_ISSUED, EXECUTION_TOKEN_CONSUMED, EXECUTION_TOKEN_REVOKED

**Tests**: 12 unit tests + 6 integration tests
- Token issuance and consumption
- Signature verification
- Expiration handling
- Revocation scenarios
- Token chaining across validation boundaries

---

### Task 4.2: Atomic Validation-to-Execution Transition
**Goal**: Lock command state during validation and execution  
**Owner**: Systems Engineer  
**Estimated**: 2 days

**Deliverables**:
- `CommandExecutionContext`: Immutable snapshot of validation state
- `ExecutionLock`: RwLock wrapper that prevents state changes during execution
- `ValidatedCommand`: Command with cached validation results and execution token
- State machine: QUEUED → VALIDATING → VALIDATED → EXECUTING → COMPLETED/FAILED

**Key Components**:
```rust
pub struct CommandExecutionContext {
    pub command_id: String,
    pub validation_timestamp_ns: u64,
    pub gate_c_snapshot: GateCSnapshot,
    pub gate_i_snapshot: GateISnapshot,
    pub requester_principal: Principal,
    pub requester_identity: PrincipalIdentity,
    pub requester_certificate: PrincipalCertificate,
    pub execution_token: ExecutionToken,
}

pub struct GateCSnapshot {
    pub allowed: bool,
    pub reason: String,
    pub capabilities: Vec<u32>,
    pub policy_version: u32,
    pub timestamp_ns: u64,
}

pub struct GateISnapshot {
    pub integrity_valid: bool,
    pub signature_valid: bool,
    pub nonce_fresh: bool,
    pub timestamp_ns: u64,
}

pub struct ExecutionLock {
    inner: Arc<RwLock<ValidatedCommand>>,
}
```

**Atomic Operations**:
```
VALIDATE_AND_LOCK (atomic):
  1. Acquire write lock on command
  2. Perform gate C validation → snapshot
  3. Perform gate I validation → snapshot
  4. Issue execution token
  5. Transition to VALIDATED state
  → Release write lock

EXECUTE (atomic):
  1. Acquire write lock on command
  2. Verify execution token not consumed
  3. Verify token not expired
  4. Perform action
  5. Mark token CONSUMED
  6. Transition to COMPLETED
  → Release write lock
```

**Integration Points**:
- Replaces current execute_command() flow
- Uses ExecutionTokens from Task 4.1
- Logs all state transitions to SecurityLedger

**Tests**: 10 unit tests + 8 integration tests
- Lock acquisition and release
- Concurrent command validation
- State machine transitions
- Token consumption
- Lock timeout handling

---

### Task 4.3: Pre-Execution State Re-validation
**Goal**: Detect state changes between validation and execution  
**Owner**: Security Engineer  
**Estimated**: 1.5 days

**Deliverables**:
- `StateChangeDetector`: Compares current state against validation snapshot
- `RevocationChecker`: Checks if principal/capability/cert revoked since validation
- `TokenExpiration`: Configurable TTL for execution tokens (default: 5 seconds)
- `StateChangeAuditLog`: Records all detected changes

**Validation Checklist at Execution Time**:
1. Token not yet consumed
2. Token not expired (validation_timestamp + TTL > now)
3. Requester principal still active (not revoked)
4. Requester identity still valid (not expired)
5. Requester certificate still valid (not revoked/expired)
6. Requester capabilities unchanged (no downgrade)
7. Command still in approved list
8. No conflicting policy changes

**Implementation**:
```rust
pub fn pre_execute_validation(&self, context: &CommandExecutionContext) -> Result<(), StateChangeError> {
    // Check token expiration
    if context.execution_token.expiration_ns < current_timestamp_ns() {
        return Err(StateChangeError::TokenExpired);
    }
    
    // Re-check requester principal active
    if !identity_registry.get_active_identity(context.requester_principal).is_some() {
        return Err(StateChangeError::PrincipalRevoked);
    }
    
    // Re-check requester certificate valid
    let cert = cert_registry.get_active_certificate(context.requester_principal)?;
    if cert.get_status() != CertificateStatus::Valid {
        return Err(StateChangeError::CertificateInvalid);
    }
    
    // Check capabilities unchanged
    let current_capabilities = capability_matrix.list_interfaces(context.requester_principal.as_u8());
    if current_capabilities != context.gate_c_snapshot.capabilities {
        return Err(StateChangeError::CapabilitiesDowngraded);
    }
    
    Ok(())
}
```

**Error Handling**:
```rust
pub enum StateChangeError {
    TokenExpired,
    TokenRevoked,
    PrincipalRevoked,
    PrincipalDeactivated,
    CertificateExpired,
    CertificateRevoked,
    CapabilitiesDowngraded,
    PolicyChanged,
    CommandRevoked,
}
```

**Integration Points**:
- Called in execute_command() before action
- Logs rejections to SecurityLedger as EXECUTION_DENIED_STATE_CHANGE
- Revokes execution token on state change detection

**Tests**: 8 unit tests + 7 integration tests
- Token expiration detection
- Principal revocation detection
- Certificate status changes
- Capability downgrade detection
- Policy version conflicts

---

### Task 4.4: Command Revocation System
**Goal**: Enable revocation of approved commands before execution  
**Owner**: Systems Engineer  
**Estimated**: 1.5 days

**Deliverables**:
- `CommandRevocationList`: Maintains revoked command IDs
- `CommandRevocationEntry`: command_id, revoked_by, revoked_timestamp_ns, reason
- `revoke_command()`: Immediate revocation, updates execution tokens
- `is_command_revoked()`: Check membership in revocation list
- Audit logging for all revocations

**Key Components**:
```rust
pub struct CommandRevocationList {
    revoked: Arc<Mutex<HashMap<String, CommandRevocationEntry>>>,
    revocation_log: Arc<Mutex<Vec<RevocationEvent>>>,
}

pub struct CommandRevocationEntry {
    pub command_id: String,
    pub revoked_by: Principal,
    pub revoked_timestamp_ns: u64,
    pub reason: String,
    pub revokes_existing_tokens: bool,
}

impl CommandRevocationList {
    pub fn revoke_command(&self, command_id: &str, reason: String) -> Result<()> {
        // Immediately add to revocation list
        // Find all execution tokens for this command
        // Mark tokens as REVOKED
        // Log revocation event
        // Notify affected Actuator instances
    }
    
    pub fn is_revoked(&self, command_id: &str) -> bool {
        self.revoked.lock().unwrap().contains_key(command_id)
    }
}
```

**Revocation Scenarios**:
- Policy immediately disallows a command
- Requester principal is compromised and all commands revoked
- Command contains malicious payload, needs immediate halt
- Urgent security patch requires command blacklist

**Cascade Effects**:
- Revoke command → mark all related execution tokens as REVOKED
- Revoke principal → revoke all tokens issued by/for that principal
- Revoke certificate → revoke all tokens pending execution

**Integration Points**:
- Policy principal can invoke revoke_command()
- Supervisor can invoke cascade revocations
- Pre-execution validation checks revocation list
- SecurityLedger tracks all revocations for audit

**Tests**: 6 unit tests + 5 integration tests
- Command revocation
- Token cascade revocation
- Revocation of in-flight commands
- Revocation list membership queries

---

### Task 4.5: Execution Snapshot and Replay Detection
**Goal**: Prevent replay of execution contexts with outdated state  
**Owner**: Crypto Engineer  
**Estimated**: 1.5 days

**Deliverables**:
- `ExecutionSnapshot`: Hash of all validation state components
- `SnapshotVerifier`: Detects tampering with cached validation state
- `ExecutionReplayLog`: Tracks all executions to detect replays
- Content-addressed snapshots (SHA-256 of validation context)

**Snapshot Components**:
```rust
pub struct ExecutionSnapshot {
    pub snapshot_hash: String,  // SHA-256(command + validation_context)
    pub command_hash: String,
    pub gate_c_hash: String,
    pub gate_i_hash: String,
    pub principal_identity_hash: String,
    pub certificate_hash: String,
    pub capability_hash: String,
    pub timestamp_ns: u64,
}

pub fn compute_snapshot(context: &CommandExecutionContext) -> String {
    let mut hasher = Sha256::new();
    hasher.update(context.command_id.as_bytes());
    hasher.update(context.gate_c_snapshot.serialize());
    hasher.update(context.gate_i_snapshot.serialize());
    hasher.update(context.requester_identity.public_key_hash.as_bytes());
    hasher.update(context.requester_certificate.content_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}
```

**Replay Detection**:
```rust
pub fn check_replay(&self, snapshot: &ExecutionSnapshot) -> Result<()> {
    let mut log = self.execution_replay_log.lock().unwrap();
    
    // Check if snapshot already executed
    if log.contains(&snapshot.snapshot_hash) {
        return Err(ExecutionError::ReplayDetected);
    }
    
    // Add to log (with TTL for garbage collection)
    log.insert(snapshot.snapshot_hash.clone(), snapshot.timestamp_ns);
    Ok(())
}
```

**Integration Points**:
- Snapshot created during VALIDATE_AND_LOCK
- Verified during pre-execution validation
- Replayed executions rejected with EXECUTION_BLOCKED_REPLAY audit log entry

**Tests**: 7 unit tests + 5 integration tests
- Snapshot generation and hashing
- Replay detection
- Snapshot tampering detection
- TTL-based log cleanup

---

### Task 4.6: Actuator Hardening & Integration
**Goal**: Integrate TOCTOU prevention into Actuator principal  
**Owner**: Systems Engineer  
**Estimated**: 2 days

**Deliverables**:
- Refactored `ActuatorPrincipal::execute_command()` using new token system
- `execute_with_token()`: Execute command with token validation
- `validate_and_issue_token()`: Atomic validation + token issuance
- Integration test suite: 15 e2e test scenarios
- Performance benchmarks: <5ms per command validation+execution

**Refactored Flow**:
```rust
pub fn execute_command(&self, request: CommandRequest) -> Result<ExecutionResult> {
    // Phase 1: ATOMIC VALIDATION AND TOKEN ISSUANCE
    let context = {
        let lock = self.acquire_execution_lock(&request.request_id)?;
        let gate_c = self.gate_c_validate(&request);
        let gate_i = self.gate_i_validate(&request);
        
        if !gate_c.allowed || !gate_i.integrity_valid {
            return Err(ExecutionError::ValidationFailed);
        }
        
        let token = self.token_issuer.issue_token(&request.request_id)?;
        CommandExecutionContext {
            command_id: request.request_id.clone(),
            validation_timestamp_ns: now(),
            gate_c_snapshot: gate_c.into(),
            gate_i_snapshot: gate_i.into(),
            requester_principal: request.requester,
            execution_token: token,
            // ... snapshots
        }
    };
    
    // Phase 2: IMMEDIATE EXECUTION (within token TTL)
    {
        let lock = self.acquire_execution_lock(&request.request_id)?;
        
        // Pre-execution: re-validate state
        self.pre_execute_validation(&context)?;
        
        // Atomic execution + token consumption
        let (output, success) = self.perform_action(&request)?;
        self.token_issuer.consume_token(&context.execution_token)?;
        
        // Log result
        self.ledger.append_event(...);
    }
    
    Ok(ExecutionResult { ... })
}
```

**New State Machine**:
```
QUEUED
  ↓ queue_command()
VALIDATING (acquire write lock)
  ↓ gate_c_validate() + gate_i_validate()
VALIDATED (issue token)
  ↓ release write lock
EXECUTING (acquire write lock on token)
  ↓ pre_execute_validation() + perform_action()
COMPLETED (consume token)
  ↓ release write lock
```

**Configuration**:
```rust
pub struct ActuatorConfig {
    pub execution_token_ttl_ms: u64,  // Default: 5000ms
    pub state_change_check_interval_ms: u64,  // Default: 1000ms
    pub max_concurrent_executions: usize,  // Default: 10
    pub execution_snapshot_retention_ms: u64,  // Default: 86400000ms (1 day)
}
```

**Performance Requirements**:
- Validation + token issuance: <2ms
- Pre-execution re-validation: <1ms
- Total validation-to-execution: <5ms (including state checks)

**Integration Points**:
- Uses ExecutionTokens (Task 4.1)
- Uses CommandExecutionContext (Task 4.2)
- Uses StateChangeDetector (Task 4.3)
- Uses CommandRevocationList (Task 4.4)
- Uses ExecutionSnapshot (Task 4.5)
- Integrates with SecurityLedger for audit

**Tests**: 15 e2e integration tests
- Happy path: valid command executes
- Token expiration: command rejected if >5s
- State change detection: command rejected if principal revoked
- Revocation: command revoked before execution
- Concurrent execution: multiple commands with proper locking
- Replay detection: same snapshot rejected twice

---

### Task 4.7: Documentation & TOCTOU Prevention Guide
**Goal**: Document TOCTOU mitigation strategy  
**Owner**: Technical Writer  
**Estimated**: 1 day

**Deliverables**:
- `TOCTOU_PREVENTION_GUIDE.md`: 400+ line architecture guide
- TOCTOU Threat Model & Mitigations
- State Machine Diagrams
- Token Lifecycle Documentation
- Integration Guide for other principals

**Documentation Contents**:
1. TOCTOU Problem Statement
   - Time-of-Check/Time-of-Use definition
   - Actuator vulnerability scenarios
   - Attack surface analysis

2. Solution Architecture
   - Execution token system
   - Atomic validation-to-execution
   - State snapshot mechanism
   - Command revocation system

3. Component Specifications
   - ExecutionToken data structure
   - CommandExecutionContext
   - StateChangeDetector interface
   - CommandRevocationList API

4. Integration Guide
   - How to use execution tokens
   - State machine transitions
   - Error handling patterns
   - Performance tuning

5. Threat Model & Mitigations
   - STRIDE analysis (Spoofing, Tampering, Repudiation, Info Disclosure, Denial of Service, Elevation)
   - Mitigations for each threat
   - Residual risks

6. Future Hardening
   - HSM-based token signing (Sprint 4+)
   - Distributed timestamp service
   - Byzantine fault tolerance
   - Zero-knowledge proofs for state validity

---

## Testing Strategy

### Unit Tests (Task-specific)
- Task 4.1: 12 token system tests
- Task 4.2: 10 atomic transition tests
- Task 4.3: 8 state change detection tests
- Task 4.4: 6 revocation tests
- Task 4.5: 7 snapshot/replay tests
- **Total**: 43 unit tests

### Integration Tests
- Task 4.1: 6 integration tests (token lifecycle)
- Task 4.2: 8 integration tests (execution locking)
- Task 4.3: 7 integration tests (state changes)
- Task 4.4: 5 integration tests (revocation cascade)
- Task 4.5: 5 integration tests (replay detection)
- Task 4.6: 15 e2e tests (complete flows)
- **Total**: 46 integration tests

### End-to-End Workflows (Task 4.6)
1. Valid command → validates → executes → completes
2. Command revoked after validation → execution blocked
3. Principal revoked after validation → execution blocked
4. Certificate expires after validation → execution blocked
5. Concurrent commands with proper isolation
6. Token expiration: execution fails if >5s since validation
7. State snapshot tampering: rejected
8. Execution replay: second execution of same snapshot rejected
9. Multi-gate failure: proper error handling
10. Partial state change: some gates pass, others fail
11. Cascading revocation: revoke principal → revoke all tokens
12. Rate limiting: max_concurrent_executions enforced
13. Lock timeout: deadlock prevention
14. Audit trail: all operations logged
15. Recovery: partial failures recover cleanly

**Total Test Coverage**: 89 tests (43 unit + 46 integration)

---

## Architecture Diagram

```
VALIDATION PHASE (Atomic)
────────────────────────────────────────
Command Request
  ↓
[Acquire Write Lock on Command]
  ↓
Gate C Validate     Gate I Validate
(authorization)    (integrity)
  ↓                 ↓
[Create GateCSnapshot]  [Create GateISnapshot]
  ↓
[Issue Execution Token (signed)]
  ↓
[Create CommandExecutionContext with snapshots]
  ↓
[Create ExecutionSnapshot (hash of context)]
  ↓
[Transition to VALIDATED state]
  ↓
[Release Write Lock]

EXECUTION PHASE (Immediate, <5s window)
────────────────────────────────────────
Execution Request with Token
  ↓
[Acquire Write Lock on Token]
  ↓
1. Check Token Not Expired
2. Check Principal Still Active
3. Check Certificate Still Valid
4. Check Capabilities Unchanged
5. Check Command Not Revoked
6. Check Snapshot Not Replayed
  ↓
All Pre-Execution Checks Pass
  ↓
[Perform Action]
  ↓
[Consume Token (mark CONSUMED)]
  ↓
[Update ExecutionSnapshot in Replay Log]
  ↓
[Log Execution to SecurityLedger]
  ↓
[Transition to COMPLETED state]
  ↓
[Release Write Lock]
```

---

## Success Criteria

✅ **Security**:
- No TOCTOU window between validation and execution
- State changes detected and execution blocked
- Commands can be revoked at any time before execution
- All execution decisions logged for forensic analysis

✅ **Performance**:
- Validation + execution <5ms per command
- Token issuance <2ms
- Pre-execution validation <1ms
- No significant latency increase vs Sprint 3

✅ **Reliability**:
- No deadlocks from execution locks
- Proper cleanup of expired tokens
- Atomic state transitions
- Error recovery without corruption

✅ **Testability**:
- 89 tests covering all code paths
- All TOCTOU attack scenarios tested
- E2E workflows for each task
- Performance benchmarks established

---

## Integration with Phase 2

### Sprint 1 (Evidence Sealing - SEC-C02)
✅ Complete: Evidence sealed by Sealer, signatures verified

### Sprint 2 (Data Classification - SEC-C02)
✅ Complete: Data classified by Declassifier, boundaries enforced

### Sprint 3 (Cross-Boundary Auth - SEC-C03)
✅ Complete: IPC messages authenticated via digital signatures

### Sprint 4 (TOCTOU Prevention - SEC-C04)
🔄 In Progress: Atomic validation prevents state-change vulnerabilities

### Sprint 5+ (Future Enhancements)
- HSM-based token signing
- Certificate Revocation Lists (CRL)
- Public Key Infrastructure (PKI)
- Time synchronization (NTP)
- Multi-signature schemes
- Byzantine fault tolerance

---

## Risks & Mitigations

| Risk | Probability | Severity | Mitigation |
|------|-------------|----------|-----------|
| Token TTL too short | LOW | MEDIUM | Default 5s; tune in Task 4.6 tests |
| Lock contention under high load | LOW | MEDIUM | Performance benchmarks in tests |
| State snapshot deserialization bugs | MEDIUM | HIGH | Comprehensive snapshot tests |
| Revocation cascade incomplete | LOW | CRITICAL | Thorough revocation tests, cascading logic |
| Token consumption race condition | MEDIUM | HIGH | Atomic consumption with write locks |
| Disk space for revocation list | LOW | LOW | TTL-based cleanup in Task 4.4 |

---

## Commit Strategy

```
Sprint 4 Task 4.1: Execution Token System
Sprint 4 Task 4.2: Atomic Validation-to-Execution Transition
Sprint 4 Task 4.3: Pre-Execution State Re-validation
Sprint 4 Task 4.4: Command Revocation System
Sprint 4 Task 4.5: Execution Snapshot and Replay Detection
Sprint 4 Task 4.6: Actuator Hardening & Integration
Sprint 4 Task 4.7: Documentation & TOCTOU Prevention Guide
Sprint 4 Completion Summary: SEC-C04 Complete
```

Each task gets its own commit with comprehensive message explaining:
- What was implemented
- Why (security rationale)
- Testing coverage
- Integration points

---

## Timeline

- **Today**: Task 4.1 (Execution Token System)
- **Tomorrow**: Tasks 4.2 & 4.3 (Atomic Transition, State Re-validation)
- **Day 3**: Tasks 4.4 & 4.5 (Revocation, Snapshot/Replay)
- **Day 4**: Task 4.6 (Actuator Integration)
- **Day 5**: Task 4.7 (Documentation) + Completion Summary

**Total**: 5 days = 1 week (5-day intensive implementation)

---

## Document Control

| Version | Date | Status |
|---------|------|--------|
| 1.0 | 2026-09-26 | Sprint 4 Planning |

**Next Update**: 2026-09-27 (Task 4.1 Completion)
