# Supervisor Module Design (Week 1-2)

**Status:** In Progress – Week 1  
**Owner:** Lead Architect + Systems Engineers  
**Timeline:** Week 1 (design + skeleton), Week 2 (startup sequence completion)  
**Target LOC:** 800–1,200  

---

## Executive Summary

The **Supervisor** is the master process orchestrator for Phase 2. It:
1. Initializes and manages 8 principal processes (PRN-POLICY, PRN-ACTUATOR, PRN-AUDIT, PRN-DECLASSIFIER, PRN-LEARNER, PRN-EVALUATOR, PRN-SEALER, PRN-DEVELOPER)
2. Enforces OS-level isolation (separate Unix users, seccomp filters, AppArmor/SELinux)
3. Coordinates inter-principal communication via named pipes (IPC)
4. Detects and responds to principal crashes (restart, log, escalate)
5. Maintains boot-scoped epoch_id and run_id for evidence authenticity

Supervisor is the **critical path blocker** for all Week 3+ work.

---

## Architecture

### 1. Process Lifecycle

**Startup Sequence (Week 1 Task 1.1):**
```
Supervisor startup
  ├── Initialize SecurityLedger (append-only log)
  ├── Load config (frozen post-Gate C)
  ├── Initialize HSM (failover to encrypted FS)
  ├── Create IPC named pipes (all 22 IF-* interfaces)
  ├── Generate run_id (UUID for this execution)
  ├── Generate boot_id (unique per boot)
  ├── Start Principal 1: PRN-POLICY
  │   ├── Set UID/GID (geometry_dash_policy user)
  │   ├── Apply seccomp filter (deny ptrace, fork, execve)
  │   ├── Apply AppArmor/SELinux profile
  │   ├── Exec policy binary
  │   └── Wait for ready signal on IPC pipe
  ├── Start Principal 2: PRN-ACTUATOR
  │   └── [same as PRN-POLICY]
  ├── Start Principals 3–8 (AUDIT, DECLASSIFIER, LEARNER, EVALUATOR, SEALER, DEVELOPER)
  │   └── [same per-principal setup]
  └── Begin polling for principal health
```

**Crash Detection & Recovery:**
- Poll each principal's IPC heartbeat (every 100ms)
- If heartbeat missing >1s: log CRITICAL to SecurityLedger, attempt restart (max 3x)
- If restart fails: log CRITICAL, enter LOCKDOWN state (fail-safe: release all pending actions)
- Health status stored in SecurityLedger (REQ-AUDIT-002)

**Graceful Shutdown:**
- On SIGTERM: signal all principals to terminate (1s timeout per principal)
- On timeout: SIGKILL remaining principals
- Flush SecurityLedger to disk
- Exit with status code (0 success, 1 failure, 2 crash detected)

---

### 2. IPC Coordination

**Named Pipes (IF-001–022):**
- 22 critical interfaces defined in Interface Contract Catalog
- Supervisor creates bidirectional pipes for each interface pair
- Example: `IF-002 (AUDIT→POLICY)` uses pipes:
  - `/var/run/geometry-dash/if002-audit-to-policy` (FIFO, mode 0600)
  - `/var/run/geometry-dash/if002-policy-to-audit` (FIFO, mode 0600)

**Message Format (Universal Header, IF-004):**
```rust
struct UniversalMessageHeader {
    interface_id: u32,           // IF-001 through IF-022
    protocol_version: u8,         // v1
    message_type: u8,             // REQUEST, RESPONSE, EVENT
    flags: u32,                   // BIT_0: requires_auth, BIT_1: requires_sig, etc
    sender_principal: u8,         // PRN-* enum (0-9)
    receiver_principal: u8,       // PRN-* enum (0-9)
    message_id: u64,              // Unique per interface
    nonce: [u8; 32],              // Duplicate detection
    timestamp_ns: u64,            // Monotonic ns since boot
    witness_signature: [u8; 64],  // Ed25519 signature
}
```

**Handshake (Week 1 Task 1.2):**
1. Supervisor sends "INIT" message to each principal
2. Principal responds with "READY" + capability flags
3. Supervisor logs initialization in SecurityLedger
4. Principal begins accepting requests from other principals

---

### 3. Configuration Management

**Frozen Configuration (REQ-CONFIG-001):**
- Read-only YAML file: `/etc/geometry-dash/config.yaml`
- Loaded once at startup; no runtime modifications
- Immutable via WORM enforcement (Week 7-8)

**Config Content:**
```yaml
supervisor:
  heartbeat_interval_ms: 100
  heartbeat_timeout_ms: 1000
  restart_max_attempts: 3
  restart_backoff_ms: 500
  epoch_id_prefix: "epoch"
  
principals:
  policy:
    uid: 1001
    gid: 1001
    seccomp_profile: strict
    apparmor_profile: policy
  actuator:
    uid: 1002
    gid: 1002
    seccomp_profile: strict
    apparmor_profile: actuator
  # ... (6 more principals)

hsm:
  enabled: true
  pkcs11_module: /usr/lib/softhsm/libsofthsm2.so
  token_label: GeometryDash
  timeout_ms: 5000
  failover_to_encrypted_fs: true
  
ipc:
  pipe_root: /var/run/geometry-dash
  pipe_mode: 0600
  max_message_age_ns: 300_000_000_000  # 5 minutes
  
security:
  max_concurrent_actions: 1000
  nonce_cache_ttl_ns: 305_000_000_000  # 5 min + 5s grace
```

---

### 4. Epoch & Run ID Management

**Epoch ID (REQ-EVIDENCE-001):**
- Unique identifier for this boot
- Format: `epoch-<boot-timestamp>-<random>`
- Generated at startup, immutable for this execution
- Used in all artifacts' `epoch_id` field (provenance schema)
- Survives process restarts within same boot

**Run ID (REQ-EVIDENCE-002):**
- Unique identifier for this Supervisor execution
- Format: UUID v4
- Changes on every Supervisor restart
- Used to correlate artifacts from single execution
- Stored in SecurityLedger as first log entry

**SecurityLedger First Entry (Week 1 Task 1.3):**
```json
{
  "timestamp_ns": 1695226800000000000,
  "event_type": "SUPERVISOR_START",
  "severity": "INFO",
  "principal": "PRN-SUPERVISOR",
  "run_id": "550e8400-e29b-41d4-a716-446655440000",
  "boot_id": "abcdef01-2345-6789-abcd-ef0123456789",
  "epoch_id": "epoch-1695226800-a1b2c3d4",
  "details": {
    "principals_to_start": ["PRN-POLICY", "PRN-ACTUATOR", ... ],
    "ipc_root": "/var/run/geometry-dash",
    "hsm_enabled": true,
    "config_file": "/etc/geometry-dash/config.yaml"
  }
}
```

---

## Week 1 Task Breakdown

### Task 1.1: Startup Sequence Design (2–3 days)
- Design process initialization order
- Define seccomp filter rules per principal
- Design AppArmor/SELinux profiles
- Create state machine diagram (startup → ready → running → shutdown)
- Create detailed checklist for each principal startup

**Deliverable:** `supervisor_startup_sequence.md` (500+ lines with pseudocode)

### Task 1.2: IPC Handshake & Health Check (2 days)
- Implement INIT/READY handshake protocol
- Implement heartbeat polling loop (100ms interval)
- Implement crash detection & restart logic
- Implement graceful shutdown (SIGTERM + timeout + SIGKILL)

**Deliverable:** `src/supervisor/ipc.rs` (400–600 LOC)

### Task 1.3: SecurityLedger Integration (1 day)
- Connect Supervisor to SecurityLedger (append-only logging)
- Log all principal starts, crashes, restarts, shutdowns
- Log configuration loaded event
- Log epoch_id and run_id assignment

**Deliverable:** `src/supervisor/logging.rs` (200–300 LOC)

### Task 1.4: Config Loading & Validation (1 day)
- Parse YAML configuration
- Validate all required fields present
- Validate timeouts, limits, paths are sensible
- Fail startup if config invalid (with clear error)

**Deliverable:** `src/supervisor/config.rs` (300–400 LOC)

### Task 1.5: Unit Tests (1 day)
- Test startup sequence (mock principals)
- Test crash detection & restart
- Test graceful shutdown
- Test config parsing & validation
- Test epoch_id/run_id generation

**Deliverable:** `tests/unit/supervisor_test.rs` (500+ LOC, 20+ test cases)

### Task 1.6: Integration Tests (1 day)
- Test Supervisor + SecurityLedger together
- Test Supervisor + IPC together
- Test Supervisor + 2–3 mock principals together
- Test multi-principal coordination

**Deliverable:** `tests/integration/supervisor_integration_test.rs` (400+ LOC, 10+ test cases)

---

## Integration Points

| Module | Interface | Week | Notes |
|--------|-----------|------|-------|
| SecurityLedger | IF-011 (Audit logging) | 1 | Supervisor writes all events |
| IPC | IF-001–022 (all) | 1 | Supervisor creates pipes, routes messages |
| Policy | IF-002, IF-003 | 2 | Supervisor starts Policy, Policy responds READY |
| Actuator | IF-004, IF-005 | 2 | Supervisor starts Actuator, Actuator responds READY |
| HSM Client | IF-015 (signature) | 1.5 | Supervisor signs epoch_id, run_id assignment |
| WORM | IF-019 (seal) | 7 | Sealer uses epoch_id to construct seals |

---

## Success Criteria (Week 1 End)

- [ ] Supervisor binary compiles (release build, no warnings)
- [ ] Startup sequence completes <500ms (measured)
- [ ] All 8 principals start and report READY within 1s
- [ ] Heartbeat detection working (crash detected <1.1s)
- [ ] SecurityLedger records all lifecycle events
- [ ] Graceful shutdown completes <2s
- [ ] All unit + integration tests pass
- [ ] Configuration validation rejects invalid config
- [ ] Code review: Architecture coherence verified by Lead Architect

---

## Blockers & Risks

| Blocker | Mitigation | Owner |
|---------|-----------|-------|
| seccomp filter definition undefined | Create filter spec in Task 1.1 | Systems Eng |
| AppArmor/SELinux policies undefined | Create profiles in Task 1.1 | Systems Eng |
| SecurityLedger schema not finalized | Use schema from Week 0 Task 1 | QA Eng |
| IPC interface contracts unclear | Reference Interface Catalog v1.0 | Lead Arch |
| HSM timeout behavior undefined | Failover design doc (Week 1.5) | Crypto Eng |

---

## Document Control

| Version | Date | Status |
|---------|------|--------|
| 1.0 | 2026-09-26 | Week 1 in progress |

**Next Update:** Week 2 (after Task 1.1–1.6 completion)
