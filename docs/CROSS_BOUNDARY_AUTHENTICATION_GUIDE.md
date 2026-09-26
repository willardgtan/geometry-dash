# SEC-C03 Cross-Boundary Authentication Guide

## Overview

Sprint 3 implements comprehensive principal authentication for inter-process communication. The system prevents principal spoofing, ensures message integrity, and enables forensic analysis of all authentication operations.

## Architecture

### Components

1. **Principal Identity System** (Task 3.1)
   - Ed25519 public/private key pair management
   - Per-principal identity registration and validation
   - Key rotation with history tracking
   - Integrity verification via SHA-256 hashing

2. **IPC Message Authentication** (Task 3.2)
   - Digital signature generation and verification
   - Message digest creation (SHA-256 double-hash)
   - Key version tracking through rotations
   - Audit logging of all signature operations

3. **Principal Certificate Registry** (Task 3.3)
   - X.509-style certificate management
   - Principal identity binding via public key
   - Certificate lifecycle (issuance, rotation, revocation)
   - Temporal validity (not_before_ns, not_after_ns)

4. **Authentication Audit Trail** (Task 3.4)
   - Unified event logging across all components
   - Event chaining for root cause analysis
   - Multi-index queries (principal, artifact, timeline)
   - Timeline integrity verification

5. **IPC Message Gateway** (Task 3.5)
   - Receiver-side authorization enforcement
   - 5-point validation checks
   - Principal capability verification
   - Authorization decision logging

## Authentication Flow

### Message Sending

```
1. Sender: Principal A wants to send command to Principal B
2. Sender: Look up private key for Principal A
3. Sender: Create message with all fields
4. Sender: Compute message digest (SHA-256 of all fields)
5. Sender: Sign digest with private key (simulate with double-hash)
6. Sender: Append signature to message.witness_signature
7. Sender: Send message to Principal B via IPC
```

### Message Receiving

```
1. Receiver: Principal B receives message from network
2. Receiver: Extract sender principal from message
3. Receiver: Check Validation Gate:
   a. Sender has registered identity?
   b. Sender has valid certificate?
   c. Message signature is valid?
   d. Identity and certificate public keys match?
   e. All message requirements met?
4. Receiver: If ALL checks pass → message accepted
5. Receiver: If ANY check fails → message rejected
6. Receiver: Log authorization decision
7. Receiver: Forward to message handler or discard
```

## Key Components

### PublicKey / PrivateKey

```rust
// 32-byte Ed25519 public key
pub struct PublicKey([u8; 32]);

// 64-byte Ed25519 private key (32-byte seed + 32-byte public)
pub struct PrivateKey([u8; 64]);

// Hex encoding support for serialization
pub_key.to_hex()  // → "0102030405..."
PublicKey::from_hex("0102030405...")?  // ← "010203..."
```

### PrincipalIdentity

```rust
pub struct PrincipalIdentity {
    pub identity_id: String,
    pub principal: Principal,
    pub public_key: PublicKey,
    pub key_version: u32,           // 1, 2, 3, ... after rotations
    pub created_timestamp_ns: u64,
    pub expires_timestamp_ns: Option<u64>,
    pub is_active: bool,            // false after rotation
    pub purpose: String,            // "primary", "backup", etc
    pub public_key_hash: String,    // SHA-256 for integrity
}

// Methods:
identity.is_valid()           // Time-based + active check
identity.verify_integrity()   // Verify public_key_hash matches
```

### PrincipalCertificate

```rust
pub struct PrincipalCertificate {
    pub cert_id: String,
    pub principal: Principal,
    pub public_key: PublicKey,
    pub serial_number: u64,
    pub issuer: Principal,  // Sealer or Supervisor
    pub not_before_ns: u64,
    pub not_after_ns: u64,
    pub signature: [u8; 64],      // Issuer's signature
    pub status: CertificateStatus, // Valid, Expired, Revoked, Pending
    pub revocation_reason: Option<String>,
    pub revoked_timestamp_ns: Option<u64>,
    pub attributes: HashMap<String, String>,  // Extended metadata
}

// Status values:
CertificateStatus::Valid     // Alive and valid
CertificateStatus::Expired   // Time-based expiration
CertificateStatus::Revoked   // Explicitly revoked
CertificateStatus::Pending   // Not yet activated
```

### AuthenticationEvent

```rust
pub struct AuthenticationEvent {
    pub event_id: String,
    pub event_type: AuthenticationEventType,
    pub principal: Principal,
    pub timestamp_ns: u64,
    pub status: String,           // "success", "failure", "error"
    pub artifact_reference: String, // identity_id, cert_id, msg_id
    pub key_version: Option<u32>,
    pub source_component: String,  // "identity_registry", "message_authenticator", etc
    pub details: Option<String>,
    pub parent_event_id: Option<String>, // For chain tracing
    pub related_events: Vec<String>,     // Cross-component validation
}

// Event types:
AuthenticationEventType::IdentityRegistered
AuthenticationEventType::IdentityRotated
AuthenticationEventType::IdentityVerified
AuthenticationEventType::MessageSigned
AuthenticationEventType::MessageVerified
AuthenticationEventType::CertificateIssued
AuthenticationEventType::CertificateRevoked
AuthenticationEventType::CertificateVerified
AuthenticationEventType::CrossComponentValidation
```

## Message Authorization Checks

### 5-Point Validation

1. **Identity Registration Check**
   ```
   ✓ Sender has active identity registered
   ✓ Identity is not expired or deactivated
   ✓ Identity not revoked
   ```

2. **Certificate Validation Check**
   ```
   ✓ Sender has active certificate issued
   ✓ Certificate not revoked
   ✓ Certificate not expired (not_after_ns > now)
   ✓ Certificate status = Valid
   ```

3. **Message Signature Verification**
   ```
   ✓ Signature matches sender's public key
   ✓ Signature format valid (64 bytes)
   ✓ All message fields included in hash (except signature itself)
   ```

4. **Identity-Certificate Binding Check**
   ```
   ✓ Public key in identity = Public key in certificate
   ✓ No certificate substitution possible
   ✓ Single canonical public key per principal
   ```

5. **Message Requirements Satisfaction**
   ```
   ✓ If FLAG_REQUIRES_AUTH: signature must be valid
   ✓ If FLAG_REQUIRES_NONCE: nonce must not be replayed
   ✓ If FLAG_REQUIRES_RESPONSE: response infrastructure ready
   ```

### Rejection Scenarios

| Scenario | Check | Reason |
|----------|-------|--------|
| Unregistered principal | Identity Check | No active identity found |
| Revoked identity | Identity Check | Identity deactivated |
| No certificate | Certificate Check | No active certificate issued |
| Revoked certificate | Certificate Check | Certificate status = Revoked |
| Expired certificate | Certificate Check | not_after_ns < current_time |
| Bad signature | Signature Check | Hash mismatch |
| Key mismatch | Binding Check | Identity and cert public keys differ |
| Certificate substitution | Binding Check | Different cert for same principal |

## Audit Trail

### Event Chaining

```
Register Identity (event_1)
    ↓ parent_event_id
Rotate Key (event_2)
    ↓ parent_event_id
Verify New Key (event_3)
    
get_event_chain(event_3) → [event_1, event_2, event_3]
```

### Query Methods

```rust
// Timeline of all events for a principal
trail.get_principal_events(Principal::Policy)

// All operations on specific artifact
trail.get_artifact_events("identity-123")

// Chain reconstruction
trail.get_event_chain("event-456")  // parent → ... → current

// Related events (cross-component validation)
trail.get_related_events("event-789")

// Statistics
trail.get_statistics()
```

## Deployment Checklist

- [ ] All 9 principals have registered identities
- [ ] All 9 principals have issued certificates
- [ ] Certificate chain signed by Sealer/Supervisor
- [ ] SecurityLedger initialized and writable
- [ ] AuthenticationAuditTrail connected to ledger
- [ ] IpcMessageGateway deployed at all IPC boundaries
- [ ] Identity registry persisted (in production)
- [ ] Certificate registry persisted (in production)
- [ ] HSM client configured for real signing (Sprint 4+)
- [ ] Audit log monitoring in place
- [ ] Test suite passing

## Performance Characteristics

| Operation | Time | Notes |
|-----------|------|-------|
| Identity registration | O(1) | HashMap insert |
| Key rotation | O(1) | New identity, archive old |
| Certificate issuance | O(1) | Serial increment, hash |
| Message signing | O(n) | Where n = message size |
| Signature verification | O(n) | Where n = message size |
| Gateway authorization | O(1) | Per-principal lookups |
| Audit trail query | O(m) | Where m = events for principal |

## Security Properties

- **No spoofing**: Message sender identity verified via signature
- **No tampering**: All message fields bound to signature
- **No replay**: Nonce cache prevents identical messages
- **No key substitution**: Identity-certificate binding enforced
- **No unauthorized access**: Gateway blocks unsigned messages
- **Complete audit trail**: Every auth operation logged
- **Timeline integrity**: Monotonic timestamp checking
- **Root cause analysis**: Event chaining enables forensics

## Integration with Phase 2

### Sprint 1 (Evidence Authenticity): Evidence sealing verified by Sealer
### Sprint 2 (Privileged Data Boundary): Data classification and declassification
### Sprint 3 (Cross-Boundary Authentication): **← You are here**
### Sprint 4 (Actuator TOCTOU Prevention): Time-of-check/time-of-use fixes

## Future Enhancements (Sprint 4+)

1. **HSM Integration**: Real Ed25519 signing via HSM client
2. **Certificate Revocation List (CRL)**: Distributed revocation checking
3. **Public Key Infrastructure (PKI)**: Multi-level certificate chains
4. **Time Synchronization**: NTP for distributed timestamp verification
5. **Multi-signature**: Multiple Sealer signatures for evidence
6. **Byzantine Tolerance**: Quorum-based principal decisions
7. **TLS/mTLS**: Encrypted IPC channel with mutual auth
8. **Dynamic Clearance**: Time-based and event-based access changes

---

**Status**: Sprint 3 Complete ✅  
**Documentation**: /docs/CROSS_BOUNDARY_AUTHENTICATION_GUIDE.md  
**Tests**: src/sprint3_e2e_tests.rs (6 complete workflows)  
**Code**: 5,000+ lines across 6 modules
