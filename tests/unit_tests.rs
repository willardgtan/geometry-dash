// Comprehensive Unit Tests for Week 1 Foundation Layer
// Tests edge cases, error conditions, and property-based scenarios

use geometry_dash::{
    SecurityEvent, EventType, Severity, Principal,
    UniversalMessage, UniversalMessageHeader, NonceCache, CapabilityMatrix,
    Supervisor, PrincipalState,
};
use std::collections::HashMap;
use tempfile::NamedTempFile;

// ============================================================================
// SecurityLedger Edge Cases
// ============================================================================

#[test]
fn test_security_event_default_timestamp() {
    let event = SecurityEvent::new(
        0,
        EventType::SupervisorStart,
        Principal::Supervisor,
        Severity::Info,
        "run-1".to_string(),
        "boot-1".to_string(),
        "epoch-1".to_string(),
        [0u8; 32],
        [0u8; 32],
        HashMap::new(),
    );

    assert!(event.timestamp_ns > 0);
}

#[test]
fn test_security_event_details_mutation() {
    let mut event = SecurityEvent::new(
        0,
        EventType::ActionRequested,
        Principal::Policy,
        Severity::Info,
        "run-1".to_string(),
        "boot-1".to_string(),
        "epoch-1".to_string(),
        [0u8; 32],
        [0u8; 32],
        HashMap::new(),
    );

    event.add_detail("key1".to_string(), "value1".to_string());
    assert_eq!(event.details.get("key1").map(|v| v.as_str()), Some("value1"));

    event.add_detail("key2".to_string(), "value2".to_string());
    assert_eq!(event.details.len(), 2);
}

#[test]
fn test_security_event_interface_context() {
    let mut event = SecurityEvent::new(
        0,
        EventType::ActionRequested,
        Principal::Policy,
        Severity::Info,
        "run-1".to_string(),
        "boot-1".to_string(),
        "epoch-1".to_string(),
        [0u8; 32],
        [0u8; 32],
        HashMap::new(),
    );

    assert_eq!(event.interface_id, None);
    event.set_interface(2, 456);
    assert_eq!(event.interface_id, Some(2));
    assert_eq!(event.message_id, Some(456));
}

#[test]
fn test_event_type_serialization() {
    let event_types = vec![
        EventType::SupervisorStart,
        EventType::ActionRequested,
        EventType::SignatureVerified,
        EventType::LockdownEntered,
    ];

    for et in event_types {
        let json = serde_json::to_string(&et).unwrap();
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, et);
    }
}

#[test]
fn test_severity_level_ordering() {
    use geometry_dash::Severity::*;

    assert!(Debug < Info);
    assert!(Info < Warn);
    assert!(Warn < Error);
    assert!(Error < Critical);
}

// ============================================================================
// IPC Message Edge Cases
// ============================================================================

#[test]
fn test_universal_message_empty_payload() {
    let msg = UniversalMessage::new(1, 0, 1, 2, 0, vec![]);

    assert!(msg.to_json().is_ok());
    assert_eq!(msg.payload.len(), 0);
}

#[test]
fn test_universal_message_large_payload() {
    let large_payload = vec![42u8; 100_000];  // 100 KB
    let msg = UniversalMessage::new(1, 0, 1, 2, 0, large_payload.clone());

    assert!(msg.validate_size().is_ok());
    assert_eq!(msg.payload.len(), 100_000);
}

#[test]
fn test_universal_message_oversized_payload() {
    let oversized = vec![42u8; 2_000_000];  // 2 MB, exceeds 1 MB limit
    let msg = UniversalMessage::new(1, 0, 1, 2, 0, oversized);

    assert!(msg.validate_size().is_err());
}

#[test]
fn test_message_header_nonce_uniqueness() {
    let h1 = UniversalMessageHeader::new(1, 0, 1, 2, 0);
    let h2 = UniversalMessageHeader::new(1, 0, 1, 2, 0);

    // Nonces should be (very likely) different
    // 256-bit random nonces have collision probability negligible
    assert_ne!(h1.nonce, h2.nonce);
}

#[test]
fn test_message_header_flags_all_combinations() {
    let flags = vec![
        0x01,  // REQUIRES_AUTH
        0x02,  // REQUIRES_NONCE
        0x04,  // REQUIRES_RESPONSE
        0x08,  // IDEMPOTENT
        0x10,  // PRIORITY_HIGH
        0x20,  // CRITICAL
        0x03,  // REQUIRES_AUTH | REQUIRES_NONCE
        0xFF,  // All flags
    ];

    for flag in flags {
        let header = UniversalMessageHeader::new(1, 0, 1, 2, flag);
        assert_eq!(header.flags, flag);
    }
}

#[test]
fn test_message_response_preserves_interface() {
    let request = UniversalMessage::new(7, 0, 2, 3, 0, b"query".to_vec());
    let response = UniversalMessage::create_response(&request, b"answer".to_vec());

    // Interface should be preserved
    assert_eq!(response.header.interface_id, request.header.interface_id);
}

// ============================================================================
// Nonce Cache Edge Cases
// ============================================================================

#[test]
fn test_nonce_cache_expired_entries() {
    let cache = NonceCache::new(100, 1000);  // 100ms TTL
    let nonce1 = [1u8; 32];
    let nonce2 = [2u8; 32];
    let ts1 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Insert first nonce
    assert!(cache.check_and_insert(nonce1, 1, 100, 1, ts1).is_ok());

    // Wait for expiry
    std::thread::sleep(std::time::Duration::from_millis(150));

    let ts2 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Now the first nonce should be expired and reacceptable
    assert!(cache.check_and_insert(nonce1, 1, 101, 1, ts2).is_ok());
}

#[test]
fn test_nonce_cache_max_entries_eviction() {
    let cache = NonceCache::new(60000, 5);  // 5 max entries
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Insert 5 nonces (max)
    for i in 0..5 {
        let mut nonce = [0u8; 32];
        nonce[0] = i as u8;
        assert!(cache.check_and_insert(nonce, 1, i as u64, 1, ts + i as u64).is_ok());
    }

    let (size, max) = cache.stats();
    assert_eq!(size, 5);
    assert_eq!(max, 5);

    // Insert 6th nonce (should evict oldest)
    let mut nonce = [0u8; 32];
    nonce[0] = 5;
    assert!(cache.check_and_insert(nonce, 1, 100, 1, ts + 1000).is_ok());

    let (size, _) = cache.stats();
    assert_eq!(size, 5);  // Still 5 (evicted one to stay at max)
}

// ============================================================================
// Capability Matrix Edge Cases
// ============================================================================

#[test]
fn test_capability_matrix_empty() {
    let matrix = CapabilityMatrix::new();

    assert!(!matrix.can_use(1, 1));
    assert_eq!(matrix.list_interfaces(1).len(), 0);
}

#[test]
fn test_capability_matrix_duplicate_allow() {
    let mut matrix = CapabilityMatrix::new();

    matrix.allow(1, 2);
    matrix.allow(1, 2);  // Duplicate

    // Should still be allowed, and list should have duplicates
    assert!(matrix.can_use(1, 2));
}

#[test]
fn test_capability_matrix_all_principals() {
    let mut matrix = CapabilityMatrix::new();

    // Give all 9 principals access to IF-011 (Audit logging)
    for i in 0..9u8 {
        matrix.allow(i, 11);
    }

    for i in 0..9u8 {
        assert!(matrix.can_use(i, 11));
    }
}

// ============================================================================
// Supervisor Principal Tracking Edge Cases
// ============================================================================

#[test]
fn test_supervisor_multiple_heartbeats() {
    let temp = NamedTempFile::new().unwrap();
    let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

    let initial = supervisor.principal_health(Principal::Policy).unwrap();
    let initial_ts = initial.last_heartbeat_ns;

    // Send multiple heartbeats
    supervisor.heartbeat(Principal::Policy);
    let after_hb1 = supervisor.principal_health(Principal::Policy).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(10));

    supervisor.heartbeat(Principal::Policy);
    let after_hb2 = supervisor.principal_health(Principal::Policy).unwrap();

    // Each heartbeat should update timestamp
    assert!(after_hb1.last_heartbeat_ns > initial_ts);
    assert!(after_hb2.last_heartbeat_ns > after_hb1.last_heartbeat_ns);
}

#[test]
fn test_supervisor_all_principals_independent() {
    let temp = NamedTempFile::new().unwrap();
    let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

    // Heartbeat only Policy
    supervisor.heartbeat(Principal::Policy);

    // Check that only Policy is healthy
    assert!(supervisor.is_principal_healthy(Principal::Policy));
    assert!(!supervisor.is_principal_healthy(Principal::Actuator));
    assert!(!supervisor.is_principal_healthy(Principal::Audit));
}

#[test]
fn test_supervisor_ledger_entry_count() {
    let temp = NamedTempFile::new().unwrap();
    let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

    let initial = supervisor.ledger_entries();
    assert!(initial >= 1);  // At least SUPERVISOR_START event

    // Log another event via ledger
    let ledger = supervisor.ledger();
    let mut details = HashMap::new();
    details.insert("test".to_string(), "value".to_string());

    let _ = ledger.append_event(
        EventType::ActionRequested,
        Principal::Policy,
        Severity::Info,
        supervisor.run_id(),
        supervisor.boot_id(),
        supervisor.epoch_id(),
        details,
    );

    let after = supervisor.ledger_entries();
    assert!(after > initial);
}

// ============================================================================
// Stress & Performance Tests
// ============================================================================

#[test]
fn test_message_serialization_stress() {
    // Serialize 1000 messages
    for i in 0..1000 {
        let payload = format!("payload-{}", i).into_bytes();
        let msg = UniversalMessage::new(
            (i % 22 + 1) as u32,
            (i % 4) as u8,
            (i % 9) as u8,
            ((i + 1) % 9) as u8,
            0,
            payload,
        );

        let json = msg.to_json().unwrap();
        let _parsed = UniversalMessage::from_json(&json).unwrap();
    }
}

#[test]
fn test_nonce_cache_large_batch() {
    let cache = NonceCache::new(5000, 100_000);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Insert 10,000 nonces
    for i in 0..10_000 {
        let mut nonce = [0u8; 32];
        nonce[0] = ((i >> 24) & 0xFF) as u8;
        nonce[1] = ((i >> 16) & 0xFF) as u8;
        nonce[2] = ((i >> 8) & 0xFF) as u8;
        nonce[3] = (i & 0xFF) as u8;

        let _ = cache.check_and_insert(nonce, 1, i as u64, 1, ts + i as u64);
    }

    let (size, max) = cache.stats();
    assert!(size <= max);
}

#[test]
fn test_multiple_supervisor_instances() {
    // Create multiple supervisor instances with separate ledgers
    let temp1 = NamedTempFile::new().unwrap();
    let temp2 = NamedTempFile::new().unwrap();

    let sup1 = Supervisor::initialize(temp1.path().to_str().unwrap(), None).unwrap();
    let sup2 = Supervisor::initialize(temp2.path().to_str().unwrap(), None).unwrap();

    // Should have different run IDs
    assert_ne!(sup1.run_id(), sup2.run_id());

    // Each should have independent principal tracking
    sup1.heartbeat(Principal::Policy);
    assert!(sup1.is_principal_healthy(Principal::Policy));
    assert!(!sup2.is_principal_healthy(Principal::Policy));
}
