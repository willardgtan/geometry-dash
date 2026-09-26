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

// ============================================================================
// Performance & Benchmarking Tests
// ============================================================================

#[test]
fn bench_message_serialization_latency() {
    use std::time::Instant;

    const NUM_MESSAGES: usize = 1000;
    let mut total_serialize_ns = 0u128;
    let mut total_deserialize_ns = 0u128;

    for i in 0..NUM_MESSAGES {
        let payload = format!("payload-{}", i).into_bytes();
        let msg = UniversalMessage::new(
            (i % 22 + 1) as u32,
            (i % 4) as u8,
            (i % 9) as u8,
            ((i + 1) % 9) as u8,
            0,
            payload,
        );

        // Measure serialization
        let start = Instant::now();
        let json = msg.to_json().unwrap();
        let serialize_ns = start.elapsed().as_nanos();
        total_serialize_ns += serialize_ns;

        // Measure deserialization
        let start = Instant::now();
        let _parsed = UniversalMessage::from_json(&json).unwrap();
        let deserialize_ns = start.elapsed().as_nanos();
        total_deserialize_ns += deserialize_ns;
    }

    let avg_serialize_us = (total_serialize_ns as f64 / NUM_MESSAGES as f64) / 1000.0;
    let avg_deserialize_us = (total_deserialize_ns as f64 / NUM_MESSAGES as f64) / 1000.0;

    eprintln!("Message serialization latency:");
    eprintln!("  Serialize: {:.2} µs average ({:.0} ns total)", avg_serialize_us, total_serialize_ns);
    eprintln!("  Deserialize: {:.2} µs average ({:.0} ns total)", avg_deserialize_us, total_deserialize_ns);

    // Target: <10ms = 10,000 µs per message round-trip
    // Average should be well under this
    assert!(avg_serialize_us < 5000.0, "Serialization too slow: {:.2} µs", avg_serialize_us);
    assert!(avg_deserialize_us < 5000.0, "Deserialization too slow: {:.2} µs", avg_deserialize_us);
}

#[test]
fn bench_nonce_cache_insertion_throughput() {
    use std::time::Instant;

    const NUM_NONCES: usize = 100_000;
    let cache = NonceCache::new(60000, 100_000);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let start = Instant::now();
    for i in 0..NUM_NONCES {
        let mut nonce = [0u8; 32];
        nonce[0] = ((i >> 24) & 0xFF) as u8;
        nonce[1] = ((i >> 16) & 0xFF) as u8;
        nonce[2] = ((i >> 8) & 0xFF) as u8;
        nonce[3] = (i & 0xFF) as u8;

        let _ = cache.check_and_insert(nonce, 1, i as u64, 1, ts + i as u64);
    }
    let elapsed = start.elapsed();

    let throughput = NUM_NONCES as f64 / elapsed.as_secs_f64();
    let avg_us = elapsed.as_secs_f64() / NUM_NONCES as f64 * 1_000_000.0;

    eprintln!("Nonce cache insertion throughput:");
    eprintln!("  {:.0} insertions/sec", throughput);
    eprintln!("  {:.2} µs per insertion", avg_us);
    eprintln!("  Total: {:.2} ms", elapsed.as_secs_f64() * 1000.0);

    // Target: ≥1,000 msg/sec = 1,000 insertions/sec
    assert!(throughput >= 1000.0, "Nonce cache too slow: {:.0} ops/sec", throughput);
}

#[test]
fn bench_security_ledger_append_latency() {
    use std::time::Instant;
    use std::collections::HashMap;

    let temp = NamedTempFile::new().unwrap();
    let ledger = geometry_dash::SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

    const NUM_EVENTS: usize = 1000;
    let mut total_ns = 0u128;

    for i in 0..NUM_EVENTS {
        let mut details = HashMap::new();
        details.insert("iteration".to_string(), i.to_string());

        let start = Instant::now();
        let _ = ledger.append_event(
            EventType::ActionRequested,
            Principal::Policy,
            Severity::Info,
            "run-1",
            "boot-1",
            "epoch-1",
            details,
        );
        let elapsed_ns = start.elapsed().as_nanos();
        total_ns += elapsed_ns;
    }

    let avg_us = (total_ns as f64 / NUM_EVENTS as f64) / 1000.0;
    eprintln!("SecurityLedger append latency:");
    eprintln!("  {:.2} µs average per event", avg_us);
    eprintln!("  Total: {:.2} ms", total_ns as f64 / 1_000_000.0);

    // Target: <100ms per event
    assert!(avg_us < 100_000.0, "Ledger append too slow: {:.2} µs", avg_us);
}

#[test]
fn bench_hash_chain_verification_speed() {
    use std::time::Instant;
    use std::collections::HashMap;

    let temp = NamedTempFile::new().unwrap();
    let ledger = geometry_dash::SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

    // Append 1000 events
    for i in 0..1000 {
        let mut details = HashMap::new();
        details.insert("iteration".to_string(), i.to_string());

        let _ = ledger.append_event(
            EventType::ActionRequested,
            Principal::Policy,
            Severity::Info,
            "run-1",
            "boot-1",
            "epoch-1",
            details,
        );
    }

    // Measure verification time
    let start = Instant::now();
    let result = ledger.verify_chain();
    let elapsed = start.elapsed();

    let elapsed_us = elapsed.as_secs_f64() * 1_000_000.0;
    eprintln!("Hash chain verification (1000 entries):");
    eprintln!("  {:.2} µs total", elapsed_us);
    eprintln!("  {:.2} µs per entry", elapsed_us / 1000.0);

    assert!(result.is_ok(), "Chain verification failed");
    assert!(elapsed_us < 50_000.0, "Chain verification too slow: {:.2} µs", elapsed_us);
}

#[test]
fn bench_supervisor_heartbeat_latency() {
    use std::time::Instant;

    let temp = NamedTempFile::new().unwrap();
    let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

    const NUM_HEARTBEATS: usize = 10_000;
    let mut total_ns = 0u128;

    for _ in 0..NUM_HEARTBEATS {
        let start = Instant::now();
        supervisor.heartbeat(Principal::Policy);
        total_ns += start.elapsed().as_nanos();
    }

    let avg_us = (total_ns as f64 / NUM_HEARTBEATS as f64) / 1000.0;
    eprintln!("Supervisor heartbeat latency:");
    eprintln!("  {:.3} µs average", avg_us);
    eprintln!("  Total: {:.2} ms", total_ns as f64 / 1_000_000.0);

    // Should be very fast (sub-microsecond)
    assert!(avg_us < 100.0, "Heartbeat too slow: {:.3} µs", avg_us);
}

// ============================================================================
// Edge Case & Failure Scenario Tests
// ============================================================================

#[test]
fn test_principal_crash_detection_via_timeout() {
    let temp = NamedTempFile::new().unwrap();
    let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

    // Principal is NotStarted, so it's unhealthy
    assert!(!supervisor.is_principal_healthy(Principal::Policy));

    // Send one heartbeat
    supervisor.heartbeat(Principal::Policy);
    assert!(supervisor.is_principal_healthy(Principal::Policy));

    // Wait for heartbeat timeout (default 1000ms)
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // Now principal should be unhealthy due to timeout
    assert!(!supervisor.is_principal_healthy(Principal::Policy));
}

#[test]
fn test_handshake_timeout_detection() {
    use std::time::Instant;

    let ctx = StartupContext::new(
        "run-1".to_string(),
        "boot-1".to_string(),
        "epoch-1".to_string(),
        "/var/run/geometry-dash".to_string(),
    );

    let mut orchestrator = PrincipalOrchestrator::new(ctx);
    orchestrator.add_principal(
        Principal::Policy,
        1001,
        1001,
        "strict".to_string(),
        "policy".to_string(),
    );

    // Send INIT but don't send READY
    let init_result = orchestrator.send_init(Principal::Policy, 100);
    assert!(init_result.is_ok());

    // Check that principal is NOT ready immediately
    assert!(!orchestrator.is_principal_ready(Principal::Policy));

    // Attempt to wait with short timeout
    let start = Instant::now();
    let wait_result = orchestrator.wait_all_ready(500);  // 500ms timeout
    let elapsed = start.elapsed();

    // Should timeout after ~500ms
    assert!(wait_result.is_err());
    assert!(elapsed.as_millis() >= 450);  // Allow some margin
}

#[test]
fn test_nonce_cache_prevents_replay_same_interface() {
    let cache = NonceCache::new(5000, 100_000);
    let nonce = [42u8; 32];
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // First insertion should succeed
    assert!(cache.check_and_insert(nonce, 1, 100, 1, ts).is_ok());

    // Replay of same nonce on same interface should fail
    let result = cache.check_and_insert(nonce, 1, 101, 1, ts + 100);
    assert!(result.is_err(), "Nonce replay not prevented!");
}

#[test]
fn test_capability_matrix_prevents_unauthorized_access() {
    let mut matrix = CapabilityMatrix::new();

    // Policy can use IF-002
    matrix.allow(1, 2);

    // Actuator cannot use IF-002 (not allowed)
    assert!(!matrix.can_use(2, 2));

    // But Policy can
    assert!(matrix.can_use(1, 2));
}

#[test]
fn test_security_ledger_chain_integrity_after_writes() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = geometry_dash::SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

    use std::collections::HashMap;

    // Write multiple events
    for i in 0..100 {
        let mut details = HashMap::new();
        details.insert("iteration".to_string(), i.to_string());

        let _ = ledger.append_event(
            EventType::ActionRequested,
            Principal::Policy,
            Severity::Info,
            "run-1",
            "boot-1",
            "epoch-1",
            details,
        );
    }

    // Verify chain integrity
    let result = ledger.verify_chain();
    assert!(result.is_ok(), "Chain integrity check failed");
}

#[test]
fn test_supervisor_lockdown_mode() {
    let temp = NamedTempFile::new().unwrap();
    let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

    // Initial state should be Initializing
    assert_eq!(supervisor.state(), SupervisorState::Initializing);

    // Enter lockdown
    supervisor.enter_lockdown();

    // Should now be in Lockdown state
    assert_eq!(supervisor.state(), SupervisorState::Lockdown);

    // Verify lockdown was logged
    assert!(supervisor.ledger_entries() > 0);
}

#[test]
fn test_message_flag_combinations_validity() {
    let test_flags = vec![
        0x01,  // REQUIRES_AUTH
        0x02,  // REQUIRES_NONCE
        0x04,  // REQUIRES_RESPONSE
        0x08,  // IDEMPOTENT
        0x10,  // PRIORITY_HIGH
        0x20,  // CRITICAL
        0x03,  // AUTH + NONCE
        0x0C,  // RESPONSE + IDEMPOTENT
        0x1F,  // Multiple flags
        0xFF,  // All flags
    ];

    for flags in test_flags {
        let msg = UniversalMessage::new(1, 0, 1, 2, flags, b"test".to_vec());
        assert_eq!(msg.header.flags, flags);
        assert!(msg.validate_size().is_ok());
    }
}

#[test]
fn test_principal_health_crash_count_independence() {
    let temp = NamedTempFile::new().unwrap();
    let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

    // Get initial health for both principals
    let health1_initial = supervisor.principal_health(Principal::Policy).unwrap();
    let health2_initial = supervisor.principal_health(Principal::Actuator).unwrap();

    assert_eq!(health1_initial.crash_count, 0);
    assert_eq!(health2_initial.crash_count, 0);

    // Send heartbeat to one principal
    supervisor.heartbeat(Principal::Policy);

    // Other principal should still be at 0 crash count
    let health2_after = supervisor.principal_health(Principal::Actuator).unwrap();
    assert_eq!(health2_after.crash_count, 0);

    // And Policy should be running
    assert_eq!(supervisor.principal_health(Principal::Policy).unwrap().state, PrincipalState::Running);
}

// ============================================================================
// Named Pipe Management Tests (Week 1 Task 1.4)
// ============================================================================

#[test]
fn test_pipe_manager_all_22_interfaces() {
    use geometry_dash::PipeManager;
    
    let temp_dir = tempfile::TempDir::new().unwrap();
    let mut pm = PipeManager::new(temp_dir.path().to_str().unwrap()).unwrap();

    // Create all 22 pipes
    let result = pm.create_all_pipes();
    assert!(result.is_ok());
    assert_eq!(pm.pipe_count(), 22);

    // Verify all exist
    for if_id in 1..=22 {
        assert!(pm.get_pipe(if_id).is_some());
    }

    pm.cleanup_all().unwrap();
}

#[test]
fn test_pipe_manager_individual_creation() {
    use geometry_dash::PipeManager;
    
    let temp_dir = tempfile::TempDir::new().unwrap();
    let mut pm = PipeManager::new(temp_dir.path().to_str().unwrap()).unwrap();

    pm.create_pipe(1).unwrap();
    assert_eq!(pm.pipe_count(), 1);

    pm.create_pipe(10).unwrap();
    assert_eq!(pm.pipe_count(), 2);

    pm.create_pipe(22).unwrap();
    assert_eq!(pm.pipe_count(), 3);

    pm.cleanup_all().unwrap();
    assert_eq!(pm.pipe_count(), 0);
}

#[test]
fn test_pipe_manager_invalid_interface_ids() {
    use geometry_dash::PipeManager;
    
    let temp_dir = tempfile::TempDir::new().unwrap();
    let mut pm = PipeManager::new(temp_dir.path().to_str().unwrap()).unwrap();

    // Test invalid IDs
    assert!(pm.create_pipe(0).is_err());   // Below range
    assert!(pm.create_pipe(23).is_err());  // Above range
    assert!(pm.create_pipe(100).is_err()); // Way above range
}

#[test]
fn test_pipe_manager_idempotent_creation() {
    use geometry_dash::PipeManager;
    
    let temp_dir = tempfile::TempDir::new().unwrap();
    let mut pm = PipeManager::new(temp_dir.path().to_str().unwrap()).unwrap();

    // Create once
    pm.create_all_pipes().unwrap();
    assert_eq!(pm.pipe_count(), 22);

    // Create again (should succeed by removing old ones)
    pm.create_all_pipes().unwrap();
    assert_eq!(pm.pipe_count(), 22);
}

#[test]
fn test_orchestrator_pipe_initialization_full_workflow() {
    use geometry_dash::PrincipalOrchestrator;
    use geometry_dash::supervisor::startup::StartupContext;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let ctx = StartupContext::new(
        "run-1".to_string(),
        "boot-1".to_string(),
        "epoch-1".to_string(),
        temp_dir.path().to_str().unwrap().to_string(),
    );

    let mut orchestrator = PrincipalOrchestrator::new(ctx);
    
    // Initialize pipes
    assert!(orchestrator.initialize_pipes().is_ok());
    assert_eq!(orchestrator.pipe_count(), 22);

    // Access pipe manager
    let pm = orchestrator.pipe_manager();
    assert_eq!(pm.pipe_count(), 22);

    // Cleanup
    let mut orch = orchestrator;
    assert!(orch.cleanup_pipes().is_ok());
    assert_eq!(orch.pipe_count(), 0);
}

#[test]
fn test_pipe_names_follow_convention() {
    use geometry_dash::PipeManager;
    
    let temp_dir = tempfile::TempDir::new().unwrap();
    let mut pm = PipeManager::new(temp_dir.path().to_str().unwrap()).unwrap();

    pm.create_all_pipes().unwrap();

    let pipes = pm.all_pipes();
    for pipe_info in pipes {
        let path_str = pipe_info.pipe_path.to_string_lossy();
        
        // Should be named if-NNN.pipe
        let filename = pipe_info.pipe_path.file_name().unwrap().to_string_lossy();
        assert!(filename.starts_with("if-"));
        assert!(filename.ends_with(".pipe"));
        
        // Extract and verify interface ID
        let parts: Vec<&str> = filename.split('-').collect();
        assert_eq!(parts.len(), 2);  // if- and rest
    }

    pm.cleanup_all().unwrap();
}

#[test]
fn test_pipe_manager_cleanup_removes_all() {
    use geometry_dash::PipeManager;
    
    let temp_dir = tempfile::TempDir::new().unwrap();
    let mut pm = PipeManager::new(temp_dir.path().to_str().unwrap()).unwrap();

    // Create pipes
    pm.create_all_pipes().unwrap();
    assert_eq!(pm.pipe_count(), 22);

    // Cleanup all
    pm.cleanup_all().unwrap();
    assert_eq!(pm.pipe_count(), 0);
    
    // Pipes list should be empty
    assert_eq!(pm.all_pipes().len(), 0);
}

#[test]
fn test_pipe_manager_selective_cleanup() {
    use geometry_dash::PipeManager;
    
    let temp_dir = tempfile::TempDir::new().unwrap();
    let mut pm = PipeManager::new(temp_dir.path().to_str().unwrap()).unwrap();

    // Create three pipes
    pm.create_pipe(1).unwrap();
    pm.create_pipe(5).unwrap();
    pm.create_pipe(10).unwrap();
    assert_eq!(pm.pipe_count(), 3);

    // Cleanup one
    pm.cleanup_pipe(5).unwrap();
    assert_eq!(pm.pipe_count(), 2);

    // Verify only 1 and 10 remain
    assert!(pm.get_pipe(1).is_some());
    assert!(pm.get_pipe(5).is_none());
    assert!(pm.get_pipe(10).is_some());
}
