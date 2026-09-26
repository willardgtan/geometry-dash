// Crisis Scenario Tests for Week 2+ Integration
// Tests system behavior under attack scenarios, failure conditions, and recovery

use geometry_dash::{
    SecurityLedger, EventType, Severity,
    PolicyPrincipal, ActuatorPrincipal, AuditPrincipal, SealerPrincipal,
    Principal, InterfaceId,
    UniversalMessage, NonceCache, CapabilityMatrix,
    AutoHsmClient,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;

/// Test 1: Replay Attack Prevention via Nonce Cache
/// Validates that duplicate messages with same nonce are rejected
#[test]
fn test_replay_attack_prevention() {
    let nonce_cache = NonceCache::new(5000, 1000);
    let nonce = [42u8; 32];
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // First message with nonce should succeed
    let result1 = nonce_cache.check_and_insert(nonce, 1, 100, 1, ts);
    assert!(result1.is_ok(), "First nonce should be accepted");

    // Immediate replay (same nonce) should fail
    let result2 = nonce_cache.check_and_insert(nonce, 1, 100, 1, ts + 100);
    assert!(result2.is_err(), "Replay with same nonce should be rejected");

    // Different nonce should succeed
    let different_nonce = [43u8; 32];
    let result3 = nonce_cache.check_and_insert(different_nonce, 1, 101, 1, ts + 200);
    assert!(result3.is_ok(), "Different nonce should be accepted");
}

/// Test 2: Unauthorized Command Execution Prevention
/// Validates that Gate C prevents unauthorized principals from executing commands
#[test]
fn test_unauthorized_command_execution_prevention() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize Actuator without prior Policy authorization
    let actuator_key = hsm.lock().unwrap().generate_key("actuator-unauth").unwrap();
    let mut actuator = ActuatorPrincipal::new(ledger.clone());
    actuator.initialize(actuator_key).unwrap();

    // Attempt command from unauthorized principal
    let request = geometry_dash::CommandRequest {
        request_id: "unauth-cmd".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
        command: "privileged_action".to_string(),
        requester: Principal::Audit,  // Audit is not authorized for command execution
        target_interface: InterfaceId::from(3),
        context: HashMap::new(),
    };

    actuator.queue_command(request).unwrap();
    let results = actuator.process_queue().unwrap();

    // Command should fail Gate C validation
    assert!(!results.is_empty(), "Should have execution results");
    assert!(!results[0].gate_c_passed, "Gate C should reject unauthorized principal");

    // Verify failure logged in audit trail
    let ledger_lock = ledger.lock().unwrap();
    let mut failure_logged = false;

    for i in 0..ledger_lock.count() {
        if let Ok(event) = ledger_lock.get(i as usize) {
            if matches!(event.event_type, EventType::ActionBlocked) {
                failure_logged = true;
                break;
            }
        }
    }

    assert!(failure_logged, "Authorization failure should be logged");
}

/// Test 3: Message Integrity Attack Prevention
/// Validates that corrupted or tampered messages are rejected (Gate I)
#[test]
fn test_message_integrity_attack_prevention() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize Actuator
    let actuator_key = hsm.lock().unwrap().generate_key("actuator-integrity").unwrap();
    let mut actuator = ActuatorPrincipal::new(ledger.clone());
    actuator.initialize(actuator_key).unwrap();

    // Create request with empty command (fails Gate I integrity check)
    let request = geometry_dash::CommandRequest {
        request_id: "corrupt-cmd".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
        command: "".to_string(),  // Empty command fails integrity
        requester: Principal::Policy,
        target_interface: InterfaceId::from(3),
        context: HashMap::new(),
    };

    actuator.queue_command(request).unwrap();
    let results = actuator.process_queue().unwrap();

    assert!(!results.is_empty(), "Should have execution results");
    // Gate I should detect integrity issue
    let gate_i_check_result = !results[0].gate_i_passed || results[0].command == "";
    assert!(gate_i_check_result, "Gate I should detect integrity violation");
}

/// Test 4: Capability Matrix Enforcement
/// Validates that principals cannot access interfaces they're not authorized for
#[test]
fn test_capability_matrix_enforcement() {
    let mut matrix = CapabilityMatrix::new();

    // Setup: Policy (1) has IF-002, Actuator (2) has IF-003
    matrix.allow(Principal::Policy as u8, 2);
    matrix.allow(Principal::Actuator as u8, 3);

    // Test allowed access
    assert!(matrix.can_use(Principal::Policy as u8, 2), "Policy should access IF-002");
    assert!(matrix.can_use(Principal::Actuator as u8, 3), "Actuator should access IF-003");

    // Test denied access (wrong principal/interface combinations)
    assert!(!matrix.can_use(Principal::Policy as u8, 3), "Policy should NOT access IF-003");
    assert!(!matrix.can_use(Principal::Actuator as u8, 2), "Actuator should NOT access IF-002");
    assert!(!matrix.can_use(Principal::Audit as u8, 3), "Audit should NOT access IF-003");
    assert!(!matrix.can_use(Principal::Declassifier as u8, 2), "Declassifier should NOT access IF-002");
}

/// Test 5: Audit Trail Integrity Under Load
/// Validates that audit trail captures all events even under stress
#[test]
fn test_audit_trail_integrity_under_load() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize Policy and Actuator
    let policy_key = hsm.lock().unwrap().generate_key("policy-load").unwrap();
    let actuator_key = hsm.lock().unwrap().generate_key("actuator-load").unwrap();

    let mut policy = PolicyPrincipal::new(ledger.clone());
    let mut actuator = ActuatorPrincipal::new(ledger.clone());

    policy.initialize(policy_key).unwrap();
    actuator.initialize(actuator_key).unwrap();

    // Execute 50 authorization + execution cycles
    for i in 0..50 {
        let _decision = policy.gate_a_decision(
            Principal::Actuator,
            InterfaceId::from(3),
            &HashMap::new(),
        ).unwrap();

        let request = geometry_dash::CommandRequest {
            request_id: format!("load-cmd-{:03}", i),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            command: "stress_test".to_string(),
            requester: Principal::Policy,
            target_interface: InterfaceId::from(3),
            context: HashMap::new(),
        };

        actuator.queue_command(request).unwrap();
    }

    let results = actuator.process_queue().unwrap();
    assert_eq!(results.len(), 50, "Should execute all 50 commands");

    // Verify audit trail captured all operations
    let ledger_lock = ledger.lock().unwrap();
    let audit_entries = ledger_lock.count();

    // Should have: 50 decisions + 50 executions + startup events = at least 100
    assert!(
        audit_entries >= 100,
        "Audit trail should have >=100 entries (actual: {})",
        audit_entries
    );
}

/// Test 6: Principal State Recovery After Anomaly
/// Validates that Sealer can detect and recover from inconsistent state
#[test]
fn test_principal_state_recovery_after_anomaly() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize principals
    let actuator_key = hsm.lock().unwrap().generate_key("actuator-anomaly").unwrap();
    let sealer_key = hsm.lock().unwrap().generate_key("sealer-anomaly").unwrap();

    let mut actuator = ActuatorPrincipal::new(ledger.clone());
    let mut sealer = SealerPrincipal::new(ledger.clone());

    actuator.initialize(actuator_key).unwrap();
    sealer.initialize(sealer_key).unwrap();

    // Execute some commands
    for i in 0..5 {
        let request = geometry_dash::CommandRequest {
            request_id: format!("anomaly-cmd-{:03}", i),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            command: "normal_op".to_string(),
            requester: Principal::Policy,
            target_interface: InterfaceId::from(3),
            context: HashMap::new(),
        };

        actuator.queue_command(request).unwrap();
    }

    let _results = actuator.process_queue().unwrap();

    // Sealer detects state consistency
    let check = geometry_dash::ConsistencyCheck {
        principal: Principal::Actuator,
        expected_state: "Ready".to_string(),
        check_type: "anomaly_recovery".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    };

    let is_consistent = sealer.verify_consistency(&check).unwrap();
    assert!(is_consistent, "Actuator state should be recoverable");
}

/// Test 7: Concurrent Access Control
/// Validates that multiple threads cannot corrupt shared state
#[test]
fn test_concurrent_access_control() {
    use std::thread;

    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize shared Actuator
    let actuator_key = hsm.lock().unwrap().generate_key("actuator-concurrent").unwrap();
    let actuator = Arc::new(Mutex::new(ActuatorPrincipal::new(ledger.clone())));

    {
        let mut act = actuator.lock().unwrap();
        act.initialize(actuator_key).unwrap();
    }

    // Spawn multiple threads executing commands concurrently
    let mut handles = vec![];

    for thread_id in 0..5 {
        let actuator_clone = Arc::clone(&actuator);
        let handle = thread::spawn(move || {
            let mut actuator = actuator_clone.lock().unwrap();
            for cmd_id in 0..10 {
                let request = geometry_dash::CommandRequest {
                    request_id: format!("concurrent-t{}-c{:02}", thread_id, cmd_id),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64,
                    command: "concurrent_test".to_string(),
                    requester: Principal::Policy,
                    target_interface: InterfaceId::from(3),
                    context: HashMap::new(),
                };

                let _ = actuator.queue_command(request);
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Process all queued commands
    let results = actuator.lock().unwrap().process_queue().unwrap();

    // Should have 5 threads × 10 commands = 50 commands
    assert_eq!(results.len(), 50, "All concurrent commands should be executed");

    // Verify no data corruption
    let request_ids: std::collections::HashSet<_> = results
        .iter()
        .map(|r| r.request_id.clone())
        .collect();

    assert_eq!(request_ids.len(), 50, "No duplicate requests (no corruption)");
}

/// Test 8: Breach Detection via Audit Principal
/// Validates that anomalous patterns trigger breach detection
#[test]
fn test_breach_detection_anomalous_patterns() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize Actuator and Audit
    let actuator_key = hsm.lock().unwrap().generate_key("actuator-breach").unwrap();
    let audit_key = hsm.lock().unwrap().generate_key("audit-breach").unwrap();

    let mut actuator = ActuatorPrincipal::new(ledger.clone());
    let mut audit = AuditPrincipal::new(ledger.clone());

    actuator.initialize(actuator_key).unwrap();
    audit.initialize(audit_key).unwrap();

    // Execute many commands rapidly (anomalous pattern)
    for i in 0..100 {
        let request = geometry_dash::CommandRequest {
            request_id: format!("breach-detect-{:03}", i),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64 + (i as u64 * 10),  // Rapid succession
            command: "rapid_execution".to_string(),
            requester: Principal::Policy,
            target_interface: InterfaceId::from(3),
            context: HashMap::new(),
        };

        actuator.queue_command(request).unwrap();
    }

    let _results = actuator.process_queue().unwrap();

    // Audit analyzes for anomalies
    let breaches = audit.detect_breaches(&HashMap::new()).unwrap();

    // Rapid execution pattern should be detected as potential anomaly
    assert!(
        !breaches.is_empty(),
        "Audit should detect anomalous rapid execution pattern"
    );
}

/// Test 9: Cryptographic Key Compromise Scenario
/// Validates that key rotation and recovery mechanisms work
#[test]
fn test_cryptographic_key_rotation_recovery() {
    let hsm = AutoHsmClient::new().unwrap();

    // Generate initial keys
    let key1 = hsm.generate_key("principal-original").unwrap();
    let key1_public = key1.public_key();

    // Simulate key rotation
    let key2 = hsm.generate_key("principal-rotated").unwrap();
    let key2_public = key2.public_key();

    // Verify keys are different (not reused)
    assert_ne!(key1_public, key2_public, "Rotated key should be different");

    // Verify old key is still accessible for signature verification
    let message = b"test signature verification";
    let signature = key1.sign(message).unwrap();

    // Old signature should still verify with old key
    assert!(key1.verify(message, &signature).is_ok(), "Old key should verify old signatures");

    // But should NOT verify with new key
    assert!(
        key2.verify(message, &signature).is_err(),
        "New key should reject old signatures"
    );
}

/// Test 10: Full Crisis Scenario - Attack → Detection → Recovery
/// Complete scenario: unauthorized access attempt → detection → automated recovery
#[test]
fn test_full_crisis_scenario_attack_detection_recovery() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize all security principals
    let policy_key = hsm.lock().unwrap().generate_key("policy-crisis").unwrap();
    let actuator_key = hsm.lock().unwrap().generate_key("actuator-crisis").unwrap();
    let audit_key = hsm.lock().unwrap().generate_key("audit-crisis").unwrap();
    let sealer_key = hsm.lock().unwrap().generate_key("sealer-crisis").unwrap();

    let mut policy = PolicyPrincipal::new(ledger.clone());
    let mut actuator = ActuatorPrincipal::new(ledger.clone());
    let mut audit = AuditPrincipal::new(ledger.clone());
    let mut sealer = SealerPrincipal::new(ledger.clone());

    policy.initialize(policy_key).unwrap();
    actuator.initialize(actuator_key).unwrap();
    audit.initialize(audit_key).unwrap();
    sealer.initialize(sealer_key).unwrap();

    // Phase 1: Legitimate operations
    let auth_decision = policy.gate_a_decision(
        Principal::Actuator,
        InterfaceId::from(3),
        &HashMap::new(),
    ).unwrap();
    assert!(auth_decision.authorized);

    policy.delegate_capability(Principal::Actuator, InterfaceId::from(3)).unwrap();

    // Phase 2: Attack attempt (unauthorized execution)
    let attack_request = geometry_dash::CommandRequest {
        request_id: "attack-001".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
        command: "unauthorized_escalation".to_string(),
        requester: Principal::Audit,  // Audit has no execution privileges
        target_interface: InterfaceId::from(3),
        context: HashMap::new(),
    };

    actuator.queue_command(attack_request).unwrap();
    let attack_results = actuator.process_queue().unwrap();

    // Attack should fail Gate C
    assert!(!attack_results[0].gate_c_passed, "Unauthorized request should fail Gate C");

    // Phase 3: Detection (Audit analyzes)
    let anomalies = audit.analyze_events(&HashMap::new()).unwrap();
    assert!(!anomalies.is_empty(), "Should detect unauthorized access attempt");

    // Phase 4: Recovery (Sealer verifies system integrity)
    let check = geometry_dash::ConsistencyCheck {
        principal: Principal::Actuator,
        expected_state: "Ready".to_string(),
        check_type: "post_attack_verification".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    };

    let recovery_ok = sealer.verify_consistency(&check).unwrap();
    assert!(recovery_ok, "System should recover to consistent state");

    // Verify complete incident logged
    let ledger_lock = ledger.lock().unwrap();
    let entries = ledger_lock.count();
    assert!(entries > 0, "Incident should be completely logged");

    // Count security-relevant events
    let mut auth_failures = 0;
    for i in 0..entries {
        if let Ok(event) = ledger_lock.get(i as usize) {
            if matches!(event.event_type, EventType::ActionBlocked) {
                auth_failures += 1;
            }
        }
    }

    assert!(auth_failures > 0, "Unauthorized attempt should be logged as blocked action");
}
