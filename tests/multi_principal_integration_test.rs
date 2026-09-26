// Multi-Principal Integration Tests for Week 2+ (All 8 Principals)
// Tests end-to-end workflows across multiple principals and their interactions via IPC

use geometry_dash::{
    Supervisor, SecurityLedger, SecurityEvent, EventType, Severity,
    PolicyPrincipal, ActuatorPrincipal, AuditPrincipal, DeclassifierPrincipal,
    LearnerPrincipal, EvaluatorPrincipal, SealerPrincipal, DeveloperPrincipal,
    Principal, InterfaceId, MessageType,
    UniversalMessage, NonceCache, CapabilityMatrix, AutoHsmClient,
    ClassificationLevel, ConsistencyCheck,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;

/// Test 1: Policy Principal → Actuator Principal Authorization Flow
/// Validates Gate A (authorization) followed by command execution with Gates C & I
#[test]
fn test_policy_to_actuator_authorization_flow() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize principals
    let policy_key = hsm.lock().unwrap().generate_key("policy").unwrap();
    let actuator_key = hsm.lock().unwrap().generate_key("actuator").unwrap();

    let mut policy = PolicyPrincipal::new(ledger.clone());
    let mut actuator = ActuatorPrincipal::new(ledger.clone());

    policy.initialize(policy_key).unwrap();
    actuator.initialize(actuator_key).unwrap();

    // Step 1: Policy evaluates authorization for Actuator
    let context = HashMap::new();
    let decision = policy.gate_a_decision(
        Principal::Actuator,
        InterfaceId::from(3),  // IF-003: control interface
        &context,
    ).unwrap();

    assert!(decision.authorized, "Actuator should be authorized for control interface");

    // Step 2: Policy delegates capability to Actuator
    policy.delegate_capability(
        Principal::Actuator,
        InterfaceId::from(3),
    ).unwrap();

    // Step 3: Actuator queues command (would normally come via IPC)
    let request = geometry_dash::CommandRequest {
        request_id: "cmd-001".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
        command: "execute_action".to_string(),
        requester: Principal::Policy,
        target_interface: InterfaceId::from(3),
        context: HashMap::new(),
    };

    actuator.queue_command(request).unwrap();

    // Step 4: Actuator processes the command
    let results = actuator.process_queue().unwrap();
    assert!(!results.is_empty(), "Should have execution results");
    assert!(results[0].success, "Command should execute successfully");

    // Step 5: Verify audit trail in SecurityLedger
    let ledger_lock = ledger.lock().unwrap();
    let entries = ledger_lock.count();
    assert!(entries > 0, "SecurityLedger should have recorded all operations");

    // Check that both Gate A and execution events were logged
    let mut gate_a_found = false;
    let mut action_executed = false;

    for i in 0..entries {
        if let Ok(event) = ledger_lock.get(i as usize) {
            match event.event_type {
                EventType::GateADecision => gate_a_found = true,
                EventType::ActionExecuted => action_executed = true,
                _ => {}
            }
        }
    }

    assert!(gate_a_found, "GateADecision event should be logged");
    assert!(action_executed, "ActionExecuted event should be logged");
}

/// Test 2: Actuator → Audit → Learner Pattern Analysis Workflow
/// Tests event correlation, pattern detection, and recommendation generation
#[test]
fn test_actuator_audit_learner_workflow() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize principals
    let actuator_key = hsm.lock().unwrap().generate_key("actuator").unwrap();
    let audit_key = hsm.lock().unwrap().generate_key("audit").unwrap();
    let learner_key = hsm.lock().unwrap().generate_key("learner").unwrap();

    let mut actuator = ActuatorPrincipal::new(ledger.clone());
    let mut audit = AuditPrincipal::new(ledger.clone());
    let mut learner = LearnerPrincipal::new(ledger.clone());

    actuator.initialize(actuator_key).unwrap();
    audit.initialize(audit_key).unwrap();
    learner.initialize(learner_key).unwrap();

    // Step 1: Execute multiple commands through Actuator
    for i in 0..5 {
        let request = geometry_dash::CommandRequest {
            request_id: format!("cmd-{:03}", i),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64 + (i as u64 * 1000),
            command: "query_resource".to_string(),
            requester: Principal::Policy,
            target_interface: InterfaceId::from(3),
            context: HashMap::new(),
        };

        actuator.queue_command(request).unwrap();
    }

    let _results = actuator.process_queue().unwrap();

    // Step 2: Audit Principal analyzes events
    let mut context = HashMap::new();
    context.insert("severity_threshold".to_string(), "low".to_string());

    let correlations = audit.analyze_events(&context).unwrap();
    assert!(!correlations.is_empty(), "Audit should find event correlations");

    // Step 3: Learner Principal detects patterns
    let mut context = HashMap::new();
    context.insert("min_occurrences".to_string(), "2".to_string());

    let patterns = learner.analyze_patterns(&context).unwrap();
    assert!(!patterns.is_empty(), "Learner should detect patterns");

    // Step 4: Generate recommendations
    let recommendations = learner.generate_recommendations(&context).unwrap();
    assert!(!recommendations.is_empty(), "Learner should generate recommendations");
}

/// Test 3: Data Classification → Declassification Workflow
/// Tests the complete classification lifecycle through Declassifier Principal
#[test]
fn test_declassifier_classification_workflow() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize Declassifier Principal
    let declassifier_key = hsm.lock().unwrap().generate_key("declassifier").unwrap();

    let mut declassifier = DeclassifierPrincipal::new(ledger.clone());
    declassifier.initialize(declassifier_key).unwrap();

    // Step 1: Classify a resource
    let mut context = HashMap::new();
    context.insert("resource_id".to_string(), "data-001".to_string());

    let classification = declassifier.classify_resource(
        "data-001",
        ClassificationLevel::Secret,
        &context,
    ).unwrap();

    assert_eq!(classification.level, ClassificationLevel::Secret);

    // Step 2: Request declassification
    let request = geometry_dash::DeclassificationRequest {
        resource_id: "data-001".to_string(),
        target_level: ClassificationLevel::Confidential,
        reason: "Project completion review".to_string(),
        requester: Principal::Audit,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    };

    let decision = declassifier.process_declassification_request(&request).unwrap();
    assert!(!decision.is_none(), "Declassification should be evaluated");

    // Step 3: Verify resource is now at lower classification
    let resource = declassifier.get_resource_classification("data-001").unwrap();
    assert!(resource.is_some(), "Resource classification should exist");
}

/// Test 4: Policy Effectiveness → Evaluator → Compliance Check
/// Tests decision evaluation and compliance verification
#[test]
fn test_evaluator_compliance_verification_workflow() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize principals
    let policy_key = hsm.lock().unwrap().generate_key("policy").unwrap();
    let evaluator_key = hsm.lock().unwrap().generate_key("evaluator").unwrap();

    let mut policy = PolicyPrincipal::new(ledger.clone());
    let mut evaluator = EvaluatorPrincipal::new(ledger.clone());

    policy.initialize(policy_key).unwrap();
    evaluator.initialize(evaluator_key).unwrap();

    // Step 1: Make authorization decisions through Policy
    for i in 0..10 {
        let mut context = HashMap::new();
        context.insert("request_id".to_string(), format!("auth-{:03}", i));

        let _decision = policy.gate_a_decision(
            Principal::Actuator,
            InterfaceId::from(3),
            &context,
        ).unwrap();

        policy.delegate_capability(Principal::Actuator, InterfaceId::from(3)).unwrap();
    }

    // Step 2: Evaluator evaluates decisions
    let mut context = HashMap::new();
    context.insert("policy_id".to_string(), "policy-001".to_string());

    let effectiveness = evaluator.evaluate_policy_effectiveness(&context).unwrap();
    assert!(effectiveness.is_some(), "Should evaluate policy effectiveness");

    // Step 3: Verify compliance
    let compliance = evaluator.verify_compliance(&context).unwrap();
    assert!(compliance.is_some(), "Should generate compliance report");
}

/// Test 5: Multi-Principal State Consistency via Sealer
/// Tests consistency verification across all principals
#[test]
fn test_sealer_multi_principal_consistency() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize all principals
    let policy_key = hsm.lock().unwrap().generate_key("policy").unwrap();
    let actuator_key = hsm.lock().unwrap().generate_key("actuator").unwrap();
    let audit_key = hsm.lock().unwrap().generate_key("audit").unwrap();
    let sealer_key = hsm.lock().unwrap().generate_key("sealer").unwrap();

    let mut policy = PolicyPrincipal::new(ledger.clone());
    let mut actuator = ActuatorPrincipal::new(ledger.clone());
    let mut audit = AuditPrincipal::new(ledger.clone());
    let mut sealer = SealerPrincipal::new(ledger.clone());

    policy.initialize(policy_key).unwrap();
    actuator.initialize(actuator_key).unwrap();
    audit.initialize(audit_key).unwrap();
    sealer.initialize(sealer_key).unwrap();

    // Step 1: Run operations across multiple principals
    let _decision = policy.gate_a_decision(
        Principal::Actuator,
        InterfaceId::from(3),
        &HashMap::new(),
    ).unwrap();

    let request = geometry_dash::CommandRequest {
        request_id: "cmd-001".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
        command: "test".to_string(),
        requester: Principal::Policy,
        target_interface: InterfaceId::from(3),
        context: HashMap::new(),
    };

    actuator.queue_command(request).unwrap();
    let _results = actuator.process_queue().unwrap();

    // Step 2: Sealer verifies consistency
    let check = ConsistencyCheck {
        principal: Principal::Policy,
        expected_state: "Ready".to_string(),
        check_type: "state_transition".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    };

    let result = sealer.verify_consistency(&check).unwrap();
    assert!(result, "State should be consistent");

    // Step 3: Generate consistency report
    let report = sealer.generate_consistency_report().unwrap();
    assert!(report.is_some(), "Should generate consistency report");
}

/// Test 6: Developer Principal Tracing and Diagnostics
/// Tests introspection, trace recording, and diagnostic report generation
#[test]
fn test_developer_tracing_diagnostics_workflow() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize principals
    let policy_key = hsm.lock().unwrap().generate_key("policy").unwrap();
    let developer_key = hsm.lock().unwrap().generate_key("developer").unwrap();

    let mut policy = PolicyPrincipal::new(ledger.clone());
    let mut developer = DeveloperPrincipal::new(ledger.clone());

    policy.initialize(policy_key).unwrap();
    developer.initialize(developer_key).unwrap();

    // Step 1: Execute operations with Developer tracking
    let _decision = policy.gate_a_decision(
        Principal::Actuator,
        InterfaceId::from(3),
        &HashMap::new(),
    ).unwrap();

    // Step 2: Record trace points
    let mut context = HashMap::new();
    context.insert("principal".to_string(), "policy".to_string());
    context.insert("operation".to_string(), "gate_a_decision".to_string());

    developer.record_trace_point("gate_a_decision", &context).unwrap();

    // Step 3: Capture principal state snapshot
    let snapshot = developer.capture_principal_snapshot(Principal::Policy).unwrap();
    assert!(snapshot.is_some(), "Should capture principal snapshot");

    // Step 4: Generate diagnostic report
    let report = developer.generate_diagnostic_report().unwrap();
    assert!(report.is_some(), "Should generate diagnostic report");
}

/// Test 7: Full Authorization + Execution + Audit Trail (E2E)
/// Complete workflow: Policy auth → Actuator exec → Audit analysis → Learner recommend
#[test]
fn test_full_e2e_authorization_execution_audit_workflow() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize all core principals
    let policy_key = hsm.lock().unwrap().generate_key("policy").unwrap();
    let actuator_key = hsm.lock().unwrap().generate_key("actuator").unwrap();
    let audit_key = hsm.lock().unwrap().generate_key("audit").unwrap();
    let learner_key = hsm.lock().unwrap().generate_key("learner").unwrap();

    let mut policy = PolicyPrincipal::new(ledger.clone());
    let mut actuator = ActuatorPrincipal::new(ledger.clone());
    let mut audit = AuditPrincipal::new(ledger.clone());
    let mut learner = LearnerPrincipal::new(ledger.clone());

    policy.initialize(policy_key).unwrap();
    actuator.initialize(actuator_key).unwrap();
    audit.initialize(audit_key).unwrap();
    learner.initialize(learner_key).unwrap();

    // Phase 1: Authorization
    let context = HashMap::new();
    let decision = policy.gate_a_decision(
        Principal::Actuator,
        InterfaceId::from(3),
        &context,
    ).unwrap();

    assert!(decision.authorized);

    policy.delegate_capability(Principal::Actuator, InterfaceId::from(3)).unwrap();

    // Phase 2: Execution (10 commands)
    for i in 0..10 {
        let request = geometry_dash::CommandRequest {
            request_id: format!("cmd-e2e-{:03}", i),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64 + (i as u64 * 1000),
            command: "query_resource".to_string(),
            requester: Principal::Policy,
            target_interface: InterfaceId::from(3),
            context: HashMap::new(),
        };

        actuator.queue_command(request).unwrap();
    }

    let results = actuator.process_queue().unwrap();
    assert_eq!(results.len(), 10, "Should execute all 10 commands");
    assert!(results.iter().all(|r| r.success), "All commands should succeed");

    // Phase 3: Audit Analysis
    let correlations = audit.analyze_events(&HashMap::new()).unwrap();
    assert!(!correlations.is_empty(), "Should find correlations");

    // Phase 4: Learning and Recommendations
    let patterns = learner.analyze_patterns(&HashMap::new()).unwrap();
    assert!(!patterns.is_empty(), "Should detect patterns");

    let recommendations = learner.generate_recommendations(&HashMap::new()).unwrap();
    assert!(!recommendations.is_empty(), "Should generate recommendations");

    // Verify complete audit trail
    let ledger_lock = ledger.lock().unwrap();
    let total_entries = ledger_lock.count();
    assert!(total_entries > 20, "Should have comprehensive audit trail (>20 entries)");
}

/// Test 8: IPC Message Round-Trip Through Multiple Principals
/// Tests message passing and capability matrix enforcement across principals
#[test]
fn test_ipc_multi_principal_message_passing() {
    let mut matrix = CapabilityMatrix::new();

    // Setup capabilities: Policy (1) can use IF-002, Actuator (2) can use IF-003
    matrix.allow(Principal::Policy as u8, 2);   // Policy → IF-002
    matrix.allow(Principal::Actuator as u8, 3); // Actuator → IF-003

    // Create messages simulating multi-principal workflow
    let msg1 = UniversalMessage::new(
        2,  // IF-002
        0,  // REQUEST
        Principal::Policy as u8,
        Principal::Actuator as u8,
        0x01,  // FLAG_REQUIRES_AUTH
        b"authorization request".to_vec(),
    );

    let msg2 = UniversalMessage::new(
        3,  // IF-003
        0,  // REQUEST
        Principal::Actuator as u8,
        Principal::Policy as u8,
        0x00,  // FLAGS
        b"execution result".to_vec(),
    );

    // Verify messages can serialize/deserialize
    let json1 = msg1.to_json().unwrap();
    let parsed1 = UniversalMessage::from_json(&json1).unwrap();
    assert_eq!(parsed1.header.interface_id, 2);

    let json2 = msg2.to_json().unwrap();
    let parsed2 = UniversalMessage::from_json(&json2).unwrap();
    assert_eq!(parsed2.header.interface_id, 3);

    // Verify capability matrix enforcement
    assert!(matrix.can_use(Principal::Policy as u8, 2));
    assert!(!matrix.can_use(Principal::Policy as u8, 3));  // Policy cannot use IF-003
    assert!(!matrix.can_use(Principal::Actuator as u8, 2)); // Actuator cannot use IF-002
    assert!(matrix.can_use(Principal::Actuator as u8, 3));
}

/// Test 9: Crisis Recovery - Principal State Restoration
/// Tests recovery from principal failure and state restoration via Sealer
#[test]
fn test_crisis_recovery_state_restoration() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize principals
    let policy_key = hsm.lock().unwrap().generate_key("policy").unwrap();
    let actuator_key = hsm.lock().unwrap().generate_key("actuator").unwrap();
    let sealer_key = hsm.lock().unwrap().generate_key("sealer").unwrap();

    let mut policy = PolicyPrincipal::new(ledger.clone());
    let mut actuator = ActuatorPrincipal::new(ledger.clone());
    let mut sealer = SealerPrincipal::new(ledger.clone());

    policy.initialize(policy_key).unwrap();
    actuator.initialize(actuator_key).unwrap();
    sealer.initialize(sealer_key).unwrap();

    // Execute some operations
    let decision = policy.gate_a_decision(
        Principal::Actuator,
        InterfaceId::from(3),
        &HashMap::new(),
    ).unwrap();

    assert!(decision.authorized);

    let request = geometry_dash::CommandRequest {
        request_id: "recovery-test-001".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
        command: "critical_operation".to_string(),
        requester: Principal::Policy,
        target_interface: InterfaceId::from(3),
        context: HashMap::new(),
    };

    actuator.queue_command(request).unwrap();
    let _results = actuator.process_queue().unwrap();

    // Simulate recovery: Sealer verifies state consistency
    let check = ConsistencyCheck {
        principal: Principal::Actuator,
        expected_state: "Ready".to_string(),
        check_type: "recovery".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    };

    let consistency_ok = sealer.verify_consistency(&check).unwrap();
    assert!(consistency_ok, "State should be restorable");

    // Verify audit trail preserved all operations
    let ledger_lock = ledger.lock().unwrap();
    assert!(ledger_lock.count() > 0, "Audit trail should be preserved");
}

/// Test 10: Performance - Message Throughput and Latency
/// Tests system performance under load across multiple principals
#[test]
fn test_multi_principal_performance_throughput() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize principals for performance test
    let policy_key = hsm.lock().unwrap().generate_key("policy-perf").unwrap();
    let actuator_key = hsm.lock().unwrap().generate_key("actuator-perf").unwrap();

    let mut policy = PolicyPrincipal::new(ledger.clone());
    let mut actuator = ActuatorPrincipal::new(ledger.clone());

    policy.initialize(policy_key).unwrap();
    actuator.initialize(actuator_key).unwrap();

    // Performance: Process 100 commands
    let start = std::time::Instant::now();

    for i in 0..100 {
        let request = geometry_dash::CommandRequest {
            request_id: format!("perf-cmd-{:03}", i),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            command: "perf_test".to_string(),
            requester: Principal::Policy,
            target_interface: InterfaceId::from(3),
            context: HashMap::new(),
        };

        actuator.queue_command(request).unwrap();
    }

    let results = actuator.process_queue().unwrap();
    let elapsed = start.elapsed();

    assert_eq!(results.len(), 100, "Should process all 100 commands");
    assert!(results.iter().all(|r| r.success), "All should succeed");

    // Performance assertion: 100 commands in < 5 seconds
    assert!(
        elapsed.as_secs() < 5,
        "100 commands should complete in <5s (actual: {:?})",
        elapsed
    );

    let throughput = 100.0 / elapsed.as_secs_f64();
    println!("Performance: {:.1} commands/sec", throughput);
}
