// Policy Principal Integration Tests (Week 2 Task 2.1)

use geometry_dash::{
    PolicyPrincipal, PolicyState, Supervisor, Principal,
    SecurityLedger, NonceCache, CapabilityMatrix,
};
use tempfile::TempDir;
use std::collections::HashMap;
use std::sync::Arc;

#[test]
fn test_policy_principal_initialization() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let policy = PolicyPrincipal::new(
        "policy-001".to_string(),
        1001,
        1001,
        ledger,
    );

    assert_eq!(policy.state(), PolicyState::NotStarted);
    assert_eq!(policy.principal_id(), "policy-001");
}

#[test]
fn test_policy_gate_a_supervisor_authorization() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let policy = PolicyPrincipal::new(
        "policy-002".to_string(),
        1001,
        1001,
        ledger,
    );

    // Supervisor requests IF-001
    let decision = policy.gate_a_decision(
        Principal::Supervisor,
        1,
        &HashMap::new(),
    );

    assert!(decision.authorized);
    assert!(!decision.delegated_interfaces.is_empty());
    assert_eq!(decision.delegated_interfaces[0], 1);
}

#[test]
fn test_policy_gate_a_actuator_authorization() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let policy = PolicyPrincipal::new(
        "policy-003".to_string(),
        1001,
        1001,
        ledger,
    );

    // Actuator requests IF-003 (control interface)
    let decision = policy.gate_a_decision(
        Principal::Actuator,
        3,
        &HashMap::new(),
    );

    assert!(decision.authorized);

    // Actuator requests IF-011 (audit interface) - should be denied
    let decision = policy.gate_a_decision(
        Principal::Actuator,
        11,
        &HashMap::new(),
    );

    assert!(!decision.authorized);
}

#[test]
fn test_policy_gate_a_audit_authorization() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let policy = PolicyPrincipal::new(
        "policy-004".to_string(),
        1001,
        1001,
        ledger,
    );

    // Audit requests IF-011 (audit interface)
    let decision = policy.gate_a_decision(
        Principal::Audit,
        11,
        &HashMap::new(),
    );

    assert!(decision.authorized);

    // Audit requests IF-001 (supervisor interface) - should be denied
    let decision = policy.gate_a_decision(
        Principal::Audit,
        1,
        &HashMap::new(),
    );

    assert!(!decision.authorized);
}

#[test]
fn test_policy_capability_delegation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let policy = PolicyPrincipal::new(
        "policy-005".to_string(),
        1001,
        1001,
        ledger,
    );

    // Delegate capability
    assert!(policy.delegate_capability(Principal::Actuator, 3).is_ok());

    let (_, granted, denied) = policy.statistics();
    assert_eq!(granted, 1);
    assert_eq!(denied, 0);
}

#[test]
fn test_policy_capability_denial() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let policy = PolicyPrincipal::new(
        "policy-006".to_string(),
        1001,
        1001,
        ledger,
    );

    // Deny capability
    assert!(policy.deny_capability(
        Principal::Learner,
        11,
        "learner_not_audit_role"
    ).is_ok());

    let (_, granted, denied) = policy.statistics();
    assert_eq!(granted, 0);
    assert_eq!(denied, 1);
}

#[test]
fn test_policy_decision_tracking() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let policy = PolicyPrincipal::new(
        "policy-007".to_string(),
        1001,
        1001,
        ledger,
    );

    // Make 5 decisions
    for i in 0..5 {
        let principal = match i % 3 {
            0 => Principal::Supervisor,
            1 => Principal::Actuator,
            _ => Principal::Audit,
        };
        let if_id = 1 + (i as u32);

        let decision = policy.gate_a_decision(principal, if_id, &HashMap::new());
        {
            let mut decisions = policy.pending_decisions.lock().unwrap();
            decisions.push_back(decision);
        }
    }

    // Process all decisions
    assert!(policy.process_pending_decisions().is_ok());

    let history = policy.decision_history();
    assert_eq!(history.len(), 5);

    let (decisions_made, _, _) = policy.statistics();
    assert_eq!(decisions_made, 5);
}

#[test]
fn test_policy_with_supervisor_integration() {
    let temp = TempDir::new().unwrap();
    let ledger_path = temp.path().join("security_ledger.jsonl");

    // Initialize Supervisor
    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    // Create Policy principal with supervisor's ledger
    let policy = PolicyPrincipal::new(
        "policy-integrated".to_string(),
        1001,
        1001,
        supervisor.ledger(),
    );

    // Verify Policy can make decisions based on Supervisor's context
    let decision = policy.gate_a_decision(
        Principal::Actuator,
        3,
        &HashMap::new(),
    );

    assert!(decision.authorized);
}

#[test]
fn test_policy_with_capability_matrix() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let policy = PolicyPrincipal::new(
        "policy-008".to_string(),
        1001,
        1001,
        ledger,
    );

    // Delegate capabilities
    assert!(policy.delegate_capability(Principal::Actuator, 3).is_ok());
    assert!(policy.delegate_capability(Principal::Audit, 11).is_ok());
    assert!(policy.delegate_capability(Principal::Declassifier, 4).is_ok());

    let (_, granted, _) = policy.statistics();
    assert_eq!(granted, 3);
}

#[test]
fn test_policy_state_transitions() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let policy = PolicyPrincipal::new(
        "policy-009".to_string(),
        1001,
        1001,
        ledger,
    );

    // Verify initial state
    assert_eq!(policy.state(), PolicyState::NotStarted);

    // Make a decision and process
    let decision = policy.gate_a_decision(Principal::Supervisor, 1, &HashMap::new());
    {
        let mut decisions = policy.pending_decisions.lock().unwrap();
        decisions.push_back(decision);
    }

    assert!(policy.process_pending_decisions().is_ok());
    assert_eq!(policy.state(), PolicyState::Running);

    // Shutdown
    assert!(policy.shutdown().is_ok());
    assert_eq!(policy.state(), PolicyState::Shutdown);
}

#[test]
fn test_policy_multiple_principals_isolation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    // Create multiple policy instances
    let policy1 = PolicyPrincipal::new(
        "policy-1".to_string(),
        1001,
        1001,
        ledger.clone(),
    );

    let policy2 = PolicyPrincipal::new(
        "policy-2".to_string(),
        1002,
        1002,
        ledger.clone(),
    );

    // Each should have independent state
    let decision1 = policy1.gate_a_decision(Principal::Supervisor, 1, &HashMap::new());
    let decision2 = policy2.gate_a_decision(Principal::Actuator, 3, &HashMap::new());

    {
        let mut decisions = policy1.pending_decisions.lock().unwrap();
        decisions.push_back(decision1);
    }

    {
        let mut decisions = policy2.pending_decisions.lock().unwrap();
        decisions.push_back(decision2);
    }

    // Process independently
    assert!(policy1.process_pending_decisions().is_ok());
    assert!(policy2.process_pending_decisions().is_ok());

    let history1 = policy1.decision_history();
    let history2 = policy2.decision_history();

    assert_eq!(history1.len(), 1);
    assert_eq!(history2.len(), 1);
    assert_ne!(history1[0].decision_id, history2[0].decision_id);
}

#[test]
fn test_policy_audit_trail_completeness() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let policy = PolicyPrincipal::new(
        "policy-010".to_string(),
        1001,
        1001,
        ledger.clone(),
    );

    // Make decisions
    for i in 0..3 {
        let decision = policy.gate_a_decision(
            if i == 0 { Principal::Supervisor } else { Principal::Actuator },
            i + 1,
            &HashMap::new(),
        );
        {
            let mut decisions = policy.pending_decisions.lock().unwrap();
            decisions.push_back(decision);
        }
    }

    assert!(policy.process_pending_decisions().is_ok());

    // Verify audit trail in ledger
    // Note: This would require reading the ledger to verify all events were logged
    let history = policy.decision_history();
    assert_eq!(history.len(), 3);

    for (i, entry) in history.iter().enumerate() {
        assert_eq!(entry.timestamp_ns > 0, true);
        assert_eq!(entry.delegated_interfaces.len(), 1);
        assert_eq!(entry.delegated_interfaces[0] as usize, i + 1);
    }
}
