// Actuator Principal Integration Tests (Week 2 Task 2.2)

use geometry_dash::{
    ActuatorPrincipal, ActuatorState, CommandRequest, Supervisor, Principal,
    SecurityLedger,
};
use tempfile::TempDir;
use std::collections::HashMap;
use std::sync::Arc;

#[test]
fn test_actuator_principal_initialization() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-001".to_string(),
        1002,
        1002,
        ledger,
    );

    assert_eq!(actuator.state(), ActuatorState::NotStarted);
    assert_eq!(actuator.principal_id(), "actuator-001");
}

#[test]
fn test_gate_c_policy_authorized() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-002".to_string(),
        1002,
        1002,
        ledger,
    );

    let request = CommandRequest {
        request_id: "cmd-001".to_string(),
        timestamp_ns: 0,
        command: "echo test".to_string(),
        requester: Principal::Policy,
        target_interface: 3,
        context: HashMap::new(),
    };

    let decision = actuator.gate_c_validate(&request);
    assert!(decision.allowed);
    assert!(decision.reason.contains("authorized"));
}

#[test]
fn test_gate_c_unauthorized_principal() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-003".to_string(),
        1002,
        1002,
        ledger,
    );

    let request = CommandRequest {
        request_id: "cmd-002".to_string(),
        timestamp_ns: 0,
        command: "echo test".to_string(),
        requester: Principal::Learner,  // Unauthorized
        target_interface: 3,
        context: HashMap::new(),
    };

    let decision = actuator.gate_c_validate(&request);
    assert!(!decision.allowed);
}

#[test]
fn test_gate_i_valid_integrity() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-004".to_string(),
        1002,
        1002,
        ledger,
    );

    let request = CommandRequest {
        request_id: "cmd-003".to_string(),
        timestamp_ns: 0,
        command: "echo test".to_string(),
        requester: Principal::Policy,
        target_interface: 3,
        context: HashMap::new(),
    };

    let decision = actuator.gate_i_validate(&request);
    assert!(decision.integrity_valid);
}

#[test]
fn test_gate_i_empty_command_fails() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-005".to_string(),
        1002,
        1002,
        ledger,
    );

    let request = CommandRequest {
        request_id: "cmd-004".to_string(),
        timestamp_ns: 0,
        command: "".to_string(),  // Empty
        requester: Principal::Policy,
        target_interface: 3,
        context: HashMap::new(),
    };

    let decision = actuator.gate_i_validate(&request);
    assert!(!decision.integrity_valid);
}

#[test]
fn test_command_execution_success() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-006".to_string(),
        1002,
        1002,
        ledger,
    );

    let request = CommandRequest {
        request_id: "cmd-005".to_string(),
        timestamp_ns: 0,
        command: "ls -la".to_string(),
        requester: Principal::Policy,
        target_interface: 3,
        context: HashMap::new(),
    };

    let result = actuator.execute_command(request).unwrap();
    assert!(result.success);
    assert!(result.gate_c_passed);
    assert!(result.gate_i_passed);
}

#[test]
fn test_command_execution_gate_c_failure() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-007".to_string(),
        1002,
        1002,
        ledger,
    );

    let request = CommandRequest {
        request_id: "cmd-006".to_string(),
        timestamp_ns: 0,
        command: "rm -rf /".to_string(),
        requester: Principal::Evaluator,  // Unauthorized
        target_interface: 3,
        context: HashMap::new(),
    };

    let result = actuator.execute_command(request).unwrap();
    assert!(!result.success);
    assert!(!result.gate_c_passed);
}

#[test]
fn test_command_queue() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-008".to_string(),
        1002,
        1002,
        ledger,
    );

    // Queue 3 commands
    for i in 0..3 {
        let request = CommandRequest {
            request_id: format!("cmd-{:03}", i),
            timestamp_ns: 0,
            command: format!("cmd {}", i),
            requester: Principal::Policy,
            target_interface: 3,
            context: HashMap::new(),
        };
        assert!(actuator.queue_command(request).is_ok());
    }

    let (received, _, _, _, _, _, _) = actuator.statistics();
    assert_eq!(received, 3);
}

#[test]
fn test_process_queue() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-009".to_string(),
        1002,
        1002,
        ledger,
    );

    // Queue 5 commands
    for i in 0..5 {
        let request = CommandRequest {
            request_id: format!("cmd-{:03}", i),
            timestamp_ns: 0,
            command: format!("cmd {}", i),
            requester: Principal::Policy,
            target_interface: 3,
            context: HashMap::new(),
        };
        assert!(actuator.queue_command(request).is_ok());
    }

    // Process all
    let results = actuator.process_queue().unwrap();
    assert_eq!(results.len(), 5);

    // All should be successful
    for result in results {
        assert!(result.success);
    }
}

#[test]
fn test_execution_statistics() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-010".to_string(),
        1002,
        1002,
        ledger,
    );

    // Queue mix of authorized and unauthorized commands
    for i in 0..5 {
        let requester = if i % 2 == 0 {
            Principal::Policy
        } else {
            Principal::Learner
        };

        let request = CommandRequest {
            request_id: format!("cmd-{:03}", i),
            timestamp_ns: 0,
            command: format!("cmd {}", i),
            requester,
            target_interface: 3,
            context: HashMap::new(),
        };
        assert!(actuator.queue_command(request).is_ok());
    }

    // Process all
    let _results = actuator.process_queue().unwrap();

    let (received, executed, failed, c_p, c_f, i_p, i_f) = actuator.statistics();
    assert_eq!(received, 5);
    assert_eq!(executed + failed, 5);  // Some passed, some failed
    assert_eq!(c_p + c_f, 5);  // Each had gate C check
    assert!(i_p > 0);  // Some passed gate I
}

#[test]
fn test_execution_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-011".to_string(),
        1002,
        1002,
        ledger,
    );

    // Execute 3 commands directly
    for i in 0..3 {
        let request = CommandRequest {
            request_id: format!("cmd-{:03}", i),
            timestamp_ns: 0,
            command: format!("cmd {}", i),
            requester: Principal::Policy,
            target_interface: 3,
            context: HashMap::new(),
        };
        let _ = actuator.execute_command(request);
    }

    let history = actuator.execution_history();
    assert_eq!(history.len(), 3);

    for (i, result) in history.iter().enumerate() {
        assert_eq!(result.request_id, format!("cmd-{:03}", i));
        assert!(result.success);
    }
}

#[test]
fn test_actuator_state_transitions() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-012".to_string(),
        1002,
        1002,
        ledger,
    );

    assert_eq!(actuator.state(), ActuatorState::NotStarted);

    // Execute a command (will transition states)
    let request = CommandRequest {
        request_id: "cmd-007".to_string(),
        timestamp_ns: 0,
        command: "test".to_string(),
        requester: Principal::Policy,
        target_interface: 3,
        context: HashMap::new(),
    };

    let _ = actuator.execute_command(request);
    assert_eq!(actuator.state(), ActuatorState::Running);

    // Shutdown
    assert!(actuator.shutdown().is_ok());
    assert_eq!(actuator.state(), ActuatorState::Shutdown);
}

#[test]
fn test_actuator_with_supervisor_integration() {
    let temp = TempDir::new().unwrap();
    let ledger_path = temp.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    let actuator = ActuatorPrincipal::new(
        "actuator-integrated".to_string(),
        1002,
        1002,
        supervisor.ledger(),
    );

    // Actuator should be able to use supervisor's ledger
    let request = CommandRequest {
        request_id: "cmd-008".to_string(),
        timestamp_ns: 0,
        command: "execute".to_string(),
        requester: Principal::Policy,
        target_interface: 3,
        context: HashMap::new(),
    };

    let result = actuator.execute_command(request).unwrap();
    assert!(result.success);
}

#[test]
fn test_actuator_supervisor_authorization() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let actuator = ActuatorPrincipal::new(
        "actuator-013".to_string(),
        1002,
        1002,
        ledger,
    );

    // Supervisor should always be authorized
    let request = CommandRequest {
        request_id: "cmd-009".to_string(),
        timestamp_ns: 0,
        command: "shutdown".to_string(),
        requester: Principal::Supervisor,
        target_interface: 3,
        context: HashMap::new(),
    };

    let decision = actuator.gate_c_validate(&request);
    assert!(decision.allowed);
}

#[test]
fn test_actuator_multiple_instances_isolation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    // Create two actuator instances
    let actuator1 = ActuatorPrincipal::new(
        "actuator-1".to_string(),
        1002,
        1002,
        ledger.clone(),
    );

    let actuator2 = ActuatorPrincipal::new(
        "actuator-2".to_string(),
        1003,
        1003,
        ledger.clone(),
    );

    // Each should have independent statistics
    for i in 0..3 {
        let request = CommandRequest {
            request_id: format!("cmd1-{}", i),
            timestamp_ns: 0,
            command: "test".to_string(),
            requester: Principal::Policy,
            target_interface: 3,
            context: HashMap::new(),
        };
        let _ = actuator1.execute_command(request);
    }

    for i in 0..5 {
        let request = CommandRequest {
            request_id: format!("cmd2-{}", i),
            timestamp_ns: 0,
            command: "test".to_string(),
            requester: Principal::Policy,
            target_interface: 3,
            context: HashMap::new(),
        };
        let _ = actuator2.execute_command(request);
    }

    let (r1, e1, _, _, _, _, _) = actuator1.statistics();
    let (r2, e2, _, _, _, _, _) = actuator2.statistics();

    assert_eq!(r1, 3);
    assert_eq!(r2, 5);
    assert_eq!(e1, 3);
    assert_eq!(e2, 5);
}
