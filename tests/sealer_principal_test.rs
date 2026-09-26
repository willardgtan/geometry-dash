// Sealer Principal Integration Tests (Week 2 Task 2.7)

use geometry_dash::{
    SealerPrincipal, SealerState, Supervisor, SecurityLedger,
};
use tempfile::TempDir;
use std::sync::Arc;

#[test]
fn test_sealer_initialization() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-001".to_string(),
        1007,
        1007,
        ledger,
    );

    assert_eq!(sealer.state(), SealerState::NotStarted);
    assert_eq!(sealer.principal_id(), "sealer-001");
}

#[test]
fn test_verify_consistent_state() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-002".to_string(),
        1007,
        1007,
        ledger,
    );

    let check = sealer.verify_principal_consistency(
        "policy".to_string(),
        "Ready".to_string(),
    ).unwrap();

    assert!(check.is_consistent);
    assert_eq!(check.severity, "none");
    assert_eq!(check.actual_state, "Ready");
}

#[test]
fn test_verify_inconsistent_state() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-003".to_string(),
        1007,
        1007,
        ledger,
    );

    let check = sealer.verify_principal_consistency(
        "actuator".to_string(),
        "Failed".to_string(),
    ).unwrap();

    assert!(!check.is_consistent);
    assert_eq!(check.severity, "high");
    assert_ne!(check.actual_state, check.expected_state);
}

#[test]
fn test_detect_state_mismatch_violation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-004".to_string(),
        1007,
        1007,
        ledger,
    );

    let violation = sealer.detect_violation(
        "state_mismatch".to_string(),
        vec!["policy".to_string(), "actuator".to_string()],
        "high".to_string(),
    ).unwrap();

    assert_eq!(violation.violation_type, "state_mismatch");
    assert_eq!(violation.affected_principals.len(), 2);
    assert_eq!(violation.severity, "high");
}

#[test]
fn test_detect_cascade_violation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-005".to_string(),
        1007,
        1007,
        ledger,
    );

    let violation = sealer.detect_violation(
        "cascade_broken".to_string(),
        vec!["audit".to_string(), "declassifier".to_string()],
        "critical".to_string(),
    ).unwrap();

    assert_eq!(violation.violation_type, "cascade_broken");
    assert_eq!(violation.severity, "critical");
}

#[test]
fn test_apply_force_state_action() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-006".to_string(),
        1007,
        1007,
        ledger,
    );

    let action = sealer.apply_consistency_action(
        "audit".to_string(),
        "force_state".to_string(),
        "Ready".to_string(),
    ).unwrap();

    assert!(action.success);
    assert_eq!(action.action_type, "force_state");
    assert_eq!(action.target_state, "Ready");
}

#[test]
fn test_apply_rollback_action() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-007".to_string(),
        1007,
        1007,
        ledger,
    );

    let action = sealer.apply_consistency_action(
        "declassifier".to_string(),
        "rollback".to_string(),
        "Ready".to_string(),
    ).unwrap();

    assert!(action.success);
    assert_eq!(action.action_type, "rollback");
}

#[test]
fn test_apply_resynchronize_action() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-008".to_string(),
        1007,
        1007,
        ledger,
    );

    let action = sealer.apply_consistency_action(
        "learner".to_string(),
        "resynchronize".to_string(),
        "Ready".to_string(),
    ).unwrap();

    assert!(action.success);
    assert_eq!(action.action_type, "resynchronize");
}

#[test]
fn test_generate_consistency_report() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-009".to_string(),
        1007,
        1007,
        ledger,
    );

    let report = sealer.generate_consistency_report().unwrap();

    assert!(!report.report_id.is_empty());
    assert!(report.principals_checked > 0);
    assert!(["fully_consistent", "partially_consistent", "inconsistent"].contains(&report.overall_consistency.as_str()));
    assert!(!report.recommendations.is_empty());
}

#[test]
fn test_check_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-010".to_string(),
        1007,
        1007,
        ledger,
    );

    let check1 = sealer.verify_principal_consistency("policy".to_string(), "Ready".to_string()).unwrap();
    let check2 = sealer.verify_principal_consistency("actuator".to_string(), "Ready".to_string()).unwrap();

    let history = sealer.check_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].check_id, check1.check_id);
    assert_eq!(history[1].check_id, check2.check_id);
}

#[test]
fn test_violation_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-011".to_string(),
        1007,
        1007,
        ledger,
    );

    let v1 = sealer.detect_violation("state_mismatch".to_string(), vec!["p1".to_string()], "high".to_string()).unwrap();
    let v2 = sealer.detect_violation("cascade_broken".to_string(), vec!["p2".to_string()], "critical".to_string()).unwrap();

    let history = sealer.violation_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].violation_id, v1.violation_id);
    assert_eq!(history[1].violation_id, v2.violation_id);
}

#[test]
fn test_action_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-012".to_string(),
        1007,
        1007,
        ledger,
    );

    let a1 = sealer.apply_consistency_action("audit".to_string(), "force_state".to_string(), "Ready".to_string()).unwrap();
    let a2 = sealer.apply_consistency_action("policy".to_string(), "resynchronize".to_string(), "Ready".to_string()).unwrap();

    let history = sealer.action_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].action_id, a1.action_id);
    assert_eq!(history[1].action_id, a2.action_id);
}

#[test]
fn test_report_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-013".to_string(),
        1007,
        1007,
        ledger,
    );

    let r1 = sealer.generate_consistency_report().unwrap();
    let r2 = sealer.generate_consistency_report().unwrap();

    let history = sealer.report_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].report_id, r1.report_id);
    assert_eq!(history[1].report_id, r2.report_id);
}

#[test]
fn test_statistics() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-014".to_string(),
        1007,
        1007,
        ledger,
    );

    // Perform various operations
    for i in 0..3 {
        let _ = sealer.verify_principal_consistency(
            format!("principal-{}", i),
            "Ready".to_string(),
        );
    }

    let _ = sealer.detect_violation("state_mismatch".to_string(), vec!["p1".to_string()], "high".to_string());
    let _ = sealer.detect_violation("cascade_broken".to_string(), vec!["p2".to_string()], "medium".to_string());

    let _ = sealer.apply_consistency_action("p1".to_string(), "force_state".to_string(), "Ready".to_string());

    let _ = sealer.generate_consistency_report();

    let (checks, violations, actions, reports) = sealer.statistics();
    assert_eq!(checks, 3);
    assert_eq!(violations, 2);
    assert_eq!(actions, 1);
    assert_eq!(reports, 1);
}

#[test]
fn test_sealer_report() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-015".to_string(),
        1007,
        1007,
        ledger,
    );

    let report = sealer.sealer_report();

    assert!(report.contains("Sealer Principal"));
    assert!(report.contains("sealer-015"));
    assert!(report.contains("Consistency Checks Performed:"));
    assert!(report.contains("Violations Found:"));
    assert!(report.contains("Actions Applied:"));
    assert!(report.contains("Reports Generated:"));
}

#[test]
fn test_state_transitions() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-016".to_string(),
        1007,
        1007,
        ledger,
    );

    assert_eq!(sealer.state(), SealerState::NotStarted);

    let _ = sealer.verify_principal_consistency("p1".to_string(), "Ready".to_string());
    assert_eq!(sealer.state(), SealerState::Ready);

    let _ = sealer.detect_violation("state_mismatch".to_string(), vec!["p1".to_string()], "high".to_string());
    assert_eq!(sealer.state(), SealerState::Ready);

    let _ = sealer.apply_consistency_action("p1".to_string(), "force_state".to_string(), "Ready".to_string());
    assert_eq!(sealer.state(), SealerState::Ready);

    let _ = sealer.generate_consistency_report();
    assert_eq!(sealer.state(), SealerState::Ready);

    let _ = sealer.shutdown();
    assert_eq!(sealer.state(), SealerState::Shutdown);
}

#[test]
fn test_with_supervisor_integration() {
    let temp = TempDir::new().unwrap();
    let ledger_path = temp.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    let sealer = SealerPrincipal::new(
        "sealer-integrated".to_string(),
        1007,
        1007,
        supervisor.ledger(),
    );

    let check = sealer.verify_principal_consistency(
        "policy".to_string(),
        "Ready".to_string(),
    ).unwrap();

    assert!(check.is_consistent);
}

#[test]
fn test_multiple_instances_isolation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer1 = SealerPrincipal::new(
        "sealer-a".to_string(),
        1007,
        1007,
        ledger.clone(),
    );

    let sealer2 = SealerPrincipal::new(
        "sealer-b".to_string(),
        1008,
        1008,
        ledger.clone(),
    );

    // Different operations for each
    for i in 0..3 {
        let _ = sealer1.verify_principal_consistency(
            format!("p1-{}", i),
            "Ready".to_string(),
        );
    }

    for i in 0..2 {
        let _ = sealer2.verify_principal_consistency(
            format!("p2-{}", i),
            "Ready".to_string(),
        );
    }

    let (c1, _, _, _) = sealer1.statistics();
    let (c2, _, _, _) = sealer2.statistics();

    assert_eq!(c1, 3);
    assert_eq!(c2, 2);
}

#[test]
fn test_consistency_report_structure() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-017".to_string(),
        1007,
        1007,
        ledger,
    );

    let report = sealer.generate_consistency_report().unwrap();

    assert!(!report.report_id.is_empty());
    assert!(report.principals_checked > 0);
    assert!(report.principals_consistent + report.principals_inconsistent <= report.principals_checked);
    assert!(!report.recommendations.is_empty());
}

#[test]
fn test_violation_severity_levels() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-018".to_string(),
        1007,
        1007,
        ledger,
    );

    let v_low = sealer.detect_violation("state_mismatch".to_string(), vec!["p".to_string()], "low".to_string()).unwrap();
    let v_medium = sealer.detect_violation("cascade_broken".to_string(), vec!["p".to_string()], "medium".to_string()).unwrap();
    let v_high = sealer.detect_violation("transition_invalid".to_string(), vec!["p".to_string()], "high".to_string()).unwrap();
    let v_critical = sealer.detect_violation("state_mismatch".to_string(), vec!["p".to_string()], "critical".to_string()).unwrap();

    assert_eq!(v_low.severity, "low");
    assert_eq!(v_medium.severity, "medium");
    assert_eq!(v_high.severity, "high");
    assert_eq!(v_critical.severity, "critical");
}

#[test]
fn test_action_type_variations() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-019".to_string(),
        1007,
        1007,
        ledger,
    );

    let a_force = sealer.apply_consistency_action("p1".to_string(), "force_state".to_string(), "Ready".to_string()).unwrap();
    let a_rollback = sealer.apply_consistency_action("p2".to_string(), "rollback".to_string(), "Ready".to_string()).unwrap();
    let a_resync = sealer.apply_consistency_action("p3".to_string(), "resynchronize".to_string(), "Ready".to_string()).unwrap();

    assert_eq!(a_force.action_type, "force_state");
    assert_eq!(a_rollback.action_type, "rollback");
    assert_eq!(a_resync.action_type, "resynchronize");
    assert!(a_force.success);
    assert!(a_rollback.success);
    assert!(a_resync.success);
}

#[test]
fn test_check_consistency_determination() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let sealer = SealerPrincipal::new(
        "sealer-020".to_string(),
        1007,
        1007,
        ledger,
    );

    let consistent = sealer.verify_principal_consistency("policy".to_string(), "Ready".to_string()).unwrap();
    let inconsistent = sealer.verify_principal_consistency("audit".to_string(), "Failed".to_string()).unwrap();

    assert!(consistent.is_consistent);
    assert_eq!(consistent.severity, "none");
    assert!(!inconsistent.is_consistent);
    assert_eq!(inconsistent.severity, "high");
}
