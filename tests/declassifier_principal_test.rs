// Declassifier Principal Integration Tests (Week 2 Task 2.4)

use geometry_dash::{
    DeclassifierPrincipal, DeclassifierState, ClassificationLevel, Supervisor,
    SecurityLedger, Principal,
};
use tempfile::TempDir;
use std::sync::Arc;

#[test]
fn test_declassifier_initialization() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-001".to_string(),
        1004,
        1004,
        ledger,
    );

    assert_eq!(declassifier.state(), DeclassifierState::NotStarted);
    assert_eq!(declassifier.principal_id(), "declassifier-001");
}

#[test]
fn test_classify_resource_authorized() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-002".to_string(),
        1004,
        1004,
        ledger,
    );

    let decision = declassifier.classify_resource(
        "resource-001".to_string(),
        ClassificationLevel::Secret,
        Principal::Supervisor,
    ).unwrap();

    assert!(decision.approved);
    assert_eq!(decision.classification, ClassificationLevel::Secret);
}

#[test]
fn test_classify_resource_unauthorized() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-003".to_string(),
        1004,
        1004,
        ledger,
    );

    let decision = declassifier.classify_resource(
        "resource-002".to_string(),
        ClassificationLevel::Confidential,
        Principal::Learner,
    ).unwrap();

    assert!(!decision.approved);
}

#[test]
fn test_declassification_request() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-004".to_string(),
        1004,
        1004,
        ledger,
    );

    let request = declassifier.request_declassification(
        "resource-003".to_string(),
        ClassificationLevel::Secret,
        ClassificationLevel::Confidential,
        "Audit review needed".to_string(),
        Principal::Policy,
    ).unwrap();

    assert_eq!(request.current_classification, ClassificationLevel::Secret);
    assert_eq!(request.target_classification, ClassificationLevel::Confidential);

    let (_, requested, _, _) = declassifier.statistics();
    assert_eq!(requested, 1);
}

#[test]
fn test_approve_declassification() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-005".to_string(),
        1004,
        1004,
        ledger,
    );

    let request = declassifier.request_declassification(
        "resource-004".to_string(),
        ClassificationLevel::Secret,
        ClassificationLevel::Internal,
        "Public release approved".to_string(),
        Principal::Supervisor,
    ).unwrap();

    let decision = declassifier.approve_declassification(
        request.request_id.clone(),
        "supervisor".to_string(),
    ).unwrap();

    assert!(decision.approved);
    assert_eq!(decision.request_id, request.request_id);

    let (_, _, approved, _) = declassifier.statistics();
    assert_eq!(approved, 1);
}

#[test]
fn test_deny_declassification() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-006".to_string(),
        1004,
        1004,
        ledger,
    );

    let request = declassifier.request_declassification(
        "resource-005".to_string(),
        ClassificationLevel::TopSecret,
        ClassificationLevel::Public,
        "Attempted unauthorized declassification".to_string(),
        Principal::Learner,
    ).unwrap();

    let decision = declassifier.deny_declassification(
        request.request_id,
        "policy".to_string(),
        "Insufficient authorization".to_string(),
    ).unwrap();

    assert!(!decision.approved);

    let (_, _, _, denied) = declassifier.statistics();
    assert_eq!(denied, 1);
}

#[test]
fn test_check_access_supervisor() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-007".to_string(),
        1004,
        1004,
        ledger,
    );

    // Supervisor can access all classifications
    assert!(declassifier.check_access(&Principal::Supervisor, &ClassificationLevel::TopSecret));
    assert!(declassifier.check_access(&Principal::Supervisor, &ClassificationLevel::Secret));
    assert!(declassifier.check_access(&Principal::Supervisor, &ClassificationLevel::Public));
}

#[test]
fn test_check_access_policy() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-008".to_string(),
        1004,
        1004,
        ledger,
    );

    // Policy can access up to Secret
    assert!(!declassifier.check_access(&Principal::Policy, &ClassificationLevel::TopSecret));
    assert!(declassifier.check_access(&Principal::Policy, &ClassificationLevel::Secret));
    assert!(declassifier.check_access(&Principal::Policy, &ClassificationLevel::Confidential));
}

#[test]
fn test_check_access_actuator() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-009".to_string(),
        1004,
        1004,
        ledger,
    );

    // Actuator can access up to Confidential
    assert!(!declassifier.check_access(&Principal::Actuator, &ClassificationLevel::Secret));
    assert!(declassifier.check_access(&Principal::Actuator, &ClassificationLevel::Confidential));
    assert!(declassifier.check_access(&Principal::Actuator, &ClassificationLevel::Public));
}

#[test]
fn test_check_access_default() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-010".to_string(),
        1004,
        1004,
        ledger,
    );

    // Others can only access Public
    assert!(!declassifier.check_access(&Principal::Learner, &ClassificationLevel::Internal));
    assert!(declassifier.check_access(&Principal::Learner, &ClassificationLevel::Public));
}

#[test]
fn test_get_classification_label() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-011".to_string(),
        1004,
        1004,
        ledger,
    );

    declassifier.classify_resource(
        "resource-006".to_string(),
        ClassificationLevel::Confidential,
        Principal::Supervisor,
    ).unwrap();

    let label = declassifier.get_label("resource-006");
    assert!(label.is_some());

    let label = label.unwrap();
    assert_eq!(label.resource_id, "resource-006");
    assert_eq!(label.classification, ClassificationLevel::Confidential);
}

#[test]
fn test_list_labels() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-012".to_string(),
        1004,
        1004,
        ledger,
    );

    // Create multiple classifications
    for i in 0..3 {
        let _ = declassifier.classify_resource(
            format!("resource-{:03}", i),
            ClassificationLevel::Internal,
            Principal::Supervisor,
        );
    }

    let labels = declassifier.list_labels();
    assert_eq!(labels.len(), 3);
}

#[test]
fn test_declassification_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-013".to_string(),
        1004,
        1004,
        ledger,
    );

    // Request and approve
    let request = declassifier.request_declassification(
        "resource-007".to_string(),
        ClassificationLevel::Secret,
        ClassificationLevel::Public,
        "Complete declassification".to_string(),
        Principal::Supervisor,
    ).unwrap();

    let _ = declassifier.approve_declassification(
        request.request_id,
        "supervisor".to_string(),
    );

    let history = declassifier.declassification_history();
    assert_eq!(history.len(), 1);
    assert!(history[0].approved);
}

#[test]
fn test_classification_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-014".to_string(),
        1004,
        1004,
        ledger,
    );

    // Create multiple classifications
    for i in 0..2 {
        let _ = declassifier.classify_resource(
            format!("resource-{:03}", i),
            ClassificationLevel::Secret,
            Principal::Supervisor,
        );
    }

    let history = declassifier.classification_history();
    assert_eq!(history.len(), 2);
}

#[test]
fn test_statistics() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-015".to_string(),
        1004,
        1004,
        ledger,
    );

    // Perform various operations
    for i in 0..2 {
        let _ = declassifier.classify_resource(
            format!("resource-{:03}", i),
            ClassificationLevel::Secret,
            Principal::Supervisor,
        );
    }

    let request = declassifier.request_declassification(
        "resource-100".to_string(),
        ClassificationLevel::Secret,
        ClassificationLevel::Confidential,
        "Test".to_string(),
        Principal::Supervisor,
    ).unwrap();

    let _ = declassifier.approve_declassification(
        request.request_id,
        "supervisor".to_string(),
    );

    let (classified, requested, approved, denied) = declassifier.statistics();
    assert_eq!(classified, 2);
    assert_eq!(requested, 1);
    assert_eq!(approved, 1);
    assert_eq!(denied, 0);
}

#[test]
fn test_report() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-016".to_string(),
        1004,
        1004,
        ledger,
    );

    let report = declassifier.report();

    assert!(report.contains("Declassifier Principal"));
    assert!(report.contains("declassifier-016"));
    assert!(report.contains("Resources Classified:"));
    assert!(report.contains("Declassifications Requested:"));
}

#[test]
fn test_state_transitions() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-017".to_string(),
        1004,
        1004,
        ledger,
    );

    assert_eq!(declassifier.state(), DeclassifierState::NotStarted);

    let _ = declassifier.classify_resource(
        "resource-008".to_string(),
        ClassificationLevel::Secret,
        Principal::Supervisor,
    );
    assert_eq!(declassifier.state(), DeclassifierState::Ready);

    let _ = declassifier.shutdown();
    assert_eq!(declassifier.state(), DeclassifierState::Shutdown);
}

#[test]
fn test_with_supervisor_integration() {
    let temp = TempDir::new().unwrap();
    let ledger_path = temp.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-integrated".to_string(),
        1004,
        1004,
        supervisor.ledger(),
    );

    let decision = declassifier.classify_resource(
        "resource-009".to_string(),
        ClassificationLevel::Confidential,
        Principal::Supervisor,
    ).unwrap();

    assert!(decision.approved);
}

#[test]
fn test_multiple_instances_isolation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let decl1 = DeclassifierPrincipal::new(
        "declassifier-a".to_string(),
        1004,
        1004,
        ledger.clone(),
    );

    let decl2 = DeclassifierPrincipal::new(
        "declassifier-b".to_string(),
        1005,
        1005,
        ledger.clone(),
    );

    // Each instance performs different operations
    for i in 0..3 {
        let _ = decl1.classify_resource(
            format!("resource-a-{}", i),
            ClassificationLevel::Secret,
            Principal::Supervisor,
        );
    }

    for i in 0..2 {
        let _ = decl2.classify_resource(
            format!("resource-b-{}", i),
            ClassificationLevel::Internal,
            Principal::Supervisor,
        );
    }

    let (c1, _, _, _) = decl1.statistics();
    let (c2, _, _, _) = decl2.statistics();

    assert_eq!(c1, 3);
    assert_eq!(c2, 2);
}

#[test]
fn test_classification_levels_hierarchy() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let declassifier = DeclassifierPrincipal::new(
        "declassifier-018".to_string(),
        1004,
        1004,
        ledger,
    );

    // Test each classification level
    let levels = vec![
        ClassificationLevel::TopSecret,
        ClassificationLevel::Secret,
        ClassificationLevel::Confidential,
        ClassificationLevel::Internal,
        ClassificationLevel::Public,
    ];

    for (i, level) in levels.iter().enumerate() {
        let decision = declassifier.classify_resource(
            format!("resource-level-{}", i),
            level.clone(),
            Principal::Supervisor,
        ).unwrap();

        assert_eq!(decision.classification, *level);
    }

    let (classified, _, _, _) = declassifier.statistics();
    assert_eq!(classified, 5);
}
