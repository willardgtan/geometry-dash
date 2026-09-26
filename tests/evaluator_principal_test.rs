// Evaluator Principal Integration Tests (Week 2 Task 2.6)

use geometry_dash::{
    EvaluatorPrincipal, EvaluatorState, Supervisor, SecurityLedger,
};
use tempfile::TempDir;
use std::sync::Arc;

#[test]
fn test_evaluator_initialization() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-001".to_string(),
        1006,
        1006,
        ledger,
    );

    assert_eq!(evaluator.state(), EvaluatorState::NotStarted);
    assert_eq!(evaluator.principal_id(), "evaluator-001");
}

#[test]
fn test_evaluate_correct_decision() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-002".to_string(),
        1006,
        1006,
        ledger,
    );

    let evaluation = evaluator.evaluate_decision(
        "decision-001".to_string(),
        true,
        "Correct decision made".to_string(),
    ).unwrap();

    assert!(evaluation.was_correct);
    assert_eq!(evaluation.correctness_score, 1.0);
    assert!(evaluation.impact_assessment.contains("Positive"));
}

#[test]
fn test_evaluate_incorrect_decision() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-003".to_string(),
        1006,
        1006,
        ledger,
    );

    let evaluation = evaluator.evaluate_decision(
        "decision-002".to_string(),
        false,
        "Incorrect decision made".to_string(),
    ).unwrap();

    assert!(!evaluation.was_correct);
    assert_eq!(evaluation.correctness_score, 0.0);
    assert!(evaluation.impact_assessment.contains("Negative"));
}

#[test]
fn test_analyze_policy_effectiveness() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-004".to_string(),
        1006,
        1006,
        ledger,
    );

    let analysis = evaluator.analyze_policy_effectiveness(
        "access_control".to_string(),
    ).unwrap();

    assert_eq!(analysis.policy_name, "access_control");
    assert!(analysis.success_rate >= 0.0 && analysis.success_rate <= 1.0);
    assert!(!analysis.recommendations.is_empty());

    let (_, effectiveness, _, _) = evaluator.statistics();
    assert_eq!(effectiveness, 1);
}

#[test]
fn test_verify_compliance() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-005".to_string(),
        1006,
        1006,
        ledger,
    );

    let report = evaluator.verify_compliance().unwrap();

    assert!(!report.report_id.is_empty());
    assert!(["full", "partial", "non-compliant"].contains(&report.compliance_level.as_str()));
    assert!(report.policies_checked > 0);

    let (_, _, compliance, _) = evaluator.statistics();
    assert_eq!(compliance, 1);
}

#[test]
fn test_calculate_good_quality_metric() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-006".to_string(),
        1006,
        1006,
        ledger,
    );

    let metric = evaluator.calculate_quality_metric(
        "authorization_success_rate".to_string(),
        0.95,
        0.90,
    ).unwrap();

    assert_eq!(metric.status, "good");
    assert_eq!(metric.value, 0.95);
    assert_eq!(metric.threshold, 0.90);
}

#[test]
fn test_calculate_warning_quality_metric() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-007".to_string(),
        1006,
        1006,
        ledger,
    );

    let metric = evaluator.calculate_quality_metric(
        "decision_accuracy".to_string(),
        0.82,
        0.90,
    ).unwrap();

    assert_eq!(metric.status, "warning");
}

#[test]
fn test_calculate_critical_quality_metric() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-008".to_string(),
        1006,
        1006,
        ledger,
    );

    let metric = evaluator.calculate_quality_metric(
        "policy_compliance".to_string(),
        0.60,
        0.90,
    ).unwrap();

    assert_eq!(metric.status, "critical");
}

#[test]
fn test_evaluation_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-009".to_string(),
        1006,
        1006,
        ledger,
    );

    let eval1 = evaluator.evaluate_decision(
        "decision-001".to_string(),
        true,
        "Good".to_string(),
    ).unwrap();

    let eval2 = evaluator.evaluate_decision(
        "decision-002".to_string(),
        false,
        "Bad".to_string(),
    ).unwrap();

    let history = evaluator.evaluation_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].evaluation_id, eval1.evaluation_id);
    assert_eq!(history[1].evaluation_id, eval2.evaluation_id);
}

#[test]
fn test_effectiveness_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-010".to_string(),
        1006,
        1006,
        ledger,
    );

    let analysis1 = evaluator.analyze_policy_effectiveness("policy1".to_string()).unwrap();
    let analysis2 = evaluator.analyze_policy_effectiveness("policy2".to_string()).unwrap();

    let history = evaluator.effectiveness_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].analysis_id, analysis1.analysis_id);
    assert_eq!(history[1].analysis_id, analysis2.analysis_id);
}

#[test]
fn test_compliance_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-011".to_string(),
        1006,
        1006,
        ledger,
    );

    let report1 = evaluator.verify_compliance().unwrap();
    let report2 = evaluator.verify_compliance().unwrap();

    let history = evaluator.compliance_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].report_id, report1.report_id);
    assert_eq!(history[1].report_id, report2.report_id);
}

#[test]
fn test_metric_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-012".to_string(),
        1006,
        1006,
        ledger,
    );

    let metric1 = evaluator.calculate_quality_metric("m1".to_string(), 0.9, 0.8).unwrap();
    let metric2 = evaluator.calculate_quality_metric("m2".to_string(), 0.7, 0.8).unwrap();
    let metric3 = evaluator.calculate_quality_metric("m3".to_string(), 0.5, 0.8).unwrap();

    let history = evaluator.metric_history();
    assert_eq!(history.len(), 3);
}

#[test]
fn test_statistics() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-013".to_string(),
        1006,
        1006,
        ledger,
    );

    // Perform various operations
    for i in 0..3 {
        let _ = evaluator.evaluate_decision(
            format!("decision-{}", i),
            i % 2 == 0,
            "Test".to_string(),
        );
    }

    let _ = evaluator.analyze_policy_effectiveness("policy1".to_string());
    let _ = evaluator.analyze_policy_effectiveness("policy2".to_string());

    let _ = evaluator.verify_compliance();

    for i in 0..2 {
        let _ = evaluator.calculate_quality_metric(
            format!("metric-{}", i),
            0.85,
            0.80,
        );
    }

    let (decisions, effectiveness, compliance, metrics) = evaluator.statistics();
    assert_eq!(decisions, 3);
    assert_eq!(effectiveness, 2);
    assert_eq!(compliance, 1);
    assert_eq!(metrics, 2);
}

#[test]
fn test_evaluation_report() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-014".to_string(),
        1006,
        1006,
        ledger,
    );

    let report = evaluator.evaluation_report();

    assert!(report.contains("Evaluator Principal"));
    assert!(report.contains("evaluator-014"));
    assert!(report.contains("Decisions Evaluated:"));
    assert!(report.contains("Effectiveness Analyses:"));
    assert!(report.contains("Compliance Checks:"));
    assert!(report.contains("Metrics Calculated:"));
}

#[test]
fn test_state_transitions() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-015".to_string(),
        1006,
        1006,
        ledger,
    );

    assert_eq!(evaluator.state(), EvaluatorState::NotStarted);

    let _ = evaluator.evaluate_decision("d1".to_string(), true, "good".to_string());
    assert_eq!(evaluator.state(), EvaluatorState::Ready);

    let _ = evaluator.analyze_policy_effectiveness("p1".to_string());
    assert_eq!(evaluator.state(), EvaluatorState::Ready);

    let _ = evaluator.verify_compliance();
    assert_eq!(evaluator.state(), EvaluatorState::Ready);

    let _ = evaluator.shutdown();
    assert_eq!(evaluator.state(), EvaluatorState::Shutdown);
}

#[test]
fn test_with_supervisor_integration() {
    let temp = TempDir::new().unwrap();
    let ledger_path = temp.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-integrated".to_string(),
        1006,
        1006,
        supervisor.ledger(),
    );

    let evaluation = evaluator.evaluate_decision(
        "decision-001".to_string(),
        true,
        "Test".to_string(),
    ).unwrap();

    assert!(evaluation.was_correct);
}

#[test]
fn test_multiple_instances_isolation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let eval1 = EvaluatorPrincipal::new(
        "evaluator-a".to_string(),
        1006,
        1006,
        ledger.clone(),
    );

    let eval2 = EvaluatorPrincipal::new(
        "evaluator-b".to_string(),
        1007,
        1007,
        ledger.clone(),
    );

    // Different operations for each
    for i in 0..3 {
        let _ = eval1.evaluate_decision(
            format!("d1-{}", i),
            true,
            "good".to_string(),
        );
    }

    for i in 0..2 {
        let _ = eval2.evaluate_decision(
            format!("d2-{}", i),
            false,
            "bad".to_string(),
        );
    }

    let (d1, _, _, _) = eval1.statistics();
    let (d2, _, _, _) = eval2.statistics();

    assert_eq!(d1, 3);
    assert_eq!(d2, 2);
}

#[test]
fn test_compliance_report_structure() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-016".to_string(),
        1006,
        1006,
        ledger,
    );

    let report = evaluator.verify_compliance().unwrap();

    assert!(!report.report_id.is_empty());
    assert!(report.policies_checked > 0);
    assert!(report.policies_compliant + report.policies_violated <= report.policies_checked);
    assert!(!report.remediation_actions.is_empty());
}

#[test]
fn test_quality_metric_details() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let evaluator = EvaluatorPrincipal::new(
        "evaluator-017".to_string(),
        1006,
        1006,
        ledger,
    );

    let metric = evaluator.calculate_quality_metric(
        "test_metric".to_string(),
        0.88,
        0.85,
    ).unwrap();

    assert_eq!(metric.metric_type, "test_metric");
    assert_eq!(metric.value, 0.88);
    assert_eq!(metric.threshold, 0.85);
    assert!(metric.details.contains("0.88"));
}
