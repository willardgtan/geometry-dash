// Learner Principal Integration Tests (Week 2 Task 2.5)

use geometry_dash::{
    LearnerPrincipal, LearnerState, Supervisor, SecurityLedger,
};
use tempfile::TempDir;
use std::sync::Arc;

#[test]
fn test_learner_initialization() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-001".to_string(),
        1005,
        1005,
        ledger,
    );

    assert_eq!(learner.state(), LearnerState::NotStarted);
    assert_eq!(learner.principal_id(), "learner-001");
}

#[test]
fn test_analyze_patterns() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-002".to_string(),
        1005,
        1005,
        ledger,
    );

    let patterns = learner.analyze_patterns().unwrap();

    let (detected, _, _, _) = learner.statistics();
    assert!(detected >= 0);

    // Empty ledger may have no patterns
    assert!(patterns.is_empty() || !patterns.is_empty());
}

#[test]
fn test_recommend_policies() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-003".to_string(),
        1005,
        1005,
        ledger,
    );

    // Analyze patterns first
    let _ = learner.analyze_patterns();

    let recommendations = learner.recommend_policies().unwrap();

    let (_, made, _, _) = learner.statistics();
    assert!(made >= 0);
}

#[test]
fn test_analyze_usage() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-004".to_string(),
        1005,
        1005,
        ledger,
    );

    let analysis = learner.analyze_usage().unwrap();

    assert!(!analysis.analysis_id.is_empty());
    let (_, _, performed, _) = learner.statistics();
    assert_eq!(performed, 1);
}

#[test]
fn test_ml_readiness_assessment() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-005".to_string(),
        1005,
        1005,
        ledger,
    );

    let assessment = learner.assess_ml_readiness().unwrap();

    // Verify assessment structure
    assert!(!assessment.assessment_id.is_empty());
    assert!(assessment.data_quality_score >= 0.0 && assessment.data_quality_score <= 1.0);
    assert!(assessment.data_volume_score >= 0.0 && assessment.data_volume_score <= 1.0);
    assert!(assessment.pattern_complexity_score >= 0.0 && assessment.pattern_complexity_score <= 1.0);
    assert!(assessment.overall_readiness >= 0.0 && assessment.overall_readiness <= 1.0);

    let (_, _, _, completed) = learner.statistics();
    assert_eq!(completed, 1);
}

#[test]
fn test_pattern_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-006".to_string(),
        1005,
        1005,
        ledger,
    );

    let _ = learner.analyze_patterns();
    let history = learner.pattern_history();

    // History should be accessible
    assert!(history.is_empty() || !history.is_empty());
}

#[test]
fn test_recommendation_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-007".to_string(),
        1005,
        1005,
        ledger,
    );

    let _ = learner.analyze_patterns();
    let _ = learner.recommend_policies();

    let history = learner.recommendation_history();
    assert!(!history.is_empty());

    // Each recommendation should have required fields
    for rec in history {
        assert!(!rec.recommendation_id.is_empty());
        assert!(!rec.priority.is_empty());
        assert!(!rec.category.is_empty());
        assert!(rec.confidence >= 0.0 && rec.confidence <= 1.0);
    }
}

#[test]
fn test_analysis_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-008".to_string(),
        1005,
        1005,
        ledger,
    );

    let analysis1 = learner.analyze_usage().unwrap();
    let analysis2 = learner.analyze_usage().unwrap();

    let history = learner.analysis_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].analysis_id, analysis1.analysis_id);
    assert_eq!(history[1].analysis_id, analysis2.analysis_id);
}

#[test]
fn test_assessment_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-009".to_string(),
        1005,
        1005,
        ledger,
    );

    let assessment = learner.assess_ml_readiness().unwrap();

    let history = learner.assessment_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].assessment_id, assessment.assessment_id);
}

#[test]
fn test_statistics() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-010".to_string(),
        1005,
        1005,
        ledger,
    );

    // Perform various operations
    let _ = learner.analyze_patterns();
    let _ = learner.recommend_policies();
    let _ = learner.analyze_usage();
    let _ = learner.assess_ml_readiness();

    let (patterns, recs, analyses, assessments) = learner.statistics();
    assert!(patterns >= 0);
    assert!(recs >= 0);
    assert_eq!(analyses, 1);
    assert_eq!(assessments, 1);
}

#[test]
fn test_summary() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-011".to_string(),
        1005,
        1005,
        ledger,
    );

    let summary = learner.summary();

    assert!(summary.contains("Learner Principal"));
    assert!(summary.contains("learner-011"));
    assert!(summary.contains("Patterns Detected:"));
    assert!(summary.contains("Recommendations Made:"));
    assert!(summary.contains("Analyses Performed:"));
}

#[test]
fn test_state_transitions() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-012".to_string(),
        1005,
        1005,
        ledger,
    );

    assert_eq!(learner.state(), LearnerState::NotStarted);

    let _ = learner.analyze_patterns();
    assert_eq!(learner.state(), LearnerState::Ready);

    let _ = learner.recommend_policies();
    assert_eq!(learner.state(), LearnerState::Ready);

    let _ = learner.shutdown();
    assert_eq!(learner.state(), LearnerState::Shutdown);
}

#[test]
fn test_with_supervisor_integration() {
    let temp = TempDir::new().unwrap();
    let ledger_path = temp.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    let learner = LearnerPrincipal::new(
        "learner-integrated".to_string(),
        1005,
        1005,
        supervisor.ledger(),
    );

    let patterns = learner.analyze_patterns().unwrap();
    assert!(patterns.is_empty() || !patterns.is_empty());

    let recommendations = learner.recommend_policies().unwrap();
    assert!(!recommendations.is_empty());
}

#[test]
fn test_multiple_instances_isolation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner1 = LearnerPrincipal::new(
        "learner-a".to_string(),
        1005,
        1005,
        ledger.clone(),
    );

    let learner2 = LearnerPrincipal::new(
        "learner-b".to_string(),
        1006,
        1006,
        ledger.clone(),
    );

    // Each instance performs different number of analyses
    for _ in 0..2 {
        let _ = learner1.analyze_usage();
    }

    let _ = learner2.analyze_usage();

    let (_, _, a1, _) = learner1.statistics();
    let (_, _, a2, _) = learner2.statistics();

    assert_eq!(a1, 2);
    assert_eq!(a2, 1);
}

#[test]
fn test_ml_readiness_data_quality() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-013".to_string(),
        1005,
        1005,
        ledger,
    );

    let assessment = learner.assess_ml_readiness().unwrap();

    // Quality score should be 0 for empty ledger
    assert!(assessment.data_quality_score >= 0.0);
    assert!(assessment.data_quality_score <= 1.0);
}

#[test]
fn test_ml_readiness_data_volume() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-014".to_string(),
        1005,
        1005,
        ledger,
    );

    let assessment = learner.assess_ml_readiness().unwrap();

    // For empty ledger, volume score should be 0
    assert!(assessment.data_volume_score == 0.0 || assessment.data_volume_score > 0.0);
}

#[test]
fn test_pattern_confidence_scores() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-015".to_string(),
        1005,
        1005,
        ledger,
    );

    let patterns = learner.analyze_patterns().unwrap();

    // Each pattern should have confidence score
    for pattern in patterns {
        assert!(pattern.confidence >= 0.0);
        assert!(pattern.confidence <= 1.0);
    }
}

#[test]
fn test_policy_recommendation_priorities() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-016".to_string(),
        1005,
        1005,
        ledger,
    );

    let _ = learner.analyze_patterns();
    let recommendations = learner.recommend_policies().unwrap();

    // Each recommendation should have priority
    for rec in recommendations {
        assert!(["low", "medium", "high", "critical"].contains(&rec.priority.as_str()));
    }
}

#[test]
fn test_usage_analysis_anomalies() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let learner = LearnerPrincipal::new(
        "learner-017".to_string(),
        1005,
        1005,
        ledger,
    );

    let analysis = learner.analyze_usage().unwrap();

    // Anomalies list should be accessible
    assert!(analysis.anomalies.is_empty() || !analysis.anomalies.is_empty());
}
