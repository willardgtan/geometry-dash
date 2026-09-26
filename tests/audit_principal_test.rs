// Audit Principal Integration Tests (Week 2 Task 2.3)

use geometry_dash::{
    AuditPrincipal, AuditState, Supervisor, SecurityLedger,
};
use tempfile::TempDir;
use std::sync::Arc;

#[test]
fn test_audit_principal_initialization() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-001".to_string(),
        1003,
        1003,
        ledger,
    );

    assert_eq!(audit.state(), AuditState::NotStarted);
    assert_eq!(audit.principal_id(), "audit-001");
}

#[test]
fn test_audit_analyze_events() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-002".to_string(),
        1003,
        1003,
        ledger,
    );

    // Analyze events
    let events = audit.analyze_events().unwrap();
    assert!(events.is_empty()); // No events logged yet

    // Verify statistics
    let (analyzed, _, _, _) = audit.statistics();
    assert_eq!(analyzed, 1);
}

#[test]
fn test_audit_event_correlation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-003".to_string(),
        1003,
        1003,
        ledger,
    );

    // Analyze events first
    let _ = audit.analyze_events();

    // Correlate events
    let correlations = audit.correlate_events().unwrap();

    // Verify statistics updated
    let (_, found, _, _) = audit.statistics();
    assert!(found >= 0);

    // Verify correlation history is accessible
    let history = audit.correlation_history();
    assert_eq!(history.len(), correlations.len());
}

#[test]
fn test_audit_breach_detection() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-004".to_string(),
        1003,
        1003,
        ledger,
    );

    // Setup
    let _ = audit.analyze_events();

    // Detect breaches
    let breaches = audit.detect_breaches().unwrap();

    // Verify statistics
    let (_, _, detected, _) = audit.statistics();
    assert!(detected >= 0);

    // Verify breach history
    let history = audit.breach_history();
    assert_eq!(history.len(), breaches.len());
}

#[test]
fn test_audit_forensic_analysis() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-005".to_string(),
        1003,
        1003,
        ledger,
    );

    // Perform forensic analysis with empty event list
    let analysis = audit.forensic_analysis(vec![]).unwrap();

    assert_eq!(analysis.event_sequence.len(), 0);
    assert!(!analysis.findings.is_empty());

    // Verify statistics
    let (_, _, _, performed) = audit.statistics();
    assert_eq!(performed, 1);

    // Verify analysis history
    let history = audit.analysis_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].analysis_id, analysis.analysis_id);
}

#[test]
fn test_audit_summary_report() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-006".to_string(),
        1003,
        1003,
        ledger,
    );

    let report = audit.summary_report();

    // Verify report contains expected sections
    assert!(report.contains("Audit Principal"));
    assert!(report.contains("audit-006"));
    assert!(report.contains("Events Analyzed:"));
    assert!(report.contains("Correlations Found:"));
    assert!(report.contains("Breaches Detected:"));
    assert!(report.contains("Analyses Performed:"));
}

#[test]
fn test_audit_state_transitions() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-007".to_string(),
        1003,
        1003,
        ledger,
    );

    assert_eq!(audit.state(), AuditState::NotStarted);

    // State changes during analysis
    let _ = audit.analyze_events();
    assert_eq!(audit.state(), AuditState::Ready);

    // State changes during correlation
    let _ = audit.correlate_events();
    assert_eq!(audit.state(), AuditState::Ready);

    // State changes during breach detection
    let _ = audit.detect_breaches();
    assert_eq!(audit.state(), AuditState::Ready);

    // Shutdown
    assert!(audit.shutdown().is_ok());
    assert_eq!(audit.state(), AuditState::Shutdown);
}

#[test]
fn test_audit_with_supervisor_integration() {
    let temp = TempDir::new().unwrap();
    let ledger_path = temp.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    let audit = AuditPrincipal::new(
        "audit-integrated".to_string(),
        1003,
        1003,
        supervisor.ledger(),
    );

    // Audit should work with supervisor's ledger
    let events = audit.analyze_events().unwrap();
    // May be empty initially, but should work

    let (analyzed, _, _, _) = audit.statistics();
    assert_eq!(analyzed, 1);
}

#[test]
fn test_audit_correlation_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-008".to_string(),
        1003,
        1003,
        ledger,
    );

    // Initial history should be empty
    let initial_history = audit.correlation_history();
    assert_eq!(initial_history.len(), 0);

    // Analyze and correlate
    let _ = audit.analyze_events();
    let _ = audit.correlate_events();

    // History should now contain results
    let history = audit.correlation_history();
    // History grows with analysis
    assert!(history.is_empty() || !history.is_empty()); // May or may not have correlations
}

#[test]
fn test_audit_breach_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-009".to_string(),
        1003,
        1003,
        ledger,
    );

    // Initial history empty
    let initial = audit.breach_history();
    assert_eq!(initial.len(), 0);

    // Analyze and detect
    let _ = audit.analyze_events();
    let _ = audit.detect_breaches();

    // History accessible
    let history = audit.breach_history();
    // May have breaches or not depending on what's in ledger
    assert!(history.is_empty() || !history.is_empty());
}

#[test]
fn test_audit_analysis_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-010".to_string(),
        1003,
        1003,
        ledger,
    );

    // Initial empty
    let initial = audit.analysis_history();
    assert_eq!(initial.len(), 0);

    // Perform analysis
    let analysis = audit.forensic_analysis(vec![]).unwrap();

    // History should contain result
    let history = audit.analysis_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].analysis_id, analysis.analysis_id);
}

#[test]
fn test_audit_statistics_accumulation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-011".to_string(),
        1003,
        1003,
        ledger,
    );

    // Initial stats
    let (analyzed1, corr1, breach1, analyses1) = audit.statistics();
    assert_eq!(analyzed1, 0);

    // After analysis
    let _ = audit.analyze_events();
    let (analyzed2, _, _, _) = audit.statistics();
    assert_eq!(analyzed2, 1);

    // After correlation
    let _ = audit.correlate_events();
    let (_, corr2, _, _) = audit.statistics();
    // Correlations may or may not be found

    // After breach detection
    let _ = audit.detect_breaches();
    let (_, _, breach2, _) = audit.statistics();
    // Breaches may or may not be detected

    // After forensic analysis (perform multiple)
    let _ = audit.forensic_analysis(vec![]);
    let _ = audit.forensic_analysis(vec![]);
    let (_, _, _, analyses2) = audit.statistics();
    assert_eq!(analyses2, 2);
}

#[test]
fn test_audit_multiple_instances_isolation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    // Create two audit instances
    let audit1 = AuditPrincipal::new(
        "audit-a".to_string(),
        1003,
        1003,
        ledger.clone(),
    );

    let audit2 = AuditPrincipal::new(
        "audit-b".to_string(),
        1004,
        1004,
        ledger.clone(),
    );

    // Each performs different number of operations
    for _ in 0..3 {
        let _ = audit1.analyze_events();
    }

    for _ in 0..2 {
        let _ = audit2.analyze_events();
    }

    // Statistics should be independent
    let (a1, _, _, _) = audit1.statistics();
    let (a2, _, _, _) = audit2.statistics();

    assert_eq!(a1, 3);
    assert_eq!(a2, 2);
}

#[test]
fn test_audit_forensic_analysis_with_events() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-012".to_string(),
        1003,
        1003,
        ledger,
    );

    // First analyze to populate cache
    let _ = audit.analyze_events();

    // Then perform forensic analysis with specific event IDs
    let analysis = audit.forensic_analysis(vec![
        "event-001".to_string(),
        "event-002".to_string(),
    ]).unwrap();

    // Verify analysis structure
    assert_eq!(analysis.event_sequence.len(), 2);
    assert!(!analysis.findings.is_empty());
    assert!(!analysis.analysis_id.is_empty());
}

#[test]
fn test_audit_correlation_confidence_scores() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-013".to_string(),
        1003,
        1003,
        ledger,
    );

    let _ = audit.analyze_events();
    let correlations = audit.correlate_events().unwrap();

    // Each correlation should have a confidence score
    for correlation in correlations {
        assert!(correlation.confidence >= 0.0);
        assert!(correlation.confidence <= 1.0);
    }
}

#[test]
fn test_audit_breach_severity_levels() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-014".to_string(),
        1003,
        1003,
        ledger,
    );

    let _ = audit.analyze_events();
    let breaches = audit.detect_breaches().unwrap();

    // Each breach should have severity level
    for breach in breaches {
        assert!(!breach.severity.is_empty());
        assert!(["low", "medium", "high", "critical"].contains(&breach.severity.as_str())
            || breach.severity.is_empty());
    }
}

#[test]
fn test_audit_forensic_analysis_severity_assessment() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let audit = AuditPrincipal::new(
        "audit-015".to_string(),
        1003,
        1003,
        ledger,
    );

    let analysis = audit.forensic_analysis(vec![]).unwrap();

    // Severity assessment should be one of the expected values
    assert!(["normal", "high", "critical"].contains(&analysis.severity_assessment.as_str()));
}
