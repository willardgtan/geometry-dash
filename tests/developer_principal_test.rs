// Developer Principal Integration Tests (Week 2 Task 2.8)

use geometry_dash::{
    DeveloperPrincipal, DeveloperState, Supervisor, SecurityLedger,
};
use tempfile::TempDir;
use std::sync::Arc;

#[test]
fn test_developer_initialization() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-001".to_string(),
        1008,
        1008,
        ledger,
    );

    assert_eq!(developer.state(), DeveloperState::NotStarted);
    assert_eq!(developer.principal_id(), "developer-001");
}

#[test]
fn test_record_trace() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-002".to_string(),
        1008,
        1008,
        ledger,
    );

    let trace = developer.record_trace(
        "policy_gate_a".to_string(),
        "decision".to_string(),
        "Policy decision made".to_string(),
    ).unwrap();

    assert!(!trace.trace_id.is_empty());
    assert_eq!(trace.location, "policy_gate_a");
    assert_eq!(trace.event_type, "decision");
}

#[test]
fn test_snapshot_principal() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-003".to_string(),
        1008,
        1008,
        ledger,
    );

    let snapshot = developer.snapshot_principal(
        "audit".to_string(),
        "Ready".to_string(),
    ).unwrap();

    assert!(!snapshot.snapshot_id.is_empty());
    assert_eq!(snapshot.principal_id, "audit");
    assert_eq!(snapshot.principal_state, "Ready");
}

#[test]
fn test_run_diagnostic() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-004".to_string(),
        1008,
        1008,
        ledger,
    );

    let report = developer.run_diagnostic().unwrap();

    assert!(!report.report_id.is_empty());
    assert!(["healthy", "degraded", "critical"].contains(&report.system_health.as_str()));
    assert!(!report.findings.is_empty());
    assert!(!report.recommendations.is_empty());
}

#[test]
fn test_collect_metric_normal() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-005".to_string(),
        1008,
        1008,
        ledger,
    );

    let metric = developer.collect_metric(
        "latency_ms".to_string(),
        10.0,
        "ms".to_string(),
        50.0,
    ).unwrap();

    assert_eq!(metric.status, "normal");
    assert_eq!(metric.value, 10.0);
}

#[test]
fn test_collect_metric_warning() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-006".to_string(),
        1008,
        1008,
        ledger,
    );

    let metric = developer.collect_metric(
        "error_rate".to_string(),
        0.75,
        "percent".to_string(),
        0.50,
    ).unwrap();

    assert_eq!(metric.status, "warning");
}

#[test]
fn test_collect_metric_critical() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-007".to_string(),
        1008,
        1008,
        ledger,
    );

    let metric = developer.collect_metric(
        "memory_usage_mb".to_string(),
        500.0,
        "mb".to_string(),
        200.0,
    ).unwrap();

    assert_eq!(metric.status, "critical");
}

#[test]
fn test_debug_log() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-008".to_string(),
        1008,
        1008,
        ledger,
    );

    let _ = developer.log_debug("Initialization started".to_string());
    let _ = developer.log_debug("Components loaded".to_string());
    let _ = developer.log_debug("Ready for operations".to_string());

    let log = developer.get_debug_log();
    assert_eq!(log.len(), 3);
    assert_eq!(log[0], "Initialization started");
    assert_eq!(log[2], "Ready for operations");
}

#[test]
fn test_trace_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-009".to_string(),
        1008,
        1008,
        ledger,
    );

    let t1 = developer.record_trace("loc1".to_string(), "type1".to_string(), "data1".to_string()).unwrap();
    let t2 = developer.record_trace("loc2".to_string(), "type2".to_string(), "data2".to_string()).unwrap();

    let history = developer.trace_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].trace_id, t1.trace_id);
    assert_eq!(history[1].trace_id, t2.trace_id);
}

#[test]
fn test_snapshot_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-010".to_string(),
        1008,
        1008,
        ledger,
    );

    let s1 = developer.snapshot_principal("p1".to_string(), "Ready".to_string()).unwrap();
    let s2 = developer.snapshot_principal("p2".to_string(), "Ready".to_string()).unwrap();

    let history = developer.snapshot_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].snapshot_id, s1.snapshot_id);
    assert_eq!(history[1].snapshot_id, s2.snapshot_id);
}

#[test]
fn test_report_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-011".to_string(),
        1008,
        1008,
        ledger,
    );

    let r1 = developer.run_diagnostic().unwrap();
    let r2 = developer.run_diagnostic().unwrap();

    let history = developer.report_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].report_id, r1.report_id);
    assert_eq!(history[1].report_id, r2.report_id);
}

#[test]
fn test_metric_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-012".to_string(),
        1008,
        1008,
        ledger,
    );

    let m1 = developer.collect_metric("m1".to_string(), 10.0, "unit".to_string(), 50.0).unwrap();
    let m2 = developer.collect_metric("m2".to_string(), 30.0, "unit".to_string(), 50.0).unwrap();

    let history = developer.metric_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].metric_id, m1.metric_id);
    assert_eq!(history[1].metric_id, m2.metric_id);
}

#[test]
fn test_statistics() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-013".to_string(),
        1008,
        1008,
        ledger,
    );

    for i in 0..3 {
        let _ = developer.record_trace(format!("loc{}", i), "type".to_string(), "data".to_string());
    }

    for i in 0..2 {
        let _ = developer.snapshot_principal(format!("p{}", i), "Ready".to_string());
    }

    let _ = developer.run_diagnostic();
    let _ = developer.run_diagnostic();

    let _ = developer.collect_metric("m1".to_string(), 10.0, "unit".to_string(), 50.0);

    let (traces, snapshots, diagnostics, metrics) = developer.statistics();
    assert_eq!(traces, 3);
    assert_eq!(snapshots, 2);
    assert_eq!(diagnostics, 2);
    assert_eq!(metrics, 1);
}

#[test]
fn test_developer_report() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-014".to_string(),
        1008,
        1008,
        ledger,
    );

    let report = developer.developer_report();

    assert!(report.contains("Developer Principal"));
    assert!(report.contains("developer-014"));
    assert!(report.contains("Trace Points Recorded:"));
    assert!(report.contains("Snapshots Taken:"));
    assert!(report.contains("Diagnostics Run:"));
    assert!(report.contains("Metrics Collected:"));
}

#[test]
fn test_state_transitions() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-015".to_string(),
        1008,
        1008,
        ledger,
    );

    assert_eq!(developer.state(), DeveloperState::NotStarted);

    let _ = developer.record_trace("loc".to_string(), "type".to_string(), "data".to_string());
    assert_eq!(developer.state(), DeveloperState::Ready);

    let _ = developer.snapshot_principal("p".to_string(), "Ready".to_string());
    assert_eq!(developer.state(), DeveloperState::Ready);

    let _ = developer.run_diagnostic();
    assert_eq!(developer.state(), DeveloperState::Ready);

    let _ = developer.shutdown();
    assert_eq!(developer.state(), DeveloperState::Shutdown);
}

#[test]
fn test_with_supervisor_integration() {
    let temp = TempDir::new().unwrap();
    let ledger_path = temp.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    let developer = DeveloperPrincipal::new(
        "developer-integrated".to_string(),
        1008,
        1008,
        supervisor.ledger(),
    );

    let trace = developer.record_trace(
        "supervisor_event".to_string(),
        "initialization".to_string(),
        "Started".to_string(),
    ).unwrap();

    assert!(!trace.trace_id.is_empty());
}

#[test]
fn test_multiple_instances_isolation() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let dev1 = DeveloperPrincipal::new(
        "dev-a".to_string(),
        1008,
        1008,
        ledger.clone(),
    );

    let dev2 = DeveloperPrincipal::new(
        "dev-b".to_string(),
        1009,
        1009,
        ledger.clone(),
    );

    for i in 0..3 {
        let _ = dev1.record_trace(format!("loc{}", i), "type".to_string(), "data".to_string());
    }

    for i in 0..2 {
        let _ = dev2.record_trace(format!("loc{}", i), "type".to_string(), "data".to_string());
    }

    let (t1, _, _, _) = dev1.statistics();
    let (t2, _, _, _) = dev2.statistics();

    assert_eq!(t1, 3);
    assert_eq!(t2, 2);
}

#[test]
fn test_diagnostic_report_structure() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-016".to_string(),
        1008,
        1008,
        ledger,
    );

    let report = developer.run_diagnostic().unwrap();

    assert!(!report.report_id.is_empty());
    assert!(report.total_events >= 0);
    assert!(report.active_principals > 0);
    assert!(report.error_count >= 0);
    assert!(report.warning_count >= 0);
    assert!(!report.findings.is_empty());
    assert!(!report.recommendations.is_empty());
}

#[test]
fn test_metric_status_determination() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-017".to_string(),
        1008,
        1008,
        ledger,
    );

    let m_normal = developer.collect_metric("m".to_string(), 10.0, "unit".to_string(), 50.0).unwrap();
    let m_warning = developer.collect_metric("m".to_string(), 60.0, "unit".to_string(), 50.0).unwrap();
    let m_critical = developer.collect_metric("m".to_string(), 100.0, "unit".to_string(), 50.0).unwrap();

    assert_eq!(m_normal.status, "normal");
    assert_eq!(m_warning.status, "warning");
    assert_eq!(m_critical.status, "critical");
}

#[test]
fn test_trace_with_full_metadata() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-018".to_string(),
        1008,
        1008,
        ledger,
    );

    let trace = developer.record_trace(
        "gate_a_policy".to_string(),
        "decision_made".to_string(),
        "approved: true, reason: valid_credentials".to_string(),
    ).unwrap();

    assert_eq!(trace.location, "gate_a_policy");
    assert_eq!(trace.event_type, "decision_made");
    assert_eq!(trace.event_data, "approved: true, reason: valid_credentials");
    assert!(trace.stack_depth >= 1);
    assert!(!trace.trace_id.is_empty());
}

#[test]
fn test_snapshot_provides_state_details() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-019".to_string(),
        1008,
        1008,
        ledger,
    );

    let snapshot = developer.snapshot_principal(
        "declassifier".to_string(),
        "Ready".to_string(),
    ).unwrap();

    assert_eq!(snapshot.principal_id, "declassifier");
    assert_eq!(snapshot.principal_state, "Ready");
    assert!(snapshot.active_operations >= 0);
    assert!(snapshot.memory_usage_estimate > 0);
}

#[test]
fn test_multiple_diagnostics_track_history() {
    let temp = TempDir::new().unwrap();
    let ledger = Arc::new(
        SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
    );

    let developer = DeveloperPrincipal::new(
        "developer-020".to_string(),
        1008,
        1008,
        ledger,
    );

    let r1 = developer.run_diagnostic().unwrap();
    let r2 = developer.run_diagnostic().unwrap();
    let r3 = developer.run_diagnostic().unwrap();

    let history = developer.report_history();
    assert_eq!(history.len(), 3);
    assert_ne!(r1.report_id, r2.report_id);
    assert_ne!(r2.report_id, r3.report_id);
}
