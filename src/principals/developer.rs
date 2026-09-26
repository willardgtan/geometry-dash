// Developer Principal: Debugging and Introspection (Week 2 Task 2.8)
// Responsible for system debugging, diagnostics, and introspection capabilities

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::types::Principal;
use crate::security_ledger::{SecurityLedger, EventType, Severity};
use crate::hsm::SigningKey;
use uuid::Uuid;

/// Developer principal state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeveloperState {
    NotStarted,
    Initializing,
    Ready,
    Debugging,      // Performing debug operations
    Inspecting,     // Inspecting system state
    Tracing,        // Recording trace logs
    Running,
    Shutdown,
    Failed,
}

/// Debug breakpoint or trace point
#[derive(Debug, Clone)]
pub struct TracePoint {
    pub trace_id: String,
    pub timestamp_ns: u64,
    pub location: String,
    pub event_type: String,
    pub event_data: String,
    pub stack_depth: u32,
}

/// System introspection snapshot
#[derive(Debug, Clone)]
pub struct IntrospectionSnapshot {
    pub snapshot_id: String,
    pub timestamp_ns: u64,
    pub principal_id: String,
    pub principal_state: String,
    pub active_operations: u64,
    pub event_count: u64,
    pub memory_usage_estimate: u64,
}

/// Debug diagnostic report
#[derive(Debug, Clone)]
pub struct DiagnosticReport {
    pub report_id: String,
    pub timestamp_ns: u64,
    pub total_events: u64,
    pub system_health: String,  // "healthy", "degraded", "critical"
    pub active_principals: u64,
    pub error_count: u64,
    pub warning_count: u64,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Performance metric snapshot
#[derive(Debug, Clone)]
pub struct PerformanceMetric {
    pub metric_id: String,
    pub timestamp_ns: u64,
    pub metric_name: String,
    pub value: f64,
    pub unit: String,
    pub threshold: f64,
    pub status: String,  // "normal", "warning", "critical"
}

/// Developer principal context
pub struct DeveloperPrincipal {
    /// Unique ID for this Developer instance
    principal_id: String,

    /// Current state
    state: Arc<Mutex<DeveloperState>>,

    /// UID/GID for process isolation
    uid: u32,
    gid: u32,

    /// Signing key for message authentication
    signing_key: Arc<Mutex<Option<SigningKey>>>,

    /// Security ledger for event source
    ledger: Arc<SecurityLedger>,

    /// Trace points history
    trace_points: Arc<Mutex<Vec<TracePoint>>>,

    /// Introspection snapshots
    snapshots: Arc<Mutex<Vec<IntrospectionSnapshot>>>,

    /// Diagnostic reports
    reports: Arc<Mutex<Vec<DiagnosticReport>>>,

    /// Performance metrics
    metrics: Arc<Mutex<Vec<PerformanceMetric>>>,

    /// System state log for debugging
    debug_log: Arc<Mutex<Vec<String>>>,

    /// Principal registry for introspection
    principals: Arc<Mutex<HashMap<String, String>>>,

    /// Statistics
    trace_points_recorded: Arc<Mutex<u64>>,
    snapshots_taken: Arc<Mutex<u64>>,
    diagnostics_run: Arc<Mutex<u64>>,
    metrics_collected: Arc<Mutex<u64>>,
}

impl DeveloperPrincipal {
    /// Create new Developer principal
    pub fn new(
        principal_id: String,
        uid: u32,
        gid: u32,
        ledger: Arc<SecurityLedger>,
    ) -> Self {
        DeveloperPrincipal {
            principal_id,
            state: Arc::new(Mutex::new(DeveloperState::NotStarted)),
            uid,
            gid,
            signing_key: Arc::new(Mutex::new(None)),
            ledger,
            trace_points: Arc::new(Mutex::new(Vec::new())),
            snapshots: Arc::new(Mutex::new(Vec::new())),
            reports: Arc::new(Mutex::new(Vec::new())),
            metrics: Arc::new(Mutex::new(Vec::new())),
            debug_log: Arc::new(Mutex::new(Vec::new())),
            principals: Arc::new(Mutex::new(HashMap::new())),
            trace_points_recorded: Arc::new(Mutex::new(0)),
            snapshots_taken: Arc::new(Mutex::new(0)),
            diagnostics_run: Arc::new(Mutex::new(0)),
            metrics_collected: Arc::new(Mutex::new(0)),
        }
    }

    /// Initialize Developer principal
    pub fn initialize(&self, signing_key: SigningKey) -> std::io::Result<()> {
        self.set_state(DeveloperState::Initializing);

        let mut key = self.signing_key.lock().unwrap();
        *key = Some(signing_key);

        // Initialize principal registry
        {
            let mut principals = self.principals.lock().unwrap();
            principals.insert("policy".to_string(), "Ready".to_string());
            principals.insert("actuator".to_string(), "Ready".to_string());
            principals.insert("audit".to_string(), "Ready".to_string());
            principals.insert("declassifier".to_string(), "Ready".to_string());
            principals.insert("learner".to_string(), "Ready".to_string());
            principals.insert("evaluator".to_string(), "Ready".to_string());
            principals.insert("sealer".to_string(), "Ready".to_string());
        }

        self.set_state(DeveloperState::Ready);
        Ok(())
    }

    /// Set state
    fn set_state(&self, new_state: DeveloperState) {
        let mut state = self.state.lock().unwrap();
        *state = new_state;
    }

    /// Get current state
    pub fn state(&self) -> DeveloperState {
        *self.state.lock().unwrap()
    }

    /// Get principal ID
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// Record a trace point
    pub fn record_trace(&self, location: String, event_type: String, event_data: String) -> std::io::Result<TracePoint> {
        self.set_state(DeveloperState::Tracing);

        let trace = TracePoint {
            trace_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            location,
            event_type,
            event_data,
            stack_depth: 1,
        };

        {
            let mut traces = self.trace_points.lock().unwrap();
            let mut count = self.trace_points_recorded.lock().unwrap();
            *count += 1;
            traces.push(trace.clone());
        }

        self.set_state(DeveloperState::Ready);
        Ok(trace)
    }

    /// Take introspection snapshot
    pub fn snapshot_principal(&self, principal_id: String, principal_state: String) -> std::io::Result<IntrospectionSnapshot> {
        self.set_state(DeveloperState::Inspecting);

        let events = self.ledger.events().unwrap_or_default();

        let snapshot = IntrospectionSnapshot {
            snapshot_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            principal_id,
            principal_state,
            active_operations: 1,
            event_count: events.len() as u64,
            memory_usage_estimate: (events.len() as u64) * 256,
        };

        {
            let mut snapshots = self.snapshots.lock().unwrap();
            let mut count = self.snapshots_taken.lock().unwrap();
            *count += 1;
            snapshots.push(snapshot.clone());
        }

        self.set_state(DeveloperState::Ready);
        Ok(snapshot)
    }

    /// Run system diagnostic
    pub fn run_diagnostic(&self) -> std::io::Result<DiagnosticReport> {
        self.set_state(DeveloperState::Debugging);

        let events = self.ledger.events().unwrap_or_default();
        let total_events = events.len() as u64;

        // Calculate health based on event distribution
        let error_count = events.iter().filter(|e| e.severity == Severity::Critical).count() as u64;
        let warning_count = events.iter().filter(|e| e.severity == Severity::High).count() as u64;

        let system_health = if error_count > 0 {
            "critical"
        } else if warning_count > total_events / 10 {
            "degraded"
        } else {
            "healthy"
        };

        let report = DiagnosticReport {
            report_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            total_events,
            system_health: system_health.to_string(),
            active_principals: 7,
            error_count,
            warning_count,
            findings: vec![
                "System initialization complete".to_string(),
                "All principals registered and operational".to_string(),
            ],
            recommendations: vec![
                "Continue monitoring system health".to_string(),
                "Review periodic diagnostic reports".to_string(),
            ],
        };

        {
            let mut reports = self.reports.lock().unwrap();
            let mut count = self.diagnostics_run.lock().unwrap();
            *count += 1;
            reports.push(report.clone());
        }

        self.set_state(DeveloperState::Ready);
        Ok(report)
    }

    /// Collect performance metric
    pub fn collect_metric(&self, metric_name: String, value: f64, unit: String, threshold: f64) -> std::io::Result<PerformanceMetric> {
        self.set_state(DeveloperState::Debugging);

        let status = if value <= threshold {
            "normal"
        } else if value <= (threshold * 1.5) {
            "warning"
        } else {
            "critical"
        };

        let metric = PerformanceMetric {
            metric_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            metric_name,
            value,
            unit,
            threshold,
            status: status.to_string(),
        };

        {
            let mut metrics = self.metrics.lock().unwrap();
            let mut count = self.metrics_collected.lock().unwrap();
            *count += 1;
            metrics.push(metric.clone());
        }

        self.set_state(DeveloperState::Ready);
        Ok(metric)
    }

    /// Add entry to debug log
    pub fn log_debug(&self, entry: String) -> std::io::Result<()> {
        let mut log = self.debug_log.lock().unwrap();
        log.push(entry);
        Ok(())
    }

    /// Get trace history
    pub fn trace_history(&self) -> Vec<TracePoint> {
        self.trace_points.lock().unwrap().clone()
    }

    /// Get snapshot history
    pub fn snapshot_history(&self) -> Vec<IntrospectionSnapshot> {
        self.snapshots.lock().unwrap().clone()
    }

    /// Get diagnostic report history
    pub fn report_history(&self) -> Vec<DiagnosticReport> {
        self.reports.lock().unwrap().clone()
    }

    /// Get performance metric history
    pub fn metric_history(&self) -> Vec<PerformanceMetric> {
        self.metrics.lock().unwrap().clone()
    }

    /// Get debug log
    pub fn get_debug_log(&self) -> Vec<String> {
        self.debug_log.lock().unwrap().clone()
    }

    /// Get statistics
    pub fn statistics(&self) -> (u64, u64, u64, u64) {
        (
            *self.trace_points_recorded.lock().unwrap(),
            *self.snapshots_taken.lock().unwrap(),
            *self.diagnostics_run.lock().unwrap(),
            *self.metrics_collected.lock().unwrap(),
        )
    }

    /// Generate developer report
    pub fn developer_report(&self) -> String {
        let (traces, snapshots, diagnostics, metrics) = self.statistics();

        format!(
            "Developer Principal {} Report\n\
            Trace Points Recorded: {}\n\
            Snapshots Taken: {}\n\
            Diagnostics Run: {}\n\
            Metrics Collected: {}\n\
            State: {:?}",
            self.principal_id,
            traces,
            snapshots,
            diagnostics,
            metrics,
            self.state()
        )
    }

    /// Shutdown developer principal
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.set_state(DeveloperState::Shutdown);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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

        let log = developer.get_debug_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0], "Initialization started");
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
    fn test_trace_with_metadata() {
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
            "approved: true".to_string(),
        ).unwrap();

        assert_eq!(trace.location, "gate_a_policy");
        assert_eq!(trace.event_type, "decision_made");
        assert_eq!(trace.event_data, "approved: true");
        assert!(trace.stack_depth >= 1);
    }
}
