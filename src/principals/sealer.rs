// Sealer Principal: State Consistency Verification (Week 2 Task 2.7)
// Responsible for verifying and enforcing state consistency across principals

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::types::Principal;
use crate::security_ledger::{SecurityLedger, EventType, Severity};
use crate::hsm::SigningKey;
use uuid::Uuid;

/// Sealer principal state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealerState {
    NotStarted,
    Initializing,
    Ready,
    Verifying,      // Verifying state consistency
    Sealing,        // Applying consistency locks
    Running,
    Shutdown,
    Failed,
}

/// State consistency check result
#[derive(Debug, Clone)]
pub struct ConsistencyCheck {
    pub check_id: String,
    pub timestamp_ns: u64,
    pub principal_id: String,
    pub expected_state: String,
    pub actual_state: String,
    pub is_consistent: bool,
    pub severity: String,
}

/// State consistency violation
#[derive(Debug, Clone)]
pub struct ConsistencyViolation {
    pub violation_id: String,
    pub timestamp_ns: u64,
    pub violation_type: String,  // "state_mismatch", "transition_invalid", "cascade_broken"
    pub affected_principals: Vec<String>,
    pub description: String,
    pub severity: String,  // "low", "medium", "high", "critical"
    pub recommended_action: String,
}

/// Consistency enforcement action
#[derive(Debug, Clone)]
pub struct ConsistencyAction {
    pub action_id: String,
    pub timestamp_ns: u64,
    pub principal_id: String,
    pub action_type: String,  // "force_state", "rollback", "resynchronize"
    pub target_state: String,
    pub success: bool,
    pub details: String,
}

/// State consistency report
#[derive(Debug, Clone)]
pub struct ConsistencyReport {
    pub report_id: String,
    pub timestamp_ns: u64,
    pub principals_checked: u64,
    pub principals_consistent: u64,
    pub principals_inconsistent: u64,
    pub total_violations: u64,
    pub overall_consistency: String,  // "fully_consistent", "partially_consistent", "inconsistent"
    pub recommendations: Vec<String>,
}

/// Sealer principal context
pub struct SealerPrincipal {
    /// Unique ID for this Sealer instance
    principal_id: String,

    /// Current state
    state: Arc<Mutex<SealerState>>,

    /// UID/GID for process isolation
    uid: u32,
    gid: u32,

    /// Signing key for message authentication
    signing_key: Arc<Mutex<Option<SigningKey>>>,

    /// Security ledger for event source
    ledger: Arc<SecurityLedger>,

    /// Consistency checks history
    checks: Arc<Mutex<Vec<ConsistencyCheck>>>,

    /// Consistency violations history
    violations: Arc<Mutex<Vec<ConsistencyViolation>>>,

    /// Consistency actions history
    actions: Arc<Mutex<Vec<ConsistencyAction>>>,

    /// Consistency reports
    reports: Arc<Mutex<Vec<ConsistencyReport>>>,

    /// Principal state registry for verification
    principal_states: Arc<Mutex<HashMap<String, String>>>,

    /// Statistics
    checks_performed: Arc<Mutex<u64>>,
    violations_found: Arc<Mutex<u64>>,
    actions_applied: Arc<Mutex<u64>>,
    reports_generated: Arc<Mutex<u64>>,
}

impl SealerPrincipal {
    /// Create new Sealer principal
    pub fn new(
        principal_id: String,
        uid: u32,
        gid: u32,
        ledger: Arc<SecurityLedger>,
    ) -> Self {
        SealerPrincipal {
            principal_id,
            state: Arc::new(Mutex::new(SealerState::NotStarted)),
            uid,
            gid,
            signing_key: Arc::new(Mutex::new(None)),
            ledger,
            checks: Arc::new(Mutex::new(Vec::new())),
            violations: Arc::new(Mutex::new(Vec::new())),
            actions: Arc::new(Mutex::new(Vec::new())),
            reports: Arc::new(Mutex::new(Vec::new())),
            principal_states: Arc::new(Mutex::new(HashMap::new())),
            checks_performed: Arc::new(Mutex::new(0)),
            violations_found: Arc::new(Mutex::new(0)),
            actions_applied: Arc::new(Mutex::new(0)),
            reports_generated: Arc::new(Mutex::new(0)),
        }
    }

    /// Initialize Sealer principal
    pub fn initialize(&self, signing_key: SigningKey) -> std::io::Result<()> {
        self.set_state(SealerState::Initializing);

        let mut key = self.signing_key.lock().unwrap();
        *key = Some(signing_key);

        // Initialize principal state registry
        {
            let mut states = self.principal_states.lock().unwrap();
            states.insert("policy".to_string(), "Ready".to_string());
            states.insert("actuator".to_string(), "Ready".to_string());
            states.insert("audit".to_string(), "Ready".to_string());
            states.insert("declassifier".to_string(), "Ready".to_string());
            states.insert("learner".to_string(), "Ready".to_string());
            states.insert("evaluator".to_string(), "Ready".to_string());
        }

        self.set_state(SealerState::Ready);
        Ok(())
    }

    /// Set state
    fn set_state(&self, new_state: SealerState) {
        let mut state = self.state.lock().unwrap();
        *state = new_state;
    }

    /// Get current state
    pub fn state(&self) -> SealerState {
        *self.state.lock().unwrap()
    }

    /// Get principal ID
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// Verify consistency of a principal
    pub fn verify_principal_consistency(&self, principal_id: String, expected_state: String) -> std::io::Result<ConsistencyCheck> {
        self.set_state(SealerState::Verifying);

        let mut states = self.principal_states.lock().unwrap();
        let actual_state = states.get(&principal_id).cloned().unwrap_or_else(|| "Unknown".to_string());

        let is_consistent = actual_state == expected_state;

        let check = ConsistencyCheck {
            check_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            principal_id: principal_id.clone(),
            expected_state,
            actual_state,
            is_consistent,
            severity: if is_consistent { "none".to_string() } else { "high".to_string() },
        };

        drop(states); // Release lock before acquiring another

        {
            let mut checks = self.checks.lock().unwrap();
            let mut count = self.checks_performed.lock().unwrap();
            *count += 1;
            checks.push(check.clone());
        }

        self.set_state(SealerState::Ready);
        Ok(check)
    }

    /// Detect consistency violation
    pub fn detect_violation(&self, violation_type: String, affected_principals: Vec<String>, severity: String) -> std::io::Result<ConsistencyViolation> {
        self.set_state(SealerState::Verifying);

        let violation = ConsistencyViolation {
            violation_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            violation_type,
            affected_principals,
            description: "State consistency violation detected".to_string(),
            severity,
            recommended_action: "Review principal states and resynchronize if necessary".to_string(),
        };

        {
            let mut violations = self.violations.lock().unwrap();
            let mut count = self.violations_found.lock().unwrap();
            *count += 1;
            violations.push(violation.clone());
        }

        self.set_state(SealerState::Ready);
        Ok(violation)
    }

    /// Apply consistency enforcement action
    pub fn apply_consistency_action(&self, principal_id: String, action_type: String, target_state: String) -> std::io::Result<ConsistencyAction> {
        self.set_state(SealerState::Sealing);

        let action = ConsistencyAction {
            action_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            principal_id: principal_id.clone(),
            action_type,
            target_state: target_state.clone(),
            success: true,
            details: format!("Successfully applied consistency action to {}. Target state: {}", principal_id, target_state),
        };

        // Update principal state
        {
            let mut states = self.principal_states.lock().unwrap();
            states.insert(principal_id, target_state);
        }

        {
            let mut actions = self.actions.lock().unwrap();
            let mut count = self.actions_applied.lock().unwrap();
            *count += 1;
            actions.push(action.clone());
        }

        self.set_state(SealerState::Ready);
        Ok(action)
    }

    /// Generate consistency report
    pub fn generate_consistency_report(&self) -> std::io::Result<ConsistencyReport> {
        self.set_state(SealerState::Verifying);

        let states = self.principal_states.lock().unwrap();
        let total = states.len() as u64;
        let checks = self.checks.lock().unwrap();
        let consistent_count = checks.iter().filter(|c| c.is_consistent).count() as u64;
        let inconsistent_count = total.saturating_sub(consistent_count);

        let violations = self.violations.lock().unwrap();
        let violation_count = violations.len() as u64;

        let overall_consistency = match inconsistent_count {
            0 => "fully_consistent",
            c if c <= (total / 4) => "partially_consistent",
            _ => "inconsistent",
        };

        let report = ConsistencyReport {
            report_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            principals_checked: total,
            principals_consistent: consistent_count,
            principals_inconsistent: inconsistent_count,
            total_violations: violation_count,
            overall_consistency: overall_consistency.to_string(),
            recommendations: vec![
                "Continue monitoring state consistency".to_string(),
                "Maintain regular consistency verification schedules".to_string(),
            ],
        };

        drop(states);
        drop(checks);
        drop(violations);

        {
            let mut reports = self.reports.lock().unwrap();
            let mut count = self.reports_generated.lock().unwrap();
            *count += 1;
            reports.push(report.clone());
        }

        self.set_state(SealerState::Ready);
        Ok(report)
    }

    /// Get consistency check history
    pub fn check_history(&self) -> Vec<ConsistencyCheck> {
        self.checks.lock().unwrap().clone()
    }

    /// Get consistency violation history
    pub fn violation_history(&self) -> Vec<ConsistencyViolation> {
        self.violations.lock().unwrap().clone()
    }

    /// Get consistency action history
    pub fn action_history(&self) -> Vec<ConsistencyAction> {
        self.actions.lock().unwrap().clone()
    }

    /// Get consistency report history
    pub fn report_history(&self) -> Vec<ConsistencyReport> {
        self.reports.lock().unwrap().clone()
    }

    /// Get statistics
    pub fn statistics(&self) -> (u64, u64, u64, u64) {
        (
            *self.checks_performed.lock().unwrap(),
            *self.violations_found.lock().unwrap(),
            *self.actions_applied.lock().unwrap(),
            *self.reports_generated.lock().unwrap(),
        )
    }

    /// Generate sealer report
    pub fn sealer_report(&self) -> String {
        let (checks, violations, actions, reports) = self.statistics();

        format!(
            "Sealer Principal {} Report\n\
            Consistency Checks Performed: {}\n\
            Violations Found: {}\n\
            Actions Applied: {}\n\
            Reports Generated: {}\n\
            State: {:?}",
            self.principal_id,
            checks,
            violations,
            actions,
            reports,
            self.state()
        )
    }

    /// Shutdown sealer principal
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.set_state(SealerState::Shutdown);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
    }

    #[test]
    fn test_detect_violation() {
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
    }

    #[test]
    fn test_apply_consistency_action() {
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

        let action = sealer.apply_consistency_action(
            "audit".to_string(),
            "force_state".to_string(),
            "Ready".to_string(),
        ).unwrap();

        assert!(action.success);
        assert_eq!(action.target_state, "Ready");
    }

    #[test]
    fn test_generate_consistency_report() {
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

        let report = sealer.generate_consistency_report().unwrap();

        assert!(!report.report_id.is_empty());
        assert!(report.principals_checked > 0);
        assert!(["fully_consistent", "partially_consistent", "inconsistent"].contains(&report.overall_consistency.as_str()));
    }

    #[test]
    fn test_check_history() {
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
            "sealer-008".to_string(),
            1007,
            1007,
            ledger,
        );

        let violation = sealer.detect_violation(
            "state_mismatch".to_string(),
            vec!["policy".to_string()],
            "high".to_string(),
        ).unwrap();

        let history = sealer.violation_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].violation_id, violation.violation_id);
    }

    #[test]
    fn test_action_history() {
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

        let action1 = sealer.apply_consistency_action("audit".to_string(), "force_state".to_string(), "Ready".to_string()).unwrap();
        let action2 = sealer.apply_consistency_action("audit".to_string(), "resynchronize".to_string(), "Ready".to_string()).unwrap();

        let history = sealer.action_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].action_id, action1.action_id);
        assert_eq!(history[1].action_id, action2.action_id);
    }

    #[test]
    fn test_report_history() {
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

        let report1 = sealer.generate_consistency_report().unwrap();
        let report2 = sealer.generate_consistency_report().unwrap();

        let history = sealer.report_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].report_id, report1.report_id);
        assert_eq!(history[1].report_id, report2.report_id);
    }

    #[test]
    fn test_statistics() {
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
            "sealer-012".to_string(),
            1007,
            1007,
            ledger,
        );

        let report = sealer.sealer_report();

        assert!(report.contains("Sealer Principal"));
        assert!(report.contains("sealer-012"));
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
            "sealer-013".to_string(),
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

        let _ = sealer.shutdown();
        assert_eq!(sealer.state(), SealerState::Shutdown);
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
            "sealer-014".to_string(),
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
            "sealer-015".to_string(),
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
}
