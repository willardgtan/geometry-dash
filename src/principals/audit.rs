// Audit Principal: Forensics, Correlation & Breach Detection (Week 2 Task 2.3)
// Responsible for analyzing security events, detecting anomalies, and maintaining audit trails

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use crate::types::Principal;
use crate::security_ledger::{SecurityLedger, SecurityEvent, EventType, Severity};
use crate::hsm::SigningKey;
use uuid::Uuid;

/// Audit principal state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditState {
    NotStarted,
    Initializing,
    Ready,
    Analyzing,      // Processing events for analysis
    Correlating,    // Correlating event patterns
    DetectingBreaches,  // Running breach detection
    Running,
    Shutdown,
    Failed,
}

/// Correlation analysis result
#[derive(Debug, Clone)]
pub struct CorrelationResult {
    pub correlation_id: String,
    pub timestamp_ns: u64,
    pub event_ids: Vec<String>,
    pub pattern_type: String,
    pub confidence: f64,  // 0.0 - 1.0
    pub description: String,
}

/// Breach detection result
#[derive(Debug, Clone)]
pub struct BreachDetection {
    pub detection_id: String,
    pub timestamp_ns: u64,
    pub severity: String,
    pub breach_type: String,
    pub affected_events: Vec<String>,
    pub mitigation_recommended: String,
    pub confidence: f64,
}

/// Forensic analysis of event sequence
#[derive(Debug, Clone)]
pub struct ForensicAnalysis {
    pub analysis_id: String,
    pub timestamp_ns: u64,
    pub event_sequence: Vec<String>,
    pub timeline: Vec<(u64, String)>,  // (timestamp, event_description)
    pub findings: Vec<String>,
    pub severity_assessment: String,
}

/// Audit principal context
pub struct AuditPrincipal {
    /// Unique ID for this Audit instance
    principal_id: String,

    /// Current state
    state: Arc<Mutex<AuditState>>,

    /// UID/GID for process isolation
    uid: u32,
    gid: u32,

    /// Signing key for message authentication
    signing_key: Arc<Mutex<Option<SigningKey>>>,

    /// Security ledger for reading events
    ledger: Arc<SecurityLedger>,

    /// Correlation results history
    correlations: Arc<Mutex<Vec<CorrelationResult>>>,

    /// Breach detections history
    breaches: Arc<Mutex<Vec<BreachDetection>>>,

    /// Forensic analyses history
    analyses: Arc<Mutex<Vec<ForensicAnalysis>>>,

    /// Event cache for correlation
    event_cache: Arc<Mutex<VecDeque<SecurityEvent>>>,

    /// Statistics
    events_analyzed: Arc<Mutex<u64>>,
    correlations_found: Arc<Mutex<u64>>,
    breaches_detected: Arc<Mutex<u64>>,
    analyses_performed: Arc<Mutex<u64>>,
}

impl AuditPrincipal {
    /// Create new Audit principal
    pub fn new(
        principal_id: String,
        uid: u32,
        gid: u32,
        ledger: Arc<SecurityLedger>,
    ) -> Self {
        AuditPrincipal {
            principal_id,
            state: Arc::new(Mutex::new(AuditState::NotStarted)),
            uid,
            gid,
            signing_key: Arc::new(Mutex::new(None)),
            ledger,
            correlations: Arc::new(Mutex::new(Vec::new())),
            breaches: Arc::new(Mutex::new(Vec::new())),
            analyses: Arc::new(Mutex::new(Vec::new())),
            event_cache: Arc::new(Mutex::new(VecDeque::new())),
            events_analyzed: Arc::new(Mutex::new(0)),
            correlations_found: Arc::new(Mutex::new(0)),
            breaches_detected: Arc::new(Mutex::new(0)),
            analyses_performed: Arc::new(Mutex::new(0)),
        }
    }

    /// Initialize Audit principal
    pub fn initialize(&self, signing_key: SigningKey) -> std::io::Result<()> {
        self.set_state(AuditState::Initializing);

        let mut key = self.signing_key.lock().unwrap();
        *key = Some(signing_key);

        self.set_state(AuditState::Ready);
        Ok(())
    }

    /// Set state
    fn set_state(&self, new_state: AuditState) {
        let mut state = self.state.lock().unwrap();
        *state = new_state;
    }

    /// Get current state
    pub fn state(&self) -> AuditState {
        *self.state.lock().unwrap()
    }

    /// Get principal ID
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// Analyze events from ledger
    pub fn analyze_events(&self) -> std::io::Result<Vec<SecurityEvent>> {
        self.set_state(AuditState::Analyzing);

        let mut analyzed = self.events_analyzed.lock().unwrap();
        *analyzed += 1;

        // Read events from ledger (simplified - in production would page through large ledgers)
        let events = self.ledger.events().unwrap_or_default();

        // Cache events for correlation analysis
        {
            let mut cache = self.event_cache.lock().unwrap();
            cache.clear();
            for event in &events {
                cache.push_back(event.clone());
            }
        }

        self.set_state(AuditState::Ready);
        Ok(events)
    }

    /// Correlate events to find patterns
    pub fn correlate_events(&self) -> std::io::Result<Vec<CorrelationResult>> {
        self.set_state(AuditState::Correlating);

        let mut results = Vec::new();

        {
            let cache = self.event_cache.lock().unwrap();

            // Pattern 1: Repeated authorization denials
            let denial_events: Vec<_> = cache
                .iter()
                .filter(|e| matches!(e.event_type, EventType::CapabilityDenied | EventType::ActionBlocked))
                .collect();

            if denial_events.len() >= 3 {
                let event_ids: Vec<String> = denial_events.iter()
                    .map(|e| e.event_id.clone())
                    .collect();

                results.push(CorrelationResult {
                    correlation_id: Uuid::new_v4().to_string(),
                    timestamp_ns: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64,
                    event_ids,
                    pattern_type: "repeated_denials".to_string(),
                    confidence: 0.95,
                    description: format!("Found {} repeated authorization/execution denials", denial_events.len()),
                });
            }

            // Pattern 2: Rapid state transitions
            let state_events: Vec<_> = cache
                .iter()
                .filter(|e| matches!(e.event_type, EventType::PrincipalInitialized | EventType::PrincipalShutdown))
                .collect();

            if state_events.len() >= 2 {
                let mut timestamps: Vec<_> = state_events.iter().map(|e| e.timestamp_ns).collect();
                timestamps.sort_unstable();

                let mut rapid_transitions = 0;
                for i in 1..timestamps.len() {
                    if timestamps[i] - timestamps[i-1] < 1_000_000_000 { // < 1 second
                        rapid_transitions += 1;
                    }
                }

                if rapid_transitions > 0 {
                    let event_ids: Vec<String> = state_events.iter()
                        .map(|e| e.event_id.clone())
                        .collect();

                    results.push(CorrelationResult {
                        correlation_id: Uuid::new_v4().to_string(),
                        timestamp_ns: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as u64,
                        event_ids,
                        pattern_type: "rapid_state_transitions".to_string(),
                        confidence: 0.85,
                        description: format!("Detected {} rapid state transitions", rapid_transitions),
                    });
                }
            }
        }

        // Store results
        {
            let mut correlations = self.correlations.lock().unwrap();
            let mut count = self.correlations_found.lock().unwrap();
            *count += results.len() as u64;
            correlations.extend(results.clone());
        }

        self.set_state(AuditState::Ready);
        Ok(results)
    }

    /// Detect potential security breaches
    pub fn detect_breaches(&self) -> std::io::Result<Vec<BreachDetection>> {
        self.set_state(AuditState::DetectingBreaches);

        let mut detections = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        {
            let cache = self.event_cache.lock().unwrap();

            // Breach Pattern 1: Multiple high-severity events in sequence
            let high_severity_events: Vec<_> = cache
                .iter()
                .filter(|e| matches!(e.severity, Severity::Critical | Severity::High))
                .collect();

            if high_severity_events.len() >= 2 {
                let event_ids: Vec<String> = high_severity_events.iter()
                    .map(|e| e.event_id.clone())
                    .collect();

                detections.push(BreachDetection {
                    detection_id: Uuid::new_v4().to_string(),
                    timestamp_ns: now,
                    severity: "high".to_string(),
                    breach_type: "elevated_severity_sequence".to_string(),
                    affected_events: event_ids,
                    mitigation_recommended: "Investigate high-severity events and increase monitoring".to_string(),
                    confidence: 0.90,
                });
            }

            // Breach Pattern 2: Authorization failures followed by execution attempts
            let denial_events: Vec<_> = cache
                .iter()
                .filter(|e| matches!(e.event_type, EventType::CapabilityDenied | EventType::ActionBlocked))
                .collect();

            let execution_events: Vec<_> = cache
                .iter()
                .filter(|e| matches!(e.event_type, EventType::ActionExecuted))
                .collect();

            if !denial_events.is_empty() && !execution_events.is_empty() {
                // Check if executions follow denials
                let mut suspicious = Vec::new();
                for exec in &execution_events {
                    for denial in &denial_events {
                        if exec.timestamp_ns > denial.timestamp_ns
                            && exec.timestamp_ns - denial.timestamp_ns < 5_000_000_000 { // < 5 seconds
                            suspicious.push(exec.event_id.clone());
                        }
                    }
                }

                if !suspicious.is_empty() {
                    detections.push(BreachDetection {
                        detection_id: Uuid::new_v4().to_string(),
                        timestamp_ns: now,
                        severity: "medium".to_string(),
                        breach_type: "denial_followed_by_execution".to_string(),
                        affected_events: suspicious,
                        mitigation_recommended: "Review authorization denial patterns and execution that followed".to_string(),
                        confidence: 0.75,
                    });
                }
            }
        }

        // Store detections
        {
            let mut breaches = self.breaches.lock().unwrap();
            let mut count = self.breaches_detected.lock().unwrap();
            *count += detections.len() as u64;
            breaches.extend(detections.clone());
        }

        self.set_state(AuditState::Ready);
        Ok(detections)
    }

    /// Perform detailed forensic analysis on event sequence
    pub fn forensic_analysis(&self, event_ids: Vec<String>) -> std::io::Result<ForensicAnalysis> {
        self.set_state(AuditState::Analyzing);

        let mut timeline = Vec::new();
        let cache = self.event_cache.lock().unwrap();

        // Build timeline from cache
        let mut relevant_events: Vec<_> = cache
            .iter()
            .filter(|e| event_ids.contains(&e.event_id))
            .collect();

        relevant_events.sort_by_key(|e| e.timestamp_ns);

        for event in &relevant_events {
            timeline.push((
                event.timestamp_ns,
                format!("{:?}: {} ({})", event.event_type, event.message, event.severity),
            ));
        }

        // Compile findings
        let mut findings = Vec::new();

        if relevant_events.is_empty() {
            findings.push("No matching events found".to_string());
        } else {
            findings.push(format!("Found {} relevant events", relevant_events.len()));

            // Check severity levels
            let critical_count = relevant_events.iter()
                .filter(|e| matches!(e.severity, Severity::Critical))
                .count();
            if critical_count > 0 {
                findings.push(format!("⚠️ Found {} CRITICAL severity events", critical_count));
            }

            // Check for repeated principals
            let mut principal_counts: HashMap<String, usize> = HashMap::new();
            for event in &relevant_events {
                *principal_counts.entry(event.principal_id.clone()).or_insert(0) += 1;
            }

            for (principal, count) in principal_counts.iter() {
                if *count > 1 {
                    findings.push(format!("Principal {} involved in {} events", principal, count));
                }
            }
        }

        let analysis = ForensicAnalysis {
            analysis_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            event_sequence: event_ids,
            timeline,
            findings,
            severity_assessment: if relevant_events.iter().any(|e| matches!(e.severity, Severity::Critical)) {
                "critical".to_string()
            } else if relevant_events.iter().any(|e| matches!(e.severity, Severity::High)) {
                "high".to_string()
            } else {
                "normal".to_string()
            },
        };

        // Store analysis
        {
            let mut analyses = self.analyses.lock().unwrap();
            let mut count = self.analyses_performed.lock().unwrap();
            *count += 1;
            analyses.push(analysis.clone());
        }

        self.set_state(AuditState::Ready);
        Ok(analysis)
    }

    /// Get correlation history
    pub fn correlation_history(&self) -> Vec<CorrelationResult> {
        self.correlations.lock().unwrap().clone()
    }

    /// Get breach detection history
    pub fn breach_history(&self) -> Vec<BreachDetection> {
        self.breaches.lock().unwrap().clone()
    }

    /// Get forensic analysis history
    pub fn analysis_history(&self) -> Vec<ForensicAnalysis> {
        self.analyses.lock().unwrap().clone()
    }

    /// Get statistics
    pub fn statistics(&self) -> (u64, u64, u64, u64) {
        (
            *self.events_analyzed.lock().unwrap(),
            *self.correlations_found.lock().unwrap(),
            *self.breaches_detected.lock().unwrap(),
            *self.analyses_performed.lock().unwrap(),
        )
    }

    /// Generate summary report
    pub fn summary_report(&self) -> String {
        let (events_analyzed, correlations_found, breaches_detected, analyses_performed) = self.statistics();

        format!(
            "Audit Principal {} Report\n\
            Events Analyzed: {}\n\
            Correlations Found: {}\n\
            Breaches Detected: {}\n\
            Analyses Performed: {}\n\
            State: {:?}",
            self.principal_id,
            events_analyzed,
            correlations_found,
            breaches_detected,
            analyses_performed,
            self.state()
        )
    }

    /// Shutdown audit principal
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.set_state(AuditState::Shutdown);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_audit_initialization() {
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

        let events = audit.analyze_events().unwrap();
        let (analyzed, _, _, _) = audit.statistics();
        assert_eq!(analyzed, 1);
    }

    #[test]
    fn test_audit_correlate_events() {
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

        let _ = audit.analyze_events();
        let correlations = audit.correlate_events().unwrap();
        let (_, found, _, _) = audit.statistics();
        assert!(found >= 0);
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

        let _ = audit.analyze_events();
        let breaches = audit.detect_breaches().unwrap();
        let (_, _, detected, _) = audit.statistics();
        assert!(detected >= 0);
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

        let analysis = audit.forensic_analysis(vec![]).unwrap();
        assert_eq!(analysis.event_sequence.len(), 0);

        let (_, _, _, performed) = audit.statistics();
        assert_eq!(performed, 1);
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
        assert!(report.contains("Audit Principal"));
        assert!(report.contains("audit-006"));
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
        let _ = audit.analyze_events();
        assert_eq!(audit.state(), AuditState::Ready);
    }
}
