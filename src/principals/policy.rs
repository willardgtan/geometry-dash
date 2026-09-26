// Policy Principal: Gate A Decision Logic (Week 2 Task 2.1)
// Responsible for initial capability authorization and delegation

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use crate::types::Principal;
use crate::security_ledger::{SecurityLedger, EventType, Severity};
use crate::ipc::{UniversalMessage, CapabilityMatrix};
use crate::hsm::SigningKey;
use uuid::Uuid;

/// Policy principal state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    NotStarted,
    Initializing,
    Ready,
    Evaluating,     // Processing Gate A decision
    Delegating,     // Delegating capabilities
    Running,
    Shutdown,
    Failed,
}

/// Gate A Decision: capability authorization result
#[derive(Debug, Clone)]
pub struct GateADecision {
    pub decision_id: String,
    pub timestamp_ns: u64,
    pub authorized: bool,
    pub reason: String,
    pub delegated_interfaces: Vec<u32>,
}

/// Policy principal context
pub struct PolicyPrincipal {
    /// Unique ID for this Policy instance
    principal_id: String,

    /// Current state
    state: Arc<Mutex<PolicyState>>,

    /// UID/GID for process isolation
    uid: u32,
    gid: u32,

    /// Signing key for message authentication
    signing_key: Arc<Mutex<Option<SigningKey>>>,

    /// Capability matrix (what this principal can delegate)
    capabilities: Arc<Mutex<CapabilityMatrix>>,

    /// Security ledger for audit logging
    ledger: Arc<SecurityLedger>,

    /// Message queue for IPC
    message_queue: Arc<Mutex<VecDeque<UniversalMessage>>>,

    /// Pending Gate A decisions awaiting processing
    pending_decisions: Arc<Mutex<VecDeque<GateADecision>>>,

    /// Decision history for recovery and audit
    decision_history: Arc<Mutex<Vec<GateADecision>>>,

    /// Statistics
    decisions_made: Arc<Mutex<u64>>,
    delegations_granted: Arc<Mutex<u64>>,
    delegations_denied: Arc<Mutex<u64>>,
}

impl PolicyPrincipal {
    /// Create new Policy principal
    pub fn new(
        principal_id: String,
        uid: u32,
        gid: u32,
        ledger: Arc<SecurityLedger>,
    ) -> Self {
        PolicyPrincipal {
            principal_id,
            state: Arc::new(Mutex::new(PolicyState::NotStarted)),
            uid,
            gid,
            signing_key: Arc::new(Mutex::new(None)),
            capabilities: Arc::new(Mutex::new(CapabilityMatrix::new())),
            ledger,
            message_queue: Arc::new(Mutex::new(VecDeque::new())),
            pending_decisions: Arc::new(Mutex::new(VecDeque::new())),
            decision_history: Arc::new(Mutex::new(Vec::new())),
            decisions_made: Arc::new(Mutex::new(0)),
            delegations_granted: Arc::new(Mutex::new(0)),
            delegations_denied: Arc::new(Mutex::new(0)),
        }
    }

    /// Initialize Policy principal
    pub fn initialize(&self, signing_key: SigningKey) -> std::io::Result<()> {
        self.set_state(PolicyState::Initializing);

        // Store signing key
        {
            let mut sk = self.signing_key.lock().unwrap();
            *sk = Some(signing_key);
        }

        // Initialize default capabilities (can delegate to all principals)
        {
            let mut caps = self.capabilities.lock().unwrap();
            for if_id in 1..=22 {
                caps.allow(Principal::Policy.as_u8(), if_id);
            }
        }

        // Log initialization
        let mut details = HashMap::new();
        details.insert("principal".to_string(), "policy".to_string());
        details.insert("uid".to_string(), format!("{}", self.uid));
        details.insert("gid".to_string(), format!("{}", self.gid));

        let _ = self.ledger.append_event(
            EventType::PrincipalInitialized,
            Principal::Policy,
            Severity::Info,
            &self.principal_id,
            "boot-policy",
            "epoch-policy",
            details,
        );

        self.set_state(PolicyState::Ready);
        Ok(())
    }

    /// Process incoming message (from Supervisor or other principals)
    pub fn process_message(&self, msg: UniversalMessage) -> std::io::Result<()> {
        // Queue the message
        {
            let mut queue = self.message_queue.lock().unwrap();
            queue.push_back(msg);
        }

        // Process Gate A decisions from queue
        self.process_pending_decisions()?;

        Ok(())
    }

    /// Gate A Decision Logic: evaluate capability request
    /// Returns true if authorization is granted
    pub fn gate_a_decision(&self,
        requesting_principal: Principal,
        requested_interface: u32,
        context: &HashMap<String, String>,
    ) -> GateADecision {
        let decision_id = Uuid::new_v4().to_string();
        let timestamp_ns = Self::current_timestamp_ns();

        let (authorized, reason) = self.evaluate_authorization(
            requesting_principal,
            requested_interface,
            context,
        );

        let mut delegated = Vec::new();
        if authorized {
            delegated.push(requested_interface);
        }

        GateADecision {
            decision_id,
            timestamp_ns,
            authorized,
            reason,
            delegated_interfaces: delegated,
        }
    }

    /// Evaluate authorization based on policy rules
    fn evaluate_authorization(
        &self,
        principal: Principal,
        interface: u32,
        _context: &HashMap<String, String>,
    ) -> (bool, String) {
        // Policy rules: simple default-allow for testing
        // In production, would check:
        // - Principal's current state
        // - Interface's data classification
        // - Time-based restrictions
        // - Historical violation records
        // - Audit trail

        match principal {
            Principal::Supervisor => {
                // Supervisor has all access
                (true, "supervisor_always_authorized".to_string())
            }
            Principal::Actuator => {
                // Actuator can access control interfaces (IF-003, IF-005)
                let authorized = interface == 3 || interface == 5;
                (
                    authorized,
                    if authorized {
                        "actuator_control_interface".to_string()
                    } else {
                        "actuator_unauthorized_interface".to_string()
                    }
                )
            }
            Principal::Audit => {
                // Audit can access all audit interfaces (IF-011, IF-016, IF-017)
                let authorized = interface == 11 || interface == 16 || interface == 17;
                (
                    authorized,
                    if authorized {
                        "audit_authorized".to_string()
                    } else {
                        "audit_unauthorized".to_string()
                    }
                )
            }
            Principal::Declassifier => {
                // Declassifier can use policy interface (IF-004)
                let authorized = interface == 4;
                (
                    authorized,
                    if authorized {
                        "declassifier_policy_interface".to_string()
                    } else {
                        "declassifier_unauthorized".to_string()
                    }
                )
            }
            _ => {
                // Default: deny unless explicitly authorized
                (false, "default_deny_policy".to_string())
            }
        }
    }

    /// Delegate capability to a principal
    pub fn delegate_capability(&self,
        target_principal: Principal,
        interface_id: u32,
    ) -> std::io::Result<()> {
        {
            let mut caps = self.capabilities.lock().unwrap();
            caps.allow(target_principal.as_u8(), interface_id);
        }

        {
            let mut count = self.delegations_granted.lock().unwrap();
            *count += 1;
        }

        // Log delegation
        let mut details = HashMap::new();
        details.insert("target_principal".to_string(), target_principal.to_string());
        details.insert("interface_id".to_string(), format!("{}", interface_id));

        let _ = self.ledger.append_event(
            EventType::CapabilityDelegated,
            Principal::Policy,
            Severity::Info,
            &self.principal_id,
            "boot-policy",
            "epoch-policy",
            details,
        );

        Ok(())
    }

    /// Deny capability request
    pub fn deny_capability(&self,
        target_principal: Principal,
        interface_id: u32,
        reason: &str,
    ) -> std::io::Result<()> {
        {
            let mut count = self.delegations_denied.lock().unwrap();
            *count += 1;
        }

        // Log denial
        let mut details = HashMap::new();
        details.insert("target_principal".to_string(), target_principal.to_string());
        details.insert("interface_id".to_string(), format!("{}", interface_id));
        details.insert("reason".to_string(), reason.to_string());

        let _ = self.ledger.append_event(
            EventType::CapabilityDenied,
            Principal::Policy,
            Severity::Warning,
            &self.principal_id,
            "boot-policy",
            "epoch-policy",
            details,
        );

        Ok(())
    }

    /// Process all pending Gate A decisions
    fn process_pending_decisions(&self) -> std::io::Result<()> {
        self.set_state(PolicyState::Evaluating);

        loop {
            let decision = {
                let mut decisions = self.pending_decisions.lock().unwrap();
                decisions.pop_front()
            };

            if let Some(decision) = decision {
                // Log decision
                let mut details = HashMap::new();
                details.insert("decision_id".to_string(), decision.decision_id.clone());
                details.insert("authorized".to_string(), format!("{}", decision.authorized));
                details.insert("reason".to_string(), decision.reason.clone());

                let _ = self.ledger.append_event(
                    EventType::GateADecision,
                    Principal::Policy,
                    if decision.authorized { Severity::Info } else { Severity::Warning },
                    &self.principal_id,
                    "boot-policy",
                    "epoch-policy",
                    details,
                );

                {
                    let mut history = self.decision_history.lock().unwrap();
                    history.push(decision);
                }

                {
                    let mut count = self.decisions_made.lock().unwrap();
                    *count += 1;
                }
            } else {
                break;
            }
        }

        self.set_state(PolicyState::Running);
        Ok(())
    }

    /// Get current state
    pub fn state(&self) -> PolicyState {
        *self.state.lock().unwrap()
    }

    /// Set state
    fn set_state(&self, state: PolicyState) {
        if let Ok(mut s) = self.state.lock().unwrap_or_else(|e| e.into_inner()) {
            *s = state;
        }
    }

    /// Get statistics
    pub fn statistics(&self) -> (u64, u64, u64) {
        let decisions = *self.decisions_made.lock().unwrap();
        let granted = *self.delegations_granted.lock().unwrap();
        let denied = *self.delegations_denied.lock().unwrap();
        (decisions, granted, denied)
    }

    /// Get decision history (for audit)
    pub fn decision_history(&self) -> Vec<GateADecision> {
        self.decision_history.lock().unwrap().clone()
    }

    /// Cleanup on shutdown
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.set_state(PolicyState::Shutdown);

        // Log shutdown
        let mut details = HashMap::new();
        let (decisions, granted, denied) = self.statistics();
        details.insert("decisions_made".to_string(), format!("{}", decisions));
        details.insert("delegations_granted".to_string(), format!("{}", granted));
        details.insert("delegations_denied".to_string(), format!("{}", denied));

        let _ = self.ledger.append_event(
            EventType::PrincipalShutdown,
            Principal::Policy,
            Severity::Info,
            &self.principal_id,
            "boot-policy",
            "epoch-policy",
            details,
        );

        Ok(())
    }

    /// Get current nanosecond timestamp
    fn current_timestamp_ns() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Public access to principal_id
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_policy_initialization() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(SecurityLedger::open(temp.path().to_str().unwrap()).unwrap());

        let policy = PolicyPrincipal::new(
            "policy-001".to_string(),
            1001,
            1001,
            ledger,
        );

        assert_eq!(policy.state(), PolicyState::NotStarted);
        assert_eq!(policy.principal_id(), "policy-001");
    }

    #[test]
    fn test_gate_a_decision_logic() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(SecurityLedger::open(temp.path().to_str().unwrap()).unwrap());

        let policy = PolicyPrincipal::new(
            "policy-002".to_string(),
            1001,
            1001,
            ledger,
        );

        // Supervisor should be authorized
        let decision = policy.gate_a_decision(
            Principal::Supervisor,
            1,
            &HashMap::new(),
        );
        assert!(decision.authorized);

        // Actuator should be authorized for control interface
        let decision = policy.gate_a_decision(
            Principal::Actuator,
            3,
            &HashMap::new(),
        );
        assert!(decision.authorized);

        // Actuator should NOT be authorized for audit interface
        let decision = policy.gate_a_decision(
            Principal::Actuator,
            11,
            &HashMap::new(),
        );
        assert!(!decision.authorized);
    }

    #[test]
    fn test_capability_delegation() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(SecurityLedger::open(temp.path().to_str().unwrap()).unwrap());

        let policy = PolicyPrincipal::new(
            "policy-003".to_string(),
            1001,
            1001,
            ledger,
        );

        // Delegate capability
        assert!(policy.delegate_capability(Principal::Actuator, 3).is_ok());

        let (_, granted, _) = policy.statistics();
        assert_eq!(granted, 1);
    }

    #[test]
    fn test_capability_denial() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(SecurityLedger::open(temp.path().to_str().unwrap()).unwrap());

        let policy = PolicyPrincipal::new(
            "policy-004".to_string(),
            1001,
            1001,
            ledger,
        );

        // Deny capability
        assert!(policy.deny_capability(
            Principal::Actuator,
            11,
            "actuator_not_authorized_for_audit"
        ).is_ok());

        let (_, _, denied) = policy.statistics();
        assert_eq!(denied, 1);
    }

    #[test]
    fn test_decision_history() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(SecurityLedger::open(temp.path().to_str().unwrap()).unwrap());

        let policy = PolicyPrincipal::new(
            "policy-005".to_string(),
            1001,
            1001,
            ledger,
        );

        // Make several decisions
        let d1 = policy.gate_a_decision(Principal::Supervisor, 1, &HashMap::new());
        let d2 = policy.gate_a_decision(Principal::Actuator, 3, &HashMap::new());

        {
            let mut decisions = policy.pending_decisions.lock().unwrap();
            decisions.push_back(d1);
            decisions.push_back(d2);
        }

        // Process decisions
        assert!(policy.process_pending_decisions().is_ok());

        let history = policy.decision_history();
        assert_eq!(history.len(), 2);
    }
}
