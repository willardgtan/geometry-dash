// Actuator Principal: Command Execution and Gate C/I Enforcement (Week 2 Task 2.2)
// Responsible for controlled action execution with multi-gate validation

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use crate::types::Principal;
use crate::security_ledger::{SecurityLedger, EventType, Severity};
use crate::ipc::CapabilityMatrix;
use crate::hsm::SigningKey;
use uuid::Uuid;

/// Actuator principal state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActuatorState {
    NotStarted,
    Initializing,
    Ready,
    Executing,          // Currently executing a command
    GateValidation,     // Validating through gates C and I
    Waiting,            // Waiting for policy decision
    Running,
    Failed,
    Shutdown,
}

/// Command execution request
#[derive(Debug, Clone)]
pub struct CommandRequest {
    pub request_id: String,
    pub timestamp_ns: u64,
    pub command: String,
    pub requester: Principal,
    pub target_interface: u32,
    pub context: HashMap<String, String>,
}

/// Gate C Decision: command validation
#[derive(Debug, Clone)]
pub struct GateCDecision {
    pub request_id: String,
    pub timestamp_ns: u64,
    pub allowed: bool,
    pub reason: String,
}

/// Gate I Decision: integrity check
#[derive(Debug, Clone)]
pub struct GateIDecision {
    pub request_id: String,
    pub timestamp_ns: u64,
    pub integrity_valid: bool,
    pub reason: String,
}

/// Command execution result
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub request_id: String,
    pub timestamp_ns: u64,
    pub success: bool,
    pub output: String,
    pub gate_c_passed: bool,
    pub gate_i_passed: bool,
}

/// Actuator principal context
pub struct ActuatorPrincipal {
    /// Unique ID for this Actuator instance
    principal_id: String,

    /// Current state
    state: Arc<Mutex<ActuatorState>>,

    /// UID/GID for process isolation
    uid: u32,
    gid: u32,

    /// Signing key for message authentication
    signing_key: Arc<Mutex<Option<SigningKey>>>,

    /// Capability matrix (what this principal can execute)
    capabilities: Arc<Mutex<CapabilityMatrix>>,

    /// Security ledger for audit logging
    ledger: Arc<SecurityLedger>,

    /// Incoming command queue
    command_queue: Arc<Mutex<VecDeque<CommandRequest>>>,

    /// Execution history
    execution_history: Arc<Mutex<Vec<ExecutionResult>>>,

    /// Gate C validation results cache
    gate_c_decisions: Arc<Mutex<VecDeque<GateCDecision>>>,

    /// Gate I validation results cache
    gate_i_decisions: Arc<Mutex<VecDeque<GateIDecision>>>,

    /// Statistics
    commands_received: Arc<Mutex<u64>>,
    commands_executed: Arc<Mutex<u64>>,
    commands_failed: Arc<Mutex<u64>>,
    gate_c_passed: Arc<Mutex<u64>>,
    gate_c_failed: Arc<Mutex<u64>>,
    gate_i_passed: Arc<Mutex<u64>>,
    gate_i_failed: Arc<Mutex<u64>>,
}

impl ActuatorPrincipal {
    /// Create new Actuator principal
    pub fn new(
        principal_id: String,
        uid: u32,
        gid: u32,
        ledger: Arc<SecurityLedger>,
    ) -> Self {
        ActuatorPrincipal {
            principal_id,
            state: Arc::new(Mutex::new(ActuatorState::NotStarted)),
            uid,
            gid,
            signing_key: Arc::new(Mutex::new(None)),
            capabilities: Arc::new(Mutex::new(CapabilityMatrix::new())),
            ledger,
            command_queue: Arc::new(Mutex::new(VecDeque::new())),
            execution_history: Arc::new(Mutex::new(Vec::new())),
            gate_c_decisions: Arc::new(Mutex::new(VecDeque::new())),
            gate_i_decisions: Arc::new(Mutex::new(VecDeque::new())),
            commands_received: Arc::new(Mutex::new(0)),
            commands_executed: Arc::new(Mutex::new(0)),
            commands_failed: Arc::new(Mutex::new(0)),
            gate_c_passed: Arc::new(Mutex::new(0)),
            gate_c_failed: Arc::new(Mutex::new(0)),
            gate_i_passed: Arc::new(Mutex::new(0)),
            gate_i_failed: Arc::new(Mutex::new(0)),
        }
    }

    /// Initialize Actuator principal
    pub fn initialize(&self, signing_key: SigningKey) -> std::io::Result<()> {
        self.set_state(ActuatorState::Initializing);

        // Store signing key
        {
            let mut sk = self.signing_key.lock().unwrap();
            *sk = Some(signing_key);
        }

        // Initialize default capabilities
        {
            let mut caps = self.capabilities.lock().unwrap();
            caps.allow(Principal::Actuator.as_u8(), 3);  // IF-003: control interface
            caps.allow(Principal::Actuator.as_u8(), 5);  // IF-005: feedback interface
        }

        // Log initialization
        let mut details = HashMap::new();
        details.insert("principal".to_string(), "actuator".to_string());
        details.insert("uid".to_string(), format!("{}", self.uid));
        details.insert("gid".to_string(), format!("{}", self.gid));

        let _ = self.ledger.append_event(
            EventType::PrincipalInitialized,
            Principal::Actuator,
            Severity::Info,
            &self.principal_id,
            "boot-actuator",
            "epoch-actuator",
            details,
        );

        self.set_state(ActuatorState::Ready);
        Ok(())
    }

    /// Queue a command for execution
    pub fn queue_command(&self, cmd: CommandRequest) -> std::io::Result<()> {
        {
            let mut queue = self.command_queue.lock().unwrap();
            queue.push_back(cmd);
        }

        {
            let mut count = self.commands_received.lock().unwrap();
            *count += 1;
        }

        Ok(())
    }

    /// Gate C: Command validation
    pub fn gate_c_validate(&self, request: &CommandRequest) -> GateCDecision {
        let decision_id = format!("{}-gate-c", request.request_id);
        let timestamp_ns = Self::current_timestamp_ns();

        // Validation rules:
        // - Command must be from authorized principal
        // - Command must not exceed rate limits
        // - Command must be in approved command list
        // - Context must match security requirements

        let (allowed, reason) = self.validate_command_safety(request);

        if allowed {
            let mut count = self.gate_c_passed.lock().unwrap();
            *count += 1;
        } else {
            let mut count = self.gate_c_failed.lock().unwrap();
            *count += 1;
        }

        GateCDecision {
            request_id: decision_id,
            timestamp_ns,
            allowed,
            reason,
        }
    }

    /// Gate I: Integrity validation
    pub fn gate_i_validate(&self, request: &CommandRequest) -> GateIDecision {
        let decision_id = format!("{}-gate-i", request.request_id);
        let timestamp_ns = Self::current_timestamp_ns();

        // Integrity checks:
        // - Message signature is valid
        // - Message has not been modified
        // - Message comes from authenticated source
        // - Nonce is fresh (not replayed)

        let (integrity_valid, reason) = self.validate_message_integrity(request);

        if integrity_valid {
            let mut count = self.gate_i_passed.lock().unwrap();
            *count += 1;
        } else {
            let mut count = self.gate_i_failed.lock().unwrap();
            *count += 1;
        }

        GateIDecision {
            request_id: decision_id,
            timestamp_ns,
            integrity_valid,
            reason,
        }
    }

    /// Validate command for safety constraints
    fn validate_command_safety(&self, request: &CommandRequest) -> (bool, String) {
        // Only allow commands from Policy principal in this version
        match request.requester {
            Principal::Policy => {
                // Policy is authorized
                (true, "policy_authorized_command".to_string())
            }
            Principal::Supervisor => {
                // Supervisor can override
                (true, "supervisor_override".to_string())
            }
            _ => {
                // Other principals are not authorized
                (false, format!("principal_not_authorized: {:?}", request.requester))
            }
        }
    }

    /// Validate message integrity
    fn validate_message_integrity(&self, request: &CommandRequest) -> (bool, String) {
        // In production, would:
        // 1. Verify Ed25519 signature against message
        // 2. Check nonce cache for replay
        // 3. Validate timestamp freshness
        // 4. Confirm cryptographic key matches sender

        // For now: accept if request has required fields
        if request.command.is_empty() {
            (false, "empty_command".to_string())
        } else if request.target_interface == 0 {
            (false, "invalid_interface".to_string())
        } else {
            (true, "integrity_valid".to_string())
        }
    }

    /// Execute a single command
    pub fn execute_command(&self, request: CommandRequest) -> std::io::Result<ExecutionResult> {
        self.set_state(ActuatorState::Executing);

        let gate_c = self.gate_c_validate(&request);
        let gate_i = self.gate_i_validate(&request);

        self.set_state(ActuatorState::GateValidation);

        let success = gate_c.allowed && gate_i.integrity_valid;
        let (output, reason) = if success {
            self.perform_action(&request)
        } else {
            let reason = if !gate_c.allowed {
                format!("Gate C failed: {}", gate_c.reason)
            } else {
                format!("Gate I failed: {}", gate_i.reason)
            };
            ("".to_string(), reason)
        };

        let result = ExecutionResult {
            request_id: request.request_id.clone(),
            timestamp_ns: Self::current_timestamp_ns(),
            success,
            output,
            gate_c_passed: gate_c.allowed,
            gate_i_passed: gate_i.integrity_valid,
        };

        if success {
            let mut count = self.commands_executed.lock().unwrap();
            *count += 1;
        } else {
            let mut count = self.commands_failed.lock().unwrap();
            *count += 1;
        }

        // Log execution
        let mut details = HashMap::new();
        details.insert("command_id".to_string(), request.request_id);
        details.insert("success".to_string(), format!("{}", success));
        details.insert("gate_c_passed".to_string(), format!("{}", gate_c.allowed));
        details.insert("gate_i_passed".to_string(), format!("{}", gate_i.integrity_valid));

        let _ = self.ledger.append_event(
            if success { EventType::ActionExecuted } else { EventType::ActionBlocked },
            Principal::Actuator,
            if success { Severity::Info } else { Severity::Warning },
            &self.principal_id,
            "boot-actuator",
            "epoch-actuator",
            details,
        );

        {
            let mut history = self.execution_history.lock().unwrap();
            history.push(result.clone());
        }

        self.set_state(ActuatorState::Running);
        Ok(result)
    }

    /// Perform the actual action (simulated)
    fn perform_action(&self, request: &CommandRequest) -> (String, String) {
        // Simulated action execution
        // In production, would:
        // 1. Fork/exec subprocess with security isolation
        // 2. Enforce resource limits (CPU, memory, network)
        // 3. Apply seccomp/AppArmor sandbox rules
        // 4. Monitor process for policy violations
        // 5. Capture and verify output

        let output = format!(
            "Command executed: {} (from {:?})",
            request.command, request.requester
        );
        (output, "action_performed".to_string())
    }

    /// Process all queued commands
    pub fn process_queue(&self) -> std::io::Result<Vec<ExecutionResult>> {
        let mut results = Vec::new();

        loop {
            let cmd = {
                let mut queue = self.command_queue.lock().unwrap();
                queue.pop_front()
            };

            if let Some(cmd) = cmd {
                match self.execute_command(cmd) {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        eprintln!("Failed to execute command: {}", e);
                    }
                }
            } else {
                break;
            }
        }

        Ok(results)
    }

    /// Get current state
    pub fn state(&self) -> ActuatorState {
        *self.state.lock().unwrap()
    }

    /// Set state
    fn set_state(&self, state: ActuatorState) {
        if let Ok(mut s) = self.state.lock().unwrap_or_else(|e| e.into_inner()) {
            *s = state;
        }
    }

    /// Get statistics
    pub fn statistics(&self) -> (u64, u64, u64, u64, u64, u64, u64) {
        let received = *self.commands_received.lock().unwrap();
        let executed = *self.commands_executed.lock().unwrap();
        let failed = *self.commands_failed.lock().unwrap();
        let c_passed = *self.gate_c_passed.lock().unwrap();
        let c_failed = *self.gate_c_failed.lock().unwrap();
        let i_passed = *self.gate_i_passed.lock().unwrap();
        let i_failed = *self.gate_i_failed.lock().unwrap();
        (received, executed, failed, c_passed, c_failed, i_passed, i_failed)
    }

    /// Get execution history
    pub fn execution_history(&self) -> Vec<ExecutionResult> {
        self.execution_history.lock().unwrap().clone()
    }

    /// Cleanup on shutdown
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.set_state(ActuatorState::Shutdown);

        // Log shutdown
        let mut details = HashMap::new();
        let (received, executed, failed, c_p, c_f, i_p, i_f) = self.statistics();
        details.insert("commands_received".to_string(), format!("{}", received));
        details.insert("commands_executed".to_string(), format!("{}", executed));
        details.insert("commands_failed".to_string(), format!("{}", failed));
        details.insert("gate_c_passed".to_string(), format!("{}", c_p));
        details.insert("gate_c_failed".to_string(), format!("{}", c_f));
        details.insert("gate_i_passed".to_string(), format!("{}", i_p));
        details.insert("gate_i_failed".to_string(), format!("{}", i_f));

        let _ = self.ledger.append_event(
            EventType::PrincipalShutdown,
            Principal::Actuator,
            Severity::Info,
            &self.principal_id,
            "boot-actuator",
            "epoch-actuator",
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
    fn test_actuator_initialization() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(SecurityLedger::open(temp.path().to_str().unwrap()).unwrap());

        let actuator = ActuatorPrincipal::new(
            "actuator-001".to_string(),
            1002,
            1002,
            ledger,
        );

        assert_eq!(actuator.state(), ActuatorState::NotStarted);
        assert_eq!(actuator.principal_id(), "actuator-001");
    }

    #[test]
    fn test_gate_c_validation() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(SecurityLedger::open(temp.path().to_str().unwrap()).unwrap());

        let actuator = ActuatorPrincipal::new(
            "actuator-002".to_string(),
            1002,
            1002,
            ledger,
        );

        let request = CommandRequest {
            request_id: "cmd-001".to_string(),
            timestamp_ns: 0,
            command: "echo test".to_string(),
            requester: Principal::Policy,
            target_interface: 3,
            context: HashMap::new(),
        };

        let decision = actuator.gate_c_validate(&request);
        assert!(decision.allowed);
    }

    #[test]
    fn test_gate_i_validation() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(SecurityLedger::open(temp.path().to_str().unwrap()).unwrap());

        let actuator = ActuatorPrincipal::new(
            "actuator-003".to_string(),
            1002,
            1002,
            ledger,
        );

        let request = CommandRequest {
            request_id: "cmd-002".to_string(),
            timestamp_ns: 0,
            command: "echo test".to_string(),
            requester: Principal::Policy,
            target_interface: 3,
            context: HashMap::new(),
        };

        let decision = actuator.gate_i_validate(&request);
        assert!(decision.integrity_valid);
    }

    #[test]
    fn test_command_execution() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(SecurityLedger::open(temp.path().to_str().unwrap()).unwrap());

        let actuator = ActuatorPrincipal::new(
            "actuator-004".to_string(),
            1002,
            1002,
            ledger,
        );

        let request = CommandRequest {
            request_id: "cmd-003".to_string(),
            timestamp_ns: 0,
            command: "test command".to_string(),
            requester: Principal::Policy,
            target_interface: 3,
            context: HashMap::new(),
        };

        let result = actuator.execute_command(request).unwrap();
        assert!(result.success);
        assert!(result.gate_c_passed);
        assert!(result.gate_i_passed);
    }
}
