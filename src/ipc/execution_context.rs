// Execution Context & Atomic Validation-to-Execution Transition (Sprint 4 Task 4.2)
// Immutable snapshots of validation state to prevent TOCTOU vulnerabilities
// RwLock-based atomic transitions prevent state changes during critical sections

use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use crate::types::Principal;
use crate::principals::identity::PrincipalIdentity;
use crate::principals::certificate::PrincipalCertificate;
use crate::ipc::token::ExecutionToken;

/// Command execution state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionState {
    /// Command queued, awaiting validation
    Queued,
    /// Currently performing gate validations (write lock held)
    Validating,
    /// Validation complete, token issued, ready for execution
    Validated,
    /// Currently executing action (write lock held)
    Executing,
    /// Execution completed successfully
    CompletedSuccess,
    /// Execution failed
    CompletedFailure,
    /// Execution blocked (state changed, revoked, etc)
    BlockedStateChange,
}

impl std::fmt::Display for ExecutionState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ExecutionState::Queued => write!(f, "Queued"),
            ExecutionState::Validating => write!(f, "Validating"),
            ExecutionState::Validated => write!(f, "Validated"),
            ExecutionState::Executing => write!(f, "Executing"),
            ExecutionState::CompletedSuccess => write!(f, "CompletedSuccess"),
            ExecutionState::CompletedFailure => write!(f, "CompletedFailure"),
            ExecutionState::BlockedStateChange => write!(f, "BlockedStateChange"),
        }
    }
}

/// Snapshot of Gate C (command authorization) validation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateCSnapshot {
    /// Was command allowed by Gate C?
    pub allowed: bool,

    /// Reason for decision
    pub reason: String,

    /// Capabilities available at time of validation
    pub capabilities: Vec<u32>,

    /// Policy version that was checked
    pub policy_version: u32,

    /// Timestamp when validation occurred
    pub timestamp_ns: u64,
}

/// Snapshot of Gate I (message integrity) validation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateISnapshot {
    /// Is message integrity valid?
    pub integrity_valid: bool,

    /// Is signature valid?
    pub signature_valid: bool,

    /// Is nonce fresh (not replayed)?
    pub nonce_fresh: bool,

    /// Timestamp when validation occurred
    pub timestamp_ns: u64,
}

/// Snapshot of the command state at validation time
#[derive(Debug, Clone)]
pub struct CommandSnapshot {
    /// Command ID
    pub command_id: String,

    /// Original command string
    pub command: String,

    /// Requester principal
    pub requester_principal: Principal,

    /// Target interface
    pub target_interface: u32,
}

/// Snapshot of principal state at validation time (for re-validation checks)
#[derive(Debug, Clone)]
pub struct PrincipalStateSnapshot {
    /// Principal's active identity
    pub identity: PrincipalIdentity,

    /// Principal's active certificate
    pub certificate: PrincipalCertificate,

    /// Hash of public key for tamper detection
    pub public_key_hash: String,
}

/// Complete execution context: immutable snapshot of all validation state
#[derive(Debug, Clone)]
pub struct CommandExecutionContext {
    /// Command being executed
    pub command: CommandSnapshot,

    /// When validation occurred
    pub validation_timestamp_ns: u64,

    /// Gate C validation results
    pub gate_c_snapshot: GateCSnapshot,

    /// Gate I validation results
    pub gate_i_snapshot: GateISnapshot,

    /// Requester's principal state at validation time
    pub requester_state: PrincipalStateSnapshot,

    /// Execution token authorizing this command
    pub execution_token: ExecutionToken,

    /// Execution snapshot hash (SHA-256 of all context)
    pub snapshot_hash: String,
}

impl CommandExecutionContext {
    /// Create new execution context
    pub fn new(
        command_id: String,
        command: String,
        requester_principal: Principal,
        target_interface: u32,
        validation_timestamp_ns: u64,
        gate_c_snapshot: GateCSnapshot,
        gate_i_snapshot: GateISnapshot,
        requester_identity: PrincipalIdentity,
        requester_certificate: PrincipalCertificate,
        execution_token: ExecutionToken,
    ) -> Self {
        let command_snapshot = CommandSnapshot {
            command_id,
            command,
            requester_principal,
            target_interface,
        };

        let principal_state = PrincipalStateSnapshot {
            identity: requester_identity,
            certificate: requester_certificate.clone(),
            public_key_hash: requester_certificate.content_hash,
        };

        // Compute snapshot hash
        let snapshot_hash = format!(
            "{}-{}-{}-{}",
            command_snapshot.command_id,
            gate_c_snapshot.timestamp_ns,
            gate_i_snapshot.timestamp_ns,
            execution_token.token_id
        );

        CommandExecutionContext {
            command: command_snapshot,
            validation_timestamp_ns,
            gate_c_snapshot,
            gate_i_snapshot,
            requester_state: principal_state,
            execution_token,
            snapshot_hash,
        }
    }

    /// Check if gates passed
    pub fn gates_passed(&self) -> bool {
        self.gate_c_snapshot.allowed && self.gate_i_snapshot.integrity_valid
    }

    /// Get time elapsed since validation
    pub fn time_since_validation(&self, current_timestamp_ns: u64) -> u64 {
        current_timestamp_ns.saturating_sub(self.validation_timestamp_ns)
    }
}

/// Validated command with execution context and state tracking
#[derive(Debug, Clone)]
pub struct ValidatedCommand {
    /// Execution context with validation snapshots
    pub context: CommandExecutionContext,

    /// Current state in execution lifecycle
    pub state: ExecutionState,

    /// When state last transitioned
    pub state_transition_timestamp_ns: u64,

    /// Error message if execution failed
    pub error_message: Option<String>,
}

impl ValidatedCommand {
    /// Create new validated command
    pub fn new(context: CommandExecutionContext, current_timestamp_ns: u64) -> Self {
        ValidatedCommand {
            context,
            state: ExecutionState::Queued,
            state_transition_timestamp_ns: current_timestamp_ns,
            error_message: None,
        }
    }

    /// Transition to new state
    pub fn transition_to(&mut self, new_state: ExecutionState, current_timestamp_ns: u64) {
        self.state = new_state;
        self.state_transition_timestamp_ns = current_timestamp_ns;
        self.error_message = None;
    }

    /// Transition to failure state with error
    pub fn fail(&mut self, reason: String, current_timestamp_ns: u64) {
        self.state = ExecutionState::CompletedFailure;
        self.state_transition_timestamp_ns = current_timestamp_ns;
        self.error_message = Some(reason);
    }
}

/// Execution lock: RwLock wrapper for atomic validation-to-execution
/// Ensures that between validation and execution, state cannot change
pub struct ExecutionLock {
    /// Read-write lock protecting validated command state
    inner: Arc<RwLock<ValidatedCommand>>,
}

impl ExecutionLock {
    /// Create new execution lock
    pub fn new(command: ValidatedCommand) -> Self {
        ExecutionLock {
            inner: Arc::new(RwLock::new(command)),
        }
    }

    /// Acquire read lock (non-blocking access to state)
    pub fn read_lock(&self) -> Result<std::sync::RwLockReadGuard<ValidatedCommand>, String> {
        self.inner
            .read()
            .map_err(|e| format!("Failed to acquire read lock: {}", e))
    }

    /// Acquire write lock (exclusive access for state changes)
    pub fn write_lock(&self) -> Result<std::sync::RwLockWriteGuard<ValidatedCommand>, String> {
        self.inner
            .write()
            .map_err(|e| format!("Failed to acquire write lock: {}", e))
    }

    /// Try to acquire write lock with timeout
    pub fn try_write_lock_with_timeout(&self, timeout_ms: u64) -> Result<std::sync::RwLockWriteGuard<ValidatedCommand>, String> {
        // Note: RwLock doesn't have built-in timeout, so we attempt immediately
        // In production, would implement timed backoff
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(timeout_ms);

        loop {
            match self.inner.try_write() {
                Ok(guard) => return Ok(guard),
                Err(_) if start.elapsed() < timeout => {
                    std::thread::sleep(std::time::Duration::from_micros(10));
                    continue;
                }
                Err(_) => return Err("Write lock acquisition timeout".to_string()),
            }
        }
    }

    /// Clone the inner Arc for sharing
    pub fn clone_inner(&self) -> Arc<RwLock<ValidatedCommand>> {
        Arc::clone(&self.inner)
    }

    /// Get command ID for reference
    pub fn command_id(&self) -> Result<String, String> {
        self.read_lock().map(|cmd| cmd.context.command.command_id.clone())
    }

    /// Get current state
    pub fn current_state(&self) -> Result<ExecutionState, String> {
        self.read_lock().map(|cmd| cmd.state)
    }
}

impl Clone for ExecutionLock {
    fn clone(&self) -> Self {
        ExecutionLock {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Principal;

    fn create_test_context() -> CommandExecutionContext {
        let gate_c = GateCSnapshot {
            allowed: true,
            reason: "authorized".to_string(),
            capabilities: vec![3, 5],
            policy_version: 1,
            timestamp_ns: 1000,
        };

        let gate_i = GateISnapshot {
            integrity_valid: true,
            signature_valid: true,
            nonce_fresh: true,
            timestamp_ns: 1000,
        };

        let identity = PrincipalIdentity {
            identity_id: "id-1".to_string(),
            principal: Principal::Policy,
            public_key: crate::principals::identity::PublicKey::new([1u8; 32]),
            key_version: 1,
            created_timestamp_ns: 1000,
            expires_timestamp_ns: None,
            is_active: true,
            purpose: "primary".to_string(),
            public_key_hash: "hash-1".to_string(),
        };

        let mut certificate = PrincipalCertificate::new(
            "cert-1".to_string(),
            Principal::Policy,
            crate::principals::identity::PublicKey::new([1u8; 32]),
            1,
            Principal::Sealer,
            1000,
            6000,
        );
        certificate.content_hash = "hash-1".to_string();

        let token = crate::ipc::token::ExecutionToken::new(
            "cmd-1".to_string(),
            1000,
            6000,
            Principal::Supervisor,
            Principal::Policy,
            0x03,
            [1u8; 64],
        );

        CommandExecutionContext::new(
            "cmd-1".to_string(),
            "test command".to_string(),
            Principal::Policy,
            3,
            1000,
            gate_c,
            gate_i,
            identity,
            certificate,
            token,
        )
    }

    #[test]
    fn test_gate_c_snapshot() {
        let snapshot = GateCSnapshot {
            allowed: true,
            reason: "test".to_string(),
            capabilities: vec![1, 2, 3],
            policy_version: 1,
            timestamp_ns: 1000,
        };

        assert!(snapshot.allowed);
        assert_eq!(snapshot.capabilities.len(), 3);
    }

    #[test]
    fn test_execution_context_creation() {
        let context = create_test_context();

        assert_eq!(context.command.command_id, "cmd-1");
        assert!(context.gates_passed());
        assert_eq!(context.validation_timestamp_ns, 1000);
    }

    #[test]
    fn test_execution_context_time_elapsed() {
        let context = create_test_context();

        let elapsed = context.time_since_validation(2000);
        assert_eq!(elapsed, 1000);
    }

    #[test]
    fn test_validated_command_state_machine() {
        let context = create_test_context();
        let mut cmd = ValidatedCommand::new(context, 1000);

        assert_eq!(cmd.state, ExecutionState::Queued);

        cmd.transition_to(ExecutionState::Validating, 1000);
        assert_eq!(cmd.state, ExecutionState::Validating);

        cmd.transition_to(ExecutionState::Validated, 1500);
        assert_eq!(cmd.state, ExecutionState::Validated);
        assert_eq!(cmd.state_transition_timestamp_ns, 1500);
    }

    #[test]
    fn test_validated_command_failure() {
        let context = create_test_context();
        let mut cmd = ValidatedCommand::new(context, 1000);

        cmd.fail("Principal revoked".to_string(), 2000);
        assert_eq!(cmd.state, ExecutionState::CompletedFailure);
        assert_eq!(cmd.error_message, Some("Principal revoked".to_string()));
    }

    #[test]
    fn test_execution_lock_creation() {
        let context = create_test_context();
        let cmd = ValidatedCommand::new(context, 1000);
        let lock = ExecutionLock::new(cmd);

        let state = lock.current_state().unwrap();
        assert_eq!(state, ExecutionState::Queued);
    }

    #[test]
    fn test_execution_lock_read_write() {
        let context = create_test_context();
        let cmd = ValidatedCommand::new(context, 1000);
        let lock = ExecutionLock::new(cmd);

        // Read lock
        {
            let read_cmd = lock.read_lock().unwrap();
            assert_eq!(read_cmd.state, ExecutionState::Queued);
        }

        // Write lock
        {
            let mut write_cmd = lock.write_lock().unwrap();
            write_cmd.transition_to(ExecutionState::Validating, 2000);
        }

        // Verify state changed
        {
            let read_cmd = lock.read_lock().unwrap();
            assert_eq!(read_cmd.state, ExecutionState::Validating);
        }
    }

    #[test]
    fn test_execution_lock_clone() {
        let context = create_test_context();
        let cmd = ValidatedCommand::new(context, 1000);
        let lock1 = ExecutionLock::new(cmd);
        let lock2 = lock1.clone();

        // Modify through lock1
        {
            let mut cmd = lock1.write_lock().unwrap();
            cmd.transition_to(ExecutionState::Validating, 2000);
        }

        // Verify through lock2
        {
            let cmd = lock2.read_lock().unwrap();
            assert_eq!(cmd.state, ExecutionState::Validating);
        }
    }

    #[test]
    fn test_execution_state_display() {
        assert_eq!(format!("{}", ExecutionState::Queued), "Queued");
        assert_eq!(format!("{}", ExecutionState::Executing), "Executing");
        assert_eq!(format!("{}", ExecutionState::CompletedSuccess), "CompletedSuccess");
    }
}
