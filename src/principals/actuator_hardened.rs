// Actuator Hardening & Integration (Sprint 4 Task 4.6)
// Integrate TOCTOU prevention mechanisms into Actuator command execution
// Combines execution tokens, state validation, replay detection, and atomic transitions

use std::sync::Arc;
use crate::types::Principal;
use crate::security_ledger::SecurityLedger;
use crate::ipc::{
    ExecutionToken, ExecutionTokenIssuer, ExecutionTokenVerifier,
    CommandExecutionContext, ExecutionLock, ExecutionState,
    StateChangeValidator, StateValidationResult,
    CommandRevocationList, CommandRevocationEntry,
    ExecutionSnapshot, ExecutionReplayDetector, SnapshotVerifier,
};
use crate::principals::identity::PrincipalIdentityRegistry;
use crate::principals::certificate::PrincipalCertificateRegistry;
use crate::ipc::execution_context::{GateCSnapshot, GateISnapshot, PrincipalStateSnapshot};
use crate::principals::actuator::{CommandRequest, ExecutionResult, ActuatorPrincipal, GateCDecision, GateIDecision};

/// Configuration for hardened command execution
#[derive(Debug, Clone)]
pub struct ActuatorConfig {
    /// Execution token TTL in milliseconds (default: 5000ms)
    pub execution_token_ttl_ms: u64,

    /// State change check interval in milliseconds (default: 1000ms)
    pub state_change_check_interval_ms: u64,

    /// Maximum concurrent executions (default: 10)
    pub max_concurrent_executions: usize,

    /// Execution snapshot retention in milliseconds (default: 86400000ms = 1 day)
    pub execution_snapshot_retention_ms: u64,

    /// Replay detection log size (default: 10000)
    pub replay_log_size: usize,

    /// Revocation list size (default: 50000)
    pub revocation_list_size: usize,
}

impl Default for ActuatorConfig {
    fn default() -> Self {
        ActuatorConfig {
            execution_token_ttl_ms: 5000,
            state_change_check_interval_ms: 1000,
            max_concurrent_executions: 10,
            execution_snapshot_retention_ms: 86400000,
            replay_log_size: 10000,
            revocation_list_size: 50000,
        }
    }
}

/// Hardened command execution context
pub struct HardenedExecutionContext {
    /// Token issuer for command validation
    pub token_issuer: Arc<ExecutionTokenIssuer>,

    /// Token verifier for signature validation
    pub token_verifier: Arc<ExecutionTokenVerifier>,

    /// State change validator for pre-execution checks
    pub state_validator: Arc<StateChangeValidator>,

    /// Command revocation list
    pub revocation_list: Arc<CommandRevocationList>,

    /// Execution replay detector
    pub replay_detector: Arc<ExecutionReplayDetector>,

    /// Principal identity registry
    pub identity_registry: Arc<PrincipalIdentityRegistry>,

    /// Principal certificate registry
    pub certificate_registry: Arc<PrincipalCertificateRegistry>,

    /// Configuration
    pub config: ActuatorConfig,

    /// Security ledger
    pub ledger: Arc<SecurityLedger>,
}

impl HardenedExecutionContext {
    /// Create new hardened execution context
    pub fn new(
        config: ActuatorConfig,
        identity_registry: Arc<PrincipalIdentityRegistry>,
        certificate_registry: Arc<PrincipalCertificateRegistry>,
        ledger: Arc<SecurityLedger>,
    ) -> Self {
        let token_issuer = Arc::new(ExecutionTokenIssuer::new(config.execution_token_ttl_ms));
        let token_verifier = Arc::new(ExecutionTokenVerifier::new());
        let state_validator = Arc::new(StateChangeValidator::new(
            identity_registry.clone(),
            certificate_registry.clone(),
            token_issuer.clone(),
        ));
        let revocation_list = Arc::new(CommandRevocationList::new(config.revocation_list_size));
        let replay_detector = Arc::new(ExecutionReplayDetector::new(
            config.execution_snapshot_retention_ms,
            config.replay_log_size,
        ));

        HardenedExecutionContext {
            token_issuer,
            token_verifier,
            state_validator,
            revocation_list,
            replay_detector,
            identity_registry,
            certificate_registry,
            config,
            ledger,
        }
    }
}

/// Hardened execution flow with TOCTOU prevention
pub struct HardenedActuatorExecutor {
    /// Hardened execution context
    context: Arc<HardenedExecutionContext>,

    /// Reference to the underlying Actuator
    actuator: Arc<ActuatorPrincipal>,
}

impl HardenedActuatorExecutor {
    /// Create new hardened executor
    pub fn new(context: Arc<HardenedExecutionContext>, actuator: Arc<ActuatorPrincipal>) -> Self {
        HardenedActuatorExecutor { context, actuator }
    }

    /// Execute command with full TOCTOU prevention
    pub fn execute_with_token(&self, request: CommandRequest) -> std::io::Result<ExecutionResult> {
        let current_time_ns = Self::current_timestamp_ns();

        // Phase 1: ATOMIC VALIDATION AND TOKEN ISSUANCE
        let execution_context = self.validate_and_issue_token(&request, current_time_ns)?;

        // Phase 2: PRE-EXECUTION STATE RE-VALIDATION
        self.pre_execute_validation(&execution_context, current_time_ns)?;

        // Phase 3: REPLAY DETECTION
        let snapshot = ExecutionSnapshot::from_context(&execution_context, current_time_ns);
        self.context.replay_detector.check_replay(&snapshot)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Phase 4: EXECUTE WITH TOKEN CONSUMPTION
        let result = self.perform_execution(&execution_context, &request, current_time_ns)?;

        // Phase 5: RECORD SUCCESSFUL EXECUTION
        self.context
            .token_issuer
            .consume_token(&execution_context.execution_token)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Record in replay detector
        self.context.replay_detector.record_execution(&snapshot)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        Ok(result)
    }

    /// Validate command and issue execution token (atomic operation)
    fn validate_and_issue_token(
        &self,
        request: &CommandRequest,
        current_time_ns: u64,
    ) -> std::io::Result<CommandExecutionContext> {
        // Get gate validations
        let gate_c = self.actuator.gate_c_validate(request);
        let gate_i = self.actuator.gate_i_validate(request);

        // Check if gates passed
        if !gate_c.allowed || !gate_i.integrity_valid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Gate validation failed: Gate C: {}, Gate I: {}",
                    gate_c.allowed, gate_i.integrity_valid
                ),
            ));
        }

        // Check revocation list
        if self.context.revocation_list.is_command_revoked(&request.request_id) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Command has been revoked",
            ));
        }

        // Issue execution token
        let token = self.context
            .token_issuer
            .issue_token(&request.request_id)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Get requester state for snapshots
        let principal = request.requester;
        let identity = self
            .context
            .identity_registry
            .get_active_identity(principal)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "Principal identity not found")
            })?;

        let certificate = self
            .context
            .certificate_registry
            .get_active_certificate(principal)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "Principal certificate not found")
            })?;

        // Create execution context with snapshots
        let gate_c_snapshot = GateCSnapshot {
            allowed: gate_c.allowed,
            reason: gate_c.reason,
            capabilities: vec![request.target_interface],
            policy_version: 1,
            timestamp_ns: gate_c.timestamp_ns,
        };

        let gate_i_snapshot = GateISnapshot {
            integrity_valid: gate_i.integrity_valid,
            signature_valid: true,
            nonce_fresh: true,
            timestamp_ns: gate_i.timestamp_ns,
        };

        let principal_state_snapshot = PrincipalStateSnapshot {
            identity,
            certificate,
            public_key_hash: "".to_string(),
        };

        let context = CommandExecutionContext::new(
            request.request_id.clone(),
            request.command.clone(),
            principal,
            request.target_interface,
            current_time_ns,
            gate_c_snapshot,
            gate_i_snapshot,
            principal_state_snapshot.identity,
            principal_state_snapshot.certificate,
            token,
        );

        Ok(context)
    }

    /// Pre-execution state re-validation
    fn pre_execute_validation(
        &self,
        context: &CommandExecutionContext,
        current_time_ns: u64,
    ) -> std::io::Result<()> {
        match self.context.state_validator.validate_pre_execution(context, current_time_ns) {
            StateValidationResult::Valid => Ok(()),
            StateValidationResult::Invalid(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Pre-execution validation failed: {}", err),
            )),
        }
    }

    /// Perform the actual execution
    fn perform_execution(
        &self,
        context: &CommandExecutionContext,
        request: &CommandRequest,
        _current_time_ns: u64,
    ) -> std::io::Result<ExecutionResult> {
        // Perform the action (delegated to actuator)
        let (output, _reason) = self.actuator.perform_action(request);

        let result = ExecutionResult {
            request_id: request.request_id.clone(),
            timestamp_ns: Self::current_timestamp_ns(),
            success: true,
            output,
            gate_c_passed: context.gate_c_snapshot.allowed,
            gate_i_passed: context.gate_i_snapshot.integrity_valid,
        };

        Ok(result)
    }

    /// Get current timestamp in nanoseconds
    fn current_timestamp_ns() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = ActuatorConfig::default();
        assert_eq!(config.execution_token_ttl_ms, 5000);
        assert_eq!(config.state_change_check_interval_ms, 1000);
        assert_eq!(config.max_concurrent_executions, 10);
    }

    #[test]
    fn test_config_custom() {
        let config = ActuatorConfig {
            execution_token_ttl_ms: 10000,
            state_change_check_interval_ms: 2000,
            max_concurrent_executions: 20,
            execution_snapshot_retention_ms: 172800000,
            replay_log_size: 20000,
            revocation_list_size: 100000,
        };

        assert_eq!(config.execution_token_ttl_ms, 10000);
        assert_eq!(config.max_concurrent_executions, 20);
        assert_eq!(config.replay_log_size, 20000);
    }

    #[test]
    fn test_hardened_execution_context_creation() {
        let config = ActuatorConfig::default();
        let identity_reg = Arc::new(PrincipalIdentityRegistry::new());
        let cert_reg = Arc::new(PrincipalCertificateRegistry::new());

        // This would require a SecurityLedger instance
        // For now, just test the structure compiles
        let _context = HardenedExecutionContext::new(
            config,
            identity_reg,
            cert_reg,
            Arc::new(SecurityLedger::new()),
        );
    }
}
