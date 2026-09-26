// Principal Orchestrator: Coordinator for startup & handshake (Week 1 Task 1.3)
// Integrates startup sequence, process spawning, and IPC handshake

use std::collections::HashMap;
use crate::types::Principal;
use crate::supervisor::startup::{StartupContext, StartupSequence, PrincipalStartupChecklist};
use crate::supervisor::process::{ProcessManager, OsIsolation};
use crate::ipc::handshake::{HandshakeCoordinator, HandshakeMessage, CAPABILITY_READ, CAPABILITY_WRITE, CAPABILITY_AUDIT};
use crate::security_ledger::EventType;

/// Result of principal startup
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupResult {
    Success,
    Timeout,
    ProcessSpawnFailed,
    HandshakeFailed,
    InvalidState,
}

/// Orchestrator: manages the full startup lifecycle
pub struct PrincipalOrchestrator {
    context: StartupContext,
    sequence: StartupSequence,
    process_manager: ProcessManager,
    handshakes: HashMap<Principal, HandshakeCoordinator>,
}

impl PrincipalOrchestrator {
    /// Create new orchestrator
    pub fn new(context: StartupContext) -> Self {
        let mut orchestrator = PrincipalOrchestrator {
            context: context.clone(),
            sequence: StartupSequence::new(context),
            process_manager: ProcessManager::new(),
            handshakes: HashMap::new(),
        };

        // Initialize handshake coordinators for all principals
        for principal in orchestrator.context.principals() {
            orchestrator.handshakes.insert(*principal, HandshakeCoordinator::new());
        }

        orchestrator
    }

    /// Register a binary path for a principal
    pub fn register_binary(&mut self, principal: Principal, path: String) {
        self.process_manager.register_binary(principal, path);
    }

    /// Add a principal to the startup sequence
    pub fn add_principal(
        &mut self,
        principal: Principal,
        uid: u32,
        gid: u32,
        seccomp_profile: String,
        apparmor_profile: String,
    ) {
        self.sequence.add_principal(
            principal,
            uid,
            gid,
            seccomp_profile,
            apparmor_profile,
        );
    }

    /// Start a single principal
    pub fn start_principal(
        &mut self,
        principal: Principal,
    ) -> Result<StartupResult, String> {
        // Get or create isolation config
        let isolation = OsIsolation::new(
            principal,
            1000 + principal.as_u8() as u32,  // Simple UID assignment
            1000 + principal.as_u8() as u32,  // Simple GID assignment
            "strict",
            format!("{}-profile", principal.name().to_lowercase()),
        );

        // Try to spawn the process
        match self.process_manager.spawn(principal, &isolation, vec![]) {
            Ok(process_info) => {
                // Update checklist
                if let Some(checklist) = self.sequence.checklist_mut(principal) {
                    checklist.mark_step("spawn");
                }

                Ok(StartupResult::Success)
            }
            Err(_) => Err(format!("Failed to spawn {:?}", principal)),
        }
    }

    /// Send INIT message to principal
    pub fn send_init(&mut self, principal: Principal, message_id: u64) -> Result<(), String> {
        let handshake = self.handshakes.get_mut(&principal)
            .ok_or_else(|| format!("No handshake for {:?}", principal))?;

        let message = HandshakeMessage::init(
            Principal::Supervisor.as_u8(),
            principal.as_u8(),
            message_id,
            self.context.run_id.clone(),
            self.context.boot_id.clone(),
            self.context.epoch_id.clone(),
        );

        handshake.send_init(message)?;

        if let Some(checklist) = self.sequence.checklist_mut(principal) {
            checklist.mark_step("pipes");
        }

        Ok(())
    }

    /// Receive READY message from principal
    pub fn receive_ready(
        &mut self,
        principal: Principal,
        message: HandshakeMessage,
    ) -> Result<(), String> {
        let handshake = self.handshakes.get_mut(&principal)
            .ok_or_else(|| format!("No handshake for {:?}", principal))?;

        handshake.receive_ready(message)?;

        if let Some(checklist) = self.sequence.checklist_mut(principal) {
            checklist.mark_step("capabilities");
            checklist.mark_step("ready");
        }

        Ok(())
    }

    /// Check if a principal is ready
    pub fn is_principal_ready(&self, principal: Principal) -> bool {
        self.sequence.checklist(principal)
            .map(|c| c.ready_signal_received)
            .unwrap_or(false)
    }

    /// Check if all principals are ready
    pub fn all_ready(&self) -> bool {
        self.sequence.all_ready()
    }

    /// Get default capabilities for a principal
    pub fn default_capabilities(principal: Principal) -> u32 {
        match principal {
            Principal::Supervisor => 0,  // Supervisor doesn't report capabilities
            Principal::Policy => CAPABILITY_READ | CAPABILITY_WRITE | CAPABILITY_AUDIT,
            Principal::Actuator => CAPABILITY_READ | CAPABILITY_WRITE,
            Principal::Audit => CAPABILITY_READ | CAPABILITY_AUDIT,
            Principal::Declassifier => CAPABILITY_READ | CAPABILITY_WRITE,
            Principal::Learner => CAPABILITY_READ | CAPABILITY_AUDIT,
            Principal::Evaluator => CAPABILITY_READ | CAPABILITY_AUDIT,
            Principal::Sealer => CAPABILITY_READ | CAPABILITY_WRITE,
            Principal::Developer => CAPABILITY_READ | CAPABILITY_AUDIT,
        }
    }

    /// Get handshake state for a principal
    pub fn handshake_complete(&self, principal: Principal) -> bool {
        self.handshakes.get(&principal)
            .map(|h| h.is_complete())
            .unwrap_or(false)
    }

    /// Get process info for a principal
    pub fn get_process_info(&self, principal: Principal) -> Option<std::sync::Arc<super::process::ProcessInfo>> {
        self.process_manager.get_process(principal).map(|p| std::sync::Arc::new(p.clone()))
    }

    /// Get orchestrator context
    pub fn context(&self) -> &StartupContext {
        &self.context
    }

    /// Get startup sequence
    pub fn sequence(&self) -> &StartupSequence {
        &self.sequence
    }

    /// Count principals ready
    pub fn principals_ready_count(&self) -> usize {
        self.sequence.principals_ready()
    }

    /// Get total principals
    pub fn total_principals(&self) -> usize {
        self.sequence.total_principals()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_creation() {
        let ctx = StartupContext::new(
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            "/var/run/geometry-dash".to_string(),
        );

        let orchestrator = PrincipalOrchestrator::new(ctx);
        assert_eq!(orchestrator.total_principals(), 0);  // No principals added yet
    }

    #[test]
    fn test_orchestrator_register_binary() {
        let ctx = StartupContext::new(
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            "/var/run/geometry-dash".to_string(),
        );

        let mut orchestrator = PrincipalOrchestrator::new(ctx);
        orchestrator.register_binary(Principal::Policy, "/usr/bin/policy".to_string());
    }

    #[test]
    fn test_orchestrator_add_principal() {
        let ctx = StartupContext::new(
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            "/var/run/geometry-dash".to_string(),
        );

        let mut orchestrator = PrincipalOrchestrator::new(ctx);
        orchestrator.add_principal(
            Principal::Policy,
            1001,
            1001,
            "strict".to_string(),
            "policy".to_string(),
        );

        assert_eq!(orchestrator.total_principals(), 1);
    }

    #[test]
    fn test_orchestrator_default_capabilities() {
        assert_eq!(
            PrincipalOrchestrator::default_capabilities(Principal::Policy),
            CAPABILITY_READ | CAPABILITY_WRITE | CAPABILITY_AUDIT
        );

        assert_eq!(
            PrincipalOrchestrator::default_capabilities(Principal::Actuator),
            CAPABILITY_READ | CAPABILITY_WRITE
        );

        assert_eq!(
            PrincipalOrchestrator::default_capabilities(Principal::Audit),
            CAPABILITY_READ | CAPABILITY_AUDIT
        );
    }

    #[test]
    fn test_orchestrator_send_init() {
        let ctx = StartupContext::new(
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            "/var/run/geometry-dash".to_string(),
        );

        let mut orchestrator = PrincipalOrchestrator::new(ctx);
        orchestrator.add_principal(
            Principal::Policy,
            1001,
            1001,
            "strict".to_string(),
            "policy".to_string(),
        );

        let result = orchestrator.send_init(Principal::Policy, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_orchestrator_ready_cycle() {
        let ctx = StartupContext::new(
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            "/var/run/geometry-dash".to_string(),
        );

        let mut orchestrator = PrincipalOrchestrator::new(ctx);
        orchestrator.add_principal(
            Principal::Policy,
            1001,
            1001,
            "strict".to_string(),
            "policy".to_string(),
        );

        // Send INIT
        assert!(orchestrator.send_init(Principal::Policy, 100).is_ok());
        assert!(!orchestrator.is_principal_ready(Principal::Policy));

        // Simulate receiving READY
        let ready_msg = HandshakeMessage::ready(
            Principal::Policy.as_u8(),
            Principal::Supervisor.as_u8(),
            100,
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            CAPABILITY_READ | CAPABILITY_WRITE,
        );

        assert!(orchestrator.receive_ready(Principal::Policy, ready_msg).is_ok());
        assert!(orchestrator.is_principal_ready(Principal::Policy));
    }

    #[test]
    fn test_orchestrator_all_ready() {
        let ctx = StartupContext::new(
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            "/var/run/geometry-dash".to_string(),
        );

        let mut orchestrator = PrincipalOrchestrator::new(ctx);

        // Add two principals
        orchestrator.add_principal(
            Principal::Policy,
            1001,
            1001,
            "strict".to_string(),
            "policy".to_string(),
        );
        orchestrator.add_principal(
            Principal::Actuator,
            1002,
            1002,
            "strict".to_string(),
            "actuator".to_string(),
        );

        assert!(!orchestrator.all_ready());

        // Start Policy
        orchestrator.send_init(Principal::Policy, 100).unwrap();
        let ready1 = HandshakeMessage::ready(
            Principal::Policy.as_u8(),
            Principal::Supervisor.as_u8(),
            100,
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            CAPABILITY_READ,
        );
        orchestrator.receive_ready(Principal::Policy, ready1).unwrap();

        // Start Actuator
        orchestrator.send_init(Principal::Actuator, 101).unwrap();
        let ready2 = HandshakeMessage::ready(
            Principal::Actuator.as_u8(),
            Principal::Supervisor.as_u8(),
            101,
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            CAPABILITY_WRITE,
        );
        orchestrator.receive_ready(Principal::Actuator, ready2).unwrap();

        assert!(orchestrator.all_ready());
    }
}
