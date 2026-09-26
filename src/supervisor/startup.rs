// Supervisor Startup Sequence (Week 1 Task 1.1)
// Process initialization, OS-level isolation, principal startup

use std::collections::HashMap;
use std::sync::Arc;
use crate::types::Principal;
use crate::supervisor::{PrincipalState, PrincipalHealth};

/// Startup context: holds information during the startup sequence
#[derive(Debug, Clone)]
pub struct StartupContext {
    pub run_id: String,
    pub boot_id: String,
    pub epoch_id: String,
    pub principals_to_start: Vec<Principal>,
    pub ipc_root: String,
}

impl StartupContext {
    /// Create new startup context
    pub fn new(
        run_id: String,
        boot_id: String,
        epoch_id: String,
        ipc_root: String,
    ) -> Self {
        // Order of principal startup (depends on other principals)
        let principals_to_start = vec![
            Principal::Audit,          // Core: auditing infrastructure
            Principal::Policy,         // Core: decision-making
            Principal::Actuator,       // Core: action execution
            Principal::Declassifier,   // Functional: classification decisions
            Principal::Learner,        // Functional: learning pipeline
            Principal::Evaluator,      // Functional: evaluation
            Principal::Sealer,         // Functional: evidence sealing
            Principal::Developer,      // Operational: introspection
        ];

        StartupContext {
            run_id,
            boot_id,
            epoch_id,
            principals_to_start,
            ipc_root,
        }
    }

    /// Get list of principals to start
    pub fn principals(&self) -> &[Principal] {
        &self.principals_to_start
    }

    /// Get IPC pipe path for an interface
    pub fn pipe_path(&self, interface_id: u32, sender: Principal, receiver: Principal) -> String {
        format!(
            "{}/if{:03d}-{}-to-{}",
            self.ipc_root,
            interface_id,
            sender.name().to_lowercase(),
            receiver.name().to_lowercase()
        )
    }
}

/// Startup state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupPhase {
    PreStartup,           // Supervisor initializing, before any principal launch
    CreatingPipes,        // Creating IPC named pipes
    StartingPrincipals,   // Spawning principal processes
    WaitingForReady,      // Waiting for principals to signal ready
    BuildingCapabilities, // Setting up authorization matrix
    Complete,             // Startup complete, system running
    Failed(usize),        // Startup failed at principal index
}

/// Startup checklist for a single principal
#[derive(Debug, Clone)]
pub struct PrincipalStartupChecklist {
    pub principal: Principal,
    pub uid: u32,
    pub gid: u32,
    pub seccomp_profile: String,
    pub apparmor_profile: String,

    // Completion status
    pub process_spawned: bool,
    pub pipes_created: bool,
    pub capabilities_set: bool,
    pub ready_signal_received: bool,
}

impl PrincipalStartupChecklist {
    /// Create new checklist for a principal
    pub fn new(
        principal: Principal,
        uid: u32,
        gid: u32,
        seccomp_profile: String,
        apparmor_profile: String,
    ) -> Self {
        PrincipalStartupChecklist {
            principal,
            uid,
            gid,
            seccomp_profile,
            apparmor_profile,
            process_spawned: false,
            pipes_created: false,
            capabilities_set: false,
            ready_signal_received: false,
        }
    }

    /// Check if all startup steps complete
    pub fn is_complete(&self) -> bool {
        self.process_spawned
            && self.pipes_created
            && self.capabilities_set
            && self.ready_signal_received
    }

    /// Mark a step as complete
    pub fn mark_step(&mut self, step: &str) {
        match step {
            "spawn" => self.process_spawned = true,
            "pipes" => self.pipes_created = true,
            "capabilities" => self.capabilities_set = true,
            "ready" => self.ready_signal_received = true,
            _ => {}
        }
    }
}

/// Startup sequence manager
pub struct StartupSequence {
    context: StartupContext,
    checklists: HashMap<Principal, PrincipalStartupChecklist>,
    phase: StartupPhase,
}

impl StartupSequence {
    /// Create new startup sequence
    pub fn new(context: StartupContext) -> Self {
        StartupSequence {
            context,
            checklists: HashMap::new(),
            phase: StartupPhase::PreStartup,
        }
    }

    /// Add principal checklist
    pub fn add_principal(
        &mut self,
        principal: Principal,
        uid: u32,
        gid: u32,
        seccomp_profile: String,
        apparmor_profile: String,
    ) {
        let checklist = PrincipalStartupChecklist::new(
            principal,
            uid,
            gid,
            seccomp_profile,
            apparmor_profile,
        );
        self.checklists.insert(principal, checklist);
    }

    /// Get current phase
    pub fn phase(&self) -> StartupPhase {
        self.phase
    }

    /// Set phase
    pub fn set_phase(&mut self, phase: StartupPhase) {
        self.phase = phase;
    }

    /// Get checklist for principal
    pub fn checklist(&self, principal: Principal) -> Option<&PrincipalStartupChecklist> {
        self.checklists.get(&principal)
    }

    /// Get mutable checklist for principal
    pub fn checklist_mut(&mut self, principal: Principal) -> Option<&mut PrincipalStartupChecklist> {
        self.checklists.get_mut(&principal)
    }

    /// Check if all principals are ready
    pub fn all_ready(&self) -> bool {
        self.checklists.values().all(|c| c.is_complete())
    }

    /// Get startup context
    pub fn context(&self) -> &StartupContext {
        &self.context
    }

    /// Count principals ready
    pub fn principals_ready(&self) -> usize {
        self.checklists.values().filter(|c| c.ready_signal_received).count()
    }

    /// Count total principals
    pub fn total_principals(&self) -> usize {
        self.checklists.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_startup_context_creation() {
        let ctx = StartupContext::new(
            "run-123".to_string(),
            "boot-123".to_string(),
            "epoch-123".to_string(),
            "/var/run/geometry-dash".to_string(),
        );

        assert_eq!(ctx.principals().len(), 8);
        assert_eq!(ctx.principals()[0], Principal::Audit);
    }

    #[test]
    fn test_startup_context_pipe_path() {
        let ctx = StartupContext::new(
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            "/var/run/geometry-dash".to_string(),
        );

        let path = ctx.pipe_path(2, Principal::Policy, Principal::Audit);
        assert!(path.contains("if002"));
        assert!(path.contains("policy-to-audit"));
    }

    #[test]
    fn test_principal_startup_checklist() {
        let mut checklist = PrincipalStartupChecklist::new(
            Principal::Policy,
            1001,
            1001,
            "strict".to_string(),
            "policy".to_string(),
        );

        assert!(!checklist.is_complete());

        checklist.mark_step("spawn");
        checklist.mark_step("pipes");
        checklist.mark_step("capabilities");
        checklist.mark_step("ready");

        assert!(checklist.is_complete());
    }

    #[test]
    fn test_startup_sequence() {
        let ctx = StartupContext::new(
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            "/var/run/geometry-dash".to_string(),
        );

        let mut seq = StartupSequence::new(ctx);
        seq.add_principal(
            Principal::Policy,
            1001,
            1001,
            "strict".to_string(),
            "policy".to_string(),
        );

        assert_eq!(seq.phase(), StartupPhase::PreStartup);
        assert_eq!(seq.total_principals(), 1);
        assert!(!seq.all_ready());
    }

    #[test]
    fn test_startup_sequence_progress() {
        let ctx = StartupContext::new(
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            "/var/run/geometry-dash".to_string(),
        );

        let mut seq = StartupSequence::new(ctx);
        seq.add_principal(
            Principal::Policy,
            1001,
            1001,
            "strict".to_string(),
            "policy".to_string(),
        );

        // Mark as complete
        if let Some(checklist) = seq.checklist_mut(Principal::Policy) {
            checklist.mark_step("spawn");
            checklist.mark_step("pipes");
            checklist.mark_step("capabilities");
            checklist.mark_step("ready");
        }

        assert_eq!(seq.principals_ready(), 1);
        assert!(seq.all_ready());
    }
}
