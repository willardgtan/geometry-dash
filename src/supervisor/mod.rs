// Supervisor Module: Master Process Orchestrator (Week 1 Tasks 1.1–1.6)

pub mod startup;
pub mod process;
pub mod orchestrator;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::security_ledger::{SecurityLedger, EventType, Severity};
use crate::types::Principal;
use crate::ipc::CapabilityMatrix;
use uuid::Uuid;
use chrono::Utc;

/// Principal process state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalState {
    NotStarted,
    Starting,
    Ready,
    Running,
    Crashed,
    Restarting,
    Shutdown,
}

/// Process health information
#[derive(Debug, Clone)]
pub struct PrincipalHealth {
    pub principal: Principal,
    pub state: PrincipalState,
    pub pid: Option<u32>,
    pub last_heartbeat_ns: u64,
    pub crash_count: u32,
    pub ready_at_ns: Option<u64>,
}

impl PrincipalHealth {
    fn new(principal: Principal) -> Self {
        PrincipalHealth {
            principal,
            state: PrincipalState::NotStarted,
            pid: None,
            last_heartbeat_ns: 0,
            crash_count: 0,
            ready_at_ns: None,
        }
    }
}

/// Configuration structure (loaded from YAML)
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub heartbeat_interval_ms: u64,
    pub heartbeat_timeout_ms: u64,
    pub restart_max_attempts: u32,
    pub restart_backoff_ms: u64,
    pub epoch_id_prefix: String,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        SupervisorConfig {
            heartbeat_interval_ms: 100,
            heartbeat_timeout_ms: 1000,
            restart_max_attempts: 3,
            restart_backoff_ms: 500,
            epoch_id_prefix: "epoch".to_string(),
        }
    }
}

/// Supervisor: Master orchestrator for all principals
pub struct Supervisor {
    /// Unique ID for this Supervisor execution
    run_id: String,

    /// Boot ID (persistent across Supervisor restarts)
    boot_id: String,

    /// Epoch ID (unique identifier for this boot, HSM-signed)
    epoch_id: String,

    /// Append-only security ledger
    ledger: Arc<SecurityLedger>,

    /// Principal health tracking
    principals: Arc<Mutex<HashMap<Principal, PrincipalHealth>>>,

    /// IPC capability matrix (who can use which interfaces)
    capabilities: Arc<Mutex<CapabilityMatrix>>,

    /// Configuration
    config: SupervisorConfig,

    /// Supervisor state (running, shutdown, lockdown)
    state: Arc<Mutex<SupervisorState>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    Initializing,
    Running,
    Shutdown,
    Lockdown,  // Fail-safe mode: all actions released immediately
}

impl Supervisor {
    /// Initialize Supervisor: create ledger, load config, prepare for startup
    pub fn initialize(ledger_path: &str, config: Option<SupervisorConfig>) -> std::io::Result<Self> {
        // Create SecurityLedger
        let ledger = Arc::new(SecurityLedger::open(ledger_path)?);

        // Use provided config or defaults
        let config = config.unwrap_or_default();

        // Generate run_id (UUID)
        let run_id = Uuid::new_v4().to_string();

        // Generate boot_id (would be read from /proc/sys/kernel/random/boot_id in real system)
        let boot_id = format!("boot-{}", Uuid::new_v4());

        // Generate epoch_id (timestamp + random)
        let now = Utc::now().timestamp();
        let random_suffix = format!("{:x}", Uuid::new_v4().as_u128() >> 64);
        let epoch_id = format!("{}-{}-{}", config.epoch_id_prefix, now, random_suffix);

        // Initialize principal health tracking (8 principals, excluding Supervisor itself)
        let mut principals = HashMap::new();
        principals.insert(Principal::Policy, PrincipalHealth::new(Principal::Policy));
        principals.insert(Principal::Actuator, PrincipalHealth::new(Principal::Actuator));
        principals.insert(Principal::Audit, PrincipalHealth::new(Principal::Audit));
        principals.insert(Principal::Declassifier, PrincipalHealth::new(Principal::Declassifier));
        principals.insert(Principal::Learner, PrincipalHealth::new(Principal::Learner));
        principals.insert(Principal::Evaluator, PrincipalHealth::new(Principal::Evaluator));
        principals.insert(Principal::Sealer, PrincipalHealth::new(Principal::Sealer));
        principals.insert(Principal::Developer, PrincipalHealth::new(Principal::Developer));

        // Initialize capability matrix (populated from config in real implementation)
        let mut capabilities = CapabilityMatrix::new();

        // Default capabilities: each principal can use its primary interfaces
        // IF-001: Supervisor → Policy
        capabilities.allow(Principal::Supervisor.as_u8(), 1);
        // IF-002: Policy → Audit
        capabilities.allow(Principal::Policy.as_u8(), 2);
        // IF-011: All → Audit (SecurityLedger)
        capabilities.allow(Principal::Policy.as_u8(), 11);
        capabilities.allow(Principal::Actuator.as_u8(), 11);
        capabilities.allow(Principal::Audit.as_u8(), 11);
        capabilities.allow(Principal::Declassifier.as_u8(), 11);
        capabilities.allow(Principal::Learner.as_u8(), 11);
        capabilities.allow(Principal::Evaluator.as_u8(), 11);
        capabilities.allow(Principal::Sealer.as_u8(), 11);
        capabilities.allow(Principal::Developer.as_u8(), 11);

        // Log initialization event
        let mut details = std::collections::HashMap::new();
        details.insert("status".to_string(), "initializing".to_string());
        details.insert("principals_count".to_string(), "8".to_string());

        let _ = ledger.append_event(
            EventType::SupervisorStart,
            Principal::Supervisor,
            Severity::Info,
            &run_id,
            &boot_id,
            &epoch_id,
            details,
        );

        Ok(Supervisor {
            run_id,
            boot_id,
            epoch_id,
            ledger,
            principals: Arc::new(Mutex::new(principals)),
            capabilities: Arc::new(Mutex::new(capabilities)),
            config,
            state: Arc::new(Mutex::new(SupervisorState::Initializing)),
        })
    }

    /// Get run ID
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Get boot ID
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// Get epoch ID
    pub fn epoch_id(&self) -> &str {
        &self.epoch_id
    }

    /// Get current state
    pub fn state(&self) -> SupervisorState {
        *self.state.lock().unwrap()
    }

    /// Get principal health status
    pub fn principal_health(&self, principal: Principal) -> Option<PrincipalHealth> {
        self.principals.lock().unwrap().get(&principal).cloned()
    }

    /// Get all principals' health status
    pub fn all_principals_health(&self) -> Vec<PrincipalHealth> {
        self.principals.lock()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// Update principal state
    fn update_principal_state(&self, principal: Principal, state: PrincipalState) {
        if let Ok(mut principals) = self.principals.lock() {
            if let Some(health) = principals.get_mut(&principal) {
                health.state = state;
                if state == PrincipalState::Ready {
                    health.ready_at_ns = Some(Self::current_timestamp_ns());
                }
            }
        }
    }

    /// Record heartbeat for a principal
    pub fn heartbeat(&self, principal: Principal) {
        if let Ok(mut principals) = self.principals.lock() {
            if let Some(health) = principals.get_mut(&principal) {
                health.last_heartbeat_ns = Self::current_timestamp_ns();
                if health.state != PrincipalState::Running {
                    health.state = PrincipalState::Running;
                }
            }
        }
    }

    /// Check if a principal is healthy (has recent heartbeat)
    pub fn is_principal_healthy(&self, principal: Principal) -> bool {
        if let Ok(principals) = self.principals.lock() {
            if let Some(health) = principals.get(&principal) {
                if health.state != PrincipalState::Running {
                    return false;
                }
                let now = Self::current_timestamp_ns();
                let timeout_ns = self.config.heartbeat_timeout_ms as u64 * 1_000_000;
                return now < health.last_heartbeat_ns + timeout_ns;
            }
        }
        false
    }

    /// Get ledger reference
    pub fn ledger(&self) -> Arc<SecurityLedger> {
        Arc::clone(&self.ledger)
    }

    /// Get capability matrix reference
    pub fn capabilities(&self) -> Arc<Mutex<CapabilityMatrix>> {
        Arc::clone(&self.capabilities)
    }

    /// Set supervisor state
    fn set_state(&self, state: SupervisorState) {
        if let Ok(mut s) = self.state.lock() {
            *s = state;
        }
    }

    /// Enter LOCKDOWN state (fail-safe: release all pending actions)
    pub fn enter_lockdown(&self) {
        self.set_state(SupervisorState::Lockdown);

        // Log critical event
        let mut details = std::collections::HashMap::new();
        details.insert("reason".to_string(), "principal_crash_or_timeout".to_string());

        let _ = self.ledger.append_event(
            EventType::LockdownEntered,
            Principal::Supervisor,
            Severity::Critical,
            &self.run_id,
            &self.boot_id,
            &self.epoch_id,
            details,
        );
    }

    /// Get current nanosecond timestamp
    fn current_timestamp_ns() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Get ledger entry count
    pub fn ledger_entries(&self) -> u64 {
        self.ledger.count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_supervisor_initialize() {
        let temp = NamedTempFile::new().unwrap();
        let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

        assert!(!supervisor.run_id().is_empty());
        assert!(!supervisor.boot_id().is_empty());
        assert!(!supervisor.epoch_id().is_empty());
        assert_eq!(supervisor.state(), SupervisorState::Initializing);
    }

    #[test]
    fn test_supervisor_principal_health() {
        let temp = NamedTempFile::new().unwrap();
        let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

        let health = supervisor.principal_health(Principal::Policy).unwrap();
        assert_eq!(health.state, PrincipalState::NotStarted);
        assert_eq!(health.crash_count, 0);
    }

    #[test]
    fn test_supervisor_heartbeat() {
        let temp = NamedTempFile::new().unwrap();
        let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

        supervisor.heartbeat(Principal::Policy);
        let health = supervisor.principal_health(Principal::Policy).unwrap();
        assert_eq!(health.state, PrincipalState::Running);
        assert!(health.last_heartbeat_ns > 0);
    }

    #[test]
    fn test_supervisor_health_check() {
        let temp = NamedTempFile::new().unwrap();
        let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

        // Initially unhealthy (no heartbeat)
        assert!(!supervisor.is_principal_healthy(Principal::Policy));

        // After heartbeat, should be healthy
        supervisor.heartbeat(Principal::Policy);
        assert!(supervisor.is_principal_healthy(Principal::Policy));
    }

    #[test]
    fn test_supervisor_all_principals() {
        let temp = NamedTempFile::new().unwrap();
        let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

        let all_health = supervisor.all_principals_health();
        assert_eq!(all_health.len(), 8);  // 8 principals (excluding Supervisor)
    }

    #[test]
    fn test_supervisor_lockdown() {
        let temp = NamedTempFile::new().unwrap();
        let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

        assert_eq!(supervisor.state(), SupervisorState::Initializing);
        supervisor.enter_lockdown();
        assert_eq!(supervisor.state(), SupervisorState::Lockdown);
    }

    #[test]
    fn test_supervisor_ledger_entries() {
        let temp = NamedTempFile::new().unwrap();
        let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

        // Should have at least one entry (SUPERVISOR_START)
        assert!(supervisor.ledger_entries() > 0);
    }
}
