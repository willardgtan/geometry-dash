// Command Revocation System (Sprint 4 Task 4.4)
// Enable immediate revocation of approved commands before execution
// Prevents compromised commands from executing even after validation

use std::collections::HashMap;
use std::sync::Mutex;
use crate::types::Principal;
use crate::ipc::token::{ExecutionTokenIssuer, TokenStatus};

/// Entry in the command revocation list
#[derive(Debug, Clone)]
pub struct CommandRevocationEntry {
    /// ID of the revoked command
    pub command_id: String,

    /// Principal that requested the revocation
    pub revoked_by: Principal,

    /// Timestamp when revocation occurred (nanoseconds)
    pub revoked_timestamp_ns: u64,

    /// Reason for revocation
    pub reason: String,

    /// Optional cascade trigger (principal revoked, certificate expired, etc)
    pub cascade_trigger: Option<RevocationCascadeTrigger>,
}

/// What caused a cascade revocation
#[derive(Debug, Clone)]
pub enum RevocationCascadeTrigger {
    /// Principal's identity was revoked
    PrincipalRevoked(Principal),

    /// Principal's certificate expired
    CertificateExpired(Principal),

    /// Security policy violation detected
    SecurityViolation(String),

    /// Manual cascade from Supervisor
    SupervisorInitiated(String),
}

impl std::fmt::Display for RevocationCascadeTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RevocationCascadeTrigger::PrincipalRevoked(p) => write!(f, "Principal revoked: {:?}", p),
            RevocationCascadeTrigger::CertificateExpired(p) => write!(f, "Certificate expired: {:?}", p),
            RevocationCascadeTrigger::SecurityViolation(reason) => write!(f, "Security violation: {}", reason),
            RevocationCascadeTrigger::SupervisorInitiated(reason) => write!(f, "Supervisor initiated: {}", reason),
        }
    }
}

/// Command revocation list: maintains set of revoked command IDs
pub struct CommandRevocationList {
    /// Map of command_id -> revocation entry
    revocations: Mutex<HashMap<String, CommandRevocationEntry>>,

    /// Token issuer reference for cascade revocation
    token_issuer: Option<std::sync::Arc<ExecutionTokenIssuer>>,

    /// Maximum number of entries to keep (with LRU eviction)
    max_entries: usize,
}

impl CommandRevocationList {
    /// Create new command revocation list
    pub fn new(max_entries: usize) -> Self {
        CommandRevocationList {
            revocations: Mutex::new(HashMap::new()),
            token_issuer: None,
            max_entries,
        }
    }

    /// Create with token issuer for cascade revocation
    pub fn with_token_issuer(max_entries: usize, token_issuer: std::sync::Arc<ExecutionTokenIssuer>) -> Self {
        CommandRevocationList {
            revocations: Mutex::new(HashMap::new()),
            token_issuer: Some(token_issuer),
            max_entries,
        }
    }

    /// Revoke a command immediately
    pub fn revoke_command(
        &self,
        command_id: String,
        revoked_by: Principal,
        revoked_timestamp_ns: u64,
        reason: String,
    ) -> Result<(), String> {
        self.revoke_command_with_cascade(
            command_id,
            revoked_by,
            revoked_timestamp_ns,
            reason,
            None,
        )
    }

    /// Revoke a command with cascade trigger information
    pub fn revoke_command_with_cascade(
        &self,
        command_id: String,
        revoked_by: Principal,
        revoked_timestamp_ns: u64,
        reason: String,
        cascade_trigger: Option<RevocationCascadeTrigger>,
    ) -> Result<(), String> {
        let entry = CommandRevocationEntry {
            command_id: command_id.clone(),
            revoked_by,
            revoked_timestamp_ns,
            reason,
            cascade_trigger,
        };

        let mut revocations = self.revocations.lock().unwrap();

        // Enforce max_entries limit with simple eviction (remove oldest)
        if revocations.len() >= self.max_entries && !revocations.contains_key(&command_id) {
            // Find and remove oldest entry
            if let Some(oldest_id) = revocations
                .values()
                .min_by_key(|e| e.revoked_timestamp_ns)
                .map(|e| e.command_id.clone())
            {
                revocations.remove(&oldest_id);
            }
        }

        revocations.insert(command_id, entry);
        Ok(())
    }

    /// Check if command is revoked
    pub fn is_command_revoked(&self, command_id: &str) -> bool {
        let revocations = self.revocations.lock().unwrap();
        revocations.contains_key(command_id)
    }

    /// Get revocation entry for a command
    pub fn get_revocation(&self, command_id: &str) -> Option<CommandRevocationEntry> {
        let revocations = self.revocations.lock().unwrap();
        revocations.get(command_id).cloned()
    }

    /// Revoke all commands issued by a principal (cascade)
    pub fn revoke_commands_by_principal(
        &self,
        principal: Principal,
        revoked_timestamp_ns: u64,
        reason: String,
    ) -> Result<usize, String> {
        // This would require tracking which commands were issued by which principal
        // For now, return count of 0 - implementation in future sprints
        // TODO (Sprint 4+): Implement principal->commands mapping for cascade revocation
        Ok(0)
    }

    /// Revoke all commands for a requester principal (cascade)
    pub fn revoke_commands_for_requester(
        &self,
        requester: Principal,
        revoked_timestamp_ns: u64,
        reason: String,
    ) -> Result<usize, String> {
        // This would require tracking which commands were requested by which principal
        // For now, return count of 0 - implementation in future sprints
        // TODO (Sprint 4+): Implement requester->commands mapping for cascade revocation
        Ok(0)
    }

    /// Get all revocations (for audit purposes)
    pub fn get_all_revocations(&self) -> Vec<CommandRevocationEntry> {
        let revocations = self.revocations.lock().unwrap();
        revocations.values().cloned().collect()
    }

    /// Get count of revoked commands
    pub fn revocation_count(&self) -> usize {
        let revocations = self.revocations.lock().unwrap();
        revocations.len()
    }

    /// Clear all revocations (for testing/maintenance)
    pub fn clear_revocations(&self) {
        let mut revocations = self.revocations.lock().unwrap();
        revocations.clear();
    }
}

/// Statistics about command revocations
#[derive(Debug, Clone)]
pub struct RevocationStatistics {
    /// Total number of revoked commands
    pub total_revocations: usize,

    /// Number of revocations by cascade
    pub cascade_revocations: usize,

    /// Most recent revocation timestamp
    pub last_revocation_timestamp_ns: Option<u64>,

    /// Principals that initiated revocations
    pub revocation_initiators: Vec<Principal>,
}

impl CommandRevocationList {
    /// Get statistics about revocations
    pub fn get_statistics(&self) -> RevocationStatistics {
        let revocations = self.revocations.lock().unwrap();

        let cascade_revocations = revocations
            .values()
            .filter(|e| e.cascade_trigger.is_some())
            .count();

        let mut initiators = revocations
            .values()
            .map(|e| e.revoked_by)
            .collect::<Vec<_>>();
        initiators.sort_by_key(|p| format!("{:?}", p));
        initiators.dedup();

        let last_revocation_timestamp_ns = revocations
            .values()
            .max_by_key(|e| e.revoked_timestamp_ns)
            .map(|e| e.revoked_timestamp_ns);

        RevocationStatistics {
            total_revocations: revocations.len(),
            cascade_revocations,
            last_revocation_timestamp_ns,
            revocation_initiators: initiators,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_list_creation() {
        let list = CommandRevocationList::new(1000);
        assert_eq!(list.revocation_count(), 0);
        assert!(!list.is_command_revoked("cmd-1"));
    }

    #[test]
    fn test_revoke_single_command() {
        let list = CommandRevocationList::new(1000);

        let result = list.revoke_command(
            "cmd-1".to_string(),
            Principal::Policy,
            1000,
            "Malicious payload detected".to_string(),
        );

        assert!(result.is_ok());
        assert!(list.is_command_revoked("cmd-1"));
        assert_eq!(list.revocation_count(), 1);
    }

    #[test]
    fn test_revoke_multiple_commands() {
        let list = CommandRevocationList::new(1000);

        for i in 0..5 {
            assert!(list
                .revoke_command(
                    format!("cmd-{}", i),
                    Principal::Policy,
                    1000 + i as u64,
                    "Test revocation".to_string(),
                )
                .is_ok());
        }

        assert_eq!(list.revocation_count(), 5);
        assert!(list.is_command_revoked("cmd-3"));
        assert!(!list.is_command_revoked("cmd-99"));
    }

    #[test]
    fn test_revocation_entry_retrieval() {
        let list = CommandRevocationList::new(1000);

        list.revoke_command(
            "cmd-1".to_string(),
            Principal::Supervisor,
            2000,
            "Security violation".to_string(),
        )
        .unwrap();

        let entry = list.get_revocation("cmd-1");
        assert!(entry.is_some());

        let entry = entry.unwrap();
        assert_eq!(entry.command_id, "cmd-1");
        assert_eq!(entry.revoked_by, Principal::Supervisor);
        assert_eq!(entry.revoked_timestamp_ns, 2000);
        assert_eq!(entry.reason, "Security violation");
    }

    #[test]
    fn test_cascade_revocation() {
        let list = CommandRevocationList::new(1000);

        let trigger = RevocationCascadeTrigger::PrincipalRevoked(Principal::Actuator);

        list.revoke_command_with_cascade(
            "cmd-1".to_string(),
            Principal::Supervisor,
            3000,
            "Principal compromised".to_string(),
            Some(trigger),
        )
        .unwrap();

        let entry = list.get_revocation("cmd-1").unwrap();
        assert!(entry.cascade_trigger.is_some());

        match entry.cascade_trigger.unwrap() {
            RevocationCascadeTrigger::PrincipalRevoked(p) => assert_eq!(p, Principal::Actuator),
            _ => panic!("Wrong cascade trigger"),
        }
    }

    #[test]
    fn test_revocation_statistics() {
        let list = CommandRevocationList::new(1000);

        // Add regular revocation
        list.revoke_command(
            "cmd-1".to_string(),
            Principal::Policy,
            1000,
            "Malicious".to_string(),
        )
        .unwrap();

        // Add cascade revocation
        let trigger = RevocationCascadeTrigger::CertificateExpired(Principal::Evaluator);
        list.revoke_command_with_cascade(
            "cmd-2".to_string(),
            Principal::Supervisor,
            2000,
            "Certificate expired".to_string(),
            Some(trigger),
        )
        .unwrap();

        let stats = list.get_statistics();
        assert_eq!(stats.total_revocations, 2);
        assert_eq!(stats.cascade_revocations, 1);
        assert_eq!(stats.last_revocation_timestamp_ns, Some(2000));
        assert!(stats.revocation_initiators.contains(&Principal::Policy));
        assert!(stats.revocation_initiators.contains(&Principal::Supervisor));
    }

    #[test]
    fn test_max_entries_eviction() {
        let list = CommandRevocationList::new(3);

        // Add 5 commands, but list can only hold 3
        for i in 0..5 {
            list.revoke_command(
                format!("cmd-{}", i),
                Principal::Policy,
                1000 + i as u64,
                "Test".to_string(),
            )
            .unwrap();
        }

        // Should only have 3 entries (oldest evicted)
        assert_eq!(list.revocation_count(), 3);

        // Oldest entries (0, 1) should be evicted, newer ones (2, 3, 4) kept
        assert!(!list.is_command_revoked("cmd-0"));
        assert!(!list.is_command_revoked("cmd-1"));
        assert!(list.is_command_revoked("cmd-2"));
        assert!(list.is_command_revoked("cmd-3"));
        assert!(list.is_command_revoked("cmd-4"));
    }

    #[test]
    fn test_clear_revocations() {
        let list = CommandRevocationList::new(1000);

        list.revoke_command(
            "cmd-1".to_string(),
            Principal::Policy,
            1000,
            "Test".to_string(),
        )
        .unwrap();

        assert_eq!(list.revocation_count(), 1);

        list.clear_revocations();

        assert_eq!(list.revocation_count(), 0);
        assert!(!list.is_command_revoked("cmd-1"));
    }

    #[test]
    fn test_revocation_entry_display() {
        let trigger = RevocationCascadeTrigger::SecurityViolation("Injection detected".to_string());
        assert!(format!("{}", trigger).contains("Injection detected"));
    }
}
