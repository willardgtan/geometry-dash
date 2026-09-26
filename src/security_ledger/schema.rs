// SecurityLedger Event Schema (Week 1 Task 2.1)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::types::Principal;

/// Security event types (23 types covering supervisor, principal, action, crypto, and error events)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    SupervisorStart,
    PrincipalStart,
    PrincipalReady,
    PrincipalCrash,
    PrincipalRestart,
    PrincipalShutdown,
    ActionRequested,
    ActionApproved,
    ActionDenied,
    ActionExecuted,
    ArtifactSealed,
    ArtifactDeclassified,
    SignatureVerified,
    SignatureFailed,
    NonceAccepted,
    NonceRejected,
    TimestampStale,
    ConfigLoaded,
    ConfigImmutable,
    LockdownEntered,
    RecoveryAttempted,
    Error,
    SecurityIssue,
}

/// Severity levels for security events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

/// A single security event in the append-only ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    // Core identity
    pub ledger_index: u64,                  // Entry number in ledger (0-indexed)
    pub timestamp_ns: u64,                  // Monotonic nanosecond timestamp

    // Event classification
    pub event_type: EventType,              // What happened (supervisor start, action, etc)
    pub severity: Severity,                 // Log level (debug, info, warn, error, critical)
    pub principal: Principal,               // Who caused it (PRN-SUPERVISOR, PRN-POLICY, etc)

    // Request/boot/epoch context
    pub run_id: String,                     // Request ID (UUID format)
    pub boot_id: String,                    // System boot ID
    pub epoch_id: String,                   // HSM-signed epoch boundary

    // Hash chain for tamper detection
    pub prev_entry_hash: [u8; 32],         // SHA-256 of previous entry (or zero for first)
    pub current_entry_hash: [u8; 32],      // SHA-256 of this entry (calculated at write time)

    // Optional interface context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_id: Option<u32>,          // IF-001 through IF-022 if applicable

    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<u64>,            // Message sequence number if applicable

    // Event details (variable, interface-specific)
    pub details: HashMap<String, String>,   // Key-value pairs for forensic analysis
}

impl SecurityEvent {
    /// Create a new security event with zero current_entry_hash (to be calculated)
    pub fn new(
        ledger_index: u64,
        event_type: EventType,
        principal: Principal,
        severity: Severity,
        run_id: String,
        boot_id: String,
        epoch_id: String,
        prev_entry_hash: [u8; 32],
        current_entry_hash: [u8; 32],
        details: HashMap<String, String>,
    ) -> Self {
        let timestamp_ns = Self::current_timestamp_ns();

        SecurityEvent {
            ledger_index,
            timestamp_ns,
            event_type,
            severity,
            principal,
            run_id,
            boot_id,
            epoch_id,
            prev_entry_hash,
            current_entry_hash,
            interface_id: None,
            message_id: None,
            details,
        }
    }

    /// Get current monotonic timestamp in nanoseconds
    fn current_timestamp_ns() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Set interface context for this event
    pub fn set_interface(&mut self, interface_id: u32, message_id: u64) {
        self.interface_id = Some(interface_id);
        self.message_id = Some(message_id);
    }

    /// Add a detail field
    pub fn add_detail(&mut self, key: String, value: String) {
        self.details.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let mut details = HashMap::new();
        details.insert("test".to_string(), "value".to_string());

        let event = SecurityEvent::new(
            0,
            EventType::SupervisorStart,
            Principal::Supervisor,
            Severity::Info,
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
            [0u8; 32],
            [0u8; 32],
            details,
        );

        assert_eq!(event.ledger_index, 0);
        assert_eq!(event.event_type, EventType::SupervisorStart);
        assert_eq!(event.severity, Severity::Info);
    }

    #[test]
    fn test_event_serialization() {
        let mut details = HashMap::new();
        details.insert("action".to_string(), "TEST".to_string());

        let event = SecurityEvent::new(
            1,
            EventType::ActionRequested,
            Principal::Policy,
            Severity::Info,
            "run-002".to_string(),
            "boot-002".to_string(),
            "epoch-002".to_string(),
            [1u8; 32],
            [2u8; 32],
            details,
        );

        let json = serde_json::to_string(&event).unwrap();
        let parsed: SecurityEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.ledger_index, event.ledger_index);
        assert_eq!(parsed.event_type, event.event_type);
    }

    #[test]
    fn test_event_with_interface() {
        let details = HashMap::new();
        let mut event = SecurityEvent::new(
            2,
            EventType::ActionApproved,
            Principal::Audit,
            Severity::Info,
            "run-003".to_string(),
            "boot-003".to_string(),
            "epoch-003".to_string(),
            [3u8; 32],
            [4u8; 32],
            details,
        );

        event.set_interface(2, 100);
        assert_eq!(event.interface_id, Some(2));
        assert_eq!(event.message_id, Some(100));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Debug < Severity::Info);
        assert!(Severity::Info < Severity::Warn);
        assert!(Severity::Warn < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }
}
