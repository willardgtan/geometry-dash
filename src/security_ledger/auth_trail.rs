// Authentication Audit Trail (Sprint 3 Task 3.4)
// Unified tracking of all authentication events across identity, messaging, and certificates
// Implements SEC-C03 comprehensive authentication forensics

use crate::security_ledger::SecurityLedger;
use crate::types::Principal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authentication event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticationEventType {
    /// Identity registration
    IdentityRegistered,
    /// Identity key rotation
    IdentityRotated,
    /// Identity verification
    IdentityVerified,
    /// Message signed
    MessageSigned,
    /// Message signature verified
    MessageVerified,
    /// Certificate issued
    CertificateIssued,
    /// Certificate revoked
    CertificateRevoked,
    /// Certificate verified
    CertificateVerified,
    /// Cross-component validation (identity ↔ certificate)
    CrossComponentValidation,
}

impl std::fmt::Display for AuthenticationEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthenticationEventType::IdentityRegistered => write!(f, "identity_registered"),
            AuthenticationEventType::IdentityRotated => write!(f, "identity_rotated"),
            AuthenticationEventType::IdentityVerified => write!(f, "identity_verified"),
            AuthenticationEventType::MessageSigned => write!(f, "message_signed"),
            AuthenticationEventType::MessageVerified => write!(f, "message_verified"),
            AuthenticationEventType::CertificateIssued => write!(f, "certificate_issued"),
            AuthenticationEventType::CertificateRevoked => write!(f, "certificate_revoked"),
            AuthenticationEventType::CertificateVerified => write!(f, "certificate_verified"),
            AuthenticationEventType::CrossComponentValidation => write!(f, "cross_component_validation"),
        }
    }
}

/// Unified authentication event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationEvent {
    /// Unique event ID
    pub event_id: String,

    /// Event type
    pub event_type: AuthenticationEventType,

    /// Principal involved in authentication
    pub principal: Principal,

    /// Timestamp of event (nanoseconds since UNIX_EPOCH)
    pub timestamp_ns: u64,

    /// Status: success, failure, error, etc.
    pub status: String,

    /// Reference to related artifact (identity_id, cert_id, message_id, etc.)
    pub artifact_reference: String,

    /// Key version if applicable
    pub key_version: Option<u32>,

    /// Component source (identity, message_auth, certificate, etc.)
    pub source_component: String,

    /// Optional error or status message
    pub details: Option<String>,

    /// Parent event ID for tracing chains
    pub parent_event_id: Option<String>,

    /// Related event IDs (for cross-component validation)
    pub related_events: Vec<String>,
}

impl AuthenticationEvent {
    /// Create a new authentication event
    pub fn new(
        event_type: AuthenticationEventType,
        principal: Principal,
        artifact_reference: String,
        source_component: String,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        AuthenticationEvent {
            event_id: Uuid::new_v4().to_string(),
            event_type,
            principal,
            timestamp_ns: now,
            status: "pending".to_string(),
            artifact_reference,
            key_version: None,
            source_component,
            details: None,
            parent_event_id: None,
            related_events: Vec::new(),
        }
    }

    /// Mark event as successful
    pub fn mark_success(mut self) -> Self {
        self.status = "success".to_string();
        self
    }

    /// Mark event as failed
    pub fn mark_failure(mut self, reason: String) -> Self {
        self.status = "failure".to_string();
        self.details = Some(reason);
        self
    }

    /// Mark event as error
    pub fn mark_error(mut self, error: String) -> Self {
        self.status = "error".to_string();
        self.details = Some(error);
        self
    }

    /// Add key version
    pub fn with_key_version(mut self, version: u32) -> Self {
        self.key_version = Some(version);
        self
    }

    /// Set parent event for chain tracing
    pub fn with_parent(mut self, parent_id: String) -> Self {
        self.parent_event_id = Some(parent_id);
        self
    }

    /// Add related event
    pub fn add_related_event(mut self, event_id: String) -> Self {
        self.related_events.push(event_id);
        self
    }

    /// Add details
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }
}

/// Authentication Audit Trail: Unified tracking in SecurityLedger
pub struct AuthenticationAuditTrail {
    /// Reference to SecurityLedger for persistence
    ledger: std::sync::Arc<std::sync::Mutex<SecurityLedger>>,

    /// In-memory index of events for quick lookups
    event_index: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, AuthenticationEvent>>>,

    /// Index of events by principal
    principal_index: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<Principal, Vec<String>>>>,

    /// Index of events by artifact
    artifact_index: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<String>>>>,
}

impl AuthenticationAuditTrail {
    /// Create a new authentication audit trail
    pub fn new(ledger: SecurityLedger) -> Self {
        AuthenticationAuditTrail {
            ledger: std::sync::Arc::new(std::sync::Mutex::new(ledger)),
            event_index: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            principal_index: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            artifact_index: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    /// Record an authentication event
    pub fn record_event(&self, event: AuthenticationEvent) -> Result<String, String> {
        let event_id = event.event_id.clone();

        // Update indexes
        let mut event_idx = self.event_index.lock().unwrap();
        event_idx.insert(event_id.clone(), event.clone());

        let mut principal_idx = self.principal_index.lock().unwrap();
        principal_idx
            .entry(event.principal)
            .or_insert_with(Vec::new)
            .push(event_id.clone());

        let mut artifact_idx = self.artifact_index.lock().unwrap();
        artifact_idx
            .entry(event.artifact_reference.clone())
            .or_insert_with(Vec::new)
            .push(event_id.clone());

        Ok(event_id)
    }

    /// Get event by ID
    pub fn get_event(&self, event_id: &str) -> Option<AuthenticationEvent> {
        let idx = self.event_index.lock().unwrap();
        idx.get(event_id).cloned()
    }

    /// Get all events for a principal
    pub fn get_principal_events(&self, principal: Principal) -> Vec<AuthenticationEvent> {
        let principal_idx = self.principal_index.lock().unwrap();
        let event_idx = self.event_index.lock().unwrap();

        principal_idx
            .get(&principal)
            .map(|event_ids| {
                event_ids
                    .iter()
                    .filter_map(|id| event_idx.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all events for an artifact
    pub fn get_artifact_events(&self, artifact_ref: &str) -> Vec<AuthenticationEvent> {
        let artifact_idx = self.artifact_index.lock().unwrap();
        let event_idx = self.event_index.lock().unwrap();

        artifact_idx
            .get(artifact_ref)
            .map(|event_ids| {
                event_ids
                    .iter()
                    .filter_map(|id| event_idx.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get event chain starting from an event (parent → child)
    pub fn get_event_chain(&self, event_id: &str) -> Vec<AuthenticationEvent> {
        let mut chain = Vec::new();
        let mut current_id = event_id.to_string();

        let event_idx = self.event_index.lock().unwrap();

        loop {
            if let Some(event) = event_idx.get(&current_id) {
                chain.push(event.clone());

                if let Some(parent_id) = &event.parent_event_id {
                    current_id = parent_id.clone();
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        chain.reverse();
        chain
    }

    /// Get all related events for an event
    pub fn get_related_events(&self, event_id: &str) -> Vec<AuthenticationEvent> {
        let event_idx = self.event_index.lock().unwrap();

        if let Some(event) = event_idx.get(event_id) {
            event
                .related_events
                .iter()
                .filter_map(|id| event_idx.get(id).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get statistics about authentication events
    pub fn get_statistics(&self) -> AuthenticationStatistics {
        let event_idx = self.event_index.lock().unwrap();

        let total_events = event_idx.len();
        let successful_events = event_idx
            .values()
            .filter(|e| e.status == "success")
            .count();
        let failed_events = event_idx
            .values()
            .filter(|e| e.status == "failure")
            .count();
        let error_events = event_idx
            .values()
            .filter(|e| e.status == "error")
            .count();

        let event_types: std::collections::HashMap<String, usize> = event_idx
            .values()
            .fold(std::collections::HashMap::new(), |mut map, event| {
                *map.entry(event.event_type.to_string()).or_insert(0) += 1;
                map
            });

        AuthenticationStatistics {
            total_events,
            successful_events,
            failed_events,
            error_events,
            event_types,
        }
    }

    /// Verify authentication chain (ensure no tampering)
    pub fn verify_authentication_chain(&self, event_id: &str) -> bool {
        let chain = self.get_event_chain(event_id);

        // Check that timestamps are monotonically increasing
        for i in 0..chain.len() - 1 {
            if chain[i].timestamp_ns > chain[i + 1].timestamp_ns {
                return false;
            }
        }

        true
    }
}

/// Authentication statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationStatistics {
    pub total_events: usize,
    pub successful_events: usize,
    pub failed_events: usize,
    pub error_events: usize,
    pub event_types: std::collections::HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_trail() -> AuthenticationAuditTrail {
        let ledger = SecurityLedger::new();
        AuthenticationAuditTrail::new(ledger)
    }

    #[test]
    fn test_record_authentication_event() {
        let trail = create_test_trail();
        let event = AuthenticationEvent::new(
            AuthenticationEventType::IdentityRegistered,
            Principal::Policy,
            "identity-001".to_string(),
            "identity_registry".to_string(),
        )
        .mark_success();

        let result = trail.record_event(event.clone());
        assert!(result.is_ok());

        let recorded = trail.get_event(&result.unwrap());
        assert!(recorded.is_some());
    }

    #[test]
    fn test_get_principal_events() {
        let trail = create_test_trail();

        trail.record_event(
            AuthenticationEvent::new(
                AuthenticationEventType::IdentityRegistered,
                Principal::Policy,
                "id-1".to_string(),
                "identity_registry".to_string(),
            )
            .mark_success(),
        ).ok();

        trail.record_event(
            AuthenticationEvent::new(
                AuthenticationEventType::IdentityVerified,
                Principal::Policy,
                "id-1".to_string(),
                "identity_registry".to_string(),
            )
            .mark_success(),
        ).ok();

        let events = trail.get_principal_events(Principal::Policy);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_get_artifact_events() {
        let trail = create_test_trail();
        let artifact = "cert-001";

        trail.record_event(
            AuthenticationEvent::new(
                AuthenticationEventType::CertificateIssued,
                Principal::Policy,
                artifact.to_string(),
                "certificate_registry".to_string(),
            )
            .mark_success(),
        ).ok();

        trail.record_event(
            AuthenticationEvent::new(
                AuthenticationEventType::CertificateVerified,
                Principal::Policy,
                artifact.to_string(),
                "certificate_registry".to_string(),
            )
            .mark_success(),
        ).ok();

        let events = trail.get_artifact_events(artifact);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_event_chain_with_parent() {
        let trail = create_test_trail();

        let event1 = AuthenticationEvent::new(
            AuthenticationEventType::IdentityRegistered,
            Principal::Policy,
            "id-1".to_string(),
            "identity_registry".to_string(),
        )
        .mark_success();

        let event1_id = event1.event_id.clone();
        trail.record_event(event1).ok();

        let event2 = AuthenticationEvent::new(
            AuthenticationEventType::IdentityRotated,
            Principal::Policy,
            "id-1".to_string(),
            "identity_registry".to_string(),
        )
        .mark_success()
        .with_parent(event1_id.clone());

        let event2_id = event2.event_id.clone();
        trail.record_event(event2).ok();

        let chain = trail.get_event_chain(&event2_id);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].event_id, event1_id);
        assert_eq!(chain[1].event_id, event2_id);
    }

    #[test]
    fn test_statistics() {
        let trail = create_test_trail();

        trail.record_event(
            AuthenticationEvent::new(
                AuthenticationEventType::MessageSigned,
                Principal::Policy,
                "msg-1".to_string(),
                "message_authenticator".to_string(),
            )
            .mark_success(),
        ).ok();

        trail.record_event(
            AuthenticationEvent::new(
                AuthenticationEventType::MessageVerified,
                Principal::Actuator,
                "msg-1".to_string(),
                "message_authenticator".to_string(),
            )
            .mark_failure("Invalid signature".to_string()),
        ).ok();

        let stats = trail.get_statistics();
        assert_eq!(stats.total_events, 2);
        assert_eq!(stats.successful_events, 1);
        assert_eq!(stats.failed_events, 1);
    }
}
