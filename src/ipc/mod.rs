// Inter-Process Communication (IPC) Layer (Week 1 Task 3)
// Implements the 22 critical interfaces (IF-001 through IF-022)
// Provides: Named pipes transport, message authentication, nonce caching, peer credential validation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::types::{Principal, InterfaceId};

pub mod message;
pub mod handshake;
pub mod pipes;
pub mod authenticator;
pub mod gateway;
pub mod token;
pub mod execution_context;

#[cfg(test)]
mod sprint3_integration_tests;

pub use message::{UniversalMessage, UniversalMessageHeader};
pub use handshake::{HandshakeMessage, HandshakeCoordinator, HandshakeState, HandshakeMessageType};
pub use pipes::{PipeManager, PipeInfo};
pub use authenticator::{IpcMessageAuthenticator, SignatureResult, VerificationResult, AuthenticationAuditRecord, AuthenticationStatistics};
pub use gateway::{IpcMessageGateway, GatewayResult, AuthorizationDecision, GatewayStatistics};
pub use token::{ExecutionToken, TokenStatus, ExecutionTokenIssuer, ExecutionTokenVerifier, TokenStatistics};
pub use execution_context::{ExecutionState, GateCSnapshot, GateISnapshot, CommandSnapshot, PrincipalStateSnapshot, CommandExecutionContext, ValidatedCommand, ExecutionLock};

/// IPC-level errors
#[derive(Debug, Clone)]
pub enum IpcError {
    PipeCreationFailed(String),
    WriteFailed(String),
    ReadFailed(String),
    Timeout,
    AuthenticationFailed(String),
    NonceRejected(String),
    InvalidPrincipal,
    PeerCredentialMismatch,
    SerializationError(String),
    FileSystemError(String),
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IpcError::PipeCreationFailed(s) => write!(f, "Pipe creation failed: {}", s),
            IpcError::WriteFailed(s) => write!(f, "Write failed: {}", s),
            IpcError::ReadFailed(s) => write!(f, "Read failed: {}", s),
            IpcError::Timeout => write!(f, "IPC timeout"),
            IpcError::AuthenticationFailed(s) => write!(f, "Authentication failed: {}", s),
            IpcError::NonceRejected(s) => write!(f, "Nonce rejected: {}", s),
            IpcError::InvalidPrincipal => write!(f, "Invalid principal"),
            IpcError::PeerCredentialMismatch => write!(f, "Peer credential mismatch"),
            IpcError::SerializationError(s) => write!(f, "Serialization error: {}", s),
            IpcError::FileSystemError(s) => write!(f, "Filesystem error: {}", s),
        }
    }
}

impl std::error::Error for IpcError {}

/// Nonce cache entry for replay detection
#[derive(Debug, Clone)]
struct NonceEntry {
    timestamp_ns: u64,
    interface_id: u32,
    message_id: u64,
    sender_principal: u8,
}

/// Nonce cache: tracks recently seen nonces to prevent replay attacks
pub struct NonceCache {
    cache: Mutex<HashMap<[u8; 32], NonceEntry>>,
    ttl: Duration,
    max_entries: usize,
}

impl NonceCache {
    /// Create a new nonce cache with TTL and max entries
    pub fn new(ttl_ms: u64, max_entries: usize) -> Self {
        NonceCache {
            cache: Mutex::new(HashMap::new()),
            ttl: Duration::from_millis(ttl_ms),
            max_entries,
        }
    }

    /// Check if nonce is valid (not a replay)
    pub fn check_and_insert(&self, nonce: [u8; 32], interface_id: u32, message_id: u64, sender: u8, timestamp_ns: u64) -> Result<(), IpcError> {
        let mut cache = self.cache.lock().unwrap();

        // If nonce exists and is still within TTL, reject as replay
        if let Some(entry) = cache.get(&nonce) {
            if timestamp_ns < entry.timestamp_ns + self.ttl.as_nanos() as u64 {
                return Err(IpcError::NonceRejected(format!(
                    "Nonce already used at message {} on IF-{:03d}",
                    entry.message_id, entry.interface_id
                )));
            }
        }

        // Add to cache
        cache.insert(nonce, NonceEntry {
            timestamp_ns,
            interface_id,
            message_id,
            sender_principal: sender,
        });

        // Evict oldest entries if cache exceeds max
        if cache.len() > self.max_entries {
            // Find and remove the oldest entry
            if let Some(oldest_nonce) = cache.iter()
                .min_by_key(|(_, entry)| entry.timestamp_ns)
                .map(|(nonce, _)| *nonce) {
                cache.remove(&oldest_nonce);
            }
        }

        Ok(())
    }

    /// Clear expired entries from cache (optional cleanup)
    pub fn cleanup_expired(&self, current_time_ns: u64) {
        let mut cache = self.cache.lock().unwrap();
        let ttl_ns = self.ttl.as_nanos() as u64;

        cache.retain(|_, entry| {
            current_time_ns < entry.timestamp_ns + ttl_ns
        });
    }

    /// Get cache statistics for monitoring
    pub fn stats(&self) -> (usize, usize) {
        let cache = self.cache.lock().unwrap();
        (cache.len(), self.max_entries)
    }
}

/// Capability matrix: who can use which interfaces
pub struct CapabilityMatrix {
    matrix: HashMap<u8, Vec<u32>>, // principal -> list of interface IDs allowed
}

impl CapabilityMatrix {
    /// Create a new capability matrix (populated from config at startup)
    pub fn new() -> Self {
        CapabilityMatrix {
            matrix: HashMap::new(),
        }
    }

    /// Add a capability: principal can use interface
    pub fn allow(&mut self, principal: u8, interface_id: u32) {
        self.matrix.entry(principal).or_insert_with(Vec::new).push(interface_id);
    }

    /// Check if principal can use interface
    pub fn can_use(&self, principal: u8, interface_id: u32) -> bool {
        self.matrix.get(&principal)
            .map(|interfaces| interfaces.contains(&interface_id))
            .unwrap_or(false)
    }

    /// Get all interfaces available to a principal
    pub fn list_interfaces(&self, principal: u8) -> Vec<u32> {
        self.matrix.get(&principal).cloned().unwrap_or_default()
    }
}

/// Convert current time to nanoseconds since UNIX_EPOCH
pub fn current_timestamp_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_cache_new() {
        let cache = NonceCache::new(5000, 100000);
        let (size, max) = cache.stats();
        assert_eq!(size, 0);
        assert_eq!(max, 100000);
    }

    #[test]
    fn test_nonce_cache_accept_new() {
        let cache = NonceCache::new(5000, 100);
        let nonce = [1u8; 32];
        let ts = current_timestamp_ns();

        let result = cache.check_and_insert(nonce, 1, 100, 1, ts);
        assert!(result.is_ok());

        let (size, _) = cache.stats();
        assert_eq!(size, 1);
    }

    #[test]
    fn test_nonce_cache_reject_replay() {
        let cache = NonceCache::new(5000, 100);
        let nonce = [2u8; 32];
        let ts = current_timestamp_ns();

        // First insertion should succeed
        assert!(cache.check_and_insert(nonce, 1, 100, 1, ts).is_ok());

        // Second insertion with same nonce should fail
        let result = cache.check_and_insert(nonce, 1, 101, 1, ts + 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_capability_matrix() {
        let mut matrix = CapabilityMatrix::new();

        // Add capabilities
        matrix.allow(1, 2);  // Policy can use IF-002
        matrix.allow(1, 4);  // Policy can use IF-004
        matrix.allow(3, 2);  // Audit can use IF-002

        // Check capabilities
        assert!(matrix.can_use(1, 2));
        assert!(matrix.can_use(1, 4));
        assert!(matrix.can_use(3, 2));
        assert!(!matrix.can_use(1, 3));  // Policy cannot use IF-003
        assert!(!matrix.can_use(2, 2));  // Actuator not configured
    }

    #[test]
    fn test_capability_list_interfaces() {
        let mut matrix = CapabilityMatrix::new();
        matrix.allow(1, 2);
        matrix.allow(1, 3);
        matrix.allow(1, 4);

        let interfaces = matrix.list_interfaces(1);
        assert_eq!(interfaces.len(), 3);
        assert!(interfaces.contains(&2));
        assert!(interfaces.contains(&3));
        assert!(interfaces.contains(&4));
    }
}
