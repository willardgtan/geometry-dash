// Principal Identity Management System (Sprint 3 Task 3.1)
// Manages Ed25519 key pairs and identity verification for all principals
// Implements SEC-C03 Cross-Boundary Authentication

use crate::types::Principal;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Ed25519 public key (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        PublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        if hex_str.len() != 64 {
            return Err("Public key hex must be 64 characters (32 bytes)".to_string());
        }
        let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err("Decoded public key must be 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(PublicKey(arr))
    }
}

/// Ed25519 private key (64 bytes: 32-byte seed + 32-byte public key)
#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateKey([u8; 64]);

impl PrivateKey {
    pub fn new(bytes: [u8; 64]) -> Self {
        PrivateKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        if hex_str.len() != 128 {
            return Err("Private key hex must be 128 characters (64 bytes)".to_string());
        }
        let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
        if bytes.len() != 64 {
            return Err("Decoded private key must be 64 bytes".to_string());
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(PrivateKey(arr))
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("hex", &"[REDACTED]")
            .finish()
    }
}

/// Principal identity certificate with public key and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalIdentity {
    /// Unique identity ID
    pub identity_id: String,

    /// Principal this identity belongs to
    pub principal: Principal,

    /// Ed25519 public key for this principal
    pub public_key: PublicKey,

    /// Key version for rotation tracking
    pub key_version: u32,

    /// Timestamp when this identity was created (nanoseconds since UNIX_EPOCH)
    pub created_timestamp_ns: u64,

    /// Timestamp when this identity expires (if any), None = no expiration
    pub expires_timestamp_ns: Option<u64>,

    /// Whether this identity is currently active
    pub is_active: bool,

    /// Purpose/role of this identity
    pub purpose: String,

    /// Hash of the public key for integrity verification
    pub public_key_hash: String,
}

impl PrincipalIdentity {
    /// Create a new principal identity
    pub fn new(
        principal: Principal,
        public_key: PublicKey,
        key_version: u32,
        purpose: String,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let identity_id = Uuid::new_v4().to_string();

        // Compute SHA-256 hash of public key for integrity
        let mut hasher = sha2::Sha256::new();
        hasher.update(public_key.as_bytes());
        let public_key_hash = hex::encode(hasher.finalize());

        PrincipalIdentity {
            identity_id,
            principal,
            public_key,
            key_version,
            created_timestamp_ns: now,
            expires_timestamp_ns: None,
            is_active: true,
            purpose,
            public_key_hash,
        }
    }

    /// Set expiration timestamp
    pub fn with_expiration(mut self, expires_ns: u64) -> Self {
        self.expires_timestamp_ns = Some(expires_ns);
        self
    }

    /// Check if this identity is currently valid
    pub fn is_valid(&self) -> bool {
        if !self.is_active {
            return false;
        }

        if let Some(expires_ns) = self.expires_timestamp_ns {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            if now > expires_ns {
                return false;
            }
        }

        true
    }

    /// Verify the public key hash for tamper detection
    pub fn verify_integrity(&self) -> bool {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.public_key.as_bytes());
        let computed_hash = hex::encode(hasher.finalize());
        computed_hash == self.public_key_hash
    }
}

/// Key pair (public + private) for a principal
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        KeyPair {
            public_key,
            private_key,
        }
    }
}

/// Principal identity registry: manages all principal identities and key pairs
pub struct PrincipalIdentityRegistry {
    // Map: Principal -> current active identity
    active_identities: Arc<Mutex<HashMap<Principal, PrincipalIdentity>>>,

    // Map: Principal -> all identities (including rotated)
    all_identities: Arc<Mutex<HashMap<Principal, Vec<PrincipalIdentity>>>>,

    // Map: Principal -> current key pair (private key - sensitive data)
    key_pairs: Arc<Mutex<HashMap<Principal, KeyPair>>>,

    // Append-only log of identity operations for audit
    identity_audit_log: Arc<Mutex<Vec<IdentityAuditRecord>>>,
}

/// Audit record for identity operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAuditRecord {
    pub record_id: String,
    pub operation: String,
    pub principal: Principal,
    pub identity_id: String,
    pub timestamp_ns: u64,
    pub status: String, // "success" or error message
}

impl PrincipalIdentityRegistry {
    /// Create a new identity registry
    pub fn new() -> Self {
        PrincipalIdentityRegistry {
            active_identities: Arc::new(Mutex::new(HashMap::new())),
            all_identities: Arc::new(Mutex::new(HashMap::new())),
            key_pairs: Arc::new(Mutex::new(HashMap::new())),
            identity_audit_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Register a new identity for a principal
    pub fn register_identity(
        &self,
        principal: Principal,
        public_key: PublicKey,
        private_key: PrivateKey,
        purpose: String,
    ) -> Result<PrincipalIdentity, String> {
        let mut active = self.active_identities.lock().unwrap();
        let mut all = self.all_identities.lock().unwrap();
        let mut keys = self.key_pairs.lock().unwrap();

        // Check if principal already has an active identity
        if active.contains_key(&principal) {
            return Err(format!(
                "Principal {} already has an active identity",
                principal
            ));
        }

        // Determine key version (next version after existing ones)
        let key_version = all
            .get(&principal)
            .map(|v| v.iter().map(|id| id.key_version).max().unwrap_or(0) + 1)
            .unwrap_or(1);

        // Create new identity
        let identity = PrincipalIdentity::new(principal, public_key, key_version, purpose);

        // Store identity
        active.insert(principal, identity.clone());

        all.entry(principal)
            .or_insert_with(Vec::new)
            .push(identity.clone());

        // Store key pair
        let key_pair = KeyPair::new(public_key, private_key);
        keys.insert(principal, key_pair);

        // Log to audit trail
        self.log_identity_operation(
            "register_identity",
            principal,
            identity.identity_id.clone(),
            "success",
        );

        Ok(identity)
    }

    /// Get the active identity for a principal
    pub fn get_active_identity(&self, principal: Principal) -> Option<PrincipalIdentity> {
        let active = self.active_identities.lock().unwrap();
        active.get(&principal).cloned()
    }

    /// Get all identities for a principal (including rotated/archived)
    pub fn get_all_identities(&self, principal: Principal) -> Vec<PrincipalIdentity> {
        let all = self.all_identities.lock().unwrap();
        all.get(&principal).cloned().unwrap_or_default()
    }

    /// Get the key pair for a principal (requires careful handling of private key)
    pub fn get_key_pair(&self, principal: Principal) -> Option<KeyPair> {
        let keys = self.key_pairs.lock().unwrap();
        keys.get(&principal).cloned()
    }

    /// Rotate the key pair for a principal
    pub fn rotate_key(&self, principal: Principal, new_public_key: PublicKey, new_private_key: PrivateKey) -> Result<PrincipalIdentity, String> {
        let mut active = self.active_identities.lock().unwrap();
        let mut all = self.all_identities.lock().unwrap();
        let mut keys = self.key_pairs.lock().unwrap();

        // Get current active identity
        let current = active
            .get(&principal)
            .ok_or(format!("No active identity for principal {}", principal))?;

        // Deactivate current identity
        let mut archived_identity = current.clone();
        archived_identity.is_active = false;

        // Get next key version
        let key_version = current.key_version + 1;

        // Create new identity with new key
        let mut new_identity = PrincipalIdentity::new(
            principal,
            new_public_key,
            key_version,
            current.purpose.clone(),
        );

        // Replace active identity
        active.insert(principal, new_identity.clone());

        // Archive old identity and store new one
        all.entry(principal)
            .or_insert_with(Vec::new)
            .push(new_identity.clone());

        // Update key pair
        let new_key_pair = KeyPair::new(new_public_key, new_private_key);
        keys.insert(principal, new_key_pair);

        // Log to audit trail
        self.log_identity_operation(
            "rotate_key",
            principal,
            new_identity.identity_id.clone(),
            "success",
        );

        Ok(new_identity)
    }

    /// Verify a principal's identity (public key integrity check)
    pub fn verify_identity(&self, principal: Principal) -> Result<bool, String> {
        let identity = self
            .get_active_identity(principal)
            .ok_or(format!("No active identity for principal {}", principal))?;

        let is_valid = identity.verify_integrity();

        self.log_identity_operation(
            "verify_identity",
            principal,
            identity.identity_id,
            if is_valid { "success" } else { "integrity_check_failed" },
        );

        Ok(is_valid)
    }

    /// Get all principals with registered identities
    pub fn get_registered_principals(&self) -> Vec<Principal> {
        let active = self.active_identities.lock().unwrap();
        active.keys().copied().collect()
    }

    /// Log an identity operation to audit trail
    fn log_identity_operation(
        &self,
        operation: &str,
        principal: Principal,
        identity_id: String,
        status: &str,
    ) {
        let record = IdentityAuditRecord {
            record_id: Uuid::new_v4().to_string(),
            operation: operation.to_string(),
            principal,
            identity_id,
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            status: status.to_string(),
        };

        let mut log = self.identity_audit_log.lock().unwrap();
        log.push(record);
    }

    /// Get audit log entries
    pub fn get_audit_log(&self) -> Vec<IdentityAuditRecord> {
        let log = self.identity_audit_log.lock().unwrap();
        log.clone()
    }

    /// Get audit log for a specific principal
    pub fn get_principal_audit_log(&self, principal: Principal) -> Vec<IdentityAuditRecord> {
        let log = self.identity_audit_log.lock().unwrap();
        log.iter()
            .filter(|record| record.principal == principal)
            .cloned()
            .collect()
    }

    /// Statistics about registered identities
    pub fn get_statistics(&self) -> IdentityStatistics {
        let active = self.active_identities.lock().unwrap();
        let all = self.all_identities.lock().unwrap();
        let log = self.identity_audit_log.lock().unwrap();

        IdentityStatistics {
            total_principals_with_identities: active.len(),
            total_all_identities: all.values().map(|v| v.len()).sum(),
            total_audit_records: log.len(),
            active_principal_count: active.values().filter(|id| id.is_active).count(),
        }
    }
}

/// Statistics about the identity registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityStatistics {
    pub total_principals_with_identities: usize,
    pub total_all_identities: usize,
    pub total_audit_records: usize,
    pub active_principal_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_creation() {
        let bytes = [42u8; 32];
        let pk = PublicKey::new(bytes);
        assert_eq!(pk.as_bytes(), &bytes);
    }

    #[test]
    fn test_public_key_hex_roundtrip() {
        let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let pk = PublicKey::new(bytes);
        let hex = pk.to_hex();
        let pk2 = PublicKey::from_hex(&hex).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_principal_identity_creation() {
        let bytes = [99u8; 32];
        let pk = PublicKey::new(bytes);
        let identity = PrincipalIdentity::new(
            Principal::Policy,
            pk,
            1,
            "test".to_string(),
        );
        assert_eq!(identity.principal, Principal::Policy);
        assert_eq!(identity.key_version, 1);
        assert!(identity.is_active);
        assert_eq!(identity.purpose, "test");
    }

    #[test]
    fn test_identity_integrity_verification() {
        let bytes = [123u8; 32];
        let pk = PublicKey::new(bytes);
        let identity = PrincipalIdentity::new(
            Principal::Sealer,
            pk,
            1,
            "sealing".to_string(),
        );
        assert!(identity.verify_integrity());
    }

    #[test]
    fn test_identity_validity_check() {
        let bytes = [88u8; 32];
        let pk = PublicKey::new(bytes);
        let identity = PrincipalIdentity::new(
            Principal::Audit,
            pk,
            1,
            "audit".to_string(),
        );
        assert!(identity.is_valid());
    }

    #[test]
    fn test_identity_registry_registration() {
        let registry = PrincipalIdentityRegistry::new();
        let pub_bytes = [11u8; 32];
        let priv_bytes = [22u8; 64];
        let pk = PublicKey::new(pub_bytes);
        let sk = PrivateKey::new(priv_bytes);

        let result = registry.register_identity(
            Principal::Policy,
            pk,
            sk,
            "primary".to_string(),
        );
        assert!(result.is_ok());

        let identity = registry.get_active_identity(Principal::Policy);
        assert!(identity.is_some());
        assert_eq!(identity.unwrap().key_version, 1);
    }

    #[test]
    fn test_identity_registry_no_duplicate_registration() {
        let registry = PrincipalIdentityRegistry::new();
        let pub_bytes = [11u8; 32];
        let priv_bytes = [22u8; 64];
        let pk = PublicKey::new(pub_bytes);
        let sk = PrivateKey::new(priv_bytes);

        let _first = registry.register_identity(
            Principal::Policy,
            pk,
            sk,
            "primary".to_string(),
        );

        let second = registry.register_identity(
            Principal::Policy,
            pk,
            sk,
            "duplicate".to_string(),
        );

        assert!(second.is_err());
    }

    #[test]
    fn test_identity_registry_key_rotation() {
        let registry = PrincipalIdentityRegistry::new();
        let pub1 = PublicKey::new([11u8; 32]);
        let priv1 = PrivateKey::new([22u8; 64]);

        registry.register_identity(
            Principal::Sealer,
            pub1,
            priv1,
            "v1".to_string(),
        ).unwrap();

        let pub2 = PublicKey::new([33u8; 32]);
        let priv2 = PrivateKey::new([44u8; 64]);

        let rotated = registry.rotate_key(Principal::Sealer, pub2, priv2).unwrap();
        assert_eq!(rotated.key_version, 2);

        let all = registry.get_all_identities(Principal::Sealer);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_identity_registry_get_registered_principals() {
        let registry = PrincipalIdentityRegistry::new();
        let pub_bytes = [11u8; 32];
        let priv_bytes = [22u8; 64];
        let pk = PublicKey::new(pub_bytes);
        let sk = PrivateKey::new(priv_bytes);

        registry.register_identity(Principal::Policy, pk, sk.clone(), "p1".to_string()).unwrap();
        registry.register_identity(Principal::Audit, pk, sk.clone(), "a1".to_string()).unwrap();
        registry.register_identity(Principal::Sealer, pk, sk, "s1".to_string()).unwrap();

        let principals = registry.get_registered_principals();
        assert_eq!(principals.len(), 3);
    }

    #[test]
    fn test_identity_registry_audit_log() {
        let registry = PrincipalIdentityRegistry::new();
        let pub_bytes = [11u8; 32];
        let priv_bytes = [22u8; 64];
        let pk = PublicKey::new(pub_bytes);
        let sk = PrivateKey::new(priv_bytes);

        registry.register_identity(Principal::Policy, pk, sk, "test".to_string()).unwrap();

        let log = registry.get_audit_log();
        assert!(!log.is_empty());
        assert_eq!(log[0].operation, "register_identity");
        assert_eq!(log[0].principal, Principal::Policy);
    }

    #[test]
    fn test_identity_registry_statistics() {
        let registry = PrincipalIdentityRegistry::new();
        let pub_bytes = [11u8; 32];
        let priv_bytes = [22u8; 64];
        let pk = PublicKey::new(pub_bytes);
        let sk = PrivateKey::new(priv_bytes);

        registry.register_identity(Principal::Policy, pk, sk.clone(), "p1".to_string()).unwrap();
        registry.register_identity(Principal::Audit, pk, sk, "a1".to_string()).unwrap();

        let stats = registry.get_statistics();
        assert_eq!(stats.total_principals_with_identities, 2);
        assert_eq!(stats.total_all_identities, 2);
        assert!(stats.total_audit_records > 0);
    }
}
