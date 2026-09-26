// Principal Certificate Registry (Sprint 3 Task 3.3)
// Manages X.509-style certificates for principal identities
// Implements SEC-C03 certificate-based principal verification

use crate::principals::identity::{PublicKey, PrincipalIdentity, PrincipalIdentityRegistry};
use crate::types::Principal;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Certificate status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateStatus {
    /// Certificate is valid and active
    Valid,
    /// Certificate has expired
    Expired,
    /// Certificate has been revoked
    Revoked,
    /// Certificate is pending activation
    Pending,
}

impl std::fmt::Display for CertificateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateStatus::Valid => write!(f, "valid"),
            CertificateStatus::Expired => write!(f, "expired"),
            CertificateStatus::Revoked => write!(f, "revoked"),
            CertificateStatus::Pending => write!(f, "pending"),
        }
    }
}

/// Principal certificate: binds public key to principal with temporal validity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalCertificate {
    /// Unique certificate ID
    pub cert_id: String,

    /// Principal this certificate is issued to
    pub principal: Principal,

    /// Public key embedded in certificate
    pub public_key: PublicKey,

    /// Certificate serial number
    pub serial_number: u64,

    /// Issuer principal (usually Sealer or Supervisor)
    pub issuer: Principal,

    /// Certificate not valid before (nanoseconds since UNIX_EPOCH)
    pub not_before_ns: u64,

    /// Certificate not valid after (nanoseconds since UNIX_EPOCH)
    pub not_after_ns: u64,

    /// Certificate signature (signed by issuer)
    pub signature: [u8; 64],

    /// Hash of certificate content for integrity
    pub content_hash: String,

    /// Current status of certificate
    pub status: CertificateStatus,

    /// If revoked, reason for revocation
    pub revocation_reason: Option<String>,

    /// If revoked, timestamp of revocation
    pub revoked_timestamp_ns: Option<u64>,

    /// Extended attributes (e.g., allowed operations)
    pub attributes: HashMap<String, String>,
}

impl PrincipalCertificate {
    /// Create a new principal certificate
    pub fn new(
        principal: Principal,
        public_key: PublicKey,
        issuer: Principal,
        serial_number: u64,
        valid_days: u32,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let cert_id = Uuid::new_v4().to_string();
        let not_before_ns = now;
        let not_after_ns = now + (valid_days as u64) * 24 * 60 * 60 * 1_000_000_000;

        // Compute content hash
        let content_data = format!(
            "{}|{}|{}|{}|{}|{}",
            cert_id, principal, issuer, serial_number, not_before_ns, not_after_ns
        );
        let mut hasher = sha2::Sha256::new();
        hasher.update(content_data);
        let content_hash = hex::encode(hasher.finalize());

        PrincipalCertificate {
            cert_id,
            principal,
            public_key,
            serial_number,
            issuer,
            not_before_ns,
            not_after_ns,
            signature: [0u8; 64],
            content_hash,
            status: CertificateStatus::Pending,
            revocation_reason: None,
            revoked_timestamp_ns: None,
            attributes: HashMap::new(),
        }
    }

    /// Set issuer signature on certificate
    pub fn set_signature(&mut self, signature: [u8; 64]) {
        self.signature = signature;
    }

    /// Check if certificate is currently valid (time-based)
    pub fn is_time_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        now >= self.not_before_ns && now <= self.not_after_ns
    }

    /// Get certificate status
    pub fn get_status(&self) -> CertificateStatus {
        if self.status == CertificateStatus::Revoked {
            return CertificateStatus::Revoked;
        }

        if !self.is_time_valid() {
            return CertificateStatus::Expired;
        }

        CertificateStatus::Valid
    }

    /// Verify certificate integrity
    pub fn verify_integrity(&self) -> bool {
        let content_data = format!(
            "{}|{}|{}|{}|{}|{}",
            self.cert_id, self.principal, self.issuer, self.serial_number, self.not_before_ns, self.not_after_ns
        );
        let mut hasher = sha2::Sha256::new();
        hasher.update(content_data);
        let computed_hash = hex::encode(hasher.finalize());

        computed_hash == self.content_hash
    }

    /// Add an attribute to the certificate
    pub fn add_attribute(&mut self, key: String, value: String) {
        self.attributes.insert(key, value);
    }

    /// Get an attribute from the certificate
    pub fn get_attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(|s| s.as_str())
    }

    /// Revoke certificate
    pub fn revoke(&mut self, reason: String) {
        self.status = CertificateStatus::Revoked;
        self.revocation_reason = Some(reason);
        self.revoked_timestamp_ns = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
        );
    }
}

/// Certificate audit record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuditRecord {
    pub record_id: String,
    pub timestamp_ns: u64,
    pub operation: String,
    pub cert_id: String,
    pub principal: Principal,
    pub status: String,
}

/// Principal Certificate Registry
pub struct PrincipalCertificateRegistry {
    /// Map: certificate ID -> certificate
    certificates: Arc<Mutex<HashMap<String, PrincipalCertificate>>>,

    /// Map: principal -> active certificate ID
    active_certs: Arc<Mutex<HashMap<Principal, String>>>,

    /// Map: principal -> all certificate IDs (including revoked/expired)
    cert_history: Arc<Mutex<HashMap<Principal, Vec<String>>>>,

    /// Next serial number for new certificates
    next_serial: Arc<Mutex<u64>>,

    /// Audit log
    audit_log: Arc<Mutex<Vec<CertificateAuditRecord>>>,
}

impl PrincipalCertificateRegistry {
    /// Create a new certificate registry
    pub fn new() -> Self {
        PrincipalCertificateRegistry {
            certificates: Arc::new(Mutex::new(HashMap::new())),
            active_certs: Arc::new(Mutex::new(HashMap::new())),
            cert_history: Arc::new(Mutex::new(HashMap::new())),
            next_serial: Arc::new(Mutex::new(1)),
            audit_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Issue a new certificate for a principal
    pub fn issue_certificate(
        &self,
        principal: Principal,
        public_key: PublicKey,
        issuer: Principal,
        valid_days: u32,
    ) -> Result<PrincipalCertificate, String> {
        let mut certs = self.certificates.lock().unwrap();
        let mut active = self.active_certs.lock().unwrap();
        let mut history = self.cert_history.lock().unwrap();
        let mut serial = self.next_serial.lock().unwrap();

        // Check if principal already has active certificate
        if active.contains_key(&principal) {
            return Err(format!(
                "Principal {} already has active certificate",
                principal
            ));
        }

        // Create certificate
        let mut cert = PrincipalCertificate::new(principal, public_key, issuer, *serial, valid_days);
        *serial += 1;

        // Simulate issuer signing (in production, use HSM)
        let signature_input = format!("{}{}", cert.cert_id, cert.content_hash);
        let mut hasher = sha2::Sha256::new();
        hasher.update(signature_input);
        let sig_hash = hasher.finalize();
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&sig_hash);
        cert.set_signature(signature);

        // Mark as valid
        cert.status = CertificateStatus::Valid;

        let cert_id = cert.cert_id.clone();

        // Store certificate
        certs.insert(cert_id.clone(), cert.clone());
        active.insert(principal, cert_id.clone());
        history
            .entry(principal)
            .or_insert_with(Vec::new)
            .push(cert_id.clone());

        self.log_certificate_operation(
            "issue",
            &cert_id,
            principal,
            "success",
        );

        Ok(cert)
    }

    /// Get active certificate for a principal
    pub fn get_active_certificate(&self, principal: Principal) -> Option<PrincipalCertificate> {
        let active = self.active_certs.lock().unwrap();
        let certs = self.certificates.lock().unwrap();

        active
            .get(&principal)
            .and_then(|cert_id| certs.get(cert_id).cloned())
    }

    /// Get certificate by ID
    pub fn get_certificate(&self, cert_id: &str) -> Option<PrincipalCertificate> {
        let certs = self.certificates.lock().unwrap();
        certs.get(cert_id).cloned()
    }

    /// Get all certificates for a principal
    pub fn get_principal_certificates(&self, principal: Principal) -> Vec<PrincipalCertificate> {
        let history = self.cert_history.lock().unwrap();
        let certs = self.certificates.lock().unwrap();

        history
            .get(&principal)
            .map(|cert_ids| {
                cert_ids
                    .iter()
                    .filter_map(|id| certs.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Revoke a certificate
    pub fn revoke_certificate(
        &self,
        cert_id: &str,
        reason: String,
    ) -> Result<(), String> {
        let mut certs = self.certificates.lock().unwrap();
        let mut active = self.active_certs.lock().unwrap();

        let cert = certs
            .get_mut(cert_id)
            .ok_or(format!("Certificate {} not found", cert_id))?;

        let principal = cert.principal;
        cert.revoke(reason);

        // Remove from active certs if it was active
        active.remove(&principal);

        self.log_certificate_operation(
            "revoke",
            cert_id,
            principal,
            "success",
        );

        Ok(())
    }

    /// Verify a certificate (integrity + validity)
    pub fn verify_certificate(&self, cert_id: &str) -> Result<bool, String> {
        let cert = self
            .get_certificate(cert_id)
            .ok_or(format!("Certificate {} not found", cert_id))?;

        let is_valid = cert.verify_integrity() && cert.get_status() == CertificateStatus::Valid;

        self.log_certificate_operation(
            "verify",
            cert_id,
            cert.principal,
            if is_valid { "success" } else { "invalid" },
        );

        Ok(is_valid)
    }

    /// Link identity registry with certificate registry for validation
    pub fn validate_against_identity(
        &self,
        cert_id: &str,
        identity_registry: &PrincipalIdentityRegistry,
    ) -> Result<bool, String> {
        let cert = self
            .get_certificate(cert_id)
            .ok_or(format!("Certificate {} not found", cert_id))?;

        // Get identity for principal
        let identity = identity_registry
            .get_active_identity(cert.principal)
            .ok_or(format!(
                "No active identity for principal {}",
                cert.principal
            ))?;

        // Compare public keys
        let keys_match = cert.public_key == identity.public_key;

        self.log_certificate_operation(
            "validate_identity",
            cert_id,
            cert.principal,
            if keys_match { "success" } else { "mismatch" },
        );

        Ok(keys_match)
    }

    /// Get all principals with active certificates
    pub fn get_principals_with_active_certs(&self) -> Vec<Principal> {
        let active = self.active_certs.lock().unwrap();
        active.keys().copied().collect()
    }

    /// Get certificate statistics
    pub fn get_statistics(&self) -> CertificateStatistics {
        let certs = self.certificates.lock().unwrap();
        let active = self.active_certs.lock().unwrap();

        let total_certs = certs.len();
        let active_cert_count = active.len();
        let valid_count = certs
            .values()
            .filter(|c| c.get_status() == CertificateStatus::Valid)
            .count();
        let revoked_count = certs
            .values()
            .filter(|c| c.status == CertificateStatus::Revoked)
            .count();
        let expired_count = certs
            .values()
            .filter(|c| c.get_status() == CertificateStatus::Expired)
            .count();

        CertificateStatistics {
            total_certificates: total_certs,
            active_certificates: active_cert_count,
            valid_certificates: valid_count,
            revoked_certificates: revoked_count,
            expired_certificates: expired_count,
        }
    }

    /// Log a certificate operation
    fn log_certificate_operation(
        &self,
        operation: &str,
        cert_id: &str,
        principal: Principal,
        status: &str,
    ) {
        let record = CertificateAuditRecord {
            record_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            operation: operation.to_string(),
            cert_id: cert_id.to_string(),
            principal,
            status: status.to_string(),
        };

        let mut log = self.audit_log.lock().unwrap();
        log.push(record);
    }

    /// Get audit log
    pub fn get_audit_log(&self) -> Vec<CertificateAuditRecord> {
        let log = self.audit_log.lock().unwrap();
        log.clone()
    }

    /// Get audit log for specific principal
    pub fn get_principal_audit_log(&self, principal: Principal) -> Vec<CertificateAuditRecord> {
        let log = self.audit_log.lock().unwrap();
        log.iter()
            .filter(|r| r.principal == principal)
            .cloned()
            .collect()
    }
}

/// Certificate statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateStatistics {
    pub total_certificates: usize,
    pub active_certificates: usize,
    pub valid_certificates: usize,
    pub revoked_certificates: usize,
    pub expired_certificates: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_creation() {
        let pub_key = PublicKey::new([1u8; 32]);
        let cert = PrincipalCertificate::new(
            Principal::Policy,
            pub_key,
            Principal::Sealer,
            1,
            365,
        );

        assert_eq!(cert.principal, Principal::Policy);
        assert_eq!(cert.issuer, Principal::Sealer);
        assert_eq!(cert.serial_number, 1);
        assert_eq!(cert.status, CertificateStatus::Pending);
    }

    #[test]
    fn test_certificate_time_validity() {
        let pub_key = PublicKey::new([2u8; 32]);
        let cert = PrincipalCertificate::new(
            Principal::Audit,
            pub_key,
            Principal::Sealer,
            1,
            365,
        );

        assert!(cert.is_time_valid());
    }

    #[test]
    fn test_certificate_integrity_verification() {
        let pub_key = PublicKey::new([3u8; 32]);
        let cert = PrincipalCertificate::new(
            Principal::Actuator,
            pub_key,
            Principal::Supervisor,
            1,
            30,
        );

        assert!(cert.verify_integrity());
    }

    #[test]
    fn test_certificate_registry_issuance() {
        let registry = PrincipalCertificateRegistry::new();
        let pub_key = PublicKey::new([4u8; 32]);

        let result = registry.issue_certificate(
            Principal::Policy,
            pub_key,
            Principal::Sealer,
            90,
        );

        assert!(result.is_ok());
        let cert = result.unwrap();
        assert_eq!(cert.principal, Principal::Policy);
        assert_eq!(cert.status, CertificateStatus::Valid);
    }

    #[test]
    fn test_get_active_certificate() {
        let registry = PrincipalCertificateRegistry::new();
        let pub_key = PublicKey::new([5u8; 32]);

        registry
            .issue_certificate(
                Principal::Audit,
                pub_key,
                Principal::Sealer,
                90,
            )
            .unwrap();

        let cert = registry.get_active_certificate(Principal::Audit);
        assert!(cert.is_some());
        assert_eq!(cert.unwrap().principal, Principal::Audit);
    }

    #[test]
    fn test_certificate_revocation() {
        let registry = PrincipalCertificateRegistry::new();
        let pub_key = PublicKey::new([6u8; 32]);

        let cert = registry
            .issue_certificate(
                Principal::Actuator,
                pub_key,
                Principal::Sealer,
                90,
            )
            .unwrap();

        let result = registry.revoke_certificate(&cert.cert_id, "Compromised key".to_string());
        assert!(result.is_ok());

        let revoked_cert = registry.get_certificate(&cert.cert_id).unwrap();
        assert_eq!(revoked_cert.status, CertificateStatus::Revoked);
        assert!(revoked_cert.revocation_reason.is_some());
    }

    #[test]
    fn test_certificate_attributes() {
        let pub_key = PublicKey::new([7u8; 32]);
        let mut cert = PrincipalCertificate::new(
            Principal::Developer,
            pub_key,
            Principal::Supervisor,
            1,
            30,
        );

        cert.add_attribute("role".to_string(), "admin".to_string());
        cert.add_attribute("department".to_string(), "security".to_string());

        assert_eq!(cert.get_attribute("role"), Some("admin"));
        assert_eq!(cert.get_attribute("department"), Some("security"));
        assert_eq!(cert.get_attribute("nonexistent"), None);
    }

    #[test]
    fn test_multiple_principals_certificates() {
        let registry = PrincipalCertificateRegistry::new();

        registry
            .issue_certificate(
                Principal::Policy,
                PublicKey::new([8u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        registry
            .issue_certificate(
                Principal::Actuator,
                PublicKey::new([9u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        let principals = registry.get_principals_with_active_certs();
        assert_eq!(principals.len(), 2);
    }

    #[test]
    fn test_certificate_statistics() {
        let registry = PrincipalCertificateRegistry::new();

        registry
            .issue_certificate(
                Principal::Policy,
                PublicKey::new([10u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        registry
            .issue_certificate(
                Principal::Audit,
                PublicKey::new([11u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        let stats = registry.get_statistics();
        assert_eq!(stats.total_certificates, 2);
        assert_eq!(stats.active_certificates, 2);
        assert_eq!(stats.valid_certificates, 2);
    }

    #[test]
    fn test_audit_log_recording() {
        let registry = PrincipalCertificateRegistry::new();

        let cert = registry
            .issue_certificate(
                Principal::Policy,
                PublicKey::new([12u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        let log = registry.get_audit_log();
        assert!(!log.is_empty());
        assert_eq!(log[0].operation, "issue");
        assert_eq!(log[0].principal, Principal::Policy);
    }

    #[test]
    fn test_principal_certificate_history() {
        let registry = PrincipalCertificateRegistry::new();

        // Issue first cert
        registry
            .issue_certificate(
                Principal::Policy,
                PublicKey::new([13u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        let first_cert = registry.get_active_certificate(Principal::Policy).unwrap();

        // Revoke first cert
        registry
            .revoke_certificate(&first_cert.cert_id, "Rotation".to_string())
            .unwrap();

        // Issue second cert
        registry
            .issue_certificate(
                Principal::Policy,
                PublicKey::new([14u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        let all_certs = registry.get_principal_certificates(Principal::Policy);
        assert_eq!(all_certs.len(), 2);
    }
}
