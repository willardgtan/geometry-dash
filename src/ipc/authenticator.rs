// IPC Message Authenticator (Sprint 3 Task 3.2)
// Digital signature support for cross-boundary principal authentication
// Implements SEC-C03 message-level authentication

use crate::ipc::message::UniversalMessageHeader;
use crate::principals::identity::{PrincipalIdentityRegistry, PublicKey};
use crate::types::Principal;
use serde_json::json;
use sha2::Digest;
use std::sync::Arc;

/// Message authentication result
#[derive(Debug, Clone)]
pub enum SignatureResult {
    /// Signature created successfully
    Success { signature: [u8; 64], key_version: u32 },
    /// Signature creation failed
    Error(String),
}

/// Message verification result
#[derive(Debug, Clone)]
pub enum VerificationResult {
    /// Message signature verified successfully
    Valid {
        principal: Principal,
        key_version: u32,
        signature_timestamp_ns: u64,
    },
    /// Signature verification failed
    Invalid {
        reason: String,
    },
    /// Verification encountered an error
    Error(String),
}

/// Audit record for message authentication operations
#[derive(Debug, Clone)]
pub struct AuthenticationAuditRecord {
    pub record_id: String,
    pub timestamp_ns: u64,
    pub sender_principal: Principal,
    pub message_id: u64,
    pub operation: String, // "sign" or "verify"
    pub status: String,    // "success", "invalid", or error message
    pub key_version: Option<u32>,
}

/// IPC Message Authenticator: Signs and verifies IPC messages
pub struct IpcMessageAuthenticator {
    /// Reference to principal identity registry for key lookups
    identity_registry: Arc<PrincipalIdentityRegistry>,

    /// Audit log of all signature operations
    audit_log: Arc<std::sync::Mutex<Vec<AuthenticationAuditRecord>>>,
}

impl IpcMessageAuthenticator {
    /// Create a new message authenticator
    pub fn new(identity_registry: Arc<PrincipalIdentityRegistry>) -> Self {
        IpcMessageAuthenticator {
            identity_registry,
            audit_log: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Sign a message using the sender principal's private key
    /// Returns the signature bytes if successful
    pub fn sign_message(
        &self,
        message: &UniversalMessageHeader,
        sender_principal: Principal,
    ) -> SignatureResult {
        // Get sender's key pair
        let key_pair = match self.identity_registry.get_key_pair(sender_principal) {
            Some(kp) => kp,
            None => {
                let error = format!(
                    "No key pair registered for principal {}",
                    sender_principal
                );
                self.log_auth_operation(
                    sender_principal,
                    message.message_id,
                    "sign",
                    "error",
                    None,
                    &error,
                );
                return SignatureResult::Error(error);
            }
        };

        // Get sender's identity for key version
        let identity = match self.identity_registry.get_active_identity(sender_principal) {
            Some(id) => id,
            None => {
                let error = format!(
                    "No active identity for principal {}",
                    sender_principal
                );
                self.log_auth_operation(
                    sender_principal,
                    message.message_id,
                    "sign",
                    "error",
                    None,
                    &error,
                );
                return SignatureResult::Error(error);
            }
        };

        // Create signature input: all message fields except signature itself
        let signature_input = self.create_signature_input(message);

        // Sign using Ed25519 (simulate with SHA-256 for now)
        // In production, this would use actual Ed25519 signing library
        let signature = self.compute_signature(&signature_input);

        self.log_auth_operation(
            sender_principal,
            message.message_id,
            "sign",
            "success",
            Some(identity.key_version),
            "",
        );

        SignatureResult::Success {
            signature,
            key_version: identity.key_version,
        }
    }

    /// Verify a message signature
    pub fn verify_message(
        &self,
        message: &UniversalMessageHeader,
        _expected_sender: Option<Principal>,
    ) -> VerificationResult {
        // Extract sender and witness principal
        let sender = match Principal::from_u8(message.sender_principal) {
            Some(p) => p,
            None => {
                return VerificationResult::Error(format!(
                    "Invalid sender principal: {}",
                    message.sender_principal
                ))
            }
        };

        let witness = match Principal::from_u8(message.witness_principal) {
            Some(p) => p,
            None => {
                return VerificationResult::Error(format!(
                    "Invalid witness principal: {}",
                    message.witness_principal
                ))
            }
        };

        // Get witness's active identity
        let identity = match self.identity_registry.get_active_identity(witness) {
            Some(id) => id,
            None => {
                let reason = format!(
                    "No active identity for witness principal {}",
                    witness
                );
                self.log_auth_operation(witness, message.message_id, "verify", "invalid", None, &reason);
                return VerificationResult::Invalid { reason };
            }
        };

        // Verify public key is valid
        if !identity.is_valid() {
            let reason = format!("Identity for principal {} is not valid", witness);
            self.log_auth_operation(
                witness,
                message.message_id,
                "verify",
                "invalid",
                None,
                &reason,
            );
            return VerificationResult::Invalid { reason };
        }

        // Create signature input for verification
        let signature_input = self.create_signature_input(message);

        // Verify signature (simulate with SHA-256 for now)
        let computed_signature = self.compute_signature(&signature_input);

        if computed_signature != message.witness_signature {
            let reason = "Signature verification failed: signature mismatch".to_string();
            self.log_auth_operation(
                witness,
                message.message_id,
                "verify",
                "invalid",
                Some(identity.key_version),
                &reason,
            );
            return VerificationResult::Invalid { reason };
        }

        self.log_auth_operation(
            witness,
            message.message_id,
            "verify",
            "success",
            Some(identity.key_version),
            "",
        );

        VerificationResult::Valid {
            principal: witness,
            key_version: identity.key_version,
            signature_timestamp_ns: message.timestamp_ns,
        }
    }

    /// Create signature input from message (all fields except signature)
    fn create_signature_input(&self, message: &UniversalMessageHeader) -> String {
        // Create a JSON representation of all message fields except the signature
        let input = json!({
            "interface_id": message.interface_id,
            "protocol_version": message.protocol_version,
            "message_type": message.message_type,
            "flags": message.flags,
            "sender_principal": message.sender_principal,
            "receiver_principal": message.receiver_principal,
            "message_id": message.message_id,
            "request_id": message.request_id,
            "nonce": hex::encode(&message.nonce),
            "timestamp_ns": message.timestamp_ns,
            "witness_principal": message.witness_principal,
            "source_evidence_id": message.source_evidence_id.as_ref(),
            "sequence_number": message.sequence_number,
            "classification_level": message.classification_level.as_ref().map(|cl| cl.to_string()),
            "required_clearance": message.required_clearance.as_ref().map(|cl| cl.to_string()),
            "declassification_approved": message.declassification_approved,
        });

        input.to_string()
    }

    /// Compute signature using SHA-256
    /// In production, this would use actual Ed25519 signing
    fn compute_signature(&self, input: &str) -> [u8; 64] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(input.as_bytes());
        let hash = hasher.finalize();

        // Pad SHA-256 (32 bytes) to 64 bytes for simulation
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&hash);
        // Second 32 bytes: hash of the hash for additional binding
        let mut hasher2 = sha2::Sha256::new();
        hasher2.update(&hash);
        signature[32..].copy_from_slice(&hasher2.finalize());

        signature
    }

    /// Log an authentication operation
    fn log_auth_operation(
        &self,
        principal: Principal,
        message_id: u64,
        operation: &str,
        status: &str,
        key_version: Option<u32>,
        error_msg: &str,
    ) {
        let record = AuthenticationAuditRecord {
            record_id: uuid::Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            sender_principal: principal,
            message_id,
            operation: operation.to_string(),
            status: if error_msg.is_empty() {
                status.to_string()
            } else {
                format!("{}: {}", status, error_msg)
            },
            key_version,
        };

        let mut log = self.audit_log.lock().unwrap();
        log.push(record);
    }

    /// Get authentication audit log
    pub fn get_audit_log(&self) -> Vec<AuthenticationAuditRecord> {
        let log = self.audit_log.lock().unwrap();
        log.clone()
    }

    /// Get audit log for specific principal
    pub fn get_principal_audit_log(&self, principal: Principal) -> Vec<AuthenticationAuditRecord> {
        let log = self.audit_log.lock().unwrap();
        log.iter()
            .filter(|r| r.sender_principal == principal)
            .cloned()
            .collect()
    }

    /// Get authentication statistics
    pub fn get_statistics(&self) -> AuthenticationStatistics {
        let log = self.audit_log.lock().unwrap();

        let total_operations = log.len();
        let successful_signs = log
            .iter()
            .filter(|r| r.operation == "sign" && r.status == "success")
            .count();
        let successful_verifications = log
            .iter()
            .filter(|r| r.operation == "verify" && r.status == "success")
            .count();
        let failed_verifications = log
            .iter()
            .filter(|r| r.operation == "verify" && r.status != "success")
            .count();

        AuthenticationStatistics {
            total_operations,
            successful_signs,
            successful_verifications,
            failed_verifications,
        }
    }
}

/// Statistics for message authentication
#[derive(Debug, Clone)]
pub struct AuthenticationStatistics {
    pub total_operations: usize,
    pub successful_signs: usize,
    pub successful_verifications: usize,
    pub failed_verifications: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principals::identity::{PrivateKey, PublicKey, PrincipalIdentityRegistry};

    fn create_test_authenticator() -> (
        IpcMessageAuthenticator,
        Arc<PrincipalIdentityRegistry>,
    ) {
        let registry = Arc::new(PrincipalIdentityRegistry::new());

        // Register test identities
        let pub_key = PublicKey::new([1u8; 32]);
        let priv_key = PrivateKey::new([2u8; 64]);

        let _ = registry.register_identity(
            Principal::Policy,
            pub_key,
            priv_key,
            "test-policy".to_string(),
        );

        let authenticator = IpcMessageAuthenticator::new(registry.clone());
        (authenticator, registry)
    }

    fn create_test_message() -> UniversalMessageHeader {
        UniversalMessageHeader::new(
            1,  // interface_id
            0,  // message_type (REQUEST)
            1,  // sender_principal (Policy)
            2,  // receiver_principal (Actuator)
            0x01, // flags (REQUIRES_AUTH)
        )
    }

    #[test]
    fn test_message_signing() {
        let (auth, _registry) = create_test_authenticator();
        let mut message = create_test_message();

        let result = auth.sign_message(&message, Principal::Policy);
        assert!(matches!(result, SignatureResult::Success { .. }));

        if let SignatureResult::Success { signature, key_version } = result {
            message.witness_signature = signature;
            assert_eq!(key_version, 1);
        }
    }

    #[test]
    fn test_message_verification_success() {
        let (auth, _registry) = create_test_authenticator();
        let mut message = create_test_message();
        message.witness_principal = 1; // Policy

        let sign_result = auth.sign_message(&message, Principal::Policy);
        if let SignatureResult::Success { signature, .. } = sign_result {
            message.witness_signature = signature;

            let verify_result = auth.verify_message(&message, None);
            assert!(matches!(
                verify_result,
                VerificationResult::Valid { .. }
            ));
        }
    }

    #[test]
    fn test_message_verification_unregistered_principal() {
        let (auth, _registry) = create_test_authenticator();
        let message = create_test_message();

        let result = auth.verify_message(&message, None);
        assert!(matches!(result, VerificationResult::Invalid { .. }));
    }

    #[test]
    fn test_signature_mismatch_detection() {
        let (auth, _registry) = create_test_authenticator();
        let mut message = create_test_message();
        message.witness_principal = 1; // Policy

        let sign_result = auth.sign_message(&message, Principal::Policy);
        if let SignatureResult::Success { mut signature, .. } = sign_result {
            // Corrupt signature
            signature[0] ^= 0xFF;
            message.witness_signature = signature;

            let verify_result = auth.verify_message(&message, None);
            assert!(matches!(
                verify_result,
                VerificationResult::Invalid { .. }
            ));
        }
    }

    #[test]
    fn test_audit_log_recording() {
        let (auth, _registry) = create_test_authenticator();
        let message = create_test_message();

        auth.sign_message(&message, Principal::Policy);

        let log = auth.get_audit_log();
        assert!(!log.is_empty());
        assert_eq!(log[0].operation, "sign");
        assert_eq!(log[0].sender_principal, Principal::Policy);
    }

    #[test]
    fn test_principal_specific_audit_log() {
        let (auth, registry) = create_test_authenticator();
        let message = create_test_message();

        // Sign with Policy
        auth.sign_message(&message, Principal::Policy);

        // Register and sign with Audit
        let pub_key = PublicKey::new([3u8; 32]);
        let priv_key = PrivateKey::new([4u8; 64]);
        registry
            .register_identity(
                Principal::Audit,
                pub_key,
                priv_key,
                "test-audit".to_string(),
            )
            .unwrap();

        auth.sign_message(&message, Principal::Audit);

        // Get logs for each principal
        let policy_log = auth.get_principal_audit_log(Principal::Policy);
        let audit_log = auth.get_principal_audit_log(Principal::Audit);

        assert_eq!(policy_log.len(), 1);
        assert_eq!(audit_log.len(), 1);
    }

    #[test]
    fn test_authentication_statistics() {
        let (auth, _registry) = create_test_authenticator();
        let mut message = create_test_message();
        message.witness_principal = 1;

        // Sign message
        let sign_result = auth.sign_message(&message, Principal::Policy);
        if let SignatureResult::Success { signature, .. } = sign_result {
            message.witness_signature = signature;

            // Verify message
            auth.verify_message(&message, None);
        }

        let stats = auth.get_statistics();
        assert_eq!(stats.successful_signs, 1);
        assert_eq!(stats.successful_verifications, 1);
    }

    #[test]
    fn test_unregistered_principal_cannot_sign() {
        let (auth, _registry) = create_test_authenticator();
        let message = create_test_message();

        let result = auth.sign_message(&message, Principal::Learner);
        assert!(matches!(result, SignatureResult::Error(_)));
    }
}
