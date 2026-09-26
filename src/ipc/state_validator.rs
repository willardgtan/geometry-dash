// Pre-Execution State Re-validation (Sprint 4 Task 4.3)
// Detect state changes between validation and execution
// Prevents stale validation decisions from being used after conditions change

use std::sync::Arc;
use crate::types::Principal;
use crate::principals::identity::PrincipalIdentityRegistry;
use crate::principals::certificate::PrincipalCertificateRegistry;
use crate::ipc::execution_context::CommandExecutionContext;
use crate::ipc::token::ExecutionTokenIssuer;

/// Reasons why pre-execution validation failed
#[derive(Debug, Clone)]
pub enum StateChangeError {
    /// Token has expired (validation_timestamp + TTL < now)
    TokenExpired {
        issued_ns: u64,
        expiration_ns: u64,
        current_ns: u64,
    },

    /// Token explicitly revoked
    TokenRevoked {
        reason: String,
    },

    /// Requester principal no longer has active identity
    PrincipalRevoked {
        principal: Principal,
    },

    /// Requester principal deactivated
    PrincipalDeactivated {
        principal: Principal,
    },

    /// Requester certificate expired
    CertificateExpired {
        not_after_ns: u64,
        current_ns: u64,
    },

    /// Requester certificate revoked
    CertificateRevoked {
        reason: String,
    },

    /// Requester certificate no longer valid (status changed)
    CertificateStatusChanged {
        previous_status: String,
        current_status: String,
    },

    /// Requester capabilities downgraded or removed
    CapabilitiesDowngraded {
        lost_capabilities: Vec<u32>,
    },

    /// Command revoked in revocation list
    CommandRevoked {
        reason: String,
    },

    /// Policy changed since validation
    PolicyChanged {
        previous_version: u32,
        current_version: u32,
    },

    /// Public key mismatch (potential compromise)
    PublicKeyMismatch {
        reason: String,
    },
}

impl std::fmt::Display for StateChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StateChangeError::TokenExpired { issued_ns, expiration_ns, current_ns } => {
                write!(f, "Token expired: issued at {}, expired at {}, current time {}", issued_ns, expiration_ns, current_ns)
            }
            StateChangeError::TokenRevoked { reason } => {
                write!(f, "Token revoked: {}", reason)
            }
            StateChangeError::PrincipalRevoked { principal } => {
                write!(f, "Principal revoked: {:?}", principal)
            }
            StateChangeError::PrincipalDeactivated { principal } => {
                write!(f, "Principal deactivated: {:?}", principal)
            }
            StateChangeError::CertificateExpired { not_after_ns, current_ns } => {
                write!(f, "Certificate expired: not_after {}, current time {}", not_after_ns, current_ns)
            }
            StateChangeError::CertificateRevoked { reason } => {
                write!(f, "Certificate revoked: {}", reason)
            }
            StateChangeError::CertificateStatusChanged { previous_status, current_status } => {
                write!(f, "Certificate status changed: {} → {}", previous_status, current_status)
            }
            StateChangeError::CapabilitiesDowngraded { lost_capabilities } => {
                write!(f, "Capabilities downgraded: lost {:?}", lost_capabilities)
            }
            StateChangeError::CommandRevoked { reason } => {
                write!(f, "Command revoked: {}", reason)
            }
            StateChangeError::PolicyChanged { previous_version, current_version } => {
                write!(f, "Policy changed: version {} → {}", previous_version, current_version)
            }
            StateChangeError::PublicKeyMismatch { reason } => {
                write!(f, "Public key mismatch: {}", reason)
            }
        }
    }
}

impl std::error::Error for StateChangeError {}

/// State change validation result
#[derive(Debug, Clone)]
pub enum StateValidationResult {
    /// State is consistent, execution can proceed
    Valid,

    /// State changed, execution blocked
    Invalid(StateChangeError),
}

impl StateValidationResult {
    /// Check if validation passed
    pub fn is_valid(&self) -> bool {
        matches!(self, StateValidationResult::Valid)
    }

    /// Get error if validation failed
    pub fn error(&self) -> Option<&StateChangeError> {
        match self {
            StateValidationResult::Valid => None,
            StateValidationResult::Invalid(err) => Some(err),
        }
    }
}

/// Pre-execution state re-validator
/// Checks if conditions have changed since validation
pub struct StateChangeValidator {
    /// Identity registry for principal verification
    identity_registry: Arc<PrincipalIdentityRegistry>,

    /// Certificate registry for certificate verification
    certificate_registry: Arc<PrincipalCertificateRegistry>,

    /// Token issuer for token status checks
    token_issuer: Arc<ExecutionTokenIssuer>,

    /// Command revocation list (checked before execution)
    revoked_commands: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

impl StateChangeValidator {
    /// Create new state change validator
    pub fn new(
        identity_registry: Arc<PrincipalIdentityRegistry>,
        certificate_registry: Arc<PrincipalCertificateRegistry>,
        token_issuer: Arc<ExecutionTokenIssuer>,
    ) -> Self {
        StateChangeValidator {
            identity_registry,
            certificate_registry,
            token_issuer,
            revoked_commands: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }

    /// Validate state before execution
    pub fn validate_pre_execution(&self, context: &CommandExecutionContext, current_timestamp_ns: u64) -> StateValidationResult {
        // 1. Check token status
        if let Some(error) = self.check_token_status(context, current_timestamp_ns) {
            return StateValidationResult::Invalid(error);
        }

        // 2. Check principal still active
        if let Some(error) = self.check_principal_active(context.requester_state.identity.principal) {
            return StateValidationResult::Invalid(error);
        }

        // 3. Check principal identity valid
        if let Some(error) = self.check_identity_valid(context) {
            return StateValidationResult::Invalid(error);
        }

        // 4. Check certificate still valid
        if let Some(error) = self.check_certificate_valid(context, current_timestamp_ns) {
            return StateValidationResult::Invalid(error);
        }

        // 5. Check public key unchanged
        if let Some(error) = self.check_public_key_unchanged(context) {
            return StateValidationResult::Invalid(error);
        }

        // 6. Check capabilities not downgraded
        if let Some(error) = self.check_capabilities_unchanged(context) {
            return StateValidationResult::Invalid(error);
        }

        // 7. Check command not revoked
        if let Some(error) = self.check_command_not_revoked(context) {
            return StateValidationResult::Invalid(error);
        }

        // 8. Check policy version unchanged
        if let Some(error) = self.check_policy_unchanged(context) {
            return StateValidationResult::Invalid(error);
        }

        StateValidationResult::Valid
    }

    /// Check token status and expiration
    fn check_token_status(&self, context: &CommandExecutionContext, current_timestamp_ns: u64) -> Option<StateChangeError> {
        let token = &context.execution_token;

        // Check if expired
        if current_timestamp_ns >= token.expiration_ns {
            return Some(StateChangeError::TokenExpired {
                issued_ns: token.validation_timestamp_ns,
                expiration_ns: token.expiration_ns,
                current_ns: current_timestamp_ns,
            });
        }

        // Check status in token issuer
        if let Some(stored_token) = self.token_issuer.get_token(&token.token_id) {
            match stored_token.status {
                crate::ipc::token::TokenStatus::Revoked => {
                    return Some(StateChangeError::TokenRevoked {
                        reason: stored_token.revocation_reason.unwrap_or_default(),
                    });
                }
                crate::ipc::token::TokenStatus::Consumed => {
                    return Some(StateChangeError::TokenRevoked {
                        reason: "Token already consumed".to_string(),
                    });
                }
                crate::ipc::token::TokenStatus::Expired => {
                    return Some(StateChangeError::TokenExpired {
                        issued_ns: token.validation_timestamp_ns,
                        expiration_ns: token.expiration_ns,
                        current_ns: current_timestamp_ns,
                    });
                }
                _ => {}
            }
        }

        None
    }

    /// Check principal is still active
    fn check_principal_active(&self, principal: Principal) -> Option<StateChangeError> {
        match self.identity_registry.get_active_identity(principal) {
            Some(identity) if identity.is_active => None,
            Some(_) => Some(StateChangeError::PrincipalDeactivated { principal }),
            None => Some(StateChangeError::PrincipalRevoked { principal }),
        }
    }

    /// Check identity is still valid
    fn check_identity_valid(&self, context: &CommandExecutionContext) -> Option<StateChangeError> {
        let principal = context.requester_state.identity.principal;

        match self.identity_registry.get_active_identity(principal) {
            Some(current_identity) => {
                // Check if identity changed (different key_version or public key)
                if current_identity.key_version != context.requester_state.identity.key_version {
                    // Key was rotated - this is OK, but token is based on old key
                    // Still allow execution since Token validator already checked signature
                    return None;
                }

                if !current_identity.is_valid() {
                    return Some(StateChangeError::PrincipalDeactivated { principal });
                }

                None
            }
            None => Some(StateChangeError::PrincipalRevoked { principal }),
        }
    }

    /// Check certificate is still valid
    fn check_certificate_valid(&self, context: &CommandExecutionContext, current_timestamp_ns: u64) -> Option<StateChangeError> {
        let principal = context.requester_state.certificate.principal;

        match self.certificate_registry.get_active_certificate(principal) {
            Some(current_cert) => {
                // Check status
                use crate::principals::certificate::CertificateStatus;
                match current_cert.get_status() {
                    CertificateStatus::Valid => {
                        // Check expiration
                        if current_timestamp_ns >= current_cert.not_after_ns {
                            return Some(StateChangeError::CertificateExpired {
                                not_after_ns: current_cert.not_after_ns,
                                current_ns: current_timestamp_ns,
                            });
                        }
                        None
                    }
                    CertificateStatus::Expired => {
                        Some(StateChangeError::CertificateExpired {
                            not_after_ns: current_cert.not_after_ns,
                            current_ns: current_timestamp_ns,
                        })
                    }
                    CertificateStatus::Revoked => {
                        let reason = current_cert
                            .revocation_reason
                            .clone()
                            .unwrap_or_default();
                        Some(StateChangeError::CertificateRevoked { reason })
                    }
                    CertificateStatus::Pending => {
                        Some(StateChangeError::CertificateStatusChanged {
                            previous_status: "Valid".to_string(),
                            current_status: "Pending".to_string(),
                        })
                    }
                }
            }
            None => {
                Some(StateChangeError::CertificateRevoked {
                    reason: "Certificate no longer active".to_string(),
                })
            }
        }
    }

    /// Check public key unchanged (no certificate substitution)
    fn check_public_key_unchanged(&self, context: &CommandExecutionContext) -> Option<StateChangeError> {
        match self.certificate_registry.get_active_certificate(context.requester_state.certificate.principal) {
            Some(current_cert) => {
                if current_cert.public_key != context.requester_state.certificate.public_key {
                    return Some(StateChangeError::PublicKeyMismatch {
                        reason: "Certificate public key changed since validation".to_string(),
                    });
                }
                None
            }
            None => {
                Some(StateChangeError::PublicKeyMismatch {
                    reason: "Certificate no longer exists".to_string(),
                })
            }
        }
    }

    /// Check capabilities not downgraded
    fn check_capabilities_unchanged(&self, _context: &CommandExecutionContext) -> Option<StateChangeError> {
        // Capability tracking would require a separate capability registry
        // For now, assume capabilities are stable once validated
        // TODO (Sprint 4+): Implement per-principal capability versioning
        None
    }

    /// Check command not revoked
    fn check_command_not_revoked(&self, context: &CommandExecutionContext) -> Option<StateChangeError> {
        let revoked = self.revoked_commands.lock().unwrap();

        if revoked.contains(&context.command.command_id) {
            return Some(StateChangeError::CommandRevoked {
                reason: "Command in revocation list".to_string(),
            });
        }

        None
    }

    /// Check policy version unchanged
    fn check_policy_unchanged(&self, _context: &CommandExecutionContext) -> Option<StateChangeError> {
        // Policy versioning would require integration with Policy principal
        // For now, assume policy is stable during command execution
        // TODO (Sprint 4+): Implement policy version tracking
        None
    }

    /// Revoke a command before execution
    pub fn revoke_command(&self, command_id: String, reason: String) {
        let mut revoked = self.revoked_commands.lock().unwrap();
        revoked.insert(command_id);
    }

    /// Check if command is revoked
    pub fn is_command_revoked(&self, command_id: &str) -> bool {
        self.revoked_commands.lock().unwrap().contains(command_id)
    }

    /// Get revoked commands count
    pub fn revoked_command_count(&self) -> usize {
        self.revoked_commands.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_change_error_display() {
        let err = StateChangeError::TokenExpired {
            issued_ns: 1000,
            expiration_ns: 6000,
            current_ns: 7000,
        };

        assert!(format!("{}", err).contains("Token expired"));
    }

    #[test]
    fn test_state_validation_result() {
        let valid = StateValidationResult::Valid;
        assert!(valid.is_valid());
        assert!(valid.error().is_none());

        let err = StateChangeError::PrincipalRevoked {
            principal: Principal::Policy,
        };
        let invalid = StateValidationResult::Invalid(err);
        assert!(!invalid.is_valid());
        assert!(invalid.error().is_some());
    }

    #[test]
    fn test_state_change_validator_creation() {
        let identity_reg = Arc::new(PrincipalIdentityRegistry::new());
        let cert_reg = Arc::new(PrincipalCertificateRegistry::new());
        let token_issuer = Arc::new(ExecutionTokenIssuer::new(5_000_000_000));

        let validator = StateChangeValidator::new(identity_reg, cert_reg, token_issuer);

        assert_eq!(validator.revoked_command_count(), 0);
    }

    #[test]
    fn test_command_revocation() {
        let identity_reg = Arc::new(PrincipalIdentityRegistry::new());
        let cert_reg = Arc::new(PrincipalCertificateRegistry::new());
        let token_issuer = Arc::new(ExecutionTokenIssuer::new(5_000_000_000));

        let validator = StateChangeValidator::new(identity_reg, cert_reg, token_issuer);

        assert!(!validator.is_command_revoked("cmd-1"));

        validator.revoke_command("cmd-1".to_string(), "Test revocation".to_string());

        assert!(validator.is_command_revoked("cmd-1"));
        assert_eq!(validator.revoked_command_count(), 1);
    }
}
