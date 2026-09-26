// Execution Token System (Sprint 4 Task 4.1)
// Signed tokens that bind validation decisions to execution identity
// Prevents Time-of-Check/Time-of-Use (TOCTOU) vulnerabilities

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::types::Principal;
use uuid::Uuid;

/// Token status in its lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenStatus {
    /// Token issued, awaiting activation
    Pending,
    /// Token activated, ready for execution
    Active,
    /// Token consumed (execution completed)
    Consumed,
    /// Token expired (TTL exceeded)
    Expired,
    /// Token explicitly revoked (capability downgrade, principal revocation, etc)
    Revoked,
}

impl std::fmt::Display for TokenStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            TokenStatus::Pending => write!(f, "Pending"),
            TokenStatus::Active => write!(f, "Active"),
            TokenStatus::Consumed => write!(f, "Consumed"),
            TokenStatus::Expired => write!(f, "Expired"),
            TokenStatus::Revoked => write!(f, "Revoked"),
        }
    }
}

/// Execution token: cryptographic proof that a command was validated
/// Binds validation timestamp, validator principal, and required gates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionToken {
    /// Unique token ID
    pub token_id: String,

    /// Command this token authorizes
    pub command_id: String,

    /// When validation occurred (nanoseconds since UNIX_EPOCH)
    pub validation_timestamp_ns: u64,

    /// When this token expires (validation_timestamp + TTL)
    pub expiration_ns: u64,

    /// Principal that issued this token (e.g., Supervisor)
    pub issuer_principal: Principal,

    /// Principal that performed the validation (e.g., Actuator Gate Validator)
    pub validator_principal: Principal,

    /// Gates that were required to pass (bitmask: bit 0 = Gate C, bit 1 = Gate I, etc)
    pub required_gates: u32,

    /// Validator's Ed25519 signature over all fields (except signature itself)
    /// Format: [u8; 64] representing Ed25519 signature
    pub signature: [u8; 64],

    /// Current status in token lifecycle
    pub status: TokenStatus,

    /// When token was consumed (if status == Consumed)
    pub consumed_timestamp_ns: Option<u64>,

    /// Reason for revocation (if status == Revoked)
    pub revocation_reason: Option<String>,
}

impl ExecutionToken {
    /// Create a new execution token
    pub fn new(
        command_id: String,
        validation_timestamp_ns: u64,
        expiration_ns: u64,
        issuer_principal: Principal,
        validator_principal: Principal,
        required_gates: u32,
        signature: [u8; 64],
    ) -> Self {
        ExecutionToken {
            token_id: format!("token-{}", Uuid::new_v4()),
            command_id,
            validation_timestamp_ns,
            expiration_ns,
            issuer_principal,
            validator_principal,
            required_gates,
            signature,
            status: TokenStatus::Pending,
            consumed_timestamp_ns: None,
            revocation_reason: None,
        }
    }

    /// Check if token is still valid (not expired, not revoked, not consumed)
    pub fn is_valid(&self, current_timestamp_ns: u64) -> bool {
        match self.status {
            TokenStatus::Active => current_timestamp_ns < self.expiration_ns,
            TokenStatus::Pending | TokenStatus::Consumed | TokenStatus::Expired | TokenStatus::Revoked => false,
        }
    }

    /// Check if token has expired based on TTL
    pub fn is_expired(&self, current_timestamp_ns: u64) -> bool {
        current_timestamp_ns >= self.expiration_ns
    }

    /// Verify signature is valid (64-byte Ed25519)
    pub fn signature_valid(&self) -> bool {
        // In production: verify Ed25519 signature against validator's public key
        // For now: check that signature is non-zero (placeholder validation)
        self.signature != [0u8; 64]
    }

    /// Get time remaining until expiration (in nanoseconds)
    pub fn time_until_expiry(&self, current_timestamp_ns: u64) -> Option<u64> {
        if current_timestamp_ns < self.expiration_ns {
            Some(self.expiration_ns - current_timestamp_ns)
        } else {
            None
        }
    }
}

/// Audit record for token operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAuditRecord {
    pub operation: String,  // "issue", "activate", "consume", "revoke", "expire"
    pub token_id: String,
    pub command_id: String,
    pub principal: Principal,
    pub timestamp_ns: u64,
    pub status_before: TokenStatus,
    pub status_after: TokenStatus,
    pub reason: Option<String>,
}

/// Execution token issuer: creates and manages tokens
pub struct ExecutionTokenIssuer {
    /// Token storage: token_id → token
    tokens: Arc<Mutex<HashMap<String, ExecutionToken>>>,

    /// Command-to-token mapping: command_id → token_id
    command_tokens: Arc<Mutex<HashMap<String, String>>>,

    /// Audit log for token operations
    audit_log: Arc<Mutex<Vec<TokenAuditRecord>>>,

    /// Token TTL in nanoseconds (default: 5 seconds = 5_000_000_000 ns)
    token_ttl_ns: u64,
}

impl ExecutionTokenIssuer {
    /// Create a new token issuer with configurable TTL
    pub fn new(token_ttl_ns: u64) -> Self {
        ExecutionTokenIssuer {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            command_tokens: Arc::new(Mutex::new(HashMap::new())),
            audit_log: Arc::new(Mutex::new(Vec::new())),
            token_ttl_ns,
        }
    }

    /// Issue a new token (PENDING status)
    pub fn issue_token(
        &self,
        command_id: String,
        validation_timestamp_ns: u64,
        issuer_principal: Principal,
        validator_principal: Principal,
        required_gates: u32,
        signature: [u8; 64],
    ) -> Result<ExecutionToken, String> {
        let expiration_ns = validation_timestamp_ns + self.token_ttl_ns;

        let token = ExecutionToken::new(
            command_id.clone(),
            validation_timestamp_ns,
            expiration_ns,
            issuer_principal,
            validator_principal,
            required_gates,
            signature,
        );

        let token_id = token.token_id.clone();

        // Store token
        {
            let mut tokens = self.tokens.lock().unwrap();
            tokens.insert(token_id.clone(), token.clone());
        }

        // Map command to token
        {
            let mut cmd_tokens = self.command_tokens.lock().unwrap();
            cmd_tokens.insert(command_id, token_id.clone());
        }

        // Log issuance
        self.log_audit(TokenAuditRecord {
            operation: "issue".to_string(),
            token_id,
            command_id: token.command_id.clone(),
            principal: issuer_principal,
            timestamp_ns: validation_timestamp_ns,
            status_before: TokenStatus::Pending,
            status_after: TokenStatus::Pending,
            reason: None,
        });

        Ok(token)
    }

    /// Activate a token (PENDING → ACTIVE)
    pub fn activate_token(&self, token_id: &str) -> Result<(), String> {
        let mut tokens = self.tokens.lock().unwrap();

        match tokens.get_mut(token_id) {
            Some(token) => {
                if token.status != TokenStatus::Pending {
                    return Err(format!("Cannot activate token in {:?} status", token.status));
                }

                let old_status = token.status;
                token.status = TokenStatus::Active;

                self.log_audit(TokenAuditRecord {
                    operation: "activate".to_string(),
                    token_id: token_id.to_string(),
                    command_id: token.command_id.clone(),
                    principal: token.issuer_principal,
                    timestamp_ns: super::current_timestamp_ns(),
                    status_before: old_status,
                    status_after: TokenStatus::Active,
                    reason: None,
                });

                Ok(())
            }
            None => Err(format!("Token not found: {}", token_id)),
        }
    }

    /// Consume a token (ACTIVE → CONSUMED)
    pub fn consume_token(&self, token_id: &str) -> Result<(), String> {
        let mut tokens = self.tokens.lock().unwrap();

        match tokens.get_mut(token_id) {
            Some(token) => {
                if token.status != TokenStatus::Active {
                    return Err(format!("Cannot consume token in {:?} status", token.status));
                }

                let old_status = token.status;
                let now = super::current_timestamp_ns();
                token.status = TokenStatus::Consumed;
                token.consumed_timestamp_ns = Some(now);

                self.log_audit(TokenAuditRecord {
                    operation: "consume".to_string(),
                    token_id: token_id.to_string(),
                    command_id: token.command_id.clone(),
                    principal: token.issuer_principal,
                    timestamp_ns: now,
                    status_before: old_status,
                    status_after: TokenStatus::Consumed,
                    reason: None,
                });

                Ok(())
            }
            None => Err(format!("Token not found: {}", token_id)),
        }
    }

    /// Revoke a token (any → REVOKED)
    pub fn revoke_token(&self, token_id: &str, reason: String) -> Result<(), String> {
        let mut tokens = self.tokens.lock().unwrap();

        match tokens.get_mut(token_id) {
            Some(token) => {
                let old_status = token.status;
                token.status = TokenStatus::Revoked;
                token.revocation_reason = Some(reason.clone());

                self.log_audit(TokenAuditRecord {
                    operation: "revoke".to_string(),
                    token_id: token_id.to_string(),
                    command_id: token.command_id.clone(),
                    principal: token.issuer_principal,
                    timestamp_ns: super::current_timestamp_ns(),
                    status_before: old_status,
                    status_after: TokenStatus::Revoked,
                    reason: Some(reason),
                });

                Ok(())
            }
            None => Err(format!("Token not found: {}", token_id)),
        }
    }

    /// Mark token as expired (any → EXPIRED)
    pub fn expire_token(&self, token_id: &str) -> Result<(), String> {
        let mut tokens = self.tokens.lock().unwrap();

        match tokens.get_mut(token_id) {
            Some(token) => {
                let old_status = token.status;
                token.status = TokenStatus::Expired;

                self.log_audit(TokenAuditRecord {
                    operation: "expire".to_string(),
                    token_id: token_id.to_string(),
                    command_id: token.command_id.clone(),
                    principal: token.issuer_principal,
                    timestamp_ns: super::current_timestamp_ns(),
                    status_before: old_status,
                    status_after: TokenStatus::Expired,
                    reason: None,
                });

                Ok(())
            }
            None => Err(format!("Token not found: {}", token_id)),
        }
    }

    /// Get token by ID
    pub fn get_token(&self, token_id: &str) -> Option<ExecutionToken> {
        self.tokens.lock().unwrap().get(token_id).cloned()
    }

    /// Get token for a command
    pub fn get_token_for_command(&self, command_id: &str) -> Option<ExecutionToken> {
        let cmd_tokens = self.command_tokens.lock().unwrap();

        match cmd_tokens.get(command_id) {
            Some(token_id) => self.tokens.lock().unwrap().get(token_id).cloned(),
            None => None,
        }
    }

    /// Revoke all tokens for a principal (cascade revocation)
    pub fn revoke_tokens_for_principal(&self, principal: Principal, reason: String) -> usize {
        let mut tokens = self.tokens.lock().unwrap();
        let mut revoked_count = 0;

        for token in tokens.values_mut() {
            if token.validator_principal == principal || token.issuer_principal == principal {
                if token.status != TokenStatus::Revoked {
                    token.status = TokenStatus::Revoked;
                    token.revocation_reason = Some(reason.clone());
                    revoked_count += 1;
                }
            }
        }

        revoked_count
    }

    /// Clean up expired tokens (returns count of cleaned up tokens)
    pub fn cleanup_expired(&self, current_timestamp_ns: u64) -> usize {
        let mut tokens = self.tokens.lock().unwrap();
        let mut cmd_tokens = self.command_tokens.lock().unwrap();

        let initial_count = tokens.len();

        // Mark expired tokens
        for token in tokens.values_mut() {
            if token.status == TokenStatus::Active && token.is_expired(current_timestamp_ns) {
                token.status = TokenStatus::Expired;
            }
        }

        // Remove consumed and expired tokens (keep revoked for audit)
        let to_remove: Vec<_> = tokens
            .iter()
            .filter(|(_, t)| t.status == TokenStatus::Consumed || t.status == TokenStatus::Expired)
            .map(|(id, _)| id.clone())
            .collect();

        for token_id in to_remove {
            if let Some(token) = tokens.remove(&token_id) {
                cmd_tokens.remove(&token.command_id);
            }
        }

        initial_count - tokens.len()
    }

    /// Get audit log
    pub fn get_audit_log(&self) -> Vec<TokenAuditRecord> {
        self.audit_log.lock().unwrap().clone()
    }

    /// Get statistics
    pub fn get_statistics(&self) -> TokenStatistics {
        let tokens = self.tokens.lock().unwrap();

        let pending = tokens.values().filter(|t| t.status == TokenStatus::Pending).count();
        let active = tokens.values().filter(|t| t.status == TokenStatus::Active).count();
        let consumed = tokens.values().filter(|t| t.status == TokenStatus::Consumed).count();
        let expired = tokens.values().filter(|t| t.status == TokenStatus::Expired).count();
        let revoked = tokens.values().filter(|t| t.status == TokenStatus::Revoked).count();

        TokenStatistics {
            total_tokens: tokens.len(),
            pending,
            active,
            consumed,
            expired,
            revoked,
        }
    }

    /// Log audit record
    fn log_audit(&self, record: TokenAuditRecord) {
        let mut log = self.audit_log.lock().unwrap();
        log.push(record);
    }
}

/// Statistics for token issuer
#[derive(Debug, Clone)]
pub struct TokenStatistics {
    pub total_tokens: usize,
    pub pending: usize,
    pub active: usize,
    pub consumed: usize,
    pub expired: usize,
    pub revoked: usize,
}

/// Execution token verifier: validates tokens at execution time
pub struct ExecutionTokenVerifier {
    issuer: Arc<ExecutionTokenIssuer>,
}

impl ExecutionTokenVerifier {
    /// Create a new token verifier
    pub fn new(issuer: Arc<ExecutionTokenIssuer>) -> Self {
        ExecutionTokenVerifier { issuer }
    }

    /// Verify token is valid for execution
    pub fn verify_token(&self, token_id: &str, current_timestamp_ns: u64) -> Result<ExecutionToken, String> {
        match self.issuer.get_token(token_id) {
            Some(token) => {
                // Check status
                if token.status == TokenStatus::Consumed {
                    return Err("Token already consumed".to_string());
                }

                if token.status == TokenStatus::Revoked {
                    return Err(format!(
                        "Token revoked: {}",
                        token.revocation_reason.unwrap_or_default()
                    ));
                }

                // Check expiration
                if token.is_expired(current_timestamp_ns) {
                    return Err("Token expired".to_string());
                }

                // Check status is Active
                if token.status != TokenStatus::Active {
                    return Err(format!("Token in invalid status: {:?}", token.status));
                }

                // Verify signature
                if !token.signature_valid() {
                    return Err("Token signature invalid".to_string());
                }

                Ok(token)
            }
            None => Err(format!("Token not found: {}", token_id)),
        }
    }

    /// Check if token can be consumed
    pub fn can_consume_token(&self, token_id: &str, current_timestamp_ns: u64) -> bool {
        self.verify_token(token_id, current_timestamp_ns).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_token_creation() {
        let token = ExecutionToken::new(
            "cmd-123".to_string(),
            1000,
            6000,  // 5s TTL
            Principal::Supervisor,
            Principal::Actuator,
            0x03,  // Gate C + Gate I
            [1u8; 64],
        );

        assert_eq!(token.command_id, "cmd-123");
        assert_eq!(token.status, TokenStatus::Pending);
        assert_eq!(token.required_gates, 0x03);
    }

    #[test]
    fn test_token_is_valid() {
        let token = ExecutionToken::new(
            "cmd-123".to_string(),
            1000,
            6000,
            Principal::Supervisor,
            Principal::Actuator,
            0x03,
            [1u8; 64],
        );

        // Token not valid while Pending
        assert!(!token.is_valid(1500));

        // Would be valid if Active
        let mut active_token = token.clone();
        active_token.status = TokenStatus::Active;
        assert!(active_token.is_valid(1500));
        assert!(!active_token.is_valid(7000));  // Expired
    }

    #[test]
    fn test_token_expiration() {
        let token = ExecutionToken::new(
            "cmd-123".to_string(),
            1000,
            6000,
            Principal::Supervisor,
            Principal::Actuator,
            0x03,
            [1u8; 64],
        );

        assert!(!token.is_expired(5000));
        assert!(token.is_expired(6000));
        assert!(token.is_expired(7000));
    }

    #[test]
    fn test_token_issuer_lifecycle() {
        let issuer = ExecutionTokenIssuer::new(5_000_000_000);  // 5s TTL

        // Issue token
        let result = issuer.issue_token(
            "cmd-123".to_string(),
            1000,
            Principal::Supervisor,
            Principal::Actuator,
            0x03,
            [1u8; 64],
        );

        assert!(result.is_ok());
        let token = result.unwrap();

        // Activate token
        let activate_result = issuer.activate_token(&token.token_id);
        assert!(activate_result.is_ok());

        // Verify status changed
        let retrieved = issuer.get_token(&token.token_id).unwrap();
        assert_eq!(retrieved.status, TokenStatus::Active);

        // Consume token
        let consume_result = issuer.consume_token(&token.token_id);
        assert!(consume_result.is_ok());

        // Verify status changed
        let consumed = issuer.get_token(&token.token_id).unwrap();
        assert_eq!(consumed.status, TokenStatus::Consumed);
    }

    #[test]
    fn test_token_revocation() {
        let issuer = ExecutionTokenIssuer::new(5_000_000_000);

        let token = issuer.issue_token(
            "cmd-123".to_string(),
            1000,
            Principal::Supervisor,
            Principal::Actuator,
            0x03,
            [1u8; 64],
        ).unwrap();

        // Revoke token
        let revoke_result = issuer.revoke_token(&token.token_id, "Key compromise".to_string());
        assert!(revoke_result.is_ok());

        // Verify status
        let revoked = issuer.get_token(&token.token_id).unwrap();
        assert_eq!(revoked.status, TokenStatus::Revoked);
        assert_eq!(revoked.revocation_reason, Some("Key compromise".to_string()));
    }

    #[test]
    fn test_token_verifier() {
        let issuer = Arc::new(ExecutionTokenIssuer::new(5_000_000_000));
        let verifier = ExecutionTokenVerifier::new(issuer.clone());

        let token = issuer.issue_token(
            "cmd-123".to_string(),
            1000,
            Principal::Supervisor,
            Principal::Actuator,
            0x03,
            [1u8; 64],
        ).unwrap();

        // Token not valid while Pending
        assert!(verifier.verify_token(&token.token_id, 2000).is_err());

        // Activate token
        issuer.activate_token(&token.token_id).ok();

        // Now valid
        assert!(verifier.verify_token(&token.token_id, 2000).is_ok());

        // Invalid when consumed
        issuer.consume_token(&token.token_id).ok();
        assert!(verifier.verify_token(&token.token_id, 2000).is_err());
    }

    #[test]
    fn test_cascade_revocation() {
        let issuer = ExecutionTokenIssuer::new(5_000_000_000);

        // Issue multiple tokens
        let token1 = issuer.issue_token(
            "cmd-1".to_string(),
            1000,
            Principal::Supervisor,
            Principal::Actuator,
            0x03,
            [1u8; 64],
        ).unwrap();

        let token2 = issuer.issue_token(
            "cmd-2".to_string(),
            1000,
            Principal::Supervisor,
            Principal::Policy,
            0x03,
            [2u8; 64],
        ).unwrap();

        let token3 = issuer.issue_token(
            "cmd-3".to_string(),
            1000,
            Principal::Supervisor,
            Principal::Actuator,
            0x03,
            [3u8; 64],
        ).unwrap();

        // Revoke all Actuator tokens
        let revoked_count = issuer.revoke_tokens_for_principal(
            Principal::Actuator,
            "Principal compromise".to_string()
        );

        // Should have revoked 2 tokens (token1 and token3)
        assert_eq!(revoked_count, 2);

        // Verify token1 and token3 are revoked
        assert_eq!(issuer.get_token(&token1.token_id).unwrap().status, TokenStatus::Revoked);
        assert_eq!(issuer.get_token(&token3.token_id).unwrap().status, TokenStatus::Revoked);

        // Verify token2 is not revoked
        assert_ne!(issuer.get_token(&token2.token_id).unwrap().status, TokenStatus::Revoked);
    }

    #[test]
    fn test_token_statistics() {
        let issuer = ExecutionTokenIssuer::new(5_000_000_000);

        // Issue tokens
        let token1 = issuer.issue_token(
            "cmd-1".to_string(),
            1000,
            Principal::Supervisor,
            Principal::Actuator,
            0x03,
            [1u8; 64],
        ).unwrap();

        let token2 = issuer.issue_token(
            "cmd-2".to_string(),
            1000,
            Principal::Supervisor,
            Principal::Actuator,
            0x03,
            [2u8; 64],
        ).unwrap();

        // Initial state: 2 pending
        let stats = issuer.get_statistics();
        assert_eq!(stats.total_tokens, 2);
        assert_eq!(stats.pending, 2);

        // Activate one
        issuer.activate_token(&token1.token_id).ok();
        let stats = issuer.get_statistics();
        assert_eq!(stats.active, 1);

        // Consume it
        issuer.consume_token(&token1.token_id).ok();
        let stats = issuer.get_statistics();
        assert_eq!(stats.consumed, 1);

        // Revoke the other
        issuer.revoke_token(&token2.token_id, "Test".to_string()).ok();
        let stats = issuer.get_statistics();
        assert_eq!(stats.revoked, 1);
    }
}
