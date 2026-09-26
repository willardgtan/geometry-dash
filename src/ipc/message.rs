// Universal Message Format for IPC (Week 1 Task 3.1)
// Sprint 2 Task 2.5: Message Classification

use serde::{Deserialize, Serialize};
use crate::types::Principal;
use crate::principals::ClassificationLevel;

// Message flags (bitflags for message properties)
pub const FLAG_REQUIRES_AUTH: u32 = 0x01;      // Signature mandatory
pub const FLAG_REQUIRES_NONCE: u32 = 0x02;     // Nonce cache check
pub const FLAG_REQUIRES_RESPONSE: u32 = 0x04;  // Expect response
pub const FLAG_IDEMPOTENT: u32 = 0x08;         // Safe to retry
pub const FLAG_PRIORITY_HIGH: u32 = 0x10;      // Expedite processing
pub const FLAG_CRITICAL: u32 = 0x20;           // Audit-critical (log at CRITICAL)

// Message types
pub const MESSAGE_TYPE_REQUEST: u8 = 0;
pub const MESSAGE_TYPE_RESPONSE: u8 = 1;
pub const MESSAGE_TYPE_EVENT: u8 = 2;
pub const MESSAGE_TYPE_ERROR: u8 = 3;

/// Universal message header: required for all IPC messages across all 22 interfaces
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalMessageHeader {
    /// Interface ID (1-22, corresponding to IF-001 through IF-022)
    pub interface_id: u32,

    /// Protocol version (currently 1)
    pub protocol_version: u8,

    /// Message type: 0=REQUEST, 1=RESPONSE, 2=EVENT, 3=ERROR
    pub message_type: u8,

    /// Flags (bit flags: REQUIRES_AUTH, REQUIRES_NONCE, REQUIRES_RESPONSE, etc)
    pub flags: u32,

    /// Sender principal (0-8, corresponding to PRN enum)
    pub sender_principal: u8,

    /// Receiver principal (0-8)
    pub receiver_principal: u8,

    /// Unique message ID per interface (incremental counter)
    pub message_id: u64,

    /// Request ID for matching requests ↔ responses
    pub request_id: u64,

    /// 256-bit random value for replay detection
    pub nonce: [u8; 32],

    /// Monotonic nanosecond timestamp (REQ-EVIDENCE-004)
    pub timestamp_ns: u64,

    /// Principal that signed this message (usually = sender_principal)
    pub witness_principal: u8,

    /// Ed25519 signature over serialized message (without signature field)
    pub witness_signature: [u8; 64],

    /// Optional: Artifact ID if this message references an evidence artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_evidence_id: Option<String>,

    /// Sequence number for ordering within an interface
    pub sequence_number: u64,

    // Data classification fields (Sprint 2 Task 2.5)
    /// Classification level of the message payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification_level: Option<ClassificationLevel>,

    /// Minimum clearance required to read/process this message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_clearance: Option<ClassificationLevel>,

    /// Flag: has payload been declassified from a higher level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declassification_approved: Option<bool>,
}

impl UniversalMessageHeader {
    /// Create a new message header
    pub fn new(
        interface_id: u32,
        message_type: u8,
        sender_principal: u8,
        receiver_principal: u8,
        flags: u32,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let nonce = Self::generate_nonce();

        UniversalMessageHeader {
            interface_id,
            protocol_version: 1,
            message_type,
            flags,
            sender_principal,
            receiver_principal,
            message_id: 0,  // Set by IPC layer
            request_id: 0,  // Set by caller for request/response pairs
            nonce,
            timestamp_ns,
            witness_principal: sender_principal,
            witness_signature: [0u8; 64],  // Set by signer before sending
            source_evidence_id: None,
            sequence_number: 0,  // Set by IPC layer
            classification_level: None,
            required_clearance: None,
            declassification_approved: None,
        }
    }

    /// Generate a random 256-bit nonce
    fn generate_nonce() -> [u8; 32] {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};

        let mut hasher = RandomState::new().build_hasher();
        SystemTime::now().hash(&mut hasher);
        let hash = hasher.finish();

        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&hash.to_le_bytes());
        nonce[8..16].copy_from_slice(&hash.wrapping_shl(16).to_le_bytes());
        nonce[16..24].copy_from_slice(&hash.wrapping_shl(32).to_le_bytes());
        nonce[24..32].copy_from_slice(&hash.wrapping_shl(48).to_le_bytes());

        nonce
    }

    /// Set source evidence ID if this message references an artifact
    pub fn set_evidence_id(&mut self, evidence_id: String) {
        self.source_evidence_id = Some(evidence_id);
    }

    /// Get message type as a readable string
    pub fn message_type_str(&self) -> &'static str {
        match self.message_type {
            MESSAGE_TYPE_REQUEST => "REQUEST",
            MESSAGE_TYPE_RESPONSE => "RESPONSE",
            MESSAGE_TYPE_EVENT => "EVENT",
            MESSAGE_TYPE_ERROR => "ERROR",
            _ => "UNKNOWN",
        }
    }

    /// Check if this message requires authentication
    pub fn requires_auth(&self) -> bool {
        (self.flags & FLAG_REQUIRES_AUTH) != 0
    }

    /// Check if this message requires nonce validation
    pub fn requires_nonce(&self) -> bool {
        (self.flags & FLAG_REQUIRES_NONCE) != 0
    }

    /// Check if this message expects a response
    pub fn requires_response(&self) -> bool {
        (self.flags & FLAG_REQUIRES_RESPONSE) != 0
    }

    /// Check if this message is idempotent (safe to retry)
    pub fn is_idempotent(&self) -> bool {
        (self.flags & FLAG_IDEMPOTENT) != 0
    }

    /// Check if this message is marked as critical
    pub fn is_critical(&self) -> bool {
        (self.flags & FLAG_CRITICAL) != 0
    }

    /// Set the classification level for this message payload
    pub fn set_classification(&mut self, level: ClassificationLevel) {
        self.classification_level = Some(level);
    }

    /// Set the minimum clearance required to process this message
    pub fn set_required_clearance(&mut self, level: ClassificationLevel) {
        self.required_clearance = Some(level);
    }

    /// Mark this message as declassified from a higher level
    pub fn mark_declassified(&mut self) {
        self.declassification_approved = Some(true);
    }

    /// Get the classification level of this message
    pub fn get_classification(&self) -> Option<ClassificationLevel> {
        self.classification_level
    }

    /// Get the required clearance level for this message
    pub fn get_required_clearance(&self) -> Option<ClassificationLevel> {
        self.required_clearance
    }

    /// Check if this message is marked as declassified
    pub fn is_declassified(&self) -> bool {
        self.declassification_approved.unwrap_or(false)
    }

    /// Validate authorization: check if receiver has required clearance
    ///
    /// Preconditions:
    /// - Both receiver principal and required clearance are known
    ///
    /// Returns: true if receiver can process message (has sufficient clearance)
    pub fn authorize_receiver(&self, principal_clearances: &[(u8, Vec<ClassificationLevel>)]) -> bool {
        // If no clearance requirement, anyone can read
        if self.required_clearance.is_none() {
            return true;
        }

        let required = self.required_clearance.unwrap();

        // Find this principal's clearances
        for (principal, clearances) in principal_clearances {
            if *principal == self.receiver_principal {
                return clearances.contains(&required);
            }
        }

        false  // Principal not found in clearance list
    }
}

/// Universal message with header and payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalMessage {
    /// Message header (required)
    pub header: UniversalMessageHeader,

    /// Interface-specific payload (variable length, max 1MB)
    pub payload: Vec<u8>,
}

impl UniversalMessage {
    /// Create a new universal message
    pub fn new(
        interface_id: u32,
        message_type: u8,
        sender_principal: u8,
        receiver_principal: u8,
        flags: u32,
        payload: Vec<u8>,
    ) -> Self {
        let header = UniversalMessageHeader::new(
            interface_id,
            message_type,
            sender_principal,
            receiver_principal,
            flags,
        );

        UniversalMessage { header, payload }
    }

    /// Serialize message to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize message from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Get total message size in bytes
    pub fn size(&self) -> usize {
        self.to_json()
            .map(|j| j.len())
            .unwrap_or(0)
    }

    /// Validate message size (max 1MB)
    pub fn validate_size(&self) -> Result<(), String> {
        const MAX_SIZE: usize = 1024 * 1024; // 1MB
        let size = self.size();
        if size > MAX_SIZE {
            Err(format!("Message size {} exceeds limit {}", size, MAX_SIZE))
        } else {
            Ok(())
        }
    }

    /// Create response message for a request
    pub fn create_response(request: &Self, payload: Vec<u8>) -> Self {
        let mut response = UniversalMessage::new(
            request.header.interface_id,
            MESSAGE_TYPE_RESPONSE,
            request.header.receiver_principal,  // Response sent by receiver
            request.header.sender_principal,     // To original sender
            0,  // Flags inherited from request typically
            payload,
        );
        response.header.request_id = request.header.message_id;
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_header_creation() {
        let header = UniversalMessageHeader::new(2, MESSAGE_TYPE_REQUEST, 1, 3, FLAG_REQUIRES_AUTH);
        assert_eq!(header.interface_id, 2);
        assert_eq!(header.protocol_version, 1);
        assert_eq!(header.message_type, MESSAGE_TYPE_REQUEST);
        assert_eq!(header.sender_principal, 1);
        assert_eq!(header.receiver_principal, 3);
        assert!(header.requires_auth());
    }

    #[test]
    fn test_message_header_flags() {
        let header = UniversalMessageHeader::new(
            2,
            MESSAGE_TYPE_REQUEST,
            1,
            3,
            FLAG_REQUIRES_AUTH | FLAG_REQUIRES_RESPONSE | FLAG_CRITICAL,
        );
        assert!(header.requires_auth());
        assert!(header.requires_response());
        assert!(header.is_critical());
        assert!(!header.is_idempotent());
    }

    #[test]
    fn test_message_type_str() {
        let h1 = UniversalMessageHeader::new(1, MESSAGE_TYPE_REQUEST, 1, 2, 0);
        let h2 = UniversalMessageHeader::new(1, MESSAGE_TYPE_RESPONSE, 1, 2, 0);
        let h3 = UniversalMessageHeader::new(1, MESSAGE_TYPE_EVENT, 1, 2, 0);
        let h4 = UniversalMessageHeader::new(1, MESSAGE_TYPE_ERROR, 1, 2, 0);

        assert_eq!(h1.message_type_str(), "REQUEST");
        assert_eq!(h2.message_type_str(), "RESPONSE");
        assert_eq!(h3.message_type_str(), "EVENT");
        assert_eq!(h4.message_type_str(), "ERROR");
    }

    #[test]
    fn test_universal_message_creation() {
        let payload = b"test payload".to_vec();
        let msg = UniversalMessage::new(2, MESSAGE_TYPE_REQUEST, 1, 3, FLAG_REQUIRES_AUTH, payload.clone());

        assert_eq!(msg.header.interface_id, 2);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn test_message_serialization() {
        let payload = b"test data".to_vec();
        let msg = UniversalMessage::new(5, MESSAGE_TYPE_REQUEST, 2, 1, 0, payload);

        let json = msg.to_json().unwrap();
        let parsed = UniversalMessage::from_json(&json).unwrap();

        assert_eq!(parsed.header.interface_id, 5);
        assert_eq!(parsed.header.sender_principal, 2);
        assert_eq!(parsed.payload, b"test data");
    }

    #[test]
    fn test_message_size() {
        let msg = UniversalMessage::new(1, MESSAGE_TYPE_REQUEST, 1, 2, 0, vec![]);
        let size = msg.size();
        assert!(size > 0);
        assert!(size < 10000);  // Should be reasonable JSON
    }

    #[test]
    fn test_message_validate_size() {
        let msg = UniversalMessage::new(1, MESSAGE_TYPE_REQUEST, 1, 2, 0, vec![0u8; 100]);
        assert!(msg.validate_size().is_ok());
    }

    #[test]
    fn test_response_creation() {
        let request = UniversalMessage::new(
            2,
            MESSAGE_TYPE_REQUEST,
            1,
            3,
            FLAG_REQUIRES_RESPONSE,
            b"request".to_vec(),
        );

        let response = UniversalMessage::create_response(&request, b"response".to_vec());

        assert_eq!(response.header.interface_id, request.header.interface_id);
        assert_eq!(response.header.message_type, MESSAGE_TYPE_RESPONSE);
        assert_eq!(response.header.sender_principal, 3);  // Was receiver
        assert_eq!(response.header.receiver_principal, 1); // Was sender
        assert_eq!(response.header.request_id, request.header.message_id);
        assert_eq!(response.payload, b"response");
    }

    #[test]
    fn test_evidence_id() {
        let mut header = UniversalMessageHeader::new(1, MESSAGE_TYPE_REQUEST, 1, 2, 0);
        assert!(header.source_evidence_id.is_none());

        header.set_evidence_id("artifact-123".to_string());
        assert_eq!(header.source_evidence_id, Some("artifact-123".to_string()));
    }

    #[test]
    fn test_message_classification() {
        let mut header = UniversalMessageHeader::new(1, MESSAGE_TYPE_REQUEST, 1, 2, 0);
        assert_eq!(header.get_classification(), None);

        header.set_classification(ClassificationLevel::SensitiveReward);
        assert_eq!(header.get_classification(), Some(ClassificationLevel::SensitiveReward));
    }

    #[test]
    fn test_message_required_clearance() {
        let mut header = UniversalMessageHeader::new(1, MESSAGE_TYPE_REQUEST, 1, 2, 0);
        assert_eq!(header.get_required_clearance(), None);

        header.set_required_clearance(ClassificationLevel::PrivilegedTelemetry);
        assert_eq!(
            header.get_required_clearance(),
            Some(ClassificationLevel::PrivilegedTelemetry)
        );
    }

    #[test]
    fn test_message_declassification() {
        let mut header = UniversalMessageHeader::new(1, MESSAGE_TYPE_REQUEST, 1, 2, 0);
        assert!(!header.is_declassified());

        header.mark_declassified();
        assert!(header.is_declassified());
    }

    #[test]
    fn test_authorize_receiver_no_clearance_required() {
        let header = UniversalMessageHeader::new(1, MESSAGE_TYPE_REQUEST, 1, 2, 0);
        // No clearance requirement set
        assert!(header.authorize_receiver(&[]));
    }

    #[test]
    fn test_authorize_receiver_with_clearance() {
        let mut header = UniversalMessageHeader::new(1, MESSAGE_TYPE_REQUEST, 1, 2, 0);
        header.set_required_clearance(ClassificationLevel::SensitiveReward);

        // Receiver principal is 2, with clearances
        let clearances = vec![(
            2,
            vec![
                ClassificationLevel::Unrestricted,
                ClassificationLevel::SensitiveReward,
            ],
        )];

        assert!(header.authorize_receiver(&clearances));
    }

    #[test]
    fn test_authorize_receiver_insufficient_clearance() {
        let mut header = UniversalMessageHeader::new(1, MESSAGE_TYPE_REQUEST, 1, 2, 0);
        header.set_required_clearance(ClassificationLevel::PrivilegedTelemetry);

        // Receiver principal is 2, but only has Unrestricted clearance
        let clearances = vec![(
            2,
            vec![ClassificationLevel::Unrestricted, ClassificationLevel::SensitiveReward],
        )];

        assert!(!header.authorize_receiver(&clearances));
    }

    #[test]
    fn test_authorize_receiver_unknown_principal() {
        let mut header = UniversalMessageHeader::new(1, MESSAGE_TYPE_REQUEST, 1, 2, 0);
        header.set_required_clearance(ClassificationLevel::SensitiveReward);

        // Principal 5 not in clearance list
        let clearances = vec![(
            3,
            vec![ClassificationLevel::Unrestricted, ClassificationLevel::SensitiveReward],
        )];

        assert!(!header.authorize_receiver(&clearances));
    }

    #[test]
    fn test_classified_message_serialization() {
        let mut header = UniversalMessageHeader::new(1, MESSAGE_TYPE_REQUEST, 1, 2, 0);
        header.set_classification(ClassificationLevel::PrivilegedTelemetry);
        header.set_required_clearance(ClassificationLevel::PrivilegedTelemetry);
        header.mark_declassified();

        let msg = UniversalMessage {
            header,
            payload: b"secret".to_vec(),
        };

        let json = msg.to_json().unwrap();
        let parsed = UniversalMessage::from_json(&json).unwrap();

        assert_eq!(
            parsed.header.get_classification(),
            Some(ClassificationLevel::PrivilegedTelemetry)
        );
        assert_eq!(
            parsed.header.get_required_clearance(),
            Some(ClassificationLevel::PrivilegedTelemetry)
        );
        assert!(parsed.header.is_declassified());
    }
}
