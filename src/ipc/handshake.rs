// IPC Handshake Protocol (Week 1 Task 1.2)
// INIT/READY message exchange for principal startup coordination

use serde::{Deserialize, Serialize};
use crate::types::Principal;

/// Handshake message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandshakeMessageType {
    Init,   // Supervisor → Principal: start up
    Ready,  // Principal → Supervisor: ready
    Ack,    // Supervisor → Principal: acknowledged
    Error,  // Either side: error occurred
}

/// Handshake capability flags
pub const CAPABILITY_READ: u32 = 0x01;
pub const CAPABILITY_WRITE: u32 = 0x02;
pub const CAPABILITY_AUDIT: u32 = 0x04;
pub const CAPABILITY_SIGN: u32 = 0x08;
pub const CAPABILITY_SEAL: u32 = 0x10;

/// Handshake message payload (JSON-serializable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    /// Message type (INIT, READY, ACK, ERROR)
    pub message_type: HandshakeMessageType,

    /// Sending principal
    pub sender: u8,

    /// Receiving principal
    pub receiver: u8,

    /// Unique message ID for this handshake exchange
    pub message_id: u64,

    /// Run ID (execution context)
    pub run_id: String,

    /// Boot ID (system boot context)
    pub boot_id: String,

    /// Epoch ID (HSM-signed boot boundary)
    pub epoch_id: String,

    /// Timestamp nanoseconds
    pub timestamp_ns: u64,

    /// Optional: Capability flags advertised by principal
    pub capabilities: Option<u32>,

    /// Optional: Error message
    pub error_message: Option<String>,

    /// Optional: Status message
    pub status_message: Option<String>,
}

impl HandshakeMessage {
    /// Create INIT message from Supervisor to Principal
    pub fn init(
        sender: u8,
        receiver: u8,
        message_id: u64,
        run_id: String,
        boot_id: String,
        epoch_id: String,
    ) -> Self {
        HandshakeMessage {
            message_type: HandshakeMessageType::Init,
            sender,
            receiver,
            message_id,
            run_id,
            boot_id,
            epoch_id,
            timestamp_ns: Self::current_timestamp_ns(),
            capabilities: None,
            error_message: None,
            status_message: Some("Supervisor: please initialize".to_string()),
        }
    }

    /// Create READY message from Principal to Supervisor
    pub fn ready(
        sender: u8,
        receiver: u8,
        message_id: u64,
        run_id: String,
        boot_id: String,
        epoch_id: String,
        capabilities: u32,
    ) -> Self {
        HandshakeMessage {
            message_type: HandshakeMessageType::Ready,
            sender,
            receiver,
            message_id,
            run_id,
            boot_id,
            epoch_id,
            timestamp_ns: Self::current_timestamp_ns(),
            capabilities: Some(capabilities),
            error_message: None,
            status_message: Some("Principal: ready for requests".to_string()),
        }
    }

    /// Create ACK message from Supervisor to Principal
    pub fn ack(
        sender: u8,
        receiver: u8,
        message_id: u64,
        run_id: String,
        boot_id: String,
        epoch_id: String,
    ) -> Self {
        HandshakeMessage {
            message_type: HandshakeMessageType::Ack,
            sender,
            receiver,
            message_id,
            run_id,
            boot_id,
            epoch_id,
            timestamp_ns: Self::current_timestamp_ns(),
            capabilities: None,
            error_message: None,
            status_message: Some("Supervisor: acknowledged".to_string()),
        }
    }

    /// Create ERROR message
    pub fn error(
        sender: u8,
        receiver: u8,
        message_id: u64,
        run_id: String,
        boot_id: String,
        epoch_id: String,
        error_msg: String,
    ) -> Self {
        HandshakeMessage {
            message_type: HandshakeMessageType::Error,
            sender,
            receiver,
            message_id,
            run_id,
            boot_id,
            epoch_id,
            timestamp_ns: Self::current_timestamp_ns(),
            capabilities: None,
            error_message: Some(error_msg),
            status_message: None,
        }
    }

    /// Check if principal has a specific capability
    pub fn has_capability(&self, cap: u32) -> bool {
        self.capabilities.map(|c| (c & cap) != 0).unwrap_or(false)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Get current timestamp in nanoseconds
    fn current_timestamp_ns() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Check if message is expired (older than max_age_ns)
    pub fn is_expired(&self, max_age_ns: u64) -> bool {
        let now = Self::current_timestamp_ns();
        now > self.timestamp_ns + max_age_ns
    }
}

/// Handshake state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    Idle,           // No handshake in progress
    AwaitingReady,  // Sent INIT, waiting for READY
    Established,    // Handshake complete
    Failed,         // Handshake failed
}

/// Handshake coordinator: manages the INIT↔READY exchange
pub struct HandshakeCoordinator {
    state: HandshakeState,
    init_message: Option<HandshakeMessage>,
    ready_message: Option<HandshakeMessage>,
    error: Option<String>,
}

impl HandshakeCoordinator {
    /// Create new handshake coordinator
    pub fn new() -> Self {
        HandshakeCoordinator {
            state: HandshakeState::Idle,
            init_message: None,
            ready_message: None,
            error: None,
        }
    }

    /// Send INIT message and transition to AwaitingReady
    pub fn send_init(&mut self, message: HandshakeMessage) -> Result<(), String> {
        if self.state != HandshakeState::Idle {
            return Err("Handshake already in progress or complete".to_string());
        }

        if message.message_type != HandshakeMessageType::Init {
            return Err("Message must be INIT type".to_string());
        }

        self.init_message = Some(message);
        self.state = HandshakeState::AwaitingReady;
        Ok(())
    }

    /// Receive READY message and transition to Established
    pub fn receive_ready(&mut self, message: HandshakeMessage) -> Result<(), String> {
        if self.state != HandshakeState::AwaitingReady {
            return Err("Not waiting for READY message".to_string());
        }

        if message.message_type != HandshakeMessageType::Ready {
            return Err("Message must be READY type".to_string());
        }

        // Validate message_id matches
        if let Some(init) = &self.init_message {
            if init.message_id != message.message_id {
                self.state = HandshakeState::Failed;
                self.error = Some("Message ID mismatch".to_string());
                return Err("Message ID mismatch".to_string());
            }
        }

        self.ready_message = Some(message);
        self.state = HandshakeState::Established;
        Ok(())
    }

    /// Receive ERROR message and fail handshake
    pub fn receive_error(&mut self, message: HandshakeMessage) -> String {
        self.state = HandshakeState::Failed;
        let error_msg = message.error_message.clone().unwrap_or_else(|| "Unknown error".to_string());
        self.error = Some(error_msg.clone());
        error_msg
    }

    /// Get current state
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Established
    }

    /// Check if handshake failed
    pub fn is_failed(&self) -> bool {
        self.state == HandshakeState::Failed
    }

    /// Get error message if failed
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Get ready message if complete
    pub fn ready_message(&self) -> Option<&HandshakeMessage> {
        self.ready_message.as_ref()
    }

    /// Get principal capabilities from ready message
    pub fn capabilities(&self) -> u32 {
        self.ready_message.as_ref()
            .and_then(|m| m.capabilities)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_message_init() {
        let msg = HandshakeMessage::init(
            0, 1, 100,
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
        );

        assert_eq!(msg.message_type, HandshakeMessageType::Init);
        assert_eq!(msg.sender, 0);
        assert_eq!(msg.receiver, 1);
        assert_eq!(msg.message_id, 100);
    }

    #[test]
    fn test_handshake_message_ready() {
        let msg = HandshakeMessage::ready(
            1, 0, 100,
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            CAPABILITY_READ | CAPABILITY_WRITE,
        );

        assert_eq!(msg.message_type, HandshakeMessageType::Ready);
        assert_eq!(msg.sender, 1);
        assert!(msg.has_capability(CAPABILITY_READ));
        assert!(msg.has_capability(CAPABILITY_WRITE));
        assert!(!msg.has_capability(CAPABILITY_SIGN));
    }

    #[test]
    fn test_handshake_coordinator_complete() {
        let mut coord = HandshakeCoordinator::new();

        let init = HandshakeMessage::init(
            0, 1, 100,
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
        );

        assert!(coord.send_init(init).is_ok());
        assert_eq!(coord.state(), HandshakeState::AwaitingReady);

        let ready = HandshakeMessage::ready(
            1, 0, 100,
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            CAPABILITY_READ,
        );

        assert!(coord.receive_ready(ready).is_ok());
        assert_eq!(coord.state(), HandshakeState::Established);
        assert!(coord.is_complete());
    }

    #[test]
    fn test_handshake_coordinator_message_id_mismatch() {
        let mut coord = HandshakeCoordinator::new();

        let init = HandshakeMessage::init(
            0, 1, 100,
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
        );

        assert!(coord.send_init(init).is_ok());

        let ready = HandshakeMessage::ready(
            1, 0, 101,  // Different message ID!
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            CAPABILITY_READ,
        );

        assert!(coord.receive_ready(ready).is_err());
        assert!(coord.is_failed());
    }

    #[test]
    fn test_handshake_coordinator_error() {
        let mut coord = HandshakeCoordinator::new();

        let init = HandshakeMessage::init(
            0, 1, 100,
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
        );

        assert!(coord.send_init(init).is_ok());

        let error = HandshakeMessage::error(
            1, 0, 100,
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            "Principal failed to initialize".to_string(),
        );

        let error_msg = coord.receive_error(error);
        assert_eq!(error_msg, "Principal failed to initialize");
        assert!(coord.is_failed());
    }

    #[test]
    fn test_handshake_message_serialization() {
        let msg = HandshakeMessage::ready(
            1, 0, 100,
            "run-1".to_string(),
            "boot-1".to_string(),
            "epoch-1".to_string(),
            CAPABILITY_READ | CAPABILITY_AUDIT,
        );

        let json = msg.to_json().unwrap();
        let parsed = HandshakeMessage::from_json(&json).unwrap();

        assert_eq!(parsed.message_type, HandshakeMessageType::Ready);
        assert_eq!(parsed.sender, 1);
        assert!(parsed.has_capability(CAPABILITY_READ));
    }
}
