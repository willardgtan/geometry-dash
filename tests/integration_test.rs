// Integration tests for Phase 2 Foundation Layer (Week 1)
// Tests the interaction between Supervisor, SecurityLedger, IPC, and Config modules

use geometry_dash::{
    Supervisor, SecurityLedger, SecurityEvent, EventType, Severity,
    UniversalMessage, UniversalMessageHeader, NonceCache, CapabilityMatrix, Principal,
};
use std::collections::HashMap;
use tempfile::NamedTempFile;

#[test]
fn test_supervisor_creates_ledger() {
    let temp = NamedTempFile::new().unwrap();
    let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

    let ledger_entries = supervisor.ledger_entries();
    assert!(ledger_entries > 0, "Supervisor should create initial ledger entry");
}

#[test]
fn test_ledger_persists_events() {
    let temp = NamedTempFile::new().unwrap();
    let ledger_path = temp.path().to_str().unwrap();

    {
        let ledger = SecurityLedger::open(ledger_path).unwrap();
        let mut details = HashMap::new();
        details.insert("action".to_string(), "test".to_string());

        ledger.append_event(
            EventType::ActionRequested,
            Principal::Policy,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            details,
        ).unwrap();

        assert_eq!(ledger.count(), 1);
    }

    // Reopen and verify
    {
        let ledger = SecurityLedger::open(ledger_path).unwrap();
        assert_eq!(ledger.count(), 1);
    }
}

#[test]
fn test_ipc_message_round_trip() {
    let msg = UniversalMessage::new(
        2,
        0,  // REQUEST
        1,  // PRN-POLICY
        3,  // PRN-AUDIT
        0x01,  // FLAG_REQUIRES_AUTH
        b"test payload".to_vec(),
    );

    let json = msg.to_json().unwrap();
    let parsed = UniversalMessage::from_json(&json).unwrap();

    assert_eq!(parsed.header.interface_id, 2);
    assert_eq!(parsed.header.sender_principal, 1);
    assert_eq!(parsed.payload, b"test payload");
}

#[test]
fn test_nonce_cache_prevents_replays() {
    let cache = NonceCache::new(5000, 1000);
    let nonce = [42u8; 32];
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // First insertion succeeds
    assert!(cache.check_and_insert(nonce, 1, 100, 1, ts).is_ok());

    // Second insertion with same nonce fails
    assert!(cache.check_and_insert(nonce, 1, 101, 1, ts + 100).is_err());
}

#[test]
fn test_capability_matrix_enforces_access() {
    let mut matrix = CapabilityMatrix::new();

    // Policy can use IF-002
    matrix.allow(1, 2);

    assert!(matrix.can_use(1, 2));   // Allowed
    assert!(!matrix.can_use(2, 2));  // Not allowed (Actuator)
    assert!(!matrix.can_use(1, 3));  // Not allowed (IF-003)
}

#[test]
fn test_supervisor_tracks_principal_health() {
    let temp = NamedTempFile::new().unwrap();
    let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

    // All principals should start not running
    let all_health = supervisor.all_principals_health();
    assert_eq!(all_health.len(), 8);

    // Record heartbeat for one principal
    supervisor.heartbeat(Principal::Policy);

    let policy_health = supervisor.principal_health(Principal::Policy).unwrap();
    assert!(policy_health.last_heartbeat_ns > 0);
}

#[test]
fn test_ledger_hash_chain_verification() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

    // Append multiple events
    for i in 0..5 {
        let mut details = HashMap::new();
        details.insert("index".to_string(), i.to_string());

        ledger.append_event(
            EventType::ActionExecuted,
            Principal::Actuator,
            Severity::Info,
            "run-001",
            "boot-001",
            "epoch-001",
            details,
        ).unwrap();
    }

    // Verify chain
    let result = ledger.verify_chain();
    assert!(result.is_ok(), "Hash chain should be valid");
    assert_eq!(ledger.count(), 5);
}

#[test]
fn test_message_response_creation() {
    let request = UniversalMessage::new(
        4,
        0,  // REQUEST
        1,  // PRN-POLICY
        4,  // PRN-DECLASSIFIER
        0x04,  // FLAG_REQUIRES_RESPONSE
        b"declassify request".to_vec(),
    );

    let response = UniversalMessage::create_response(&request, b"approved".to_vec());

    // Verify response properties
    assert_eq!(response.header.interface_id, request.header.interface_id);
    assert_eq!(response.header.sender_principal, 4);  // Was receiver
    assert_eq!(response.header.receiver_principal, 1); // Was sender
    assert_eq!(response.payload, b"approved");
}

#[test]
fn test_supervisor_lockdown() {
    let temp = NamedTempFile::new().unwrap();
    let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

    // Initial state should be Initializing
    assert_eq!(
        format!("{:?}", supervisor.state()),
        "Initializing"
    );

    // Enter lockdown
    supervisor.enter_lockdown();
    assert_eq!(
        format!("{:?}", supervisor.state()),
        "Lockdown"
    );

    // Should have logged a critical event
    assert!(supervisor.ledger_entries() > 1);
}

#[test]
fn test_full_workflow_supervisor_to_ledger() {
    let temp = NamedTempFile::new().unwrap();
    let ledger_path = temp.path().to_str().unwrap();

    // Initialize supervisor
    let supervisor = Supervisor::initialize(ledger_path, None).unwrap();

    // Verify initial state
    assert!(!supervisor.run_id().is_empty());
    assert!(!supervisor.epoch_id().is_empty());
    assert_eq!(supervisor.state(), geometry_dash::SupervisorState::Initializing);

    // Access ledger through supervisor
    let ledger_entries = supervisor.ledger_entries();
    assert!(ledger_entries >= 1);

    // Record principal activities
    supervisor.heartbeat(Principal::Policy);
    supervisor.heartbeat(Principal::Audit);

    // Verify principal health
    assert!(supervisor.is_principal_healthy(Principal::Policy));
    assert!(supervisor.is_principal_healthy(Principal::Audit));
}

#[test]
fn test_ipc_and_ledger_integration() {
    let temp = NamedTempFile::new().unwrap();
    let supervisor = Supervisor::initialize(temp.path().to_str().unwrap(), None).unwrap();

    // Create IPC message
    let msg = UniversalMessage::new(
        2,  // IF-002: Policy → Audit
        0,  // REQUEST
        1,  // PRN-POLICY
        3,  // PRN-AUDIT
        0x03,  // FLAG_REQUIRES_AUTH | FLAG_REQUIRES_NONCE
        b"observation".to_vec(),
    );

    // Verify message can be serialized
    let json = msg.to_json().unwrap();
    assert!(!json.is_empty());

    // Verify supervisor can log the interaction
    let ledger = supervisor.ledger();
    let mut details = HashMap::new();
    details.insert("interface".to_string(), "IF-002".to_string());
    details.insert("message_type".to_string(), "REQUEST".to_string());

    let result = ledger.append_event(
        EventType::ActionRequested,
        Principal::Policy,
        Severity::Info,
        supervisor.run_id(),
        supervisor.boot_id(),
        supervisor.epoch_id(),
        details,
    );

    assert!(result.is_ok());
}
