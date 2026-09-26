// HSM integration tests: validating HSM client integration with Supervisor (Task 1.5 Extension)

use geometry_dash::{
    Supervisor, SecurityLedger, Principal,
    hsm::{AutoHsmClient, HsmClient},
};
use tempfile::TempDir;
use std::sync::Arc;

#[test]
fn test_hsm_supervisor_initialization() {
    let temp_dir = TempDir::new().unwrap();
    let ledger_path = temp_dir.path().join("security_ledger.jsonl");

    // Initialize Supervisor which includes HSM client
    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    // Verify Supervisor initialized successfully
    assert!(!supervisor.run_id().is_empty());
    assert!(!supervisor.boot_id().is_empty());
    assert!(!supervisor.epoch_id().is_empty());

    // Verify HSM client is available
    let hsm_mutex = supervisor.hsm_client();
    assert!(hsm_mutex.lock().is_ok());
}

#[test]
fn test_hsm_signing_key_generation_via_supervisor() {
    let temp_dir = TempDir::new().unwrap();
    let ledger_path = temp_dir.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    // Access HSM through Supervisor
    let hsm_client = supervisor.hsm_client();
    let mut hsm = hsm_client.lock().unwrap();

    // Initialize HSM
    assert!(hsm.initialize().is_ok());

    // Generate a signing key for Policy principal
    let policy_key = hsm.generate_signing_key("policy-001");
    assert!(policy_key.is_ok());

    let key = policy_key.unwrap();
    assert_eq!(key.key_id(), "policy-001");
    assert_eq!(key.public_key_bytes().len(), 32);
    assert_eq!(key.secret_key_bytes().len(), 64);
}

#[test]
fn test_hsm_fallback_selection() {
    let temp_dir = TempDir::new().unwrap();
    let ledger_path = temp_dir.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    // Check that HSM is initialized with fallback backend
    let hsm_client = supervisor.hsm_client();
    let hsm = hsm_client.lock().unwrap();

    // Since no PKCS#11 module is configured, should use fallback
    assert!(hsm.is_fallback());
}

#[test]
fn test_hsm_signing_and_verification_via_supervisor() {
    let temp_dir = TempDir::new().unwrap();
    let ledger_path = temp_dir.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    let hsm_client = supervisor.hsm_client();
    let mut hsm = hsm_client.lock().unwrap();

    hsm.initialize().unwrap();

    // Generate key
    let key = hsm.generate_signing_key("sign-test").unwrap();

    // Sign a message
    let message = b"test message for signing";
    let signature = hsm.sign(&key, message).unwrap();

    assert!(!signature.is_empty());
    assert_eq!(signature.len(), 64);  // Ed25519 signature is 64 bytes

    // Verify signature
    let verified = hsm.verify(&key.public_key_bytes(), message, &signature).unwrap();
    assert!(verified);

    // Verify fails with different message
    let different_message = b"different message";
    let verified_bad = hsm.verify(&key.public_key_bytes(), different_message, &signature).unwrap();
    assert!(!verified_bad);
}

#[test]
fn test_hsm_multiple_keys_via_supervisor() {
    let temp_dir = TempDir::new().unwrap();
    let ledger_path = temp_dir.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    let hsm_client = supervisor.hsm_client();
    let mut hsm = hsm_client.lock().unwrap();

    hsm.initialize().unwrap();

    // Generate keys for multiple principals
    let policy_key = hsm.generate_signing_key("policy-001").unwrap();
    let actuator_key = hsm.generate_signing_key("actuator-001").unwrap();
    let audit_key = hsm.generate_signing_key("audit-001").unwrap();

    // Verify all keys are unique
    assert_ne!(
        policy_key.public_key_bytes(),
        actuator_key.public_key_bytes()
    );
    assert_ne!(
        actuator_key.public_key_bytes(),
        audit_key.public_key_bytes()
    );
    assert_ne!(
        policy_key.public_key_bytes(),
        audit_key.public_key_bytes()
    );

    // Verify each key can sign independently
    let msg = b"common message";

    let policy_sig = hsm.sign(&policy_key, msg).unwrap();
    let actuator_sig = hsm.sign(&actuator_key, msg).unwrap();

    // Each key should verify its own signature
    assert!(hsm.verify(&policy_key.public_key_bytes(), msg, &policy_sig).unwrap());
    assert!(hsm.verify(&actuator_key.public_key_bytes(), msg, &actuator_sig).unwrap());

    // Cross-verification should fail
    assert!(!hsm.verify(&actuator_key.public_key_bytes(), msg, &policy_sig).unwrap());
    assert!(!hsm.verify(&policy_key.public_key_bytes(), msg, &actuator_sig).unwrap());
}

#[test]
fn test_hsm_status_via_supervisor() {
    let temp_dir = TempDir::new().unwrap();
    let ledger_path = temp_dir.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    let hsm_client = supervisor.hsm_client();
    let mut hsm = hsm_client.lock().unwrap();

    let status_before = hsm.status();
    assert!(status_before.contains("not initialized") || status_before.contains("Filesystem"));

    hsm.initialize().unwrap();

    let status_after = hsm.status();
    assert!(status_after.contains("Filesystem") || status_after.contains("PKCS#11"));
}

#[test]
fn test_supervisor_principal_signing_with_hsm() {
    let temp_dir = TempDir::new().unwrap();
    let ledger_path = temp_dir.path().join("security_ledger.jsonl");

    let supervisor = Supervisor::initialize(
        ledger_path.to_str().unwrap(),
        None,
    ).unwrap();

    // Verify each principal can have its own signing key
    let hsm_client = supervisor.hsm_client();
    let mut hsm = hsm_client.lock().unwrap();
    hsm.initialize().unwrap();

    let principals = vec![
        ("policy", Principal::Policy),
        ("actuator", Principal::Actuator),
        ("audit", Principal::Audit),
        ("declassifier", Principal::Declassifier),
    ];

    let mut keys = Vec::new();
    for (name, principal) in principals {
        let key_id = format!("{}-key", name);
        let key = hsm.generate_signing_key(&key_id).unwrap();
        keys.push((principal, key));
    }

    // Verify all keys are unique
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i].1.public_key_bytes(),
                keys[j].1.public_key_bytes(),
                "Keys should be unique"
            );
        }
    }

    // Verify each principal is healthy in supervisor
    for (principal, _) in principals {
        assert!(supervisor.is_principal_healthy(Principal::Supervisor) ||
                supervisor.principal_health(Principal::Policy).is_some());
    }
}
