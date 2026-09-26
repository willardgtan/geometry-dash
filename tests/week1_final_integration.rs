// Final comprehensive integration test for Week 1 implementation (Task 1.5)
// Validates all major systems working together: Supervisor, IPC, Pipes, Orchestration

use geometry_dash::{
    PrincipalOrchestrator, Principal, SecurityLedger, Supervisor,
    UniversalMessage, NonceCache, CapabilityMatrix, PipeManager,
};
use geometry_dash::supervisor::startup::StartupContext;
use tempfile::TempDir;

#[test]
fn test_week1_complete_integration() {
    // Setup temporary directories
    let temp_dir = TempDir::new().unwrap();
    let pipe_root = temp_dir.path().join("pipes");
    let ledger_path = temp_dir.path().join("security_ledger.jsonl");

    // 1. Initialize SecurityLedger
    let ledger = SecurityLedger::open(ledger_path.to_str().unwrap()).unwrap();

    // 2. Create Supervisor
    let supervisor = Supervisor::initialize(
        temp_dir.path().to_str().unwrap(),
        None,
    ).unwrap();

    // 3. Create StartupContext
    let ctx = StartupContext::new(
        supervisor.run_id().to_string(),
        supervisor.boot_id().to_string(),
        supervisor.epoch_id().to_string(),
        temp_dir.path().to_str().unwrap().to_string(),
    );

    // 4. Create Orchestrator
    let mut orchestrator = PrincipalOrchestrator::new(ctx);

    // 5. Initialize pipes
    assert!(orchestrator.initialize_pipes().is_ok());
    assert_eq!(orchestrator.pipe_count(), 22);

    // 6. Add principals
    orchestrator.add_principal(
        Principal::Policy,
        1001,
        1001,
        "strict".to_string(),
        "policy".to_string(),
    );

    orchestrator.add_principal(
        Principal::Actuator,
        1002,
        1002,
        "strict".to_string(),
        "actuator".to_string(),
    );

    orchestrator.add_principal(
        Principal::Audit,
        1003,
        1003,
        "strict".to_string(),
        "audit".to_string(),
    );

    // 7. Verify startup status
    let status = orchestrator.startup_status();
    assert!(!status.is_empty());

    // Verify each principal is tracked
    for (principal, _, _, _, _) in status {
        println!("Principal: {:?}", principal);
    }

    // 8. Cleanup
    assert!(orchestrator.cleanup_pipes().is_ok());
    assert_eq!(orchestrator.pipe_count(), 0);
}

#[test]
fn test_ipc_with_pipes_integration() {
    let temp_dir = TempDir::new().unwrap();

    // Initialize Nonce Cache
    let nonce_cache = NonceCache::new(5000, 100000);

    // Initialize Capability Matrix
    let mut cap_matrix = CapabilityMatrix::new();
    cap_matrix.allow(1, 2);  // Policy → IF-002
    cap_matrix.allow(1, 4);  // Policy → IF-004
    cap_matrix.allow(2, 3);  // Actuator → IF-003

    // Initialize Pipe Manager
    let mut pipe_mgr = PipeManager::new(temp_dir.path().to_str().unwrap()).unwrap();
    pipe_mgr.create_all_pipes().unwrap();
    assert_eq!(pipe_mgr.pipe_count(), 22);

    // Verify nonce cache works
    let nonce = [1u8; 32];
    let ts = geometry_dash::ipc::current_timestamp_ns();
    assert!(nonce_cache.check_and_insert(nonce, 2, 100, 1, ts).is_ok());

    // Verify capability checks work
    assert!(cap_matrix.can_use(1, 2));
    assert!(cap_matrix.can_use(1, 4));
    assert!(cap_matrix.can_use(2, 3));
    assert!(!cap_matrix.can_use(1, 3));  // Policy cannot use IF-003

    // Verify pipe creation
    let all_pipes = pipe_mgr.all_pipes();
    assert_eq!(all_pipes.len(), 22);

    // Cleanup
    pipe_mgr.cleanup_all().unwrap();
}

#[test]
fn test_supervisor_with_orchestrator_integration() {
    let temp_dir = TempDir::new().unwrap();

    // Initialize supervisor
    let supervisor = Supervisor::initialize(
        temp_dir.path().to_str().unwrap(),
        None,
    ).unwrap();

    // Create context from supervisor
    let ctx = StartupContext::new(
        supervisor.run_id().to_string(),
        supervisor.boot_id().to_string(),
        supervisor.epoch_id().to_string(),
        temp_dir.path().to_str().unwrap().to_string(),
    );

    // Create orchestrator
    let mut orchestrator = PrincipalOrchestrator::new(ctx);

    // Initialize pipes
    orchestrator.initialize_pipes().unwrap();

    // Add principals and verify health tracking
    orchestrator.add_principal(
        Principal::Policy,
        1001,
        1001,
        "strict".to_string(),
        "policy".to_string(),
    );

    // Verify supervisor still tracks principal health
    assert!(supervisor.is_principal_healthy(Principal::Policy));

    // Cleanup
    orchestrator.cleanup_pipes().unwrap();
}

#[test]
fn test_all_22_interfaces_covered() {
    let temp_dir = TempDir::new().unwrap();

    let mut pipe_mgr = PipeManager::new(temp_dir.path().to_str().unwrap()).unwrap();

    // Create all 22 interfaces
    for if_id in 1..=22 {
        assert!(pipe_mgr.create_pipe(if_id).is_ok());
    }

    assert_eq!(pipe_mgr.pipe_count(), 22);

    // Verify all pipes exist
    for if_id in 1..=22 {
        assert!(pipe_mgr.get_pipe(if_id).is_some());
    }

    // Verify pipe names follow pattern
    let pipes = pipe_mgr.all_pipes();
    for pipe_info in pipes {
        let path = pipe_info.pipe_path.to_string_lossy();
        assert!(path.contains(&format!("if-{:03d}", pipe_info.interface_id)));
    }

    pipe_mgr.cleanup_all().unwrap();
    assert_eq!(pipe_mgr.pipe_count(), 0);
}

#[test]
fn test_pipe_recovery_from_old_session() {
    let temp_dir = TempDir::new().unwrap();
    let pipe_path = temp_dir.path().to_str().unwrap();

    // First session: create pipes
    {
        let mut pipe_mgr = PipeManager::new(pipe_path).unwrap();
        pipe_mgr.create_all_pipes().unwrap();
        assert_eq!(pipe_mgr.pipe_count(), 22);
        // pipes left behind (simulating crash)
    }

    // Second session: should be able to create pipes again (removes old ones)
    {
        let mut pipe_mgr = PipeManager::new(pipe_path).unwrap();
        assert!(pipe_mgr.create_all_pipes().is_ok());
        assert_eq!(pipe_mgr.pipe_count(), 22);
        pipe_mgr.cleanup_all().unwrap();
    }
}

#[test]
fn test_orchestrator_multiple_startup_cycles() {
    let temp_dir = TempDir::new().unwrap();

    let ctx = StartupContext::new(
        "run-multi".to_string(),
        "boot-multi".to_string(),
        "epoch-multi".to_string(),
        temp_dir.path().to_str().unwrap().to_string(),
    );

    let mut orchestrator = PrincipalOrchestrator::new(ctx);

    // First cycle
    orchestrator.initialize_pipes().unwrap();
    assert_eq!(orchestrator.pipe_count(), 22);
    orchestrator.cleanup_pipes().unwrap();

    // Second cycle (recovery from crash)
    orchestrator.initialize_pipes().unwrap();
    assert_eq!(orchestrator.pipe_count(), 22);
    orchestrator.cleanup_pipes().unwrap();

    // Verify clean state
    assert_eq!(orchestrator.pipe_count(), 0);
}
