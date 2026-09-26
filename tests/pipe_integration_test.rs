// Integration tests for pipe management (Week 1 Task 1.4)

use geometry_dash::{PrincipalOrchestrator, Principal};
use geometry_dash::supervisor::startup::StartupContext;
use tempfile::TempDir;

#[test]
fn test_orchestrator_with_pipes_full_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = StartupContext::new(
        "run-1".to_string(),
        "boot-1".to_string(),
        "epoch-1".to_string(),
        temp_dir.path().to_str().unwrap().to_string(),
    );

    let mut orchestrator = PrincipalOrchestrator::new(ctx);

    // Initialize pipes
    assert!(orchestrator.initialize_pipes().is_ok());
    assert_eq!(orchestrator.pipe_count(), 22);

    // Verify all pipes exist
    let pipe_manager = orchestrator.pipe_manager();
    let pipes = pipe_manager.all_pipes();
    assert_eq!(pipes.len(), 22);

    // Cleanup
    assert!(orchestrator.cleanup_pipes().is_ok());
    assert_eq!(orchestrator.pipe_count(), 0);
}

#[test]
fn test_orchestrator_pipes_with_startup_integration() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = StartupContext::new(
        "run-2".to_string(),
        "boot-2".to_string(),
        "epoch-2".to_string(),
        temp_dir.path().to_str().unwrap().to_string(),
    );

    let mut orchestrator = PrincipalOrchestrator::new(ctx);

    // Add principals
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

    // Initialize pipes before startup
    assert!(orchestrator.initialize_pipes().is_ok());

    // Verify pipe count
    assert_eq!(orchestrator.pipe_count(), 22);

    // Simulate startup sequence
    orchestrator.send_init(Principal::Policy, 100).unwrap();
    orchestrator.send_init(Principal::Actuator, 101).unwrap();

    // Cleanup
    assert!(orchestrator.cleanup_pipes().is_ok());
}

#[test]
fn test_pipe_manager_individual_pipes() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = StartupContext::new(
        "run-3".to_string(),
        "boot-3".to_string(),
        "epoch-3".to_string(),
        temp_dir.path().to_str().unwrap().to_string(),
    );

    let mut orchestrator = PrincipalOrchestrator::new(ctx);

    // Create only specific pipes
    orchestrator.pipe_manager_mut().create_pipe(1).unwrap();
    orchestrator.pipe_manager_mut().create_pipe(5).unwrap();
    orchestrator.pipe_manager_mut().create_pipe(22).unwrap();

    assert_eq!(orchestrator.pipe_count(), 3);

    // Verify pipe info
    let pipe_1 = orchestrator.pipe_manager().get_pipe(1);
    assert!(pipe_1.is_some());
    assert_eq!(pipe_1.unwrap().interface_id, 1);

    let pipe_5 = orchestrator.pipe_manager().get_pipe(5);
    assert!(pipe_5.is_some());
    assert_eq!(pipe_5.unwrap().interface_id, 5);

    let pipe_22 = orchestrator.pipe_manager().get_pipe(22);
    assert!(pipe_22.is_some());
    assert_eq!(pipe_22.unwrap().interface_id, 22);

    // Cleanup
    assert!(orchestrator.cleanup_pipes().is_ok());
    assert_eq!(orchestrator.pipe_count(), 0);
}

#[test]
fn test_pipes_created_with_proper_names() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = StartupContext::new(
        "run-4".to_string(),
        "boot-4".to_string(),
        "epoch-4".to_string(),
        temp_dir.path().to_str().unwrap().to_string(),
    );

    let mut orchestrator = PrincipalOrchestrator::new(ctx);
    orchestrator.initialize_pipes().unwrap();

    let pipe_manager = orchestrator.pipe_manager();
    let pipes = pipe_manager.all_pipes();

    for pipe_info in pipes {
        // Verify pipe path follows pattern: if-NNN.pipe
        let path_str = pipe_info.pipe_path.to_string_lossy();
        assert!(path_str.contains("if-"));
        assert!(path_str.ends_with(".pipe"));
    }

    orchestrator.cleanup_pipes().unwrap();
}

#[test]
fn test_pipe_creation_idempotency() {
    let temp_dir = TempDir::new().unwrap();
    let ctx = StartupContext::new(
        "run-5".to_string(),
        "boot-5".to_string(),
        "epoch-5".to_string(),
        temp_dir.path().to_str().unwrap().to_string(),
    );

    let mut orchestrator = PrincipalOrchestrator::new(ctx);

    // Create pipes twice
    orchestrator.initialize_pipes().unwrap();
    assert_eq!(orchestrator.pipe_count(), 22);

    // Creating again should succeed (removes old pipes first)
    orchestrator.initialize_pipes().unwrap();
    assert_eq!(orchestrator.pipe_count(), 22);

    orchestrator.cleanup_pipes().unwrap();
}
