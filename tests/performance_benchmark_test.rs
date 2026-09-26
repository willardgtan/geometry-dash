// Performance and Stress Testing for Week 2+ System
// Benchmarks throughput, latency, and resource utilization across principals

use geometry_dash::{
    SecurityLedger,
    PolicyPrincipal, ActuatorPrincipal, AuditPrincipal, LearnerPrincipal,
    Principal, InterfaceId,
    NonceCache, CapabilityMatrix,
    AutoHsmClient,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tempfile::NamedTempFile;

/// Benchmark 1: Policy Principal Decision Throughput
/// Measures Gate A authorization decisions per second
#[test]
fn bench_policy_gate_a_throughput() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    let policy_key = hsm.lock().unwrap().generate_key("policy-bench").unwrap();
    let mut policy = PolicyPrincipal::new(ledger.clone());
    policy.initialize(policy_key).unwrap();

    let decisions = 1000;
    let start = Instant::now();

    for i in 0..decisions {
        let mut context = HashMap::new();
        context.insert("request_id".to_string(), format!("auth-{:04}", i));

        let _decision = policy.gate_a_decision(
            Principal::Actuator,
            InterfaceId::from(3),
            &context,
        ).unwrap();
    }

    let elapsed = start.elapsed();
    let throughput = decisions as f64 / elapsed.as_secs_f64();

    println!(
        "Policy Gate A: {:.0} decisions/sec ({} decisions in {:.2}s)",
        throughput,
        decisions,
        elapsed.as_secs_f64()
    );

    assert!(
        throughput > 100.0,
        "Policy throughput should exceed 100 decisions/sec (actual: {:.0})",
        throughput
    );
}

/// Benchmark 2: Actuator Principal Command Execution Throughput
/// Measures authorized command execution rate
#[test]
fn bench_actuator_command_throughput() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    let actuator_key = hsm.lock().unwrap().generate_key("actuator-bench").unwrap();
    let mut actuator = ActuatorPrincipal::new(ledger.clone());
    actuator.initialize(actuator_key).unwrap();

    let commands = 500;
    let start = Instant::now();

    for i in 0..commands {
        let request = geometry_dash::CommandRequest {
            request_id: format!("bench-cmd-{:04}", i),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            command: "benchmark".to_string(),
            requester: Principal::Policy,
            target_interface: InterfaceId::from(3),
            context: HashMap::new(),
        };

        actuator.queue_command(request).unwrap();
    }

    let _results = actuator.process_queue().unwrap();
    let elapsed = start.elapsed();
    let throughput = commands as f64 / elapsed.as_secs_f64();

    println!(
        "Actuator Execution: {:.0} commands/sec ({} commands in {:.2}s)",
        throughput,
        commands,
        elapsed.as_secs_f64()
    );

    assert!(
        throughput > 50.0,
        "Actuator throughput should exceed 50 commands/sec (actual: {:.0})",
        throughput
    );
}

/// Benchmark 3: Nonce Cache Performance
/// Measures nonce validation throughput
#[test]
fn bench_nonce_cache_throughput() {
    let cache = NonceCache::new(10000, 1000);
    let validations = 5000;

    let start = Instant::now();

    for i in 0..validations {
        let mut nonce = [0u8; 32];
        nonce[0] = (i % 256) as u8;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64 + (i as u64 * 1000);

        let _result = cache.check_and_insert(nonce, 1, 100, 1, ts);
    }

    let elapsed = start.elapsed();
    let throughput = validations as f64 / elapsed.as_secs_f64();

    println!(
        "Nonce Cache: {:.0} validations/sec ({} validations in {:.2}s)",
        throughput,
        validations,
        elapsed.as_secs_f64()
    );

    assert!(
        throughput > 1000.0,
        "Nonce cache throughput should exceed 1000 validations/sec (actual: {:.0})",
        throughput
    );
}

/// Benchmark 4: Capability Matrix Lookup Performance
/// Measures permission check latency
#[test]
fn bench_capability_matrix_lookup() {
    let mut matrix = CapabilityMatrix::new();

    // Setup 100 principals × 5 interfaces = 500 capabilities
    for principal in 1..=100u8 {
        for interface in 1..=5u8 {
            matrix.allow(principal, interface as u32);
        }
    }

    let lookups = 10000;
    let start = Instant::now();

    for i in 0..lookups {
        let principal = ((i % 100) + 1) as u8;
        let interface = ((i % 5) + 1) as u32;
        let _result = matrix.can_use(principal, interface);
    }

    let elapsed = start.elapsed();
    let throughput = lookups as f64 / elapsed.as_secs_f64();
    let latency_us = (elapsed.as_micros() as f64) / (lookups as f64);

    println!(
        "Capability Matrix: {:.0} lookups/sec ({:.2}μs latency)",
        throughput,
        latency_us
    );

    assert!(
        latency_us < 100.0,
        "Capability lookup latency should be <100μs (actual: {:.2}μs)",
        latency_us
    );
}

/// Benchmark 5: SecurityLedger Write Throughput
/// Measures event logging performance
#[test]
fn bench_ledger_write_throughput() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

    let events = 1000;
    let start = Instant::now();

    for i in 0..events {
        let mut details = HashMap::new();
        details.insert("event_id".to_string(), format!("evt-{:04}", i));
        details.insert("data".to_string(), "test payload".to_string());

        ledger.append_event(
            geometry_dash::EventType::ActionRequested,
            Principal::Policy,
            geometry_dash::Severity::Info,
            &format!("run-{:04}", i % 10),
            &format!("boot-{:04}", i % 5),
            &format!("epoch-{:04}", i % 3),
            details,
        ).unwrap();
    }

    let elapsed = start.elapsed();
    let throughput = events as f64 / elapsed.as_secs_f64();

    println!(
        "SecurityLedger: {:.0} events/sec ({} events in {:.2}s)",
        throughput,
        events,
        elapsed.as_secs_f64()
    );

    assert!(
        throughput > 50.0,
        "Ledger throughput should exceed 50 events/sec (actual: {:.0})",
        throughput
    );
}

/// Benchmark 6: Multi-Principal Concurrent Load
/// Stress test with multiple principals operating concurrently
#[test]
fn bench_multi_principal_concurrent_load() {
    use std::thread;

    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize principals
    let policy_key = hsm.lock().unwrap().generate_key("policy-concurrent").unwrap();
    let actuator_key = hsm.lock().unwrap().generate_key("actuator-concurrent").unwrap();

    let policy = Arc::new(Mutex::new(PolicyPrincipal::new(ledger.clone())));
    let actuator = Arc::new(Mutex::new(ActuatorPrincipal::new(ledger.clone())));

    {
        policy.lock().unwrap().initialize(policy_key).unwrap();
        actuator.lock().unwrap().initialize(actuator_key).unwrap();
    }

    let total_commands = 1000;
    let threads = 10;
    let commands_per_thread = total_commands / threads;

    let start = Instant::now();
    let mut handles = vec![];

    // Spawn threads for policy decisions
    for thread_id in 0..threads {
        let policy_clone = Arc::clone(&policy);
        let handle = thread::spawn(move || {
            let mut policy = policy_clone.lock().unwrap();
            for cmd in 0..commands_per_thread {
                let mut context = HashMap::new();
                context.insert("thread".to_string(), format!("policy-{}", thread_id));
                context.insert("cmd".to_string(), format!("{}", cmd));

                let _decision = policy.gate_a_decision(
                    Principal::Actuator,
                    InterfaceId::from(3),
                    &context,
                );
            }
        });
        handles.push(handle);
    }

    // Spawn threads for actuator commands
    for thread_id in 0..threads {
        let actuator_clone = Arc::clone(&actuator);
        let handle = thread::spawn(move || {
            let mut actuator = actuator_clone.lock().unwrap();
            for cmd in 0..commands_per_thread {
                let request = geometry_dash::CommandRequest {
                    request_id: format!("bench-t{}-c{:03}", thread_id, cmd),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64,
                    command: "concurrent".to_string(),
                    requester: Principal::Policy,
                    target_interface: InterfaceId::from(3),
                    context: HashMap::new(),
                };

                let _ = actuator.queue_command(request);
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = start.elapsed();
    let throughput = total_commands as f64 / elapsed.as_secs_f64();

    println!(
        "Multi-Principal Concurrent: {:.0} ops/sec ({} ops, {} threads in {:.2}s)",
        throughput,
        total_commands,
        threads * 2,
        elapsed.as_secs_f64()
    );

    assert!(
        throughput > 100.0,
        "Concurrent throughput should exceed 100 ops/sec (actual: {:.0})",
        throughput
    );
}

/// Benchmark 7: Audit Event Correlation Performance
/// Measures event analysis throughput
#[test]
fn bench_audit_event_correlation() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Populate ledger with events
    {
        let ledger = ledger.lock().unwrap();
        for i in 0..500 {
            let mut details = HashMap::new();
            details.insert("action".to_string(), "test".to_string());
            details.insert("sequence".to_string(), format!("{}", i));

            ledger.append_event(
                geometry_dash::EventType::ActionRequested,
                Principal::Policy,
                geometry_dash::Severity::Info,
                "run-001",
                "boot-001",
                "epoch-001",
                details,
            ).unwrap();
        }
    }

    let audit_key = hsm.lock().unwrap().generate_key("audit-bench").unwrap();
    let mut audit = AuditPrincipal::new(ledger.clone());
    audit.initialize(audit_key).unwrap();

    let analyses = 100;
    let start = Instant::now();

    for _i in 0..analyses {
        let _correlations = audit.analyze_events(&HashMap::new()).unwrap();
    }

    let elapsed = start.elapsed();
    let throughput = analyses as f64 / elapsed.as_secs_f64();

    println!(
        "Audit Event Correlation: {:.1} analyses/sec ({} analyses on 500 events in {:.2}s)",
        throughput,
        analyses,
        elapsed.as_secs_f64()
    );

    assert!(
        throughput > 5.0,
        "Audit correlation throughput should exceed 5 analyses/sec (actual: {:.1})",
        throughput
    );
}

/// Benchmark 8: Learner Pattern Detection Performance
/// Measures pattern analysis throughput
#[test]
fn bench_learner_pattern_detection() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Populate ledger with patterns
    {
        let ledger = ledger.lock().unwrap();
        for cycle in 0..10 {
            for event in 0..100 {
                let mut details = HashMap::new();
                details.insert("pattern".to_string(), "query".to_string());
                details.insert("cycle".to_string(), format!("{}", cycle));
                details.insert("event".to_string(), format!("{}", event));

                ledger.append_event(
                    geometry_dash::EventType::ActionRequested,
                    Principal::Actuator,
                    geometry_dash::Severity::Info,
                    "run-001",
                    "boot-001",
                    "epoch-001",
                    details,
                ).unwrap();
            }
        }
    }

    let learner_key = hsm.lock().unwrap().generate_key("learner-bench").unwrap();
    let mut learner = LearnerPrincipal::new(ledger.clone());
    learner.initialize(learner_key).unwrap();

    let analyses = 50;
    let start = Instant::now();

    for _i in 0..analyses {
        let _patterns = learner.analyze_patterns(&HashMap::new()).unwrap();
    }

    let elapsed = start.elapsed();
    let throughput = analyses as f64 / elapsed.as_secs_f64();

    println!(
        "Learner Pattern Detection: {:.1} analyses/sec ({} pattern analyses in {:.2}s)",
        throughput,
        analyses,
        elapsed.as_secs_f64()
    );

    assert!(
        throughput > 3.0,
        "Pattern detection throughput should exceed 3 analyses/sec (actual: {:.1})",
        throughput
    );
}

/// Benchmark 9: HSM Key Operation Performance
/// Measures cryptographic operation latency
#[test]
fn bench_hsm_key_operations() {
    let hsm = AutoHsmClient::new().unwrap();

    // Key generation performance
    let key_generations = 10;
    let start = Instant::now();

    for i in 0..key_generations {
        let _key = hsm.generate_key(&format!("bench-key-{}", i)).unwrap();
    }

    let gen_elapsed = start.elapsed();
    let gen_latency_ms = gen_elapsed.as_millis() as f64 / key_generations as f64;

    println!(
        "HSM Key Generation: {:.2}ms per key ({} keys in {:.2}s)",
        gen_latency_ms,
        key_generations,
        gen_elapsed.as_secs_f64()
    );

    // Sign operation performance
    let key = hsm.generate_key("bench-sign-key").unwrap();
    let message = b"benchmark message";
    let signatures = 100;

    let start = Instant::now();

    for _i in 0..signatures {
        let _signature = key.sign(message).unwrap();
    }

    let sig_elapsed = start.elapsed();
    let sig_latency_us = sig_elapsed.as_micros() as f64 / signatures as f64;

    println!(
        "HSM Signing: {:.2}μs per signature ({} signatures in {:.2}s)",
        sig_latency_us,
        signatures,
        sig_elapsed.as_secs_f64()
    );

    assert!(
        sig_latency_us < 10000.0,
        "HSM signature latency should be <10ms (actual: {:.2}μs)",
        sig_latency_us
    );
}

/// Benchmark 10: End-to-End Workflow Performance
/// Measures complete authorization + execution + audit workflow
#[test]
fn bench_e2e_workflow_performance() {
    let temp = NamedTempFile::new().unwrap();
    let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));

    let hsm = AutoHsmClient::new().unwrap();
    let hsm = Arc::new(Mutex::new(hsm));

    // Initialize all principals
    let policy_key = hsm.lock().unwrap().generate_key("policy-e2e").unwrap();
    let actuator_key = hsm.lock().unwrap().generate_key("actuator-e2e").unwrap();
    let audit_key = hsm.lock().unwrap().generate_key("audit-e2e").unwrap();
    let learner_key = hsm.lock().unwrap().generate_key("learner-e2e").unwrap();

    let mut policy = PolicyPrincipal::new(ledger.clone());
    let mut actuator = ActuatorPrincipal::new(ledger.clone());
    let mut audit = AuditPrincipal::new(ledger.clone());
    let mut learner = LearnerPrincipal::new(ledger.clone());

    policy.initialize(policy_key).unwrap();
    actuator.initialize(actuator_key).unwrap();
    audit.initialize(audit_key).unwrap();
    learner.initialize(learner_key).unwrap();

    let workflows = 100;
    let start = Instant::now();

    for i in 0..workflows {
        // Step 1: Authorization
        let _decision = policy.gate_a_decision(
            Principal::Actuator,
            InterfaceId::from(3),
            &HashMap::new(),
        ).unwrap();

        // Step 2: Execution
        for j in 0..10 {
            let request = geometry_dash::CommandRequest {
                request_id: format!("e2e-{:03}-{:02}", i, j),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64,
                command: "workflow".to_string(),
                requester: Principal::Policy,
                target_interface: InterfaceId::from(3),
                context: HashMap::new(),
            };

            actuator.queue_command(request).unwrap();
        }

        let _exec_results = actuator.process_queue().unwrap();

        // Step 3: Analysis
        let _correlations = audit.analyze_events(&HashMap::new()).unwrap();
        let _patterns = learner.analyze_patterns(&HashMap::new()).unwrap();
    }

    let elapsed = start.elapsed();
    let total_operations = workflows * (1 + 10 + 1 + 1);  // auth + 10 execs + audit + learner
    let throughput = total_operations as f64 / elapsed.as_secs_f64();

    println!(
        "E2E Workflow: {:.0} total ops/sec ({} workflows with {} ops each in {:.2}s)",
        throughput,
        workflows,
        1 + 10 + 1 + 1,
        elapsed.as_secs_f64()
    );

    assert!(
        throughput > 100.0,
        "E2E throughput should exceed 100 ops/sec (actual: {:.0})",
        throughput
    );
}
