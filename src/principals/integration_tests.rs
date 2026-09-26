// Integration Tests for Evidence Sealing & Verification (Task 1.5)
// End-to-end tests of SEC-C02 remediation workflow

#[cfg(test)]
mod evidence_sealing_integration {
    use geometry_dash::{
        SealerPrincipal, EvidenceVerifier, VerificationStatus,
        SecurityLedger, EventType, Severity,
        EvidenceManifest, ArtifactRef, ArtifactType,
        Principal,
    };
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;
    use std::collections::HashMap;
    use std::sync::Arc;

    // Helper: Create test artifact with content
    fn create_test_artifact(path: &str, content: &[u8]) -> [u8; 32] {
        let mut file = fs::File::create(path).expect("Failed to create artifact");
        file.write_all(content).expect("Failed to write artifact");
        drop(file);

        // Compute hash
        let verifier = EvidenceVerifier::new(
            std::path::Path::new(path)
                .parent()
                .unwrap()
                .to_str()
                .unwrap()
        );
        verifier.compute_file_hash(path).expect("Failed to hash artifact")
    }

    // Helper: Create security ledger with events
    fn create_test_ledger(path: &str, event_count: usize) -> [u8; 32] {
        let ledger = SecurityLedger::open(path).expect("Failed to create ledger");

        let mut details = HashMap::new();
        details.insert("test".to_string(), "event".to_string());

        for i in 0..event_count {
            details.insert(
                "event_num".to_string(),
                i.to_string(),
            );

            ledger.append_event(
                EventType::PolicyDecision,
                Principal::Policy,
                Severity::Info,
                "run-001",
                "boot-001",
                "epoch-001",
                details.clone(),
            ).expect("Failed to append event");
        }

        ledger.compute_event_root_hash().expect("Failed to compute event root")
    }

    #[test]
    fn test_workflow_single_artifact() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Step 1: Create artifact
        let artifact_path = format!("{}/output.log", temp_path);
        let artifact_hash = create_test_artifact(&artifact_path, b"execution log data");

        // Step 2: Create ArtifactRef
        let artifact = ArtifactRef::new(
            "output.log".to_string(),
            ArtifactType::CustomMetadata,
            artifact_hash,
            17,  // "execution log data" is 17 bytes
            Principal::Developer,
            "Execution output log".to_string(),
        );

        // Step 3: Create sealer
        let sealer = SealerPrincipal::new(
            "sealer-001".to_string(),
            0,
            0,
            Arc::new(SecurityLedger::open(&format!("{}/ledger.jsonl", temp_path)).unwrap()),
        );

        // Step 4: Seal evidence
        let seal_result = sealer.seal_evidence(
            "bundle-001".to_string(),
            "run-001".to_string(),
            "boot-001".to_string(),
            "epoch-001".to_string(),
            temp_path,
            vec![artifact],
            [0xAAu8; 32],  // policy snapshot
            [0xBBu8; 32],  // config snapshot
            [0u8; 32],     // empty event root (no events yet)
        ).expect("Failed to seal evidence");

        assert!(seal_result.success);
        assert_eq!(seal_result.total_artifact_size, 17);

        // Step 5: Verify sealed evidence
        let verifier = EvidenceVerifier::new(temp_path);
        let verification = verifier.verify_sealed_evidence();

        assert_eq!(verification.status, VerificationStatus::Valid);
        assert!(verification.tamper_evident);
        assert_eq!(verification.artifacts_verified, 1);
        assert!(verification.artifact_details[0].matches);
    }

    #[test]
    fn test_workflow_multiple_artifacts() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Step 1: Create multiple artifacts
        let mut artifacts = Vec::new();

        for i in 0..3 {
            let artifact_path = format!("{}/file{}.bin", temp_path, i);
            let content = format!("file {} content", i);
            let hash = create_test_artifact(&artifact_path, content.as_bytes());

            let artifact = ArtifactRef::new(
                format!("file{}.bin", i),
                ArtifactType::CustomMetadata,
                hash,
                content.len() as u64,
                Principal::Developer,
                format!("Test artifact {}", i),
            );

            artifacts.push(artifact);
        }

        // Step 2: Seal multiple artifacts
        let sealer = SealerPrincipal::new(
            "sealer-001".to_string(),
            0,
            0,
            Arc::new(SecurityLedger::open(&format!("{}/ledger.jsonl", temp_path)).unwrap()),
        );

        let seal_result = sealer.seal_evidence(
            "bundle-002".to_string(),
            "run-002".to_string(),
            "boot-002".to_string(),
            "epoch-002".to_string(),
            temp_path,
            artifacts,
            [0xCCu8; 32],
            [0xDDu8; 32],
            [0u8; 32],
        ).expect("Failed to seal evidence");

        assert!(seal_result.success);
        assert_eq!(seal_result.total_artifact_size, 27);  // 5 + 7 + 15

        // Step 3: Verify all artifacts
        let verifier = EvidenceVerifier::new(temp_path);
        let verification = verifier.verify_sealed_evidence();

        assert_eq!(verification.status, VerificationStatus::Valid);
        assert!(verification.tamper_evident);
        assert_eq!(verification.artifacts_verified, 3);
        assert_eq!(verification.artifacts_total, 3);

        for detail in &verification.artifact_details {
            assert!(detail.matches);
        }
    }

    #[test]
    fn test_workflow_with_event_chain() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Step 1: Create ledger with events
        let ledger_path = format!("{}/ledger.jsonl", temp_path);
        let event_root = create_test_ledger(&ledger_path, 5);

        // Step 2: Create artifact
        let artifact_path = format!("{}/data.json", temp_path);
        let artifact_hash = create_test_artifact(&artifact_path, b"{\"result\": \"success\"}");

        let artifact = ArtifactRef::new(
            "data.json".to_string(),
            ArtifactType::CustomMetadata,
            artifact_hash,
            18,
            Principal::Policy,
            "Decision result".to_string(),
        );

        // Step 3: Seal with event root
        let sealer = SealerPrincipal::new(
            "sealer-001".to_string(),
            0,
            0,
            Arc::new(SecurityLedger::open(&ledger_path).unwrap()),
        );

        let seal_result = sealer.seal_evidence(
            "bundle-003".to_string(),
            "run-003".to_string(),
            "boot-003".to_string(),
            "epoch-003".to_string(),
            temp_path,
            vec![artifact],
            [0xEEu8; 32],
            [0xFFu8; 32],
            event_root,  // Real event root
        ).expect("Failed to seal evidence");

        assert!(seal_result.success);

        // Step 4: Verify with ledger
        let verifier = EvidenceVerifier::new(temp_path)
            .with_ledger(&ledger_path);
        let verification = verifier.verify_sealed_evidence();

        assert_eq!(verification.status, VerificationStatus::Valid);
        assert!(verification.tamper_evident);
        assert!(verification.event_chain_valid);
        assert_eq!(verification.event_count, 5);
    }

    #[test]
    fn test_tamper_detection_artifact_modified() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Step 1: Create and seal artifact
        let artifact_path = format!("{}/config.toml", temp_path);
        let original_hash = create_test_artifact(&artifact_path, b"[server]\nport=8080\n");

        let artifact = ArtifactRef::new(
            "config.toml".to_string(),
            ArtifactType::ConfigSnapshot,
            original_hash,
            20,
            Principal::Sealer,
            "Server configuration".to_string(),
        );

        let sealer = SealerPrincipal::new(
            "sealer-001".to_string(),
            0,
            0,
            Arc::new(SecurityLedger::open(&format!("{}/ledger.jsonl", temp_path)).unwrap()),
        );

        let seal_result = sealer.seal_evidence(
            "bundle-004".to_string(),
            "run-004".to_string(),
            "boot-004".to_string(),
            "epoch-004".to_string(),
            temp_path,
            vec![artifact],
            [0x11u8; 32],
            [0x22u8; 32],
            [0u8; 32],
        ).expect("Failed to seal evidence");

        assert!(seal_result.success);

        // Step 2: Tamper with artifact
        fs::write(&artifact_path, b"[server]\nport=9999\n")
            .expect("Failed to modify artifact");

        // Step 3: Verify - should detect tampering
        let verifier = EvidenceVerifier::new(temp_path);
        let verification = verifier.verify_sealed_evidence();

        assert_eq!(verification.status, VerificationStatus::ArtifactHashMismatch);
        assert!(!verification.tamper_evident);
        assert!(!verification.artifact_details[0].matches);
    }

    #[test]
    fn test_tamper_detection_manifest_removed() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Step 1: Create and seal
        let artifact_path = format!("{}/data.txt", temp_path);
        let artifact_hash = create_test_artifact(&artifact_path, b"sealed data");

        let artifact = ArtifactRef::new(
            "data.txt".to_string(),
            ArtifactType::CustomMetadata,
            artifact_hash,
            11,
            Principal::Developer,
            "Sealed data".to_string(),
        );

        let sealer = SealerPrincipal::new(
            "sealer-001".to_string(),
            0,
            0,
            Arc::new(SecurityLedger::open(&format!("{}/ledger.jsonl", temp_path)).unwrap()),
        );

        let _ = sealer.seal_evidence(
            "bundle-005".to_string(),
            "run-005".to_string(),
            "boot-005".to_string(),
            "epoch-005".to_string(),
            temp_path,
            vec![artifact],
            [0x33u8; 32],
            [0x44u8; 32],
            [0u8; 32],
        ).expect("Failed to seal evidence");

        // Step 2: Delete manifest
        let manifest_path = format!("{}/MANIFEST.json", temp_path);
        fs::remove_file(&manifest_path).expect("Failed to delete manifest");

        // Step 3: Verify - should detect missing manifest
        let verifier = EvidenceVerifier::new(temp_path);
        let verification = verifier.verify_sealed_evidence();

        assert_eq!(verification.status, VerificationStatus::ManifestMissing);
        assert!(!verification.tamper_evident);
    }

    #[test]
    fn test_tamper_detection_artifact_added() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Step 1: Create and seal one artifact
        let artifact_path = format!("{}/file1.txt", temp_path);
        let artifact_hash = create_test_artifact(&artifact_path, b"original file");

        let artifact = ArtifactRef::new(
            "file1.txt".to_string(),
            ArtifactType::CustomMetadata,
            artifact_hash,
            13,
            Principal::Developer,
            "Original file".to_string(),
        );

        let sealer = SealerPrincipal::new(
            "sealer-001".to_string(),
            0,
            0,
            Arc::new(SecurityLedger::open(&format!("{}/ledger.jsonl", temp_path)).unwrap()),
        );

        let _ = sealer.seal_evidence(
            "bundle-006".to_string(),
            "run-006".to_string(),
            "boot-006".to_string(),
            "epoch-006".to_string(),
            temp_path,
            vec![artifact],
            [0x55u8; 32],
            [0x66u8; 32],
            [0u8; 32],
        ).expect("Failed to seal evidence");

        // Step 2: Add extra artifact (not in manifest)
        let extra_path = format!("{}/file2.txt", temp_path);
        fs::write(&extra_path, b"extra file").expect("Failed to create extra file");

        // Step 3: Verify - manifest should still be valid (extra files don't break seal)
        let verifier = EvidenceVerifier::new(temp_path);
        let verification = verifier.verify_sealed_evidence();

        // Extra files outside manifest are allowed
        assert_eq!(verification.status, VerificationStatus::Valid);
        assert!(verification.tamper_evident);
        assert_eq!(verification.artifacts_verified, 1);
    }

    #[test]
    fn test_tamper_detection_manifest_corrupted() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Step 1: Create and seal
        let artifact_path = format!("{}/test.txt", temp_path);
        let artifact_hash = create_test_artifact(&artifact_path, b"test");

        let artifact = ArtifactRef::new(
            "test.txt".to_string(),
            ArtifactType::CustomMetadata,
            artifact_hash,
            4,
            Principal::Developer,
            "Test".to_string(),
        );

        let sealer = SealerPrincipal::new(
            "sealer-001".to_string(),
            0,
            0,
            Arc::new(SecurityLedger::open(&format!("{}/ledger.jsonl", temp_path)).unwrap()),
        );

        let _ = sealer.seal_evidence(
            "bundle-007".to_string(),
            "run-007".to_string(),
            "boot-007".to_string(),
            "epoch-007".to_string(),
            temp_path,
            vec![artifact],
            [0x77u8; 32],
            [0x88u8; 32],
            [0u8; 32],
        ).expect("Failed to seal evidence");

        // Step 2: Corrupt manifest JSON
        let manifest_path = format!("{}/MANIFEST.json", temp_path);
        fs::write(&manifest_path, b"{ invalid json").expect("Failed to corrupt manifest");

        // Step 3: Verify - should detect corruption
        let verifier = EvidenceVerifier::new(temp_path);
        let verification = verifier.verify_sealed_evidence();

        assert_eq!(verification.status, VerificationStatus::ManifestCorrupted);
        assert!(!verification.tamper_evident);
    }

    #[test]
    fn test_event_chain_tampering() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Step 1: Create ledger with events
        let ledger_path = format!("{}/ledger.jsonl", temp_path);
        let event_root = create_test_ledger(&ledger_path, 3);

        // Step 2: Create and seal with event root
        let artifact_path = format!("{}/result.txt", temp_path);
        let artifact_hash = create_test_artifact(&artifact_path, b"result");

        let artifact = ArtifactRef::new(
            "result.txt".to_string(),
            ArtifactType::CustomMetadata,
            artifact_hash,
            6,
            Principal::Policy,
            "Result".to_string(),
        );

        let sealer = SealerPrincipal::new(
            "sealer-001".to_string(),
            0,
            0,
            Arc::new(SecurityLedger::open(&ledger_path).unwrap()),
        );

        let _ = sealer.seal_evidence(
            "bundle-008".to_string(),
            "run-008".to_string(),
            "boot-008".to_string(),
            "epoch-008".to_string(),
            temp_path,
            vec![artifact],
            [0x99u8; 32],
            [0xAAu8; 32],
            event_root,
        ).expect("Failed to seal evidence");

        // Step 3: Tamper with ledger by appending event
        let ledger = SecurityLedger::open(&ledger_path).unwrap();
        let mut tamper_details = HashMap::new();
        tamper_details.insert("tamper".to_string(), "event".to_string());

        ledger.append_event(
            EventType::SecurityAlert,
            Principal::Audit,
            Severity::Critical,
            "run-008",
            "boot-008",
            "epoch-008",
            tamper_details,
        ).expect("Failed to append tamper event");

        // Step 4: Verify - should detect event chain break
        let verifier = EvidenceVerifier::new(temp_path)
            .with_ledger(&ledger_path);
        let verification = verifier.verify_sealed_evidence();

        assert_eq!(verification.status, VerificationStatus::EventRootHashMismatch);
        assert!(!verification.tamper_evident);
        assert!(!verification.event_chain_valid);
    }

    #[test]
    fn test_seal_result_consistency() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Create multiple artifacts
        let mut artifacts = Vec::new();
        let mut total_size = 0u64;

        for i in 0..5 {
            let artifact_path = format!("{}/artifact{}.dat", temp_path, i);
            let content = vec![i as u8; (i + 1) * 10];  // 10, 20, 30, 40, 50 bytes
            total_size += content.len() as u64;

            let hash = create_test_artifact(&artifact_path, &content);

            let artifact = ArtifactRef::new(
                format!("artifact{}.dat", i),
                ArtifactType::CustomMetadata,
                hash,
                content.len() as u64,
                Principal::Developer,
                format!("Artifact {}", i),
            );

            artifacts.push(artifact);
        }

        let sealer = SealerPrincipal::new(
            "sealer-001".to_string(),
            0,
            0,
            Arc::new(SecurityLedger::open(&format!("{}/ledger.jsonl", temp_path)).unwrap()),
        );

        let seal_result = sealer.seal_evidence(
            "bundle-009".to_string(),
            "run-009".to_string(),
            "boot-009".to_string(),
            "epoch-009".to_string(),
            temp_path,
            artifacts,
            [0xBBu8; 32],
            [0xCCu8; 32],
            [0u8; 32],
        ).expect("Failed to seal evidence");

        // Verify result consistency
        assert_eq!(seal_result.total_artifact_size, total_size);
        assert_eq!(seal_result.total_artifact_size, 150);  // 10+20+30+40+50
        assert!(seal_result.success);
        assert_ne!(seal_result.seal_signature, [0u8; 64]);

        // Verify via verifier
        let verifier = EvidenceVerifier::new(temp_path);
        let verification = verifier.verify_sealed_evidence();

        assert_eq!(verification.status, VerificationStatus::Valid);
        assert_eq!(verification.artifacts_verified, 5);
    }
}
