// Sprint 2 Integration Tests: Privileged Data Boundary (SEC-C01)
// Tests the complete data classification, access control, declassification, and lineage workflow

#[cfg(test)]
mod sprint2_tests {
    use crate::principals::{
        ClassificationLevel, ClassificationLabel, ClassificationRegistry, DeclassificationPolicy,
        DeclassificationRecord, AccessControlEngine, DeclassificationEngine,
    };
    use crate::types::Principal;
    use crate::security_ledger::{SecurityLedger, EventType, Severity};
    use crate::ipc::{UniversalMessageHeader, UniversalMessage, MESSAGE_TYPE_REQUEST, FLAG_REQUIRES_AUTH};
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use std::collections::HashMap;

    /// Helper: Create a test classification registry
    fn create_test_registry() -> ClassificationRegistry {
        let ledger = Arc::new(SecurityLedger::open(":memory:").unwrap());
        ClassificationRegistry::new(ledger)
    }

    /// Helper: Create a test access control engine
    fn create_test_access_control() -> AccessControlEngine {
        let mut engine = AccessControlEngine::new();
        // Give Policy principal Unrestricted clearance
        engine.principal_clearances.insert(
            Principal::Policy as u8,
            vec![ClassificationLevel::Unrestricted],
        );
        // Give Audit principal all clearances
        engine.principal_clearances.insert(
            Principal::Audit as u8,
            vec![
                ClassificationLevel::Unrestricted,
                ClassificationLevel::SensitiveReward,
                ClassificationLevel::PrivilegedTelemetry,
                ClassificationLevel::Internal,
            ],
        );
        engine
    }

    /// Test 1: Basic classification and registry
    #[test]
    fn test_classification_registry_workflow() {
        let registry = create_test_registry();

        // Apply classification
        let label = registry
            .apply_classification(
                "physics_probe".to_string(),
                ClassificationLevel::PrivilegedTelemetry,
                Principal::Audit,
                "High-frequency physics probe data".to_string(),
            )
            .unwrap();

        // Verify label created
        assert_eq!(label.field_name, "physics_probe");
        assert_eq!(label.level, ClassificationLevel::PrivilegedTelemetry);
        assert_eq!(label.applied_by, Principal::Audit);

        // Retrieve label
        let retrieved = registry
            .get_label(&label.field_name)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.level, ClassificationLevel::PrivilegedTelemetry);

        // List all labels
        let all_labels = registry.list_labels();
        assert_eq!(all_labels.len(), 1);
    }

    /// Test 2: Access control enforcement
    #[test]
    fn test_access_control_enforcement() {
        let engine = create_test_access_control();

        // Policy principal: can read Unrestricted
        assert!(engine
            .can_read(Principal::Policy, ClassificationLevel::Unrestricted)
            .unwrap());

        // Policy principal: cannot read PrivilegedTelemetry
        assert!(!engine
            .can_read(Principal::Policy, ClassificationLevel::PrivilegedTelemetry)
            .unwrap());

        // Audit principal: can read everything
        assert!(engine
            .can_read(Principal::Audit, ClassificationLevel::Internal)
            .unwrap());
    }

    /// Test 3: Declassification policy registration and validation
    #[test]
    fn test_declassification_policy_registration() {
        let engine = create_test_access_control();
        let declassifier = DeclassificationEngine::new(engine);

        // Register policy with 2 approvals
        let policy = declassifier
            .register_policy(
                "policy-001".to_string(),
                1,
                "physics_probe".to_string(),
                ClassificationLevel::PrivilegedTelemetry,
                ClassificationLevel::SensitiveReward,
                Some("hash_sha256".to_string()),
                vec![Principal::Audit, Principal::Learner],
                0,
                None,
            )
            .unwrap();

        assert_eq!(policy.policy_id, "policy-001");
        assert_eq!(policy.source_level, ClassificationLevel::PrivilegedTelemetry);
        assert_eq!(policy.target_level, ClassificationLevel::SensitiveReward);

        // Retrieve policy
        let retrieved = declassifier.get_policy("policy-001").unwrap().unwrap();
        assert_eq!(retrieved.field_name, "physics_probe");
    }

    /// Test 4: Declassification with transformation
    #[test]
    fn test_declassification_with_transformation() {
        let engine = create_test_access_control();
        let declassifier = DeclassificationEngine::new(engine);

        // Register policy with hash transformation
        declassifier
            .register_policy(
                "hash-policy".to_string(),
                1,
                "reward_signal".to_string(),
                ClassificationLevel::PrivilegedTelemetry,
                ClassificationLevel::Unrestricted,
                Some("hash_sha256".to_string()),
                vec![Principal::Audit, Principal::Learner],
                0,
                None,
            )
            .unwrap();

        // Declassify value
        let original = b"sensitive_reward_value";
        let (declassified, record) = declassifier
            .declassify(
                Principal::Audit,
                "hash-policy",
                original,
                ClassificationLevel::PrivilegedTelemetry,
                vec![],
            )
            .unwrap();

        // Verify hash transformation
        assert_ne!(declassified, original);  // Should be hashed
        assert_eq!(declassified.len(), 32);  // SHA-256 is 32 bytes

        // Verify record created
        assert_eq!(record.field_name, "reward_signal");
        assert!(record.declassified_value_hash != [0u8; 32]);
    }

    /// Test 5: Declassification with lineage tracking
    #[test]
    fn test_declassification_lineage_tracking() {
        let engine = create_test_access_control();
        let declassifier = DeclassificationEngine::new(engine);

        // Register policy
        declassifier
            .register_policy(
                "lineage-policy".to_string(),
                1,
                "trace_data".to_string(),
                ClassificationLevel::Internal,
                ClassificationLevel::SensitiveReward,
                None,
                vec![Principal::Audit, Principal::Developer],
                0,
                None,
            )
            .unwrap();

        // Declassify with parent lineage
        let lineage = vec!["parent-001".to_string(), "parent-002".to_string()];
        let (_, record) = declassifier
            .declassify(
                Principal::Audit,
                "lineage-policy",
                b"trace_content",
                ClassificationLevel::Internal,
                lineage.clone(),
            )
            .unwrap();

        // Verify lineage recorded
        assert_eq!(record.lineage, lineage);
        assert!(!record.record_id.is_empty());
    }

    /// Test 6: IPC message classification
    #[test]
    fn test_ipc_message_classification() {
        let mut header =
            UniversalMessageHeader::new(5, MESSAGE_TYPE_REQUEST, 1, 2, FLAG_REQUIRES_AUTH);

        // Set classification
        header.set_classification(ClassificationLevel::PrivilegedTelemetry);
        header.set_required_clearance(ClassificationLevel::PrivilegedTelemetry);
        header.mark_declassified();

        // Verify classification
        assert_eq!(
            header.get_classification(),
            Some(ClassificationLevel::PrivilegedTelemetry)
        );
        assert_eq!(
            header.get_required_clearance(),
            Some(ClassificationLevel::PrivilegedTelemetry)
        );
        assert!(header.is_declassified());
    }

    /// Test 7: IPC message authorization enforcement
    #[test]
    fn test_ipc_message_authorization() {
        let mut header =
            UniversalMessageHeader::new(5, MESSAGE_TYPE_REQUEST, 1, 2, FLAG_REQUIRES_AUTH);

        // Require SensitiveReward clearance
        header.set_required_clearance(ClassificationLevel::SensitiveReward);

        // Clearance: principal 2 has SensitiveReward
        let clearances = vec![(
            2,
            vec![
                ClassificationLevel::Unrestricted,
                ClassificationLevel::SensitiveReward,
            ],
        )];

        // Should authorize
        assert!(header.authorize_receiver(&clearances));

        // Change clearance to something principal doesn't have
        header.set_required_clearance(ClassificationLevel::Internal);
        assert!(!header.authorize_receiver(&clearances));
    }

    /// Test 8: SecurityLedger classified event tracking
    #[test]
    fn test_security_ledger_classified_events() {
        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

        // Append classified event
        ledger
            .append_classified_event(
                EventType::ArtifactDeclassified,
                Principal::Audit,
                Severity::Info,
                "run-001",
                "boot-001",
                "epoch-001",
                ClassificationLevel::PrivilegedTelemetry,
                None,
                None,
                HashMap::new(),
            )
            .unwrap();

        // Append classified event with lineage
        let lineage = vec!["source-001".to_string()];
        ledger
            .append_classified_event(
                EventType::ArtifactDeclassified,
                Principal::Audit,
                Severity::Info,
                "run-001",
                "boot-001",
                "epoch-001",
                ClassificationLevel::SensitiveReward,
                Some("parent-001".to_string()),
                Some(lineage.clone()),
                HashMap::new(),
            )
            .unwrap();

        // Retrieve lineage
        let result = ledger.get_lineage("parent-001").unwrap();
        assert!(result.is_some());
        let events = result.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].ledger_index, 1);

        // Get classified events for principal
        let audit_events = ledger
            .get_principal_classified_events(Principal::Audit)
            .unwrap();
        assert_eq!(audit_events.len(), 2);
    }

    /// Test 9: End-to-end classification → declassification → lineage flow
    #[test]
    fn test_end_to_end_classification_flow() {
        // Setup components
        let registry = create_test_registry();
        let access_control = create_test_access_control();
        let declassifier = DeclassificationEngine::new(access_control);
        let temp = NamedTempFile::new().unwrap();
        let ledger = SecurityLedger::open(temp.path().to_str().unwrap()).unwrap();

        // Step 1: Apply classification
        let label = registry
            .apply_classification(
                "reward_value".to_string(),
                ClassificationLevel::PrivilegedTelemetry,
                Principal::Audit,
                "Sensitive reward signal".to_string(),
            )
            .unwrap();

        assert_eq!(label.level, ClassificationLevel::PrivilegedTelemetry);

        // Step 2: Register declassification policy
        let policy = declassifier
            .register_policy(
                "reward-declassify".to_string(),
                1,
                "reward_value".to_string(),
                ClassificationLevel::PrivilegedTelemetry,
                ClassificationLevel::SensitiveReward,
                Some("hash_sha256".to_string()),
                vec![Principal::Audit, Principal::Learner],
                0,
                None,
            )
            .unwrap();

        assert_eq!(policy.source_level, ClassificationLevel::PrivilegedTelemetry);

        // Step 3: Perform declassification
        let original = b"0.95";
        let (declassified, declassification_record) = declassifier
            .declassify(
                Principal::Audit,
                "reward-declassify",
                original,
                ClassificationLevel::PrivilegedTelemetry,
                vec![label.label_id.clone()],
            )
            .unwrap();

        // Verify declassification
        assert_ne!(declassified, original);  // Hash transformation
        assert_eq!(declassification_record.field_name, "reward_value");

        // Step 4: Log declassification to SecurityLedger
        let lineage = vec![label.label_id.clone()];
        ledger
            .append_classified_event(
                EventType::ArtifactDeclassified,
                Principal::Audit,
                Severity::Info,
                "run-001",
                "boot-001",
                "epoch-001",
                ClassificationLevel::SensitiveReward,
                Some(declassification_record.record_id.clone()),
                Some(lineage.clone()),
                {
                    let mut details = HashMap::new();
                    details.insert("field".to_string(), "reward_value".to_string());
                    details.insert("policy".to_string(), "reward-declassify".to_string());
                    details
                },
            )
            .unwrap();

        // Step 5: Verify lineage tracking
        let ledger_lineage = ledger
            .get_lineage(&declassification_record.record_id)
            .unwrap();
        assert!(ledger_lineage.is_some());

        // Step 6: Create IPC message with declassified data
        let mut ipc_header =
            UniversalMessageHeader::new(10, MESSAGE_TYPE_REQUEST, 3, 4, FLAG_REQUIRES_AUTH);
        ipc_header.set_classification(ClassificationLevel::SensitiveReward);
        ipc_header.set_required_clearance(ClassificationLevel::SensitiveReward);
        ipc_header.mark_declassified();

        let ipc_msg = UniversalMessage::new(
            10,
            MESSAGE_TYPE_REQUEST,
            3,
            4,
            FLAG_REQUIRES_AUTH,
            declassified.clone(),
        );

        // Verify end-to-end flow
        assert_eq!(
            ipc_msg.header.get_classification(),
            Some(ClassificationLevel::SensitiveReward)
        );
        assert!(ipc_msg.header.is_declassified());
        assert_eq!(ipc_msg.payload, declassified);
    }

    /// Test 10: Multi-level declassification chain
    #[test]
    fn test_multi_level_declassification_chain() {
        let engine = create_test_access_control();
        let declassifier = DeclassificationEngine::new(engine);

        // Policy 1: Internal → PrivilegedTelemetry
        declassifier
            .register_policy(
                "step1".to_string(),
                1,
                "data".to_string(),
                ClassificationLevel::Internal,
                ClassificationLevel::PrivilegedTelemetry,
                None,
                vec![Principal::Audit, Principal::Developer],
                0,
                None,
            )
            .unwrap();

        // Policy 2: PrivilegedTelemetry → SensitiveReward
        declassifier
            .register_policy(
                "step2".to_string(),
                1,
                "data".to_string(),
                ClassificationLevel::PrivilegedTelemetry,
                ClassificationLevel::SensitiveReward,
                None,
                vec![Principal::Audit, Principal::Learner],
                0,
                None,
            )
            .unwrap();

        // Step 1 declassification
        let (intermediate, record1) = declassifier
            .declassify(
                Principal::Audit,
                "step1",
                b"sensitive",
                ClassificationLevel::Internal,
                vec!["original".to_string()],
            )
            .unwrap();

        // Step 2 declassification
        let (final_value, record2) = declassifier
            .declassify(
                Principal::Audit,
                "step2",
                &intermediate,
                ClassificationLevel::PrivilegedTelemetry,
                vec!["original".to_string(), record1.record_id.clone()],
            )
            .unwrap();

        // Verify chain
        assert_eq!(record1.field_name, "data");
        assert_eq!(record2.field_name, "data");
        assert_eq!(record2.lineage.len(), 2);  // Both steps in lineage
        assert_eq!(record2.lineage[0], "original");
        assert_eq!(record2.lineage[1], record1.record_id);
    }

    /// Test 11: Denial of unauthorized declassification
    #[test]
    fn test_unauthorized_declassification_denied() {
        // Create engine where Policy principal has minimal clearance
        let engine = create_test_access_control();
        let declassifier = DeclassificationEngine::new(engine);

        // Register policy (requires Audit/Learner approval)
        declassifier
            .register_policy(
                "policy".to_string(),
                1,
                "field".to_string(),
                ClassificationLevel::PrivilegedTelemetry,
                ClassificationLevel::SensitiveReward,
                None,
                vec![Principal::Audit, Principal::Learner],
                0,
                None,
            )
            .unwrap();

        // Try to declassify with unauthorized principal
        let result = declassifier.declassify(
            Principal::Policy,  // Policy has no declassify capability
            "policy",
            b"secret",
            ClassificationLevel::PrivilegedTelemetry,
            vec![],
        );

        // Should fail authorization
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("not authorized to declassify"));
    }

    /// Test 12: Statistics and audit trail
    #[test]
    fn test_classification_statistics() {
        let registry = create_test_registry();

        // Apply multiple classifications
        for i in 0..3 {
            registry
                .apply_classification(
                    format!("field_{}", i),
                    ClassificationLevel::SensitiveReward,
                    Principal::Audit,
                    format!("Field {}", i),
                )
                .unwrap();
        }

        // Check statistics
        let stats = registry.statistics();
        assert_eq!(stats.0, 3);  // 3 labels
    }
}
