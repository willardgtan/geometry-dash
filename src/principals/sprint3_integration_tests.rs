// Sprint 3 Integration Tests: Cross-Boundary Authentication
// Tests for SEC-C03 remediation: IPC principal verification

#[cfg(test)]
mod tests {
    use crate::principals::identity::{
        PrincipalIdentity, PrincipalIdentityRegistry, PublicKey, PrivateKey,
    };
    use crate::types::Principal;

    fn create_test_registry() -> PrincipalIdentityRegistry {
        PrincipalIdentityRegistry::new()
    }

    #[test]
    fn test_sprint3_principal_identity_registration() {
        let registry = create_test_registry();

        // Register Policy principal
        let pub_key = PublicKey::new([1u8; 32]);
        let priv_key = PrivateKey::new([2u8; 64]);

        let result = registry.register_identity(
            Principal::Policy,
            pub_key,
            priv_key,
            "policy-primary".to_string(),
        );

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.principal, Principal::Policy);
        assert_eq!(identity.key_version, 1);
        assert!(identity.is_active);
    }

    #[test]
    fn test_sprint3_multiple_principals_registration() {
        let registry = create_test_registry();

        let principals = vec![
            Principal::Policy,
            Principal::Actuator,
            Principal::Audit,
            Principal::Sealer,
        ];

        for (i, principal) in principals.iter().enumerate() {
            let pub_key = PublicKey::new([i as u8; 32]);
            let priv_key = PrivateKey::new([((i + 1) as u8); 64]);

            let result = registry.register_identity(
                *principal,
                pub_key,
                priv_key,
                format!("{}-identity", principal),
            );

            assert!(result.is_ok());
        }

        let registered = registry.get_registered_principals();
        assert_eq!(registered.len(), 4);
    }

    #[test]
    fn test_sprint3_key_rotation_preserves_history() {
        let registry = create_test_registry();

        // Register initial key
        let pub_key_v1 = PublicKey::new([10u8; 32]);
        let priv_key_v1 = PrivateKey::new([20u8; 64]);

        registry
            .register_identity(
                Principal::Sealer,
                pub_key_v1,
                priv_key_v1,
                "sealer-v1".to_string(),
            )
            .unwrap();

        // Rotate key
        let pub_key_v2 = PublicKey::new([30u8; 32]);
        let priv_key_v2 = PrivateKey::new([40u8; 64]);

        let rotated = registry
            .rotate_key(Principal::Sealer, pub_key_v2, priv_key_v2)
            .unwrap();

        assert_eq!(rotated.key_version, 2);

        // Verify both identities are stored
        let all_identities = registry.get_all_identities(Principal::Sealer);
        assert_eq!(all_identities.len(), 2);

        // First should be inactive, second active
        assert!(!all_identities[0].is_active);
        assert!(all_identities[1].is_active);
    }

    #[test]
    fn test_sprint3_identity_integrity_verification() {
        let registry = create_test_registry();

        let pub_key = PublicKey::new([55u8; 32]);
        let priv_key = PrivateKey::new([66u8; 64]);

        registry
            .register_identity(
                Principal::Audit,
                pub_key,
                priv_key,
                "audit-verify".to_string(),
            )
            .unwrap();

        // Verify integrity
        let result = registry.verify_identity(Principal::Audit);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_sprint3_audit_trail_for_all_operations() {
        let registry = create_test_registry();

        // Register identity
        let pub_key_v1 = PublicKey::new([11u8; 32]);
        let priv_key_v1 = PrivateKey::new([22u8; 64]);

        registry
            .register_identity(
                Principal::Policy,
                pub_key_v1,
                priv_key_v1,
                "v1".to_string(),
            )
            .unwrap();

        // Rotate key
        let pub_key_v2 = PublicKey::new([33u8; 32]);
        let priv_key_v2 = PrivateKey::new([44u8; 64]);

        registry
            .rotate_key(Principal::Policy, pub_key_v2, priv_key_v2)
            .unwrap();

        // Verify identity
        let _ = registry.verify_identity(Principal::Policy);

        // Check audit log
        let log = registry.get_audit_log();
        assert!(log.len() >= 3); // register, rotate, verify

        let register_ops: Vec<_> = log
            .iter()
            .filter(|r| r.operation == "register_identity")
            .collect();
        assert_eq!(register_ops.len(), 1);

        let rotate_ops: Vec<_> = log
            .iter()
            .filter(|r| r.operation == "rotate_key")
            .collect();
        assert_eq!(rotate_ops.len(), 1);
    }

    #[test]
    fn test_sprint3_principal_specific_audit_log() {
        let registry = create_test_registry();

        let pub_key = PublicKey::new([1u8; 32]);
        let priv_key = PrivateKey::new([2u8; 64]);

        // Register Policy
        registry
            .register_identity(
                Principal::Policy,
                pub_key,
                priv_key.clone(),
                "policy".to_string(),
            )
            .unwrap();

        // Register Audit
        registry
            .register_identity(
                Principal::Audit,
                pub_key,
                priv_key,
                "audit".to_string(),
            )
            .unwrap();

        // Get audit log for Policy only
        let policy_log = registry.get_principal_audit_log(Principal::Policy);
        assert!(!policy_log.is_empty());
        assert!(policy_log.iter().all(|r| r.principal == Principal::Policy));
    }

    #[test]
    fn test_sprint3_registry_statistics() {
        let registry = create_test_registry();

        let pub_key = PublicKey::new([77u8; 32]);
        let priv_key = PrivateKey::new([88u8; 64]);

        // Register three principals
        registry
            .register_identity(
                Principal::Policy,
                pub_key,
                priv_key.clone(),
                "p".to_string(),
            )
            .unwrap();

        registry
            .register_identity(
                Principal::Actuator,
                pub_key,
                priv_key.clone(),
                "a".to_string(),
            )
            .unwrap();

        registry
            .register_identity(
                Principal::Audit,
                pub_key,
                priv_key,
                "au".to_string(),
            )
            .unwrap();

        let stats = registry.get_statistics();
        assert_eq!(stats.total_principals_with_identities, 3);
        assert_eq!(stats.total_all_identities, 3);
        assert_eq!(stats.active_principal_count, 3);
    }

    #[test]
    fn test_sprint3_get_key_pair_after_registration() {
        let registry = create_test_registry();

        let pub_key = PublicKey::new([99u8; 32]);
        let priv_key = PrivateKey::new([111u8; 64]);

        registry
            .register_identity(
                Principal::Sealer,
                pub_key,
                priv_key,
                "sealer".to_string(),
            )
            .unwrap();

        let key_pair = registry.get_key_pair(Principal::Sealer);
        assert!(key_pair.is_some());
        let kp = key_pair.unwrap();
        assert_eq!(kp.public_key, pub_key);
    }

    #[test]
    fn test_sprint3_identity_expiration_handling() {
        let registry = create_test_registry();

        let pub_key = PublicKey::new([42u8; 32]);
        let priv_key = PrivateKey::new([84u8; 64]);

        let identity = registry
            .register_identity(
                Principal::Developer,
                pub_key,
                priv_key,
                "dev-temp".to_string(),
            )
            .unwrap();

        // Check that current identity is valid
        assert!(identity.is_valid());

        // Check that active identity is valid
        let active = registry
            .get_active_identity(Principal::Developer)
            .unwrap();
        assert!(active.is_valid());
    }

    #[test]
    fn test_sprint3_cross_principal_isolation() {
        let registry = create_test_registry();

        let pub_key_1 = PublicKey::new([1u8; 32]);
        let priv_key_1 = PrivateKey::new([2u8; 64]);

        let pub_key_2 = PublicKey::new([3u8; 32]);
        let priv_key_2 = PrivateKey::new([4u8; 64]);

        registry
            .register_identity(
                Principal::Policy,
                pub_key_1,
                priv_key_1,
                "policy".to_string(),
            )
            .unwrap();

        registry
            .register_identity(
                Principal::Audit,
                pub_key_2,
                priv_key_2,
                "audit".to_string(),
            )
            .unwrap();

        // Get identity for Policy, verify it's not Audit's identity
        let policy_id = registry.get_active_identity(Principal::Policy).unwrap();
        let audit_id = registry.get_active_identity(Principal::Audit).unwrap();

        assert_eq!(policy_id.principal, Principal::Policy);
        assert_eq!(audit_id.principal, Principal::Audit);
        assert_ne!(policy_id.public_key, audit_id.public_key);
    }

    #[test]
    fn test_sprint3_no_identity_for_unregistered_principal() {
        let registry = create_test_registry();

        let identity = registry.get_active_identity(Principal::Learner);
        assert!(identity.is_none());
    }

    #[test]
    fn test_sprint3_complete_lifecycle() {
        let registry = create_test_registry();

        // Phase 1: Initial registration
        let pub_v1 = PublicKey::new([10u8; 32]);
        let priv_v1 = PrivateKey::new([20u8; 64]);

        registry
            .register_identity(
                Principal::Sealer,
                pub_v1,
                priv_v1,
                "sealer-v1".to_string(),
            )
            .unwrap();

        // Phase 2: Verify initial identity
        assert!(registry.verify_identity(Principal::Sealer).unwrap());

        // Phase 3: Key rotation
        let pub_v2 = PublicKey::new([30u8; 32]);
        let priv_v2 = PrivateKey::new([40u8; 64]);

        registry
            .rotate_key(Principal::Sealer, pub_v2, priv_v2)
            .unwrap();

        // Phase 4: Verify rotated identity
        assert!(registry.verify_identity(Principal::Sealer).unwrap());

        // Phase 5: Check history
        let all = registry.get_all_identities(Principal::Sealer);
        assert_eq!(all.len(), 2);

        // Phase 6: Audit trail
        let log = registry.get_principal_audit_log(Principal::Sealer);
        assert!(log.len() >= 3);
    }
}
