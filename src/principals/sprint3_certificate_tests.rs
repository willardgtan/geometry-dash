// Sprint 3 Integration Tests: Principal Certificate Registry
// Tests SEC-C03 certificate-based principal verification

#[cfg(test)]
mod tests {
    use crate::principals::certificate::{
        CertificateStatus, PrincipalCertificate, PrincipalCertificateRegistry,
    };
    use crate::principals::identity::{PrivateKey, PublicKey, PrincipalIdentityRegistry};
    use crate::types::Principal;
    use std::sync::Arc;

    fn create_test_registry() -> PrincipalCertificateRegistry {
        PrincipalCertificateRegistry::new()
    }

    fn create_identity_registry() -> Arc<PrincipalIdentityRegistry> {
        Arc::new(PrincipalIdentityRegistry::new())
    }

    #[test]
    fn test_certificate_issuance() {
        let registry = create_test_registry();
        let pub_key = PublicKey::new([1u8; 32]);

        let result = registry.issue_certificate(
            Principal::Policy,
            pub_key,
            Principal::Sealer,
            365,
        );

        assert!(result.is_ok());
        let cert = result.unwrap();
        assert_eq!(cert.principal, Principal::Policy);
        assert_eq!(cert.issuer, Principal::Sealer);
        assert_eq!(cert.status, CertificateStatus::Valid);
    }

    #[test]
    fn test_get_active_certificate() {
        let registry = create_test_registry();
        let pub_key = PublicKey::new([2u8; 32]);

        registry
            .issue_certificate(Principal::Audit, pub_key, Principal::Sealer, 90)
            .unwrap();

        let cert = registry.get_active_certificate(Principal::Audit);
        assert!(cert.is_some());
        assert_eq!(cert.unwrap().principal, Principal::Audit);
    }

    #[test]
    fn test_duplicate_issuance_prevented() {
        let registry = create_test_registry();
        let pub_key1 = PublicKey::new([3u8; 32]);
        let pub_key2 = PublicKey::new([4u8; 32]);

        // First issuance succeeds
        assert!(registry
            .issue_certificate(Principal::Policy, pub_key1, Principal::Sealer, 90)
            .is_ok());

        // Second issuance for same principal fails
        let result = registry.issue_certificate(Principal::Policy, pub_key2, Principal::Sealer, 90);
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_revocation() {
        let registry = create_test_registry();
        let pub_key = PublicKey::new([5u8; 32]);

        let cert = registry
            .issue_certificate(Principal::Actuator, pub_key, Principal::Sealer, 90)
            .unwrap();

        // Revoke certificate
        let result = registry.revoke_certificate(
            &cert.cert_id,
            "Key compromise".to_string(),
        );
        assert!(result.is_ok());

        // Check revocation
        let revoked = registry.get_certificate(&cert.cert_id).unwrap();
        assert_eq!(revoked.status, CertificateStatus::Revoked);
        assert!(revoked.revocation_reason.is_some());
        assert!(revoked.revoked_timestamp_ns.is_some());
    }

    #[test]
    fn test_certificate_integrity_verification() {
        let registry = create_test_registry();
        let pub_key = PublicKey::new([6u8; 32]);

        let cert = registry
            .issue_certificate(Principal::Policy, pub_key, Principal::Sealer, 90)
            .unwrap();

        let result = registry.verify_certificate(&cert.cert_id);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_certificate_attributes() {
        let registry = create_test_registry();
        let pub_key = PublicKey::new([7u8; 32]);

        let mut cert = registry
            .issue_certificate(Principal::Developer, pub_key, Principal::Supervisor, 90)
            .unwrap();

        cert.add_attribute("role".to_string(), "security-admin".to_string());
        cert.add_attribute("department".to_string(), "engineering".to_string());

        assert_eq!(cert.get_attribute("role"), Some("security-admin"));
        assert_eq!(cert.get_attribute("department"), Some("engineering"));
    }

    #[test]
    fn test_multiple_principals_certificates() {
        let registry = create_test_registry();

        let pub_key1 = PublicKey::new([8u8; 32]);
        let pub_key2 = PublicKey::new([9u8; 32]);
        let pub_key3 = PublicKey::new([10u8; 32]);

        registry
            .issue_certificate(Principal::Policy, pub_key1, Principal::Sealer, 90)
            .unwrap();
        registry
            .issue_certificate(Principal::Actuator, pub_key2, Principal::Sealer, 90)
            .unwrap();
        registry
            .issue_certificate(Principal::Audit, pub_key3, Principal::Sealer, 90)
            .unwrap();

        let principals = registry.get_principals_with_active_certs();
        assert_eq!(principals.len(), 3);
    }

    #[test]
    fn test_certificate_statistics() {
        let registry = create_test_registry();

        registry
            .issue_certificate(
                Principal::Policy,
                PublicKey::new([11u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        registry
            .issue_certificate(
                Principal::Actuator,
                PublicKey::new([12u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        let stats = registry.get_statistics();
        assert_eq!(stats.total_certificates, 2);
        assert_eq!(stats.active_certificates, 2);
        assert_eq!(stats.valid_certificates, 2);
        assert_eq!(stats.revoked_certificates, 0);
    }

    #[test]
    fn test_audit_log_issuance() {
        let registry = create_test_registry();
        let pub_key = PublicKey::new([13u8; 32]);

        registry
            .issue_certificate(Principal::Policy, pub_key, Principal::Sealer, 90)
            .unwrap();

        let log = registry.get_audit_log();
        assert!(!log.is_empty());
        assert_eq!(log[0].operation, "issue");
        assert_eq!(log[0].principal, Principal::Policy);
        assert_eq!(log[0].status, "success");
    }

    #[test]
    fn test_principal_audit_log() {
        let registry = create_test_registry();

        registry
            .issue_certificate(
                Principal::Policy,
                PublicKey::new([14u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        registry
            .issue_certificate(
                Principal::Audit,
                PublicKey::new([15u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        let policy_log = registry.get_principal_audit_log(Principal::Policy);
        let audit_log = registry.get_principal_audit_log(Principal::Audit);

        assert_eq!(policy_log.len(), 1);
        assert_eq!(audit_log.len(), 1);
    }

    #[test]
    fn test_certificate_lifecycle() {
        let registry = create_test_registry();

        // Phase 1: Issue certificate
        let cert1 = registry
            .issue_certificate(
                Principal::Policy,
                PublicKey::new([16u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        assert_eq!(cert1.status, CertificateStatus::Valid);

        // Phase 2: Verify certificate
        let verify1 = registry.verify_certificate(&cert1.cert_id).unwrap();
        assert!(verify1);

        // Phase 3: Revoke certificate
        registry
            .revoke_certificate(&cert1.cert_id, "Rotation".to_string())
            .unwrap();

        // Phase 4: Verify no active cert
        assert!(registry.get_active_certificate(Principal::Policy).is_none());

        // Phase 5: Issue new certificate
        let cert2 = registry
            .issue_certificate(
                Principal::Policy,
                PublicKey::new([17u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        // Phase 6: New certificate is active
        let active = registry.get_active_certificate(Principal::Policy).unwrap();
        assert_eq!(active.cert_id, cert2.cert_id);
    }

    #[test]
    fn test_principal_certificate_history() {
        let registry = create_test_registry();

        // Issue first cert
        let _cert1 = registry
            .issue_certificate(
                Principal::Actuator,
                PublicKey::new([18u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        let first_active = registry
            .get_active_certificate(Principal::Actuator)
            .unwrap();

        // Revoke and issue second cert
        registry
            .revoke_certificate(&first_active.cert_id, "Rotation".to_string())
            .unwrap();

        let _cert2 = registry
            .issue_certificate(
                Principal::Actuator,
                PublicKey::new([19u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        // Check history
        let history = registry.get_principal_certificates(Principal::Actuator);
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_certificate_identity_binding() {
        let cert_registry = create_test_registry();
        let id_registry = create_identity_registry();

        let pub_key = PublicKey::new([20u8; 32]);
        let priv_key = PrivateKey::new([21u8; 64]);

        // Register identity
        id_registry
            .register_identity(Principal::Policy, pub_key, priv_key, "policy-id".to_string())
            .unwrap();

        // Issue certificate with same public key
        let _cert = cert_registry
            .issue_certificate(Principal::Policy, pub_key, Principal::Sealer, 90)
            .unwrap();

        // Validate certificate against identity
        let cert = cert_registry.get_active_certificate(Principal::Policy).unwrap();
        let result = cert_registry.validate_against_identity(&cert.cert_id, &id_registry);

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_certificate_key_mismatch_detection() {
        let cert_registry = create_test_registry();
        let id_registry = create_identity_registry();

        let pub_key1 = PublicKey::new([22u8; 32]);
        let pub_key2 = PublicKey::new([23u8; 32]);
        let priv_key = PrivateKey::new([24u8; 64]);

        // Register identity with key1
        id_registry
            .register_identity(Principal::Policy, pub_key1, priv_key, "policy-id".to_string())
            .unwrap();

        // Issue certificate with different key2
        let _cert = cert_registry
            .issue_certificate(Principal::Policy, pub_key2, Principal::Sealer, 90)
            .unwrap();

        // Validation should fail
        let cert = cert_registry.get_active_certificate(Principal::Policy).unwrap();
        let result = cert_registry.validate_against_identity(&cert.cert_id, &id_registry);

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_serial_number_increment() {
        let registry = create_test_registry();

        let cert1 = registry
            .issue_certificate(
                Principal::Policy,
                PublicKey::new([25u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        registry
            .revoke_certificate(&cert1.cert_id, "Rotation".to_string())
            .unwrap();

        let cert2 = registry
            .issue_certificate(
                Principal::Policy,
                PublicKey::new([26u8; 32]),
                Principal::Sealer,
                90,
            )
            .unwrap();

        assert!(cert2.serial_number > cert1.serial_number);
    }

    #[test]
    fn test_concurrent_principal_certificates() {
        let registry = create_test_registry();

        let principals = vec![
            Principal::Policy,
            Principal::Actuator,
            Principal::Audit,
            Principal::Sealer,
            Principal::Declassifier,
        ];

        for (i, principal) in principals.iter().enumerate() {
            let pub_key = PublicKey::new([(i as u8); 32]);
            registry
                .issue_certificate(*principal, pub_key, Principal::Supervisor, 180)
                .unwrap();
        }

        let active_principals = registry.get_principals_with_active_certs();
        assert_eq!(active_principals.len(), 5);

        let stats = registry.get_statistics();
        assert_eq!(stats.total_certificates, 5);
        assert_eq!(stats.active_certificates, 5);
    }
}
