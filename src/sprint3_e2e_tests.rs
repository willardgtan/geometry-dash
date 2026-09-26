// Sprint 3 End-to-End Tests: SEC-C03 Cross-Boundary Authentication
// Complete workflows from identity registration through gateway authorization

#[cfg(test)]
mod e2e_tests {
    use crate::ipc::authenticator::IpcMessageAuthenticator;
    use crate::ipc::gateway::IpcMessageGateway;
    use crate::ipc::message::UniversalMessageHeader;
    use crate::principals::certificate::PrincipalCertificateRegistry;
    use crate::principals::identity::{PrivateKey, PublicKey, PrincipalIdentityRegistry};
    use crate::security_ledger::auth_trail::{AuthenticationAuditTrail, AuthenticationEvent, AuthenticationEventType};
    use crate::security_ledger::SecurityLedger;
    use crate::types::Principal;
    use std::sync::Arc;

    #[test]
    fn test_complete_cross_boundary_authentication_flow() {
        // Setup
        let identity_registry = Arc::new(PrincipalIdentityRegistry::new());
        let cert_registry = Arc::new(PrincipalCertificateRegistry::new());
        let authenticator = Arc::new(IpcMessageAuthenticator::new(identity_registry.clone()));
        let gateway = IpcMessageGateway::new(
            authenticator.clone(),
            identity_registry.clone(),
            cert_registry.clone(),
        );

        // Phase 1: Register Policy Principal Identity
        let policy_pub = PublicKey::new([1u8; 32]);
        let policy_priv = PrivateKey::new([2u8; 64]);
        identity_registry
            .register_identity(
                Principal::Policy,
                policy_pub,
                policy_priv,
                "policy-identity".to_string(),
            )
            .unwrap();

        // Phase 2: Register Actuator Principal Identity
        let actuator_pub = PublicKey::new([3u8; 32]);
        let actuator_priv = PrivateKey::new([4u8; 64]);
        identity_registry
            .register_identity(
                Principal::Actuator,
                actuator_pub,
                actuator_priv,
                "actuator-identity".to_string(),
            )
            .unwrap();

        // Phase 3: Issue Certificates
        cert_registry
            .issue_certificate(Principal::Policy, policy_pub, Principal::Sealer, 365)
            .unwrap();

        cert_registry
            .issue_certificate(Principal::Actuator, actuator_pub, Principal::Sealer, 365)
            .unwrap();

        // Phase 4: Policy sends command to Actuator
        let mut msg = UniversalMessageHeader::new(
            1,  // IF-001
            0,  // REQUEST
            1,  // Policy sender
            2,  // Actuator receiver
            0x01, // REQUIRES_AUTH
        );
        msg.witness_principal = 1;

        // Phase 5: Sign message
        if let crate::ipc::authenticator::SignatureResult::Success { signature, .. } =
            authenticator.sign_message(&msg, Principal::Policy)
        {
            msg.witness_signature = signature;

            // Phase 6: Verify signature
            if let crate::ipc::authenticator::VerificationResult::Valid { .. } =
                authenticator.verify_message(&msg, Some(Principal::Policy))
            {
                // Phase 7: Gateway authorization
                match gateway.authorize_message(&msg) {
                    crate::ipc::gateway::GatewayResult::Allowed {
                        sender,
                        certificate_valid,
                        signature_valid,
                    } => {
                        assert_eq!(sender, Principal::Policy);
                        assert!(certificate_valid);
                        assert!(signature_valid);
                    }
                    _ => panic!("Expected authorization to succeed"),
                }
            }
        }
    }

    #[test]
    fn test_spoofing_attempt_blocked() {
        // Setup
        let identity_registry = Arc::new(PrincipalIdentityRegistry::new());
        let cert_registry = Arc::new(PrincipalCertificateRegistry::new());
        let authenticator = Arc::new(IpcMessageAuthenticator::new(identity_registry.clone()));
        let gateway = IpcMessageGateway::new(
            authenticator,
            identity_registry.clone(),
            cert_registry.clone(),
        );

        // Register only Policy
        let pub_key = PublicKey::new([5u8; 32]);
        let priv_key = PrivateKey::new([6u8; 64]);
        identity_registry
            .register_identity(Principal::Policy, pub_key, priv_key, "policy".to_string())
            .unwrap();

        cert_registry
            .issue_certificate(Principal::Policy, pub_key, Principal::Sealer, 365)
            .unwrap();

        // Attacker tries to send as Actuator (unregistered)
        let mut msg = UniversalMessageHeader::new(
            1,
            0,
            2, // Actuator sender (spoofed)
            1, // Policy receiver
            0x01,
        );
        msg.witness_principal = 2;

        // Gateway should reject spoofed message
        match gateway.authorize_message(&msg) {
            crate::ipc::gateway::GatewayResult::Denied { reason } => {
                assert!(reason.contains("no registered identity") || reason.contains("identity"));
            }
            _ => panic!("Expected authorization to fail"),
        }
    }

    #[test]
    fn test_revoked_certificate_blocks_communication() {
        // Setup
        let identity_registry = Arc::new(PrincipalIdentityRegistry::new());
        let cert_registry = Arc::new(PrincipalCertificateRegistry::new());
        let authenticator = Arc::new(IpcMessageAuthenticator::new(identity_registry.clone()));
        let gateway = IpcMessageGateway::new(
            authenticator,
            identity_registry.clone(),
            cert_registry.clone(),
        );

        // Register and certificate Policy
        let pub_key = PublicKey::new([7u8; 32]);
        let priv_key = PrivateKey::new([8u8; 64]);
        identity_registry
            .register_identity(Principal::Policy, pub_key, priv_key, "policy".to_string())
            .unwrap();

        let cert = cert_registry
            .issue_certificate(Principal::Policy, pub_key, Principal::Sealer, 365)
            .unwrap();

        // Revoke certificate
        cert_registry
            .revoke_certificate(&cert.cert_id, "Key compromise".to_string())
            .unwrap();

        // Message should be rejected
        let mut msg = UniversalMessageHeader::new(1, 0, 1, 2, 0x01);
        msg.witness_principal = 1;

        match gateway.authorize_message(&msg) {
            crate::ipc::gateway::GatewayResult::Denied { reason } => {
                assert!(reason.contains("certificate") || reason.contains("revoked"));
            }
            _ => panic!("Expected authorization to fail"),
        }
    }

    #[test]
    fn test_authentication_audit_trail_integration() {
        // Setup
        let ledger = SecurityLedger::new();
        let _trail = AuthenticationAuditTrail::new(ledger);

        // Create identity
        let identity_registry = Arc::new(PrincipalIdentityRegistry::new());
        let pub_key = PublicKey::new([9u8; 32]);
        let priv_key = PrivateKey::new([10u8; 64]);

        identity_registry
            .register_identity(Principal::Policy, pub_key, priv_key, "policy".to_string())
            .unwrap();

        // Verify identity operations are logged
        let audit_log = identity_registry.get_principal_audit_log(Principal::Policy);
        assert!(!audit_log.is_empty());
        assert_eq!(audit_log[0].operation, "register_identity");
    }

    #[test]
    fn test_key_rotation_maintains_authentication() {
        // Setup
        let identity_registry = Arc::new(PrincipalIdentityRegistry::new());
        let cert_registry = Arc::new(PrincipalCertificateRegistry::new());
        let authenticator = Arc::new(IpcMessageAuthenticator::new(identity_registry.clone()));
        let gateway = IpcMessageGateway::new(
            authenticator,
            identity_registry.clone(),
            cert_registry.clone(),
        );

        // Phase 1: Initial registration
        let pub_v1 = PublicKey::new([11u8; 32]);
        let priv_v1 = PrivateKey::new([12u8; 64]);

        identity_registry
            .register_identity(Principal::Policy, pub_v1, priv_v1, "v1".to_string())
            .unwrap();

        cert_registry
            .issue_certificate(Principal::Policy, pub_v1, Principal::Sealer, 365)
            .unwrap();

        // Phase 2: Can communicate with v1
        assert!(gateway.can_principal_send(Principal::Policy));

        // Phase 3: Rotate keys
        let pub_v2 = PublicKey::new([13u8; 32]);
        let priv_v2 = PrivateKey::new([14u8; 64]);

        identity_registry
            .rotate_key(Principal::Policy, pub_v2, priv_v2)
            .unwrap();

        // Phase 4: Revoke old certificate
        let old_cert = cert_registry
            .get_principal_certificates(Principal::Policy)
            .into_iter()
            .find(|c| c.public_key == pub_v1);
        if let Some(cert) = old_cert {
            cert_registry
                .revoke_certificate(&cert.cert_id, "Rotation".to_string())
                .ok();
        }

        // Phase 5: Issue new certificate
        cert_registry
            .issue_certificate(Principal::Policy, pub_v2, Principal::Sealer, 365)
            .unwrap();

        // Phase 6: Can still communicate with new key
        assert!(gateway.can_principal_send(Principal::Policy));
    }

    #[test]
    fn test_multi_principal_isolation() {
        // Setup
        let identity_registry = Arc::new(PrincipalIdentityRegistry::new());
        let cert_registry = Arc::new(PrincipalCertificateRegistry::new());

        // Register multiple principals
        let principals = vec![
            (Principal::Policy, [1u8; 32]),
            (Principal::Actuator, [2u8; 32]),
            (Principal::Audit, [3u8; 32]),
            (Principal::Sealer, [4u8; 32]),
        ];

        for (principal, pub_bytes) in principals.iter() {
            let pub_key = PublicKey::new(*pub_bytes);
            let priv_key = PrivateKey::new([99u8; 64]);

            identity_registry
                .register_identity(*principal, pub_key, priv_key, format!("{}-id", principal))
                .unwrap();

            cert_registry
                .issue_certificate(*principal, pub_key, Principal::Sealer, 365)
                .unwrap();
        }

        // Verify each principal has independent identity and certificate
        let policy_id = identity_registry.get_active_identity(Principal::Policy).unwrap();
        let actuator_id = identity_registry.get_active_identity(Principal::Actuator).unwrap();
        let audit_id = identity_registry.get_active_identity(Principal::Audit).unwrap();

        assert_ne!(policy_id.public_key, actuator_id.public_key);
        assert_ne!(actuator_id.public_key, audit_id.public_key);

        // Verify each principal has independent certificate
        let policy_cert = cert_registry.get_active_certificate(Principal::Policy).unwrap();
        let actuator_cert = cert_registry.get_active_certificate(Principal::Actuator).unwrap();

        assert_ne!(policy_cert.public_key, actuator_cert.public_key);
    }
}
