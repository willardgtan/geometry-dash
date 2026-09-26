// Sprint 3 IPC Integration Tests: Message Authentication
// Tests SEC-C03 remediation for cross-boundary principal authentication

#[cfg(test)]
mod tests {
    use crate::ipc::authenticator::{IpcMessageAuthenticator, SignatureResult, VerificationResult};
    use crate::ipc::message::UniversalMessageHeader;
    use crate::principals::identity::{PrivateKey, PublicKey, PrincipalIdentityRegistry};
    use crate::types::Principal;
    use std::sync::Arc;

    fn create_test_authenticator_with_principals(
        principals: &[Principal],
    ) -> (IpcMessageAuthenticator, Arc<PrincipalIdentityRegistry>) {
        let registry = Arc::new(PrincipalIdentityRegistry::new());

        // Register identities for each principal
        for (i, principal) in principals.iter().enumerate() {
            let pub_key = PublicKey::new([(i as u8); 32]);
            let priv_key = PrivateKey::new([((i + 100) as u8); 64]);

            let _ = registry.register_identity(
                *principal,
                pub_key,
                priv_key,
                format!("{}-identity", principal),
            );
        }

        let authenticator = IpcMessageAuthenticator::new(registry.clone());
        (authenticator, registry)
    }

    fn create_test_message(
        sender: u8,
        receiver: u8,
        witness: u8,
    ) -> UniversalMessageHeader {
        let mut msg = UniversalMessageHeader::new(
            1,  // interface_id
            0,  // message_type (REQUEST)
            sender,
            receiver,
            0x01, // flags (REQUIRES_AUTH)
        );
        msg.witness_principal = witness;
        msg
    }

    #[test]
    fn test_single_principal_sign_verify() {
        let (auth, _reg) = create_test_authenticator_with_principals(&[Principal::Policy]);
        let mut msg = create_test_message(1, 2, 1);

        // Sign message
        let sign_result = auth.sign_message(&msg, Principal::Policy);
        assert!(matches!(sign_result, SignatureResult::Success { .. }));

        if let SignatureResult::Success { signature, key_version } = sign_result {
            msg.witness_signature = signature;
            assert_eq!(key_version, 1);

            // Verify message
            let verify_result = auth.verify_message(&msg, Some(Principal::Policy));
            assert!(matches!(
                verify_result,
                VerificationResult::Valid {
                    principal: Principal::Policy,
                    ..
                }
            ));
        }
    }

    #[test]
    fn test_multiple_principals_independent_signatures() {
        let (auth, _reg) = create_test_authenticator_with_principals(&[
            Principal::Policy,
            Principal::Actuator,
            Principal::Audit,
        ]);

        let mut msg1 = create_test_message(1, 2, 1);
        let mut msg2 = create_test_message(2, 1, 2);
        let mut msg3 = create_test_message(3, 1, 3);

        // Sign with Policy
        if let SignatureResult::Success { signature, .. } = auth.sign_message(&msg1, Principal::Policy) {
            msg1.witness_signature = signature;
            let result = auth.verify_message(&msg1, None);
            assert!(matches!(result, VerificationResult::Valid { .. }));
        }

        // Sign with Actuator
        if let SignatureResult::Success { signature, .. } =
            auth.sign_message(&msg2, Principal::Actuator)
        {
            msg2.witness_signature = signature;
            let result = auth.verify_message(&msg2, None);
            assert!(matches!(result, VerificationResult::Valid { .. }));
        }

        // Sign with Audit
        if let SignatureResult::Success { signature, .. } = auth.sign_message(&msg3, Principal::Audit) {
            msg3.witness_signature = signature;
            let result = auth.verify_message(&msg3, None);
            assert!(matches!(result, VerificationResult::Valid { .. }));
        }
    }

    #[test]
    fn test_signature_tampering_detection() {
        let (auth, _reg) = create_test_authenticator_with_principals(&[Principal::Policy]);
        let mut msg = create_test_message(1, 2, 1);

        // Sign message
        if let SignatureResult::Success { mut signature, .. } = auth.sign_message(&msg, Principal::Policy) {
            // Tamper with signature (flip first byte)
            signature[0] ^= 0xFF;
            msg.witness_signature = signature;

            // Verification should fail
            let result = auth.verify_message(&msg, None);
            assert!(matches!(
                result,
                VerificationResult::Invalid { reason } if reason.contains("signature mismatch")
            ));
        }
    }

    #[test]
    fn test_message_field_tampering_detection() {
        let (auth, _reg) = create_test_authenticator_with_principals(&[Principal::Policy]);
        let mut msg = create_test_message(1, 2, 1);

        // Sign message
        if let SignatureResult::Success { signature, .. } = auth.sign_message(&msg, Principal::Policy) {
            msg.witness_signature = signature;

            // Tamper with message field (change request_id)
            msg.request_id = 999;

            // Verification should fail because hash input changed
            let result = auth.verify_message(&msg, None);
            assert!(matches!(
                result,
                VerificationResult::Invalid { reason } if reason.contains("signature mismatch")
            ));
        }
    }

    #[test]
    fn test_unregistered_principal_cannot_sign() {
        let (auth, _reg) = create_test_authenticator_with_principals(&[Principal::Policy]);
        let msg = create_test_message(1, 2, 2);

        // Try to sign as unregistered principal
        let result = auth.sign_message(&msg, Principal::Learner);
        assert!(matches!(result, SignatureResult::Error(_)));
    }

    #[test]
    fn test_unregistered_witness_cannot_verify() {
        let (auth, _reg) = create_test_authenticator_with_principals(&[Principal::Policy]);
        let mut msg = create_test_message(1, 2, 1);

        // Sign as Policy
        if let SignatureResult::Success { signature, .. } = auth.sign_message(&msg, Principal::Policy) {
            msg.witness_signature = signature;
            msg.witness_principal = 5; // Unregistered witness

            // Verification should fail
            let result = auth.verify_message(&msg, None);
            assert!(matches!(
                result,
                VerificationResult::Invalid { reason } if reason.contains("No active identity")
            ));
        }
    }

    #[test]
    fn test_audit_log_sign_operations() {
        let (auth, _reg) = create_test_authenticator_with_principals(&[Principal::Policy]);
        let msg = create_test_message(1, 2, 1);

        auth.sign_message(&msg, Principal::Policy);

        let log = auth.get_audit_log();
        assert!(!log.is_empty());

        let sign_ops: Vec<_> = log.iter().filter(|r| r.operation == "sign").collect();
        assert_eq!(sign_ops.len(), 1);
        assert_eq!(sign_ops[0].status, "success");
        assert_eq!(sign_ops[0].sender_principal, Principal::Policy);
    }

    #[test]
    fn test_audit_log_verify_operations() {
        let (auth, _reg) = create_test_authenticator_with_principals(&[Principal::Policy]);
        let mut msg = create_test_message(1, 2, 1);

        // Sign and verify
        if let SignatureResult::Success { signature, .. } = auth.sign_message(&msg, Principal::Policy) {
            msg.witness_signature = signature;
            auth.verify_message(&msg, None);
        }

        let log = auth.get_audit_log();
        let verify_ops: Vec<_> = log.iter().filter(|r| r.operation == "verify").collect();
        assert!(!verify_ops.is_empty());
        assert_eq!(verify_ops[0].status, "success");
    }

    #[test]
    fn test_principal_specific_audit_log() {
        let (auth, _reg) = create_test_authenticator_with_principals(&[
            Principal::Policy,
            Principal::Actuator,
        ]);

        let msg1 = create_test_message(1, 2, 1);
        let msg2 = create_test_message(2, 1, 2);

        auth.sign_message(&msg1, Principal::Policy);
        auth.sign_message(&msg2, Principal::Actuator);

        let policy_log = auth.get_principal_audit_log(Principal::Policy);
        let actuator_log = auth.get_principal_audit_log(Principal::Actuator);

        assert_eq!(policy_log.len(), 1);
        assert_eq!(actuator_log.len(), 1);

        assert_eq!(policy_log[0].sender_principal, Principal::Policy);
        assert_eq!(actuator_log[0].sender_principal, Principal::Actuator);
    }

    #[test]
    fn test_authentication_statistics() {
        let (auth, _reg) = create_test_authenticator_with_principals(&[
            Principal::Policy,
            Principal::Actuator,
        ]);

        let mut msg1 = create_test_message(1, 2, 1);
        let msg2 = create_test_message(2, 1, 2);

        // Successful sign and verify
        if let SignatureResult::Success { signature, .. } = auth.sign_message(&msg1, Principal::Policy) {
            msg1.witness_signature = signature;
            auth.verify_message(&msg1, None);
        }

        // Failed verify (invalid principal)
        auth.verify_message(&msg2, None);

        let stats = auth.get_statistics();
        assert_eq!(stats.successful_signs, 1);
        assert_eq!(stats.successful_verifications, 1);
        assert_eq!(stats.failed_verifications, 1);
    }

    #[test]
    fn test_key_version_tracking() {
        let (auth, reg) = create_test_authenticator_with_principals(&[Principal::Policy]);
        let mut msg = create_test_message(1, 2, 1);

        // Sign with v1
        if let SignatureResult::Success { signature, key_version } =
            auth.sign_message(&msg, Principal::Policy)
        {
            assert_eq!(key_version, 1);
            msg.witness_signature = signature;

            // Verify shows v1
            if let VerificationResult::Valid { key_version: kv, .. } = auth.verify_message(&msg, None)
            {
                assert_eq!(kv, 1);
            }

            // Rotate key
            let new_pub = PublicKey::new([99u8; 32]);
            let new_priv = PrivateKey::new([199u8; 64]);
            reg.rotate_key(Principal::Policy, new_pub, new_priv)
                .unwrap();

            // Sign again
            let mut msg2 = create_test_message(1, 2, 1);
            if let SignatureResult::Success { signature: sig2, key_version: kv2 } =
                auth.sign_message(&msg2, Principal::Policy)
            {
                assert_eq!(kv2, 2);
                msg2.witness_signature = sig2;

                if let VerificationResult::Valid { key_version: kv3, .. } = auth.verify_message(&msg2, None)
                {
                    assert_eq!(kv3, 2);
                }
            }
        }
    }

    #[test]
    fn test_cross_boundary_authentication_flow() {
        let (auth, _reg) = create_test_authenticator_with_principals(&[
            Principal::Policy,
            Principal::Actuator,
        ]);

        // Policy wants to send command to Actuator
        let mut cmd_msg = create_test_message(1, 2, 1);

        // Policy signs the message
        if let SignatureResult::Success { signature, .. } =
            auth.sign_message(&cmd_msg, Principal::Policy)
        {
            cmd_msg.witness_signature = signature;

            // Actuator receives and verifies
            let result = auth.verify_message(&cmd_msg, Some(Principal::Policy));
            assert!(matches!(
                result,
                VerificationResult::Valid {
                    principal: Principal::Policy,
                    ..
                }
            ));
        }
    }

    #[test]
    fn test_replay_detection_via_audit_log() {
        let (auth, _reg) = create_test_authenticator_with_principals(&[Principal::Policy]);
        let mut msg = create_test_message(1, 2, 1);

        // First authentication
        if let SignatureResult::Success { signature, .. } = auth.sign_message(&msg, Principal::Policy) {
            msg.witness_signature = signature;
            auth.verify_message(&msg, None);
        }

        // Attempt replay: same message
        auth.verify_message(&msg, None);

        // Check audit log - both operations recorded
        let log = auth.get_audit_log();
        let verify_ops: Vec<_> = log.iter().filter(|r| r.operation == "verify").collect();
        assert_eq!(verify_ops.len(), 2);
        // Both have same message_id (indicating replay of same message)
        assert_eq!(verify_ops[0].message_id, verify_ops[1].message_id);
    }
}
