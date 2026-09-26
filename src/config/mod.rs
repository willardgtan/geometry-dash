// Configuration Module (Week 1 Task 1.4)
// Loads and validates configuration from YAML files

use serde::{Deserialize, Serialize};

/// Top-level configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub supervisor: SupervisorConfig,
    pub principals: PrincipalsConfig,
    pub hsm: HsmConfig,
    pub ipc: IpcConfig,
    pub security: SecurityConfig,
}

/// Supervisor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorConfig {
    pub heartbeat_interval_ms: u64,
    pub heartbeat_timeout_ms: u64,
    pub restart_max_attempts: u32,
    pub restart_backoff_ms: u64,
    pub epoch_id_prefix: String,
}

/// Per-principal configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalConfig {
    pub uid: u32,
    pub gid: u32,
    pub seccomp_profile: String,
    pub apparmor_profile: String,
}

/// All principals' configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalsConfig {
    pub policy: PrincipalConfig,
    pub actuator: PrincipalConfig,
    pub audit: PrincipalConfig,
    pub declassifier: PrincipalConfig,
    pub learner: PrincipalConfig,
    pub evaluator: PrincipalConfig,
    pub sealer: PrincipalConfig,
    pub developer: PrincipalConfig,
}

/// HSM (Hardware Security Module) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    pub enabled: bool,
    pub pkcs11_module: String,
    pub token_label: String,
    pub timeout_ms: u64,
    pub failover_to_encrypted_fs: bool,
}

/// IPC (Inter-Process Communication) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcConfig {
    pub pipe_root: String,
    pub pipe_mode: String,  // Octal string like "0600"
    pub max_message_age_ns: u64,
}

/// Security policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub max_concurrent_actions: u32,
    pub nonce_cache_ttl_ns: u64,
}

impl Config {
    /// Create default configuration
    pub fn default() -> Self {
        Config {
            supervisor: SupervisorConfig {
                heartbeat_interval_ms: 100,
                heartbeat_timeout_ms: 1000,
                restart_max_attempts: 3,
                restart_backoff_ms: 500,
                epoch_id_prefix: "epoch".to_string(),
            },
            principals: PrincipalsConfig {
                policy: PrincipalConfig {
                    uid: 1001,
                    gid: 1001,
                    seccomp_profile: "strict".to_string(),
                    apparmor_profile: "policy".to_string(),
                },
                actuator: PrincipalConfig {
                    uid: 1002,
                    gid: 1002,
                    seccomp_profile: "strict".to_string(),
                    apparmor_profile: "actuator".to_string(),
                },
                audit: PrincipalConfig {
                    uid: 1003,
                    gid: 1003,
                    seccomp_profile: "permissive".to_string(),
                    apparmor_profile: "audit".to_string(),
                },
                declassifier: PrincipalConfig {
                    uid: 1004,
                    gid: 1004,
                    seccomp_profile: "strict".to_string(),
                    apparmor_profile: "declassifier".to_string(),
                },
                learner: PrincipalConfig {
                    uid: 1005,
                    gid: 1005,
                    seccomp_profile: "permissive".to_string(),
                    apparmor_profile: "learner".to_string(),
                },
                evaluator: PrincipalConfig {
                    uid: 1006,
                    gid: 1006,
                    seccomp_profile: "permissive".to_string(),
                    apparmor_profile: "evaluator".to_string(),
                },
                sealer: PrincipalConfig {
                    uid: 1007,
                    gid: 1007,
                    seccomp_profile: "strict".to_string(),
                    apparmor_profile: "sealer".to_string(),
                },
                developer: PrincipalConfig {
                    uid: 1008,
                    gid: 1008,
                    seccomp_profile: "permissive".to_string(),
                    apparmor_profile: "developer".to_string(),
                },
            },
            hsm: HsmConfig {
                enabled: true,
                pkcs11_module: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
                token_label: "GeometryDash".to_string(),
                timeout_ms: 5000,
                failover_to_encrypted_fs: true,
            },
            ipc: IpcConfig {
                pipe_root: "/var/run/geometry-dash".to_string(),
                pipe_mode: "0600".to_string(),
                max_message_age_ns: 300_000_000_000,  // 5 minutes
            },
            security: SecurityConfig {
                max_concurrent_actions: 1000,
                nonce_cache_ttl_ns: 305_000_000_000,  // 5 min + 5s grace
            },
        }
    }

    /// Validate configuration (all required fields present, values reasonable)
    pub fn validate(&self) -> Result<(), String> {
        // Supervisor config validations
        if self.supervisor.heartbeat_interval_ms == 0 {
            return Err("heartbeat_interval_ms must be > 0".to_string());
        }
        if self.supervisor.heartbeat_timeout_ms < self.supervisor.heartbeat_interval_ms {
            return Err("heartbeat_timeout_ms must be >= heartbeat_interval_ms".to_string());
        }

        // Security config validations
        if self.security.nonce_cache_ttl_ns < 1_000_000_000 {
            return Err("nonce_cache_ttl_ns should be at least 1 second".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(config.supervisor.heartbeat_interval_ms > 0);
        assert!(config.security.nonce_cache_ttl_ns > 0);
    }

    #[test]
    fn test_config_validate() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_fails_on_invalid_heartbeat() {
        let mut config = Config::default();
        config.supervisor.heartbeat_interval_ms = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_principal_config_struct() {
        let principal = PrincipalConfig {
            uid: 1001,
            gid: 1001,
            seccomp_profile: "strict".to_string(),
            apparmor_profile: "policy".to_string(),
        };
        assert_eq!(principal.uid, 1001);
        assert_eq!(principal.seccomp_profile, "strict");
    }
}
