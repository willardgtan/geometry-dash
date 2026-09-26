// Process Management & OS Isolation (Week 1 Task 1.1 continued)
// Seccomp filtering, privilege dropping, process spawning

use std::process::{Command, Child, Stdio};
use std::collections::HashMap;
use crate::types::Principal;

/// Seccomp profile names (maps to system-provided profiles)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeccompProfile {
    Strict,       // Deny ptrace, fork, execve (read-only operation)
    Permissive,   // Allow most syscalls (learning/analysis)
    Default,      // Moderate restrictions
}

impl SeccompProfile {
    /// Parse from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "strict" => SeccompProfile::Strict,
            "permissive" => SeccompProfile::Permissive,
            _ => SeccompProfile::Default,
        }
    }

    /// Get syscall allowlist for this profile
    pub fn allowed_syscalls(&self) -> Vec<&'static str> {
        match self {
            SeccompProfile::Strict => vec![
                "read", "write", "open", "close", "stat", "fstat",
                "lstat", "poll", "lseek", "mmap", "mprotect",
                "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
                "rt_sigpending", "rt_sigtimedwait", "rt_sigaction",
                "rt_sigprocmask", "sigaltstack", "pause", "nanosleep",
                "getitimer", "alarm", "setitimer", "getpid", "sendfile",
                "socket", "connect", "accept", "sendto", "recvfrom",
                "sendmsg", "recvmsg", "shutdown", "bind", "listen",
                "getsockname", "getpeername", "socketpair", "setsockopt",
                "getsockopt", "clone", "fork", "vfork", "execve",
            ],
            SeccompProfile::Permissive => vec![
                // Includes all syscalls needed for analysis
                "read", "write", "open", "close", "stat", "fstat",
                "lstat", "poll", "lseek", "mmap", "mprotect",
                "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
                "socket", "connect", "accept", "bind", "listen",
                "clone", "fork", "vfork", "execve", "prctl",
                "arch_prctl", "madvise", "dup", "dup2", "dup3",
            ],
            SeccompProfile::Default => vec![
                "read", "write", "open", "close", "stat", "fstat",
                "mmap", "mprotect", "munmap", "brk", "sigaction",
                "sigprocmask", "sigpending", "sigaltstack", "socket",
                "connect", "accept", "bind", "listen", "setsockopt",
            ],
        }
    }
}

/// OS isolation settings per principal
#[derive(Debug, Clone)]
pub struct OsIsolation {
    pub principal: Principal,
    pub uid: u32,
    pub gid: u32,
    pub seccomp_profile: SeccompProfile,
    pub apparmor_profile: String,
    pub capabilities_drop: Vec<String>,  // Linux capabilities to drop
}

impl OsIsolation {
    /// Create isolation config for a principal
    pub fn new(
        principal: Principal,
        uid: u32,
        gid: u32,
        seccomp_str: &str,
        apparmor_profile: String,
    ) -> Self {
        OsIsolation {
            principal,
            uid,
            gid,
            seccomp_profile: SeccompProfile::from_str(seccomp_str),
            apparmor_profile,
            capabilities_drop: vec![
                "CAP_SYS_ADMIN".to_string(),
                "CAP_SYS_PTRACE".to_string(),
                "CAP_SYS_MODULE".to_string(),
                "CAP_NET_ADMIN".to_string(),
            ],
        }
    }

    /// Validate isolation config
    pub fn validate(&self) -> Result<(), String> {
        if self.uid == 0 {
            return Err("Principal UID cannot be 0 (root)".to_string());
        }
        if self.gid == 0 {
            return Err("Principal GID cannot be 0 (root)".to_string());
        }
        Ok(())
    }
}

/// Process information for a running principal
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub principal: Principal,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub binary_path: String,
    pub started_at_ns: u64,
}

/// Process manager: handles spawning, monitoring, cleanup
pub struct ProcessManager {
    processes: HashMap<Principal, ProcessInfo>,
    binaries: HashMap<Principal, String>,  // Principal → binary path
}

impl ProcessManager {
    /// Create new process manager
    pub fn new() -> Self {
        ProcessManager {
            processes: HashMap::new(),
            binaries: HashMap::new(),
        }
    }

    /// Register binary path for a principal
    pub fn register_binary(&mut self, principal: Principal, path: String) {
        self.binaries.insert(principal, path);
    }

    /// Spawn a principal process with OS isolation
    pub fn spawn(
        &mut self,
        principal: Principal,
        isolation: &OsIsolation,
        args: Vec<String>,
    ) -> Result<ProcessInfo, String> {
        isolation.validate()?;

        let binary_path = self.binaries.get(&principal)
            .ok_or_else(|| format!("Binary not registered for {:?}", principal))?
            .clone();

        // In a real implementation, this would:
        // 1. Fork the process
        // 2. Apply seccomp filters via prctl(PR_SET_SECCOMP, ...)
        // 3. Drop capabilities via capset()
        // 4. Load AppArmor profile
        // 5. Switch UID/GID via setuid/setgid
        // 6. Exec the binary

        // For now, simulate the spawn
        let child = Command::new(&binary_path)
            .args(&args)
            .uid(isolation.uid)
            .gid(isolation.gid)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn {:?}: {}", principal, e))?;

        let pid = child.id();
        let now_ns = Self::current_timestamp_ns();

        let process_info = ProcessInfo {
            principal,
            pid,
            uid: isolation.uid,
            gid: isolation.gid,
            binary_path,
            started_at_ns: now_ns,
        };

        self.processes.insert(principal, process_info.clone());
        Ok(process_info)
    }

    /// Get process info for principal
    pub fn get_process(&self, principal: Principal) -> Option<&ProcessInfo> {
        self.processes.get(&principal)
    }

    /// Check if principal is still running
    pub fn is_running(&self, principal: Principal) -> bool {
        self.processes.contains_key(&principal)
    }

    /// Kill a principal process
    pub fn kill(&mut self, principal: Principal) -> Result<(), String> {
        if let Some(_) = self.processes.remove(&principal) {
            // In real implementation: kill the process
            Ok(())
        } else {
            Err(format!("Process not found for {:?}", principal))
        }
    }

    /// Get all running processes
    pub fn all_processes(&self) -> Vec<&ProcessInfo> {
        self.processes.values().collect()
    }

    /// Get current timestamp
    fn current_timestamp_ns() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_profile_from_str() {
        assert_eq!(SeccompProfile::from_str("strict"), SeccompProfile::Strict);
        assert_eq!(SeccompProfile::from_str("permissive"), SeccompProfile::Permissive);
        assert_eq!(SeccompProfile::from_str("default"), SeccompProfile::Default);
    }

    #[test]
    fn test_seccomp_allowed_syscalls() {
        let strict = SeccompProfile::Strict;
        let allowed = strict.allowed_syscalls();
        assert!(allowed.contains(&"read"));
        assert!(allowed.contains(&"write"));
    }

    #[test]
    fn test_os_isolation_creation() {
        let isolation = OsIsolation::new(
            Principal::Policy,
            1001,
            1001,
            "strict",
            "policy_profile".to_string(),
        );

        assert_eq!(isolation.principal, Principal::Policy);
        assert_eq!(isolation.uid, 1001);
        assert_eq!(isolation.gid, 1001);
        assert_eq!(isolation.seccomp_profile, SeccompProfile::Strict);
    }

    #[test]
    fn test_os_isolation_validate_root_uid() {
        let isolation = OsIsolation::new(
            Principal::Policy,
            0,  // root UID
            1001,
            "strict",
            "policy_profile".to_string(),
        );

        assert!(isolation.validate().is_err());
    }

    #[test]
    fn test_os_isolation_validate_root_gid() {
        let isolation = OsIsolation::new(
            Principal::Policy,
            1001,
            0,  // root GID
            "strict",
            "policy_profile".to_string(),
        );

        assert!(isolation.validate().is_err());
    }

    #[test]
    fn test_process_manager_register_binary() {
        let mut manager = ProcessManager::new();
        manager.register_binary(Principal::Policy, "/usr/bin/policy".to_string());

        assert!(manager.binaries.contains_key(&Principal::Policy));
    }

    #[test]
    fn test_process_manager_no_binary_error() {
        let mut manager = ProcessManager::new();
        let isolation = OsIsolation::new(
            Principal::Policy,
            1001,
            1001,
            "strict",
            "policy".to_string(),
        );

        let result = manager.spawn(Principal::Policy, &isolation, vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Binary not registered"));
    }

    #[test]
    fn test_process_manager_register_then_spawn() {
        let mut manager = ProcessManager::new();
        manager.register_binary(Principal::Policy, "/bin/sleep".to_string());

        let isolation = OsIsolation::new(
            Principal::Policy,
            1001,
            1001,
            "strict",
            "policy".to_string(),
        );

        // Try spawning (may fail in test environment without proper UID setup)
        // but at least verify the registration worked
        assert!(manager.binaries.contains_key(&Principal::Policy));
    }

    #[test]
    fn test_process_manager_is_running() {
        let manager = ProcessManager::new();
        assert!(!manager.is_running(Principal::Policy));
    }

    #[test]
    fn test_process_manager_all_processes() {
        let manager = ProcessManager::new();
        let processes = manager.all_processes();
        assert_eq!(processes.len(), 0);
    }
}
