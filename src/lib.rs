// Geometry Dash Phase 2 - Main Library
// Week 1 Foundation Layer: Supervisor, SecurityLedger, IPC, HSM Client

pub mod supervisor;
pub mod security_ledger;
pub mod ipc;
pub mod config;
pub mod types;

pub use supervisor::{Supervisor, SupervisorState, PrincipalState, PrincipalHealth};
pub use security_ledger::{SecurityLedger, SecurityEvent, EventType, Severity};
pub use ipc::{UniversalMessage, UniversalMessageHeader, IpcError, NonceCache, CapabilityMatrix};
pub use types::{Principal, InterfaceId, MessageType, DataClass};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lib_compiles() {
        // Basic sanity check
        assert!(true);
    }
}
