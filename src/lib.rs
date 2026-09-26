// Geometry Dash Phase 2 - Main Library
// Week 1 Foundation Layer: Supervisor, SecurityLedger, IPC, HSM Client
// Sprint 1: Evidence Authenticity & Sealing (SEC-C02 remediation)

pub mod supervisor;
pub mod security_ledger;
pub mod ipc;
pub mod hsm;
pub mod principals;
pub mod config;
pub mod types;
pub mod evidence;

pub use supervisor::{Supervisor, SupervisorState, PrincipalState, PrincipalHealth, orchestrator::PrincipalOrchestrator};
pub use security_ledger::{SecurityLedger, SecurityEvent, EventType, Severity};
pub use ipc::{UniversalMessage, UniversalMessageHeader, IpcError, NonceCache, CapabilityMatrix, PipeManager, PipeInfo};
pub use hsm::{HsmClient, AutoHsmClient, RealHsmClient, FilesystemHsmClient, SigningKey, HsmError, HsmResult};
pub use principals::{
    PolicyPrincipal, PolicyState, GateADecision,
    ActuatorPrincipal, ActuatorState, CommandRequest, ExecutionResult, GateCDecision, GateIDecision,
    AuditPrincipal, AuditState, CorrelationResult, BreachDetection, ForensicAnalysis,
    DeclassifierPrincipal, DeclassifierState, ClassificationLevel, ClassificationDecision, DeclassificationRequest, DeclassificationDecision, ClassificationLabel,
    LearnerPrincipal, LearnerState, SecurityPattern, PolicyRecommendation, UsageAnalysis, MLReadiness,
    EvaluatorPrincipal, EvaluatorState, DecisionEvaluation, PolicyEffectiveness, ComplianceReport, DecisionQuality,
    SealerPrincipal, SealerState, ConsistencyCheck, ConsistencyViolation, ConsistencyAction, ConsistencyReport,
    DeveloperPrincipal, DeveloperState, TracePoint, IntrospectionSnapshot, DiagnosticReport, PerformanceMetric,
};
pub use types::{Principal, InterfaceId, MessageType, DataClass};
pub use evidence::{EvidenceManifest, ArtifactRef, ArtifactType};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lib_compiles() {
        // Basic sanity check
        assert!(true);
    }
}
