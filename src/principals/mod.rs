// Principal implementations for Phase 2 (Week 2+)
// Each principal is a specialized security function with its own state machine

pub mod policy;
pub mod actuator;
pub mod audit;
pub mod declassifier;
pub mod learner;

pub use policy::{PolicyPrincipal, PolicyState, GateADecision};
pub use actuator::{ActuatorPrincipal, ActuatorState, CommandRequest, ExecutionResult, GateCDecision, GateIDecision};
pub use audit::{AuditPrincipal, AuditState, CorrelationResult, BreachDetection, ForensicAnalysis};
pub use declassifier::{DeclassifierPrincipal, DeclassifierState, ClassificationLevel, ClassificationDecision, DeclassificationRequest, DeclassificationDecision, ClassificationLabel};
pub use learner::{LearnerPrincipal, LearnerState, SecurityPattern, PolicyRecommendation, UsageAnalysis, MLReadiness};
