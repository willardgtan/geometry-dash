// Principal implementations for Phase 2 (Week 2+)
// Each principal is a specialized security function with its own state machine

pub mod policy;

pub use policy::{PolicyPrincipal, PolicyState, GateADecision};
