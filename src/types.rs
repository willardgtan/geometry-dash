// Shared types for Phase 2

use serde::{Deserialize, Serialize};
use std::fmt;

/// Principal identifiers (9 security principals)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[repr(u8)]
pub enum Principal {
    Supervisor = 0,
    Policy = 1,
    Actuator = 2,
    Audit = 3,
    Declassifier = 4,
    Learner = 5,
    Evaluator = 6,
    Sealer = 7,
    Developer = 8,
}

impl Principal {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Principal::Supervisor),
            1 => Some(Principal::Policy),
            2 => Some(Principal::Actuator),
            3 => Some(Principal::Audit),
            4 => Some(Principal::Declassifier),
            5 => Some(Principal::Learner),
            6 => Some(Principal::Evaluator),
            7 => Some(Principal::Sealer),
            8 => Some(Principal::Developer),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn name(&self) -> &'static str {
        match self {
            Principal::Supervisor => "PRN-SUPERVISOR",
            Principal::Policy => "PRN-POLICY",
            Principal::Actuator => "PRN-ACTUATOR",
            Principal::Audit => "PRN-AUDIT",
            Principal::Declassifier => "PRN-DECLASSIFIER",
            Principal::Learner => "PRN-LEARNER",
            Principal::Evaluator => "PRN-EVALUATOR",
            Principal::Sealer => "PRN-SEALER",
            Principal::Developer => "PRN-DEVELOPER",
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Interface identifiers (22 critical interfaces)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceId {
    IF001 = 1,   // Supervisor → Policy
    IF002 = 2,   // Policy → Audit
    IF003 = 3,   // Policy → Actuator
    IF004 = 4,   // Declassifier → Policy
    IF005 = 5,   // Actuator → Policy
    IF006 = 6,   // Learner → Audit
    IF007 = 7,   // Evaluator → Audit
    IF008 = 8,   // Sealer → Audit
    IF009 = 9,   // Sealer → Policy
    IF010 = 10,  // Developer → Supervisor
    IF011 = 11,  // All → Audit (SecurityLedger)
    IF012 = 12,  // Policy → Declassifier
    IF013 = 13,  // Actuator → Supervisor (heartbeat)
    IF014 = 14,  // Supervisor → All (shutdown)
    IF015 = 15,  // All → HSM (sign)
    IF016 = 16,  // Audit → Auditor (forensics)
    IF017 = 17,  // Auditor → Supervisor (Gate I)
    IF018 = 18,  // All → SecurityLedger (verify)
    IF019 = 19,  // Sealer → All (broadcast seal)
    IF020 = 20,  // Policy → Developer (introspection)
    IF021 = 21,  // Evaluator → Declassifier
    IF022 = 22,  // Learner → Sealer
}

impl InterfaceId {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(InterfaceId::IF001),
            2 => Some(InterfaceId::IF002),
            3 => Some(InterfaceId::IF003),
            4 => Some(InterfaceId::IF004),
            5 => Some(InterfaceId::IF005),
            6 => Some(InterfaceId::IF006),
            7 => Some(InterfaceId::IF007),
            8 => Some(InterfaceId::IF008),
            9 => Some(InterfaceId::IF009),
            10 => Some(InterfaceId::IF010),
            11 => Some(InterfaceId::IF011),
            12 => Some(InterfaceId::IF012),
            13 => Some(InterfaceId::IF013),
            14 => Some(InterfaceId::IF014),
            15 => Some(InterfaceId::IF015),
            16 => Some(InterfaceId::IF016),
            17 => Some(InterfaceId::IF017),
            18 => Some(InterfaceId::IF018),
            19 => Some(InterfaceId::IF019),
            20 => Some(InterfaceId::IF020),
            21 => Some(InterfaceId::IF021),
            22 => Some(InterfaceId::IF022),
            _ => None,
        }
    }
}

/// Message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    Request = 0,
    Response = 1,
    Event = 2,
    Error = 3,
}

/// Data classification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataClass {
    Public,
    Internal,
    Sensitive,
    Privileged,
    Secret,
    TopSecret,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_conversion() {
        assert_eq!(Principal::from_u8(0), Some(Principal::Supervisor));
        assert_eq!(Principal::from_u8(1), Some(Principal::Policy));
        assert_eq!(Principal::from_u8(9), None);
    }

    #[test]
    fn test_principal_name() {
        assert_eq!(Principal::Policy.name(), "PRN-POLICY");
        assert_eq!(Principal::Supervisor.name(), "PRN-SUPERVISOR");
    }
}
