// Declassifier Principal: Data Classification Management (Week 2 Task 2.4)
// Responsible for managing data classifications and declassification policies

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use crate::types::{Principal, DataClass};
use crate::security_ledger::{SecurityLedger, EventType, Severity};
use crate::hsm::SigningKey;
use uuid::Uuid;

/// Declassifier principal state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclassifierState {
    NotStarted,
    Initializing,
    Ready,
    Classifying,    // Processing classification requests
    Declassifying,  // Processing declassification requests
    Enforcing,      // Enforcing access controls
    Running,
    Shutdown,
    Failed,
}

/// Data classification level
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassificationLevel {
    TopSecret,      // Highest classification
    Secret,
    Confidential,
    Internal,
    Public,         // Lowest classification
}

impl std::fmt::Display for ClassificationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClassificationLevel::TopSecret => write!(f, "top-secret"),
            ClassificationLevel::Secret => write!(f, "secret"),
            ClassificationLevel::Confidential => write!(f, "confidential"),
            ClassificationLevel::Internal => write!(f, "internal"),
            ClassificationLevel::Public => write!(f, "public"),
        }
    }
}

/// Classification decision
#[derive(Debug, Clone)]
pub struct ClassificationDecision {
    pub decision_id: String,
    pub timestamp_ns: u64,
    pub resource_id: String,
    pub classification: ClassificationLevel,
    pub requester: Principal,
    pub approved: bool,
    pub reason: String,
}

/// Declassification request
#[derive(Debug, Clone)]
pub struct DeclassificationRequest {
    pub request_id: String,
    pub timestamp_ns: u64,
    pub resource_id: String,
    pub current_classification: ClassificationLevel,
    pub target_classification: ClassificationLevel,
    pub justification: String,
    pub requester: Principal,
    pub metadata: HashMap<String, String>,
}

/// Declassification approval/denial
#[derive(Debug, Clone)]
pub struct DeclassificationDecision {
    pub decision_id: String,
    pub timestamp_ns: u64,
    pub request_id: String,
    pub approved: bool,
    pub authorized_by: String,
    pub reason: String,
}

/// Classification label
#[derive(Debug, Clone)]
pub struct ClassificationLabel {
    pub label_id: String,
    pub resource_id: String,
    pub classification: ClassificationLevel,
    pub created_at: u64,
    pub created_by: String,
    pub expires_at: Option<u64>,
    pub metadata: HashMap<String, String>,
}

/// Declassifier principal context
pub struct DeclassifierPrincipal {
    /// Unique ID for this Declassifier instance
    principal_id: String,

    /// Current state
    state: Arc<Mutex<DeclassifierState>>,

    /// UID/GID for process isolation
    uid: u32,
    gid: u32,

    /// Signing key for message authentication
    signing_key: Arc<Mutex<Option<SigningKey>>>,

    /// Security ledger for audit logging
    ledger: Arc<SecurityLedger>,

    /// Resource classification labels
    labels: Arc<Mutex<HashMap<String, ClassificationLabel>>>,

    /// Declassification requests history
    requests: Arc<Mutex<VecDeque<DeclassificationRequest>>>,

    /// Classification decisions history
    classification_decisions: Arc<Mutex<Vec<ClassificationDecision>>>,

    /// Declassification decisions history
    declassification_decisions: Arc<Mutex<Vec<DeclassificationDecision>>>,

    /// Access control policies
    access_policies: Arc<Mutex<HashMap<String, Vec<String>>>>,

    /// Statistics
    resources_classified: Arc<Mutex<u64>>,
    declassifications_requested: Arc<Mutex<u64>>,
    declassifications_approved: Arc<Mutex<u64>>,
    declassifications_denied: Arc<Mutex<u64>>,
}

impl DeclassifierPrincipal {
    /// Create new Declassifier principal
    pub fn new(
        principal_id: String,
        uid: u32,
        gid: u32,
        ledger: Arc<SecurityLedger>,
    ) -> Self {
        DeclassifierPrincipal {
            principal_id,
            state: Arc::new(Mutex::new(DeclassifierState::NotStarted)),
            uid,
            gid,
            signing_key: Arc::new(Mutex::new(None)),
            ledger,
            labels: Arc::new(Mutex::new(HashMap::new())),
            requests: Arc::new(Mutex::new(VecDeque::new())),
            classification_decisions: Arc::new(Mutex::new(Vec::new())),
            declassification_decisions: Arc::new(Mutex::new(Vec::new())),
            access_policies: Arc::new(Mutex::new(HashMap::new())),
            resources_classified: Arc::new(Mutex::new(0)),
            declassifications_requested: Arc::new(Mutex::new(0)),
            declassifications_approved: Arc::new(Mutex::new(0)),
            declassifications_denied: Arc::new(Mutex::new(0)),
        }
    }

    /// Initialize Declassifier principal
    pub fn initialize(&self, signing_key: SigningKey) -> std::io::Result<()> {
        self.set_state(DeclassifierState::Initializing);

        let mut key = self.signing_key.lock().unwrap();
        *key = Some(signing_key);

        // Initialize default access policies
        {
            let mut policies = self.access_policies.lock().unwrap();
            // Supervisor can access all classifications
            policies.insert("supervisor".to_string(), vec![
                "top-secret".to_string(),
                "secret".to_string(),
                "confidential".to_string(),
                "internal".to_string(),
                "public".to_string(),
            ]);
            // Audit can access all for forensics
            policies.insert("audit".to_string(), vec![
                "top-secret".to_string(),
                "secret".to_string(),
                "confidential".to_string(),
                "internal".to_string(),
                "public".to_string(),
            ]);
            // Policy can access up to secret
            policies.insert("policy".to_string(), vec![
                "secret".to_string(),
                "confidential".to_string(),
                "internal".to_string(),
                "public".to_string(),
            ]);
            // Actuator can access up to confidential
            policies.insert("actuator".to_string(), vec![
                "confidential".to_string(),
                "internal".to_string(),
                "public".to_string(),
            ]);
            // Others can access only public
            policies.insert("default".to_string(), vec![
                "public".to_string(),
            ]);
        }

        self.set_state(DeclassifierState::Ready);
        Ok(())
    }

    /// Set state
    fn set_state(&self, new_state: DeclassifierState) {
        let mut state = self.state.lock().unwrap();
        *state = new_state;
    }

    /// Get current state
    pub fn state(&self) -> DeclassifierState {
        *self.state.lock().unwrap()
    }

    /// Get principal ID
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// Classify a resource
    pub fn classify_resource(
        &self,
        resource_id: String,
        classification: ClassificationLevel,
        requester: Principal,
    ) -> std::io::Result<ClassificationDecision> {
        self.set_state(DeclassifierState::Classifying);

        // Check if requester is authorized to classify
        let authorized = matches!(requester, Principal::Supervisor | Principal::Policy | Principal::Declassifier);

        let decision = ClassificationDecision {
            decision_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            resource_id: resource_id.clone(),
            classification: classification.clone(),
            requester,
            approved: authorized,
            reason: if authorized {
                "Authorized principal".to_string()
            } else {
                "Unauthorized requester".to_string()
            },
        };

        if authorized {
            // Create label
            let label = ClassificationLabel {
                label_id: Uuid::new_v4().to_string(),
                resource_id,
                classification,
                created_at: decision.timestamp_ns,
                created_by: format!("{:?}", requester),
                expires_at: None,
                metadata: HashMap::new(),
            };

            // Store label
            {
                let mut labels = self.labels.lock().unwrap();
                labels.insert(label.resource_id.clone(), label);

                let mut count = self.resources_classified.lock().unwrap();
                *count += 1;
            }
        }

        // Record decision
        {
            let mut decisions = self.classification_decisions.lock().unwrap();
            decisions.push(decision.clone());
        }

        self.set_state(DeclassifierState::Ready);
        Ok(decision)
    }

    /// Request declassification
    pub fn request_declassification(
        &self,
        resource_id: String,
        current_classification: ClassificationLevel,
        target_classification: ClassificationLevel,
        justification: String,
        requester: Principal,
    ) -> std::io::Result<DeclassificationRequest> {
        self.set_state(DeclassifierState::Declassifying);

        let request = DeclassificationRequest {
            request_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            resource_id,
            current_classification,
            target_classification,
            justification,
            requester,
            metadata: HashMap::new(),
        };

        // Queue request
        {
            let mut reqs = self.requests.lock().unwrap();
            reqs.push_back(request.clone());

            let mut count = self.declassifications_requested.lock().unwrap();
            *count += 1;
        }

        self.set_state(DeclassifierState::Ready);
        Ok(request)
    }

    /// Approve declassification
    pub fn approve_declassification(
        &self,
        request_id: String,
        authorized_by: String,
    ) -> std::io::Result<DeclassificationDecision> {
        let decision = DeclassificationDecision {
            decision_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            request_id,
            approved: true,
            authorized_by,
            reason: "Declassification approved".to_string(),
        };

        {
            let mut decisions = self.declassification_decisions.lock().unwrap();
            decisions.push(decision.clone());

            let mut count = self.declassifications_approved.lock().unwrap();
            *count += 1;
        }

        Ok(decision)
    }

    /// Deny declassification
    pub fn deny_declassification(
        &self,
        request_id: String,
        authorized_by: String,
        reason: String,
    ) -> std::io::Result<DeclassificationDecision> {
        let decision = DeclassificationDecision {
            decision_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            request_id,
            approved: false,
            authorized_by,
            reason,
        };

        {
            let mut decisions = self.declassification_decisions.lock().unwrap();
            decisions.push(decision.clone());

            let mut count = self.declassifications_denied.lock().unwrap();
            *count += 1;
        }

        Ok(decision)
    }

    /// Check access for principal to resource
    pub fn check_access(&self, principal: &Principal, classification: &ClassificationLevel) -> bool {
        let policies = self.access_policies.lock().unwrap();

        let principal_name = match principal {
            Principal::Supervisor => "supervisor",
            Principal::Policy => "policy",
            Principal::Actuator => "actuator",
            Principal::Audit => "audit",
            Principal::Declassifier => "declassifier",
            _ => "default",
        };

        let allowed_classes = policies.get(principal_name)
            .or_else(|| policies.get("default"))
            .unwrap_or(&vec![]);

        allowed_classes.contains(&classification.to_string())
    }

    /// Get classification label for resource
    pub fn get_label(&self, resource_id: &str) -> Option<ClassificationLabel> {
        self.labels.lock().unwrap().get(resource_id).cloned()
    }

    /// Get all labels
    pub fn list_labels(&self) -> Vec<ClassificationLabel> {
        self.labels.lock().unwrap().values().cloned().collect()
    }

    /// Get declassification history
    pub fn declassification_history(&self) -> Vec<DeclassificationDecision> {
        self.declassification_decisions.lock().unwrap().clone()
    }

    /// Get classification decisions history
    pub fn classification_history(&self) -> Vec<ClassificationDecision> {
        self.classification_decisions.lock().unwrap().clone()
    }

    /// Get statistics
    pub fn statistics(&self) -> (u64, u64, u64, u64) {
        (
            *self.resources_classified.lock().unwrap(),
            *self.declassifications_requested.lock().unwrap(),
            *self.declassifications_approved.lock().unwrap(),
            *self.declassifications_denied.lock().unwrap(),
        )
    }

    /// Generate classification report
    pub fn report(&self) -> String {
        let (classified, requested, approved, denied) = self.statistics();

        format!(
            "Declassifier Principal {} Report\n\
            Resources Classified: {}\n\
            Declassifications Requested: {}\n\
            Declassifications Approved: {}\n\
            Declassifications Denied: {}\n\
            Labels Active: {}\n\
            State: {:?}",
            self.principal_id,
            classified,
            requested,
            approved,
            denied,
            self.labels.lock().unwrap().len(),
            self.state()
        )
    }

    /// Shutdown declassifier principal
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.set_state(DeclassifierState::Shutdown);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_declassifier_initialization() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );

        let declassifier = DeclassifierPrincipal::new(
            "declassifier-001".to_string(),
            1004,
            1004,
            ledger,
        );

        assert_eq!(declassifier.state(), DeclassifierState::NotStarted);
        assert_eq!(declassifier.principal_id(), "declassifier-001");
    }

    #[test]
    fn test_classify_resource() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );

        let declassifier = DeclassifierPrincipal::new(
            "declassifier-002".to_string(),
            1004,
            1004,
            ledger,
        );

        let decision = declassifier.classify_resource(
            "resource-001".to_string(),
            ClassificationLevel::Secret,
            Principal::Supervisor,
        ).unwrap();

        assert!(decision.approved);
        let (classified, _, _, _) = declassifier.statistics();
        assert_eq!(classified, 1);
    }

    #[test]
    fn test_declassification_request() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );

        let declassifier = DeclassifierPrincipal::new(
            "declassifier-003".to_string(),
            1004,
            1004,
            ledger,
        );

        let request = declassifier.request_declassification(
            "resource-001".to_string(),
            ClassificationLevel::Secret,
            ClassificationLevel::Confidential,
            "Needs access".to_string(),
            Principal::Policy,
        ).unwrap();

        assert!(!request.request_id.is_empty());
        let (_, requested, _, _) = declassifier.statistics();
        assert_eq!(requested, 1);
    }

    #[test]
    fn test_approve_declassification() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );

        let declassifier = DeclassifierPrincipal::new(
            "declassifier-004".to_string(),
            1004,
            1004,
            ledger,
        );

        let request = declassifier.request_declassification(
            "resource-001".to_string(),
            ClassificationLevel::Secret,
            ClassificationLevel::Confidential,
            "Needs access".to_string(),
            Principal::Policy,
        ).unwrap();

        let decision = declassifier.approve_declassification(
            request.request_id,
            "supervisor".to_string(),
        ).unwrap();

        assert!(decision.approved);
        let (_, _, approved, _) = declassifier.statistics();
        assert_eq!(approved, 1);
    }

    #[test]
    fn test_check_access() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );

        let declassifier = DeclassifierPrincipal::new(
            "declassifier-005".to_string(),
            1004,
            1004,
            ledger,
        );

        // Supervisor can access all
        assert!(declassifier.check_access(&Principal::Supervisor, &ClassificationLevel::TopSecret));

        // Policy can access up to secret
        assert!(declassifier.check_access(&Principal::Policy, &ClassificationLevel::Secret));
        assert!(!declassifier.check_access(&Principal::Policy, &ClassificationLevel::TopSecret));

        // Others can access only public
        assert!(!declassifier.check_access(&Principal::Learner, &ClassificationLevel::Confidential));
        assert!(declassifier.check_access(&Principal::Learner, &ClassificationLevel::Public));
    }
}
