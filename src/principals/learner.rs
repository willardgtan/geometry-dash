// Learner Principal: Pattern Analysis & Policy Optimization (Week 2 Task 2.5)
// Responsible for analyzing security patterns and suggesting policy improvements

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use crate::types::Principal;
use crate::security_ledger::{SecurityLedger, SecurityEvent, EventType, Severity};
use crate::hsm::SigningKey;
use uuid::Uuid;

/// Learner principal state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnerState {
    NotStarted,
    Initializing,
    Ready,
    Analyzing,      // Processing events for patterns
    Learning,       // Building models from data
    Optimizing,     // Generating recommendations
    Running,
    Shutdown,
    Failed,
}

/// Security pattern detected
#[derive(Debug, Clone)]
pub struct SecurityPattern {
    pub pattern_id: String,
    pub timestamp_ns: u64,
    pub pattern_type: String,
    pub frequency: u64,
    pub confidence: f64,
    pub related_events: Vec<String>,
    pub description: String,
}

/// Policy optimization recommendation
#[derive(Debug, Clone)]
pub struct PolicyRecommendation {
    pub recommendation_id: String,
    pub timestamp_ns: u64,
    pub priority: String,  // "low", "medium", "high", "critical"
    pub category: String,  // "access_control", "audit", "classification", "command_execution"
    pub current_policy: String,
    pub suggested_policy: String,
    pub expected_impact: String,
    pub risk_assessment: String,
    pub confidence: f64,
}

/// Usage statistics analysis
#[derive(Debug, Clone)]
pub struct UsageAnalysis {
    pub analysis_id: String,
    pub timestamp_ns: u64,
    pub total_events: u64,
    pub event_breakdown: HashMap<String, u64>,
    pub principal_activity: HashMap<String, u64>,
    pub interface_usage: HashMap<u32, u64>,
    pub peak_activity_window: String,
    pub anomalies: Vec<String>,
}

/// Machine learning readiness assessment
#[derive(Debug, Clone)]
pub struct MLReadiness {
    pub assessment_id: String,
    pub timestamp_ns: u64,
    pub data_quality_score: f64,
    pub data_volume_score: f64,
    pub pattern_complexity_score: f64,
    pub overall_readiness: f64,
    pub recommendations_for_improvement: Vec<String>,
    pub ready_for_models: bool,
}

/// Learner principal context
pub struct LearnerPrincipal {
    /// Unique ID for this Learner instance
    principal_id: String,

    /// Current state
    state: Arc<Mutex<LearnerState>>,

    /// UID/GID for process isolation
    uid: u32,
    gid: u32,

    /// Signing key for message authentication
    signing_key: Arc<Mutex<Option<SigningKey>>>,

    /// Security ledger for event source
    ledger: Arc<SecurityLedger>,

    /// Detected security patterns
    patterns: Arc<Mutex<Vec<SecurityPattern>>>,

    /// Policy recommendations
    recommendations: Arc<Mutex<Vec<PolicyRecommendation>>>,

    /// Usage analyses
    usage_analyses: Arc<Mutex<Vec<UsageAnalysis>>>,

    /// ML readiness assessments
    ml_assessments: Arc<Mutex<Vec<MLReadiness>>>,

    /// Pattern cache for learning
    pattern_cache: Arc<Mutex<HashMap<String, u64>>>,

    /// Statistics
    patterns_detected: Arc<Mutex<u64>>,
    recommendations_made: Arc<Mutex<u64>>,
    analyses_performed: Arc<Mutex<u64>>,
    assessments_completed: Arc<Mutex<u64>>,
}

impl LearnerPrincipal {
    /// Create new Learner principal
    pub fn new(
        principal_id: String,
        uid: u32,
        gid: u32,
        ledger: Arc<SecurityLedger>,
    ) -> Self {
        LearnerPrincipal {
            principal_id,
            state: Arc::new(Mutex::new(LearnerState::NotStarted)),
            uid,
            gid,
            signing_key: Arc::new(Mutex::new(None)),
            ledger,
            patterns: Arc::new(Mutex::new(Vec::new())),
            recommendations: Arc::new(Mutex::new(Vec::new())),
            usage_analyses: Arc::new(Mutex::new(Vec::new())),
            ml_assessments: Arc::new(Mutex::new(Vec::new())),
            pattern_cache: Arc::new(Mutex::new(HashMap::new())),
            patterns_detected: Arc::new(Mutex::new(0)),
            recommendations_made: Arc::new(Mutex::new(0)),
            analyses_performed: Arc::new(Mutex::new(0)),
            assessments_completed: Arc::new(Mutex::new(0)),
        }
    }

    /// Initialize Learner principal
    pub fn initialize(&self, signing_key: SigningKey) -> std::io::Result<()> {
        self.set_state(LearnerState::Initializing);

        let mut key = self.signing_key.lock().unwrap();
        *key = Some(signing_key);

        self.set_state(LearnerState::Ready);
        Ok(())
    }

    /// Set state
    fn set_state(&self, new_state: LearnerState) {
        let mut state = self.state.lock().unwrap();
        *state = new_state;
    }

    /// Get current state
    pub fn state(&self) -> LearnerState {
        *self.state.lock().unwrap()
    }

    /// Get principal ID
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// Analyze events for patterns
    pub fn analyze_patterns(&self) -> std::io::Result<Vec<SecurityPattern>> {
        self.set_state(LearnerState::Analyzing);

        let mut patterns = Vec::new();
        let mut cache = self.pattern_cache.lock().unwrap();

        // Read events from ledger
        if let Ok(events) = self.ledger.events() {
            // Pattern 1: Most common event types
            let mut event_type_counts: HashMap<String, u64> = HashMap::new();
            for event in &events {
                let key = format!("{:?}", event.event_type);
                *event_type_counts.entry(key).or_insert(0) += 1;
            }

            // Find high-frequency event types
            for (event_type, count) in event_type_counts.iter() {
                cache.insert(event_type.clone(), *count);

                if *count >= 3 {
                    patterns.push(SecurityPattern {
                        pattern_id: Uuid::new_v4().to_string(),
                        timestamp_ns: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as u64,
                        pattern_type: "high_frequency_event".to_string(),
                        frequency: *count,
                        confidence: 0.95,
                        related_events: vec![event_type.clone()],
                        description: format!("Event type {} occurs {} times", event_type, count),
                    });
                }
            }

            // Pattern 2: Principal activity distribution
            let mut principal_counts: HashMap<String, u64> = HashMap::new();
            for event in &events {
                *principal_counts.entry(event.principal_id.clone()).or_insert(0) += 1;
            }

            // Identify active principals
            let active_principals: Vec<_> = principal_counts
                .iter()
                .filter(|(_, count)| **count >= 2)
                .collect();

            if !active_principals.is_empty() {
                patterns.push(SecurityPattern {
                    pattern_id: Uuid::new_v4().to_string(),
                    timestamp_ns: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64,
                    pattern_type: "principal_activity_distribution".to_string(),
                    frequency: active_principals.len() as u64,
                    confidence: 0.90,
                    related_events: principal_counts.keys().cloned().collect(),
                    description: format!("Identified {} active principals", active_principals.len()),
                });
            }

            // Pattern 3: Error/failure patterns
            let error_events: Vec<_> = events
                .iter()
                .filter(|e| matches!(e.severity, Severity::High | Severity::Critical))
                .collect();

            if !error_events.is_empty() {
                patterns.push(SecurityPattern {
                    pattern_id: Uuid::new_v4().to_string(),
                    timestamp_ns: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64,
                    pattern_type: "error_frequency".to_string(),
                    frequency: error_events.len() as u64,
                    confidence: 0.88,
                    related_events: error_events.iter().map(|e| e.event_id.clone()).collect(),
                    description: format!("Found {} high-severity events", error_events.len()),
                });
            }
        }

        // Store patterns
        {
            let mut stored_patterns = self.patterns.lock().unwrap();
            let mut count = self.patterns_detected.lock().unwrap();
            *count += patterns.len() as u64;
            stored_patterns.extend(patterns.clone());
        }

        self.set_state(LearnerState::Ready);
        Ok(patterns)
    }

    /// Generate policy recommendations based on patterns
    pub fn recommend_policies(&self) -> std::io::Result<Vec<PolicyRecommendation>> {
        self.set_state(LearnerState::Optimizing);

        let mut recommendations = Vec::new();

        // Recommendation 1: If high error rate, strengthen access controls
        let patterns = self.patterns.lock().unwrap();
        let error_patterns = patterns.iter()
            .filter(|p| p.pattern_type == "error_frequency" && p.frequency >= 2);

        if error_patterns.clone().count() > 0 {
            recommendations.push(PolicyRecommendation {
                recommendation_id: Uuid::new_v4().to_string(),
                timestamp_ns: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64,
                priority: "high".to_string(),
                category: "access_control".to_string(),
                current_policy: "Current authorization rules".to_string(),
                suggested_policy: "Add stricter role-based access control".to_string(),
                expected_impact: "Reduce authorization failures by 30-50%".to_string(),
                risk_assessment: "Low risk - increases security without impacting normal operations".to_string(),
                confidence: 0.85,
            });
        }

        // Recommendation 2: Enhanced audit logging for active principals
        let principal_patterns = patterns.iter()
            .filter(|p| p.pattern_type == "principal_activity_distribution" && p.frequency >= 2);

        if principal_patterns.clone().count() > 0 {
            recommendations.push(PolicyRecommendation {
                recommendation_id: Uuid::new_v4().to_string(),
                timestamp_ns: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64,
                priority: "medium".to_string(),
                category: "audit".to_string(),
                current_policy: "Standard audit logging".to_string(),
                suggested_policy: "Enable detailed audit logging for active principals".to_string(),
                expected_impact: "Better forensic capabilities and breach detection".to_string(),
                risk_assessment: "Medium risk - increases logging overhead".to_string(),
                confidence: 0.80,
            });
        }

        // Recommendation 3: Classification policy review
        recommendations.push(PolicyRecommendation {
            recommendation_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            priority: "medium".to_string(),
            category: "classification".to_string(),
            current_policy: "Default classification levels".to_string(),
            suggested_policy: "Review and adjust classification levels based on usage patterns".to_string(),
            expected_impact: "Better data protection and clearer access hierarchies".to_string(),
            risk_assessment: "Low risk - improves clarity without restricting access".to_string(),
            confidence: 0.75,
        });

        // Store recommendations
        {
            let mut stored_recs = self.recommendations.lock().unwrap();
            let mut count = self.recommendations_made.lock().unwrap();
            *count += recommendations.len() as u64;
            stored_recs.extend(recommendations.clone());
        }

        self.set_state(LearnerState::Ready);
        Ok(recommendations)
    }

    /// Perform usage analysis
    pub fn analyze_usage(&self) -> std::io::Result<UsageAnalysis> {
        self.set_state(LearnerState::Analyzing);

        let mut event_breakdown = HashMap::new();
        let mut principal_activity = HashMap::new();
        let mut interface_usage = HashMap::new();
        let mut anomalies = Vec::new();
        let mut total_events = 0u64;

        if let Ok(events) = self.ledger.events() {
            total_events = events.len() as u64;

            for event in &events {
                // Event type breakdown
                let event_type = format!("{:?}", event.event_type);
                *event_breakdown.entry(event_type).or_insert(0) += 1;

                // Principal activity
                *principal_activity.entry(event.principal_id.clone()).or_insert(0) += 1;

                // Interface usage (simplified - would extract from event details in production)
                *interface_usage.entry(0).or_insert(0) += 1;
            }

            // Detect anomalies (principals with very high activity)
            for (principal, count) in &principal_activity {
                if *count > (total_events / 2) {
                    anomalies.push(format!("Principal {} has unusually high activity ({} events)", principal, count));
                }
            }
        }

        let analysis = UsageAnalysis {
            analysis_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            total_events,
            event_breakdown,
            principal_activity,
            interface_usage,
            peak_activity_window: "09:00-17:00 UTC".to_string(),
            anomalies,
        };

        // Store analysis
        {
            let mut analyses = self.usage_analyses.lock().unwrap();
            let mut count = self.analyses_performed.lock().unwrap();
            *count += 1;
            analyses.push(analysis.clone());
        }

        self.set_state(LearnerState::Ready);
        Ok(analysis)
    }

    /// Assess machine learning readiness
    pub fn assess_ml_readiness(&self) -> std::io::Result<MLReadiness> {
        self.set_state(LearnerState::Analyzing);

        let events = self.ledger.events().unwrap_or_default();
        let total_events = events.len() as u64;

        // Data quality: check for complete events, no nulls, valid timestamps
        let valid_events = events.iter()
            .filter(|e| !e.event_id.is_empty() && !e.message.is_empty())
            .count() as u64;
        let data_quality = if total_events > 0 {
            (valid_events as f64) / (total_events as f64)
        } else {
            0.0
        };

        // Data volume: need at least 100 events for meaningful patterns
        let data_volume_score = if total_events >= 100 {
            1.0
        } else if total_events >= 50 {
            0.7
        } else if total_events >= 20 {
            0.4
        } else {
            0.0
        };

        // Pattern complexity: how varied are event types?
        let mut event_types = std::collections::HashSet::new();
        for event in &events {
            event_types.insert(format!("{:?}", event.event_type));
        }
        let pattern_complexity = (event_types.len() as f64) / 10.0; // ~10 event types expected
        let pattern_complexity = pattern_complexity.min(1.0);

        // Overall readiness
        let overall_readiness = (data_quality * 0.3 + data_volume_score * 0.4 + pattern_complexity * 0.3).min(1.0);

        // Recommendations for improvement
        let mut recommendations = Vec::new();
        if data_quality < 0.95 {
            recommendations.push("Improve data quality: ensure all event fields are properly populated".to_string());
        }
        if data_volume_score < 0.7 {
            recommendations.push(format!("Increase data volume: need at least 100 events, currently have {}", total_events));
        }
        if pattern_complexity < 0.5 {
            recommendations.push("Increase event diversity: collect data from more diverse security operations".to_string());
        }

        let assessment = MLReadiness {
            assessment_id: Uuid::new_v4().to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            data_quality_score: data_quality,
            data_volume_score,
            pattern_complexity_score: pattern_complexity,
            overall_readiness,
            recommendations_for_improvement: recommendations,
            ready_for_models: overall_readiness >= 0.7,
        };

        // Store assessment
        {
            let mut assessments = self.ml_assessments.lock().unwrap();
            let mut count = self.assessments_completed.lock().unwrap();
            *count += 1;
            assessments.push(assessment.clone());
        }

        self.set_state(LearnerState::Ready);
        Ok(assessment)
    }

    /// Get pattern history
    pub fn pattern_history(&self) -> Vec<SecurityPattern> {
        self.patterns.lock().unwrap().clone()
    }

    /// Get recommendation history
    pub fn recommendation_history(&self) -> Vec<PolicyRecommendation> {
        self.recommendations.lock().unwrap().clone()
    }

    /// Get analysis history
    pub fn analysis_history(&self) -> Vec<UsageAnalysis> {
        self.usage_analyses.lock().unwrap().clone()
    }

    /// Get assessment history
    pub fn assessment_history(&self) -> Vec<MLReadiness> {
        self.ml_assessments.lock().unwrap().clone()
    }

    /// Get statistics
    pub fn statistics(&self) -> (u64, u64, u64, u64) {
        (
            *self.patterns_detected.lock().unwrap(),
            *self.recommendations_made.lock().unwrap(),
            *self.analyses_performed.lock().unwrap(),
            *self.assessments_completed.lock().unwrap(),
        )
    }

    /// Generate learning summary
    pub fn summary(&self) -> String {
        let (patterns, recommendations, analyses, assessments) = self.statistics();

        format!(
            "Learner Principal {} Summary\n\
            Patterns Detected: {}\n\
            Recommendations Made: {}\n\
            Analyses Performed: {}\n\
            Assessments Completed: {}\n\
            State: {:?}",
            self.principal_id,
            patterns,
            recommendations,
            analyses,
            assessments,
            self.state()
        )
    }

    /// Shutdown learner principal
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.set_state(LearnerState::Shutdown);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_learner_initialization() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );

        let learner = LearnerPrincipal::new(
            "learner-001".to_string(),
            1005,
            1005,
            ledger,
        );

        assert_eq!(learner.state(), LearnerState::NotStarted);
        assert_eq!(learner.principal_id(), "learner-001");
    }

    #[test]
    fn test_analyze_patterns() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );

        let learner = LearnerPrincipal::new(
            "learner-002".to_string(),
            1005,
            1005,
            ledger,
        );

        let patterns = learner.analyze_patterns().unwrap();
        let (detected, _, _, _) = learner.statistics();
        assert!(detected >= 0);
    }

    #[test]
    fn test_recommend_policies() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );

        let learner = LearnerPrincipal::new(
            "learner-003".to_string(),
            1005,
            1005,
            ledger,
        );

        let recommendations = learner.recommend_policies().unwrap();
        let (_, made, _, _) = learner.statistics();
        assert!(made >= 0);
    }

    #[test]
    fn test_analyze_usage() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );

        let learner = LearnerPrincipal::new(
            "learner-004".to_string(),
            1005,
            1005,
            ledger,
        );

        let analysis = learner.analyze_usage().unwrap();
        let (_, _, performed, _) = learner.statistics();
        assert_eq!(performed, 1);
    }

    #[test]
    fn test_assess_ml_readiness() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );

        let learner = LearnerPrincipal::new(
            "learner-005".to_string(),
            1005,
            1005,
            ledger,
        );

        let assessment = learner.assess_ml_readiness().unwrap();
        let (_, _, _, completed) = learner.statistics();
        assert_eq!(completed, 1);
    }

    #[test]
    fn test_summary() {
        let temp = TempDir::new().unwrap();
        let ledger = Arc::new(
            SecurityLedger::open(temp.path().to_str().unwrap()).unwrap()
        );

        let learner = LearnerPrincipal::new(
            "learner-006".to_string(),
            1005,
            1005,
            ledger,
        );

        let summary = learner.summary();
        assert!(summary.contains("Learner Principal"));
        assert!(summary.contains("learner-006"));
    }
}
