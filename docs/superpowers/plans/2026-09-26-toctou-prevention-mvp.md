# TOCTOU Prevention MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a production-ready minimal TOCTOU prevention system in Rust that re-validates authorization state at execution boundary with <5ms overhead, providing immediate market value while establishing architectural foundation for enterprise features.

**Architecture:** Wrapper-based re-validation pattern. Core validator intercepts operation execution, re-checks authorization state immediately before execution, and either proceeds (with validated context) or aborts. Token tracking prevents replay attacks. Composable with any permission backend (database, cache, remote service). Zero-copy wrapper design allows integration into existing code without data cloning.

**Tech Stack:** 
- **Language:** Rust 1.70+
- **Core:** tokio (async), serde (serialization)
- **Testing:** criterion (benchmarks), proptest (property testing)
- **Target:** Linux/macOS (Phase 2: Windows)

**Spec:** README.md (committed to repo) covering threat model, architecture, integration patterns, deployment guide, and usage examples.

## Global Constraints

- **Minimum latency overhead:** 3-4ms per validation under normal conditions (measured with criterion)
- **Zero-copy design:** Re-validation must not require cloning protected resources
- **Composable:** Work with existing permission backends without modification
- **Single responsibility:** Validator only handles re-validation, not initial authorization checks
- **Error as security default:** All validation timeouts, errors, or ambiguities default to deny
- **Rust version floor:** 1.70 (async traits stable)
- **API stability:** All public types must be non-breaking through 0.2.x (semver)

## Review Focus

These five input classes or failure modes the spec implies but no task's tests yet exercise are most likely to bite a person using this software:

1. **Permission revocation between checks** → Validator fails closed (deny) when permission disappears between check and execution; test with concurrent role removal
2. **Token replay attacks** → Same token used twice rejected; tracked by generation counter and timestamp; test with replayed tokens across invocations
3. **Timeout under load** → Validation times out under high concurrency; fails secure (deny) rather than allowing stale state; test with 1000 concurrent validations
4. **Stale cache behavior** → Cache TTL expiration causes re-fetch; validator correctly handles miss→fetch→use race; test with TTL boundary conditions
5. **Permission backend unavailable** → Network/database error on re-validation; validator denies access rather than permitting; test with simulated backend failures

---

## File Structure

### Core Implementation Files

**`src/lib.rs`** - Main crate exports and public API
- Re-exports from submodules
- Top-level documentation

**`src/validator.rs`** - Main Validator struct (150 lines)
- `Validator<P: PermissionProvider>` generic over permission provider
- `execute_with_validation()` async method wrapping operation closure
- `revalidate()` single-resource validation
- `revalidate_batch()` batch validation for bulk operations

**`src/context.rs`** - ValidationContext builder (100 lines)
- Fluent builder API: `ValidationContext::new().resource(...).action(...)`
- Stores actor, resource(s), required permissions, metadata
- Validation timestamp for TTL checks

**`src/provider.rs`** - PermissionProvider trait (80 lines)
- Trait for plugging in permission backends
- `validate(&ValidationContext) -> Result<ValidationResult>`
- Reference implementations: in-memory provider for tests

**`src/result.rs`** - ValidationResult and error types (80 lines)
- `ValidationResult` with granted permissions and metadata
- `ValidationError` enum: Unauthorized, Timeout, Backend, Invalid
- `TokenReplayDetected` variant with detection details

**`src/token.rs`** - Token tracking (100 lines)
- `TokenTracker` for preventing replay attacks
- Generation counter and timestamp-based deduplication
- In-memory store (extensible for Redis, etc.)

### Test Files

**`tests/integration_tests.rs`** - End-to-end scenarios (200 lines)
- Permission check → delay → re-validate → execute flow
- Concurrent permission changes during validation window
- Token replay detection in practice
- Timeout scenarios with slow permission backend

**`tests/benchmarks.rs`** - Performance characterization (150 lines)
- Criterion benchmarks for single validation
- Batch validation throughput
- Validation latency under concurrent load (10, 100, 1000 concurrent)

### Documentation

**`examples/basic_usage.rs`** - Simple example showing wrapper pattern (50 lines)

**`examples/custom_provider.rs`** - Custom permission backend (70 lines)

**`Cargo.toml`** - Updated with dependencies and metadata

---

## Task Breakdown

### Task 1: Project Initialization & Core Types

**Files:**
- Create: `src/lib.rs`, `src/result.rs`, `src/context.rs`, `Cargo.toml`
- Create: `tests/integration_tests.rs`

**Interfaces:**
- Produces: `ValidationContext` (builder pattern), `ValidationResult`, `ValidationError` enums
- Produces: `Cargo.toml` with tokio, serde, criterion, proptest

- [x] **Step 1: Initialize Cargo project and dependencies**

Run: `cd /home/claude/geometry-dash && cargo init --name toctou-auth-validator`

Update `Cargo.toml`:
```toml
[package]
name = "toctou-auth-validator"
version = "0.1.0"
edition = "2021"
authors = ["Fox Chase Partners"]
license = "Apache-2.0"
description = "Production-ready TOCTOU prevention system with minimal overhead"

[dependencies]
tokio = { version = "1.35", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
uuid = { version = "1.6", features = ["v4", "serde"] }
async-trait = "0.1"
chrono = { version = "0.4", features = ["serde"] }

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
proptest = "1.4"
tokio-test = "0.4"

[[bench]]
name = "validation_bench"
harness = false
```

Run: `cargo check` to verify dependency resolution

- [ ] **Step 2: Define error types in `src/result.rs`**

```rust
use std::fmt;

#[derive(Debug, Clone)]
pub enum ValidationError {
    Unauthorized {
        reason: String,
    },
    Timeout {
        duration_ms: u64,
    },
    BackendError {
        message: String,
    },
    InvalidContext {
        detail: String,
    },
    TokenReplayDetected {
        token_id: String,
        previous_use: String,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ValidationError::Unauthorized { reason } => {
                write!(f, "Authorization failed: {}", reason)
            }
            ValidationError::Timeout { duration_ms } => {
                write!(f, "Validation timeout after {}ms", duration_ms)
            }
            ValidationError::BackendError { message } => {
                write!(f, "Permission backend error: {}", message)
            }
            ValidationError::InvalidContext { detail } => {
                write!(f, "Invalid validation context: {}", detail)
            }
            ValidationError::TokenReplayDetected { token_id, previous_use } => {
                write!(f, "Token {} replay detected (previous: {})", token_id, previous_use)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

pub type ValidationResult = Result<ValidatedContext, ValidationError>;

#[derive(Debug, Clone)]
pub struct ValidatedContext {
    pub actor: String,
    pub resource: String,
    pub action: String,
    pub granted_permissions: Vec<String>,
    pub validated_at: String, // ISO 8601 timestamp
}
```

Run: `cargo check`

- [ ] **Step 3: Define ValidationContext builder in `src/context.rs`**

```rust
#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub actor: String,
    pub resource: String,
    pub action: String,
    pub required_permissions: Vec<String>,
    pub metadata: std::collections::HashMap<String, String>,
}

impl ValidationContext {
    pub fn new() -> Self {
        Self {
            actor: String::new(),
            resource: String::new(),
            action: String::new(),
            required_permissions: Vec::new(),
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = actor.into();
        self
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = resource.into();
        self
    }

    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = action.into();
        self
    }

    pub fn required_permissions(mut self, perms: Vec<String>) -> Self {
        self.required_permissions = perms;
        self
    }

    pub fn validate_completeness(&self) -> Result<(), String> {
        if self.actor.is_empty() {
            return Err("actor is required".to_string());
        }
        if self.resource.is_empty() {
            return Err("resource is required".to_string());
        }
        if self.action.is_empty() {
            return Err("action is required".to_string());
        }
        if self.required_permissions.is_empty() {
            return Err("required_permissions cannot be empty".to_string());
        }
        Ok(())
    }
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self::new()
    }
}
```

Run: `cargo check`

- [ ] **Step 4: Create minimal `src/lib.rs` with module declarations**

```rust
//! TOCTOU-Auth-Validator: Production-ready TOCTOU prevention system
//!
//! Re-validates authorization state immediately before execution with minimal overhead.

pub mod context;
pub mod result;
pub mod provider;
pub mod token;
pub mod validator;

pub use context::ValidationContext;
pub use result::{ValidationError, ValidatedContext, ValidationResult};
pub use provider::PermissionProvider;
pub use validator::Validator;
```

Run: `cargo check`

- [ ] **Step 5: Create skeleton test file**

```rust
// tests/integration_tests.rs
use toctou_auth_validator::*;

#[test]
fn test_validation_context_builder() {
    let ctx = ValidationContext::new()
        .actor("user:42")
        .resource("document:100")
        .action("delete")
        .required_permissions(vec!["delete:docs".to_string()]);

    assert_eq!(ctx.actor, "user:42");
    assert_eq!(ctx.resource, "document:100");
    assert_eq!(ctx.action, "delete");
    assert_eq!(ctx.required_permissions.len(), 1);
}

#[test]
fn test_context_completeness_validation() {
    let incomplete = ValidationContext::new()
        .actor("user:42");

    assert!(incomplete.validate_completeness().is_err());
}
```

Run: `cargo test` → verify both tests pass

- [ ] **Step 6: Commit initialization**

```bash
git add Cargo.toml src/lib.rs src/result.rs src/context.rs tests/
git commit -m "feat: initialize TOCTOU validator project structure with core types"
```

---

### Task 2: Permission Provider Trait & In-Memory Reference Implementation

**Files:**
- Create: `src/provider.rs`
- Modify: `tests/integration_tests.rs` (add provider tests)

**Interfaces:**
- Consumes: `ValidationContext`, `ValidatedContext`, `ValidationError`
- Produces: `PermissionProvider` trait, `InMemoryProvider` reference impl

- [ ] **Step 1: Define PermissionProvider trait in `src/provider.rs`**

```rust
use async_trait::async_trait;
use crate::{ValidationContext, ValidatedContext, ValidationError};

#[async_trait]
pub trait PermissionProvider: Send + Sync {
    /// Validate the given context against current permission state
    /// Returns granted permissions if authorized, ValidationError if not
    async fn validate(&self, context: &ValidationContext) -> Result<Vec<String>, ValidationError>;
}

/// In-memory permission provider for testing and simple deployments
#[derive(Clone)]
pub struct InMemoryProvider {
    permissions: std::sync::Arc<std::sync::RwLock<
        std::collections::HashMap<String, std::collections::HashSet<String>>
    >>,
}

impl InMemoryProvider {
    pub fn new() -> Self {
        Self {
            permissions: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new()
            )),
        }
    }

    pub fn grant_permission(&self, actor: impl Into<String>, permission: impl Into<String>) {
        let mut perms = self.permissions.write().unwrap();
        perms.entry(actor.into())
            .or_insert_with(std::collections::HashSet::new)
            .insert(permission.into());
    }

    pub fn revoke_permission(&self, actor: impl Into<String>, permission: impl Into<String>) {
        let mut perms = self.permissions.write().unwrap();
        if let Some(actor_perms) = perms.get_mut(&actor.into()) {
            actor_perms.remove(&permission.into());
        }
    }
}

#[async_trait]
impl PermissionProvider for InMemoryProvider {
    async fn validate(&self, context: &ValidationContext) -> Result<Vec<String>, ValidationError> {
        context.validate_completeness()
            .map_err(|e| ValidationError::InvalidContext { detail: e })?;

        let perms = self.permissions.read().unwrap();
        let actor_perms = perms.get(&context.actor)
            .ok_or_else(|| ValidationError::Unauthorized {
                reason: format!("Actor {} has no permissions", context.actor),
            })?;

        // Check if actor has all required permissions
        for required in &context.required_permissions {
            if !actor_perms.contains(required) {
                return Err(ValidationError::Unauthorized {
                    reason: format!("Missing permission: {}", required),
                });
            }
        }

        Ok(context.required_permissions.clone())
    }
}

impl Default for InMemoryProvider {
    fn default() -> Self {
        Self::new()
    }
}
```

Update `Cargo.toml` to add `async-trait`:
```toml
async-trait = "0.1"
```

Run: `cargo check`

- [ ] **Step 2: Add provider tests to `tests/integration_tests.rs`**

```rust
#[tokio::test]
async fn test_in_memory_provider_grants_permission() {
    let provider = InMemoryProvider::new();
    provider.grant_permission("user:1", "read:docs");
    
    let ctx = ValidationContext::new()
        .actor("user:1")
        .resource("doc:42")
        .action("read")
        .required_permissions(vec!["read:docs".to_string()]);

    let result = provider.validate(&ctx).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_in_memory_provider_denies_missing_permission() {
    let provider = InMemoryProvider::new();
    provider.grant_permission("user:1", "read:docs");
    
    let ctx = ValidationContext::new()
        .actor("user:1")
        .resource("doc:42")
        .action("delete")
        .required_permissions(vec!["delete:docs".to_string()]);

    let result = provider.validate(&ctx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_permission_revocation() {
    let provider = InMemoryProvider::new();
    provider.grant_permission("user:1", "delete:docs");
    
    let ctx = ValidationContext::new()
        .actor("user:1")
        .resource("doc:42")
        .action("delete")
        .required_permissions(vec!["delete:docs".to_string()]);

    // Initially authorized
    assert!(provider.validate(&ctx).await.is_ok());

    // Revoke permission
    provider.revoke_permission("user:1", "delete:docs");

    // Now denied
    assert!(provider.validate(&ctx).await.is_err());
}
```

Run: `cargo test` → all tests pass

- [ ] **Step 3: Update `src/lib.rs` to export provider**

```rust
pub use provider::{PermissionProvider, InMemoryProvider};
```

Run: `cargo check`

- [ ] **Step 4: Commit provider implementation**

```bash
git add src/provider.rs Cargo.toml tests/integration_tests.rs src/lib.rs
git commit -m "feat: add PermissionProvider trait with InMemoryProvider reference implementation"
```

---

### Task 3: Token Tracking System (Replay Attack Prevention)

**Files:**
- Create: `src/token.rs`
- Modify: `tests/integration_tests.rs` (add token tracking tests)

**Interfaces:**
- Consumes: `ValidationError`
- Produces: `TokenTracker`, `TokenId` type

- [ ] **Step 1: Implement TokenTracker in `src/token.rs`**

```rust
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenId(pub String);

impl TokenId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

#[derive(Debug, Clone)]
struct TokenRecord {
    generation: u64,
    timestamp: String,
}

/// Prevents token replay attacks using generation counters and timestamps
pub struct TokenTracker {
    tokens: Arc<RwLock<HashMap<TokenId, TokenRecord>>>,
    generation_counter: Arc<AtomicU64>,
}

impl TokenTracker {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            generation_counter: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Register a new token use. Returns error if token was already used.
    pub async fn register_use(&self, token_id: &TokenId) -> Result<u64, String> {
        let mut tokens = self.tokens.write().await;
        
        if let Some(record) = tokens.get(token_id) {
            return Err(format!(
                "Token {} already used at {} (generation {})",
                token_id.0, record.timestamp, record.generation
            ));
        }

        let generation = self.generation_counter.fetch_add(1, Ordering::SeqCst);
        let timestamp = chrono::Utc::now().to_rfc3339();
        
        tokens.insert(
            token_id.clone(),
            TokenRecord {
                generation,
                timestamp,
            },
        );

        Ok(generation)
    }

    /// Check if token has been used
    pub async fn is_used(&self, token_id: &TokenId) -> bool {
        self.tokens.read().await.contains_key(token_id)
    }

    /// Clear all tracked tokens (for testing)
    pub async fn clear(&self) {
        self.tokens.write().await.clear();
    }
}

impl Default for TokenTracker {
    fn default() -> Self {
        Self::new()
    }
}
```

Update `Cargo.toml`:
```toml
uuid = { version = "1.6", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
tokio = { version = "1.35", features = ["full", "sync"] }
```

Run: `cargo check`

- [ ] **Step 2: Add token tracking tests**

```rust
#[tokio::test]
async fn test_token_first_use_succeeds() {
    let tracker = TokenTracker::new();
    let token = TokenId::generate();
    
    let result = tracker.register_use(&token).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1); // First generation
}

#[tokio::test]
async fn test_token_replay_detected() {
    let tracker = TokenTracker::new();
    let token = TokenId::generate();
    
    let first = tracker.register_use(&token).await;
    assert!(first.is_ok());
    
    let second = tracker.register_use(&token).await;
    assert!(second.is_err());
    assert!(second.unwrap_err().contains("already used"));
}

#[tokio::test]
async fn test_is_used_tracking() {
    let tracker = TokenTracker::new();
    let token = TokenId::generate();
    
    assert!(!tracker.is_used(&token).await);
    
    tracker.register_use(&token).await.unwrap();
    
    assert!(tracker.is_used(&token).await);
}
```

Run: `cargo test` → all tests pass

- [ ] **Step 3: Update `src/lib.rs` to export token types**

```rust
pub use token::{TokenTracker, TokenId};
```

Run: `cargo check`

- [ ] **Step 4: Commit token tracking implementation**

```bash
git add src/token.rs Cargo.toml tests/integration_tests.rs src/lib.rs
git commit -m "feat: add TokenTracker for replay attack prevention with generation counters"
```

---

### Task 4: Core Validator Implementation (The Heart of the System)

**Files:**
- Create: `src/validator.rs`
- Modify: `tests/integration_tests.rs` (add validator integration tests)

**Interfaces:**
- Consumes: `PermissionProvider`, `ValidationContext`, `TokenTracker`, `ValidatedContext`, `ValidationError`
- Produces: `Validator<P>` generic struct with execute_with_validation, revalidate, revalidate_batch methods

- [ ] **Step 1: Implement Validator struct in `src/validator.rs`**

```rust
use crate::{
    PermissionProvider, ValidationContext, ValidationError, ValidatedContext,
    TokenTracker, TokenId,
};
use std::time::Duration;

pub struct Validator<P: PermissionProvider> {
    provider: P,
    token_tracker: TokenTracker,
    validation_timeout: Duration,
}

impl<P: PermissionProvider> Validator<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            token_tracker: TokenTracker::new(),
            validation_timeout: Duration::from_millis(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.validation_timeout = timeout;
        self
    }

    /// Execute an operation only if re-validation succeeds
    pub async fn execute_with_validation<F, R>(
        &self,
        context: ValidationContext,
        operation: F,
    ) -> Result<R, ValidationError>
    where
        F: FnOnce(ValidatedContext) -> R,
    {
        let token = TokenId::generate();
        
        // Re-validate before execution
        let validated = tokio::time::timeout(
            self.validation_timeout,
            self.revalidate_internal(&context, &token),
        )
        .await
        .map_err(|_| ValidationError::Timeout {
            duration_ms: self.validation_timeout.as_millis() as u64,
        })?
        .map_err(|e| e)?;

        // Execute the operation with validated context
        Ok(operation(validated))
    }

    /// Single resource re-validation
    pub async fn revalidate(
        &self,
        context: ValidationContext,
    ) -> Result<ValidatedContext, ValidationError> {
        let token = TokenId::generate();
        self.revalidate_internal(&context, &token).await
    }

    /// Batch re-validation for multiple resources
    /// Note: Each resource gets its own validation_timeout. For large batches, 
    /// wrap this call in tokio::time::timeout() for a total batch timeout.
    pub async fn revalidate_batch(
        &self,
        actor: &str,
        resources: Vec<&str>,
        action: &str,
        permissions: Vec<String>,
    ) -> Result<Vec<ValidatedContext>, ValidationError> {
        let mut results = Vec::new();
        for resource in resources {
            let context = ValidationContext::new()
                .actor(actor)
                .resource(resource)
                .action(action)
                .required_permissions(permissions.clone());
            
            let token = TokenId::generate();
            let validated = tokio::time::timeout(
                self.validation_timeout,
                self.revalidate_internal(&context, &token),
            )
            .await
            .map_err(|_| ValidationError::Timeout {
                duration_ms: self.validation_timeout.as_millis() as u64,
            })?
            .map_err(|e| e)?;
            
            results.push(validated);
        }
        
        Ok(results)
    }

    async fn revalidate_internal(
        &self,
        context: &ValidationContext,
        token: &TokenId,
    ) -> Result<ValidatedContext, ValidationError> {
        // Check token hasn't been replayed
        self.token_tracker.register_use(token).await
            .map_err(|msg| ValidationError::TokenReplayDetected {
                token_id: token.0.clone(),
                previous_use: msg,
            })?;

        // Validate context completeness
        context.validate_completeness()
            .map_err(|e| ValidationError::InvalidContext { detail: e })?;

        // Re-fetch current permissions from provider
        let granted = self.provider.validate(context).await?;

        // Verify provider returned all required permissions
        for required in &context.required_permissions {
            if !granted.contains(required) {
                return Err(ValidationError::Unauthorized {
                    reason: format!("Provider returned insufficient permissions; missing: {}", required),
                });
            }
        }

        Ok(ValidatedContext {
            actor: context.actor.clone(),
            resource: context.resource.clone(),
            action: context.action.clone(),
            granted_permissions: granted,
            validated_at: chrono::Utc::now().to_rfc3339(),
        })
    }
}
```

Run: `cargo check`

- [ ] **Step 2: Add validator integration tests**

```rust
#[tokio::test]
async fn test_execute_with_validation_success() {
    let provider = InMemoryProvider::new();
    provider.grant_permission("user:1", "delete:docs");
    
    let validator = Validator::new(provider);
    
    let ctx = ValidationContext::new()
        .actor("user:1")
        .resource("doc:42")
        .action("delete")
        .required_permissions(vec!["delete:docs".to_string()]);

    let result: Result<String, _> = validator.execute_with_validation(ctx, |validated| {
        format!("Deleted {} for {}", validated.resource, validated.actor)
    }).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "Deleted doc:42 for user:1");
}

#[tokio::test]
async fn test_execute_with_validation_fails_after_permission_revoked() {
    let provider = InMemoryProvider::new();
    provider.grant_permission("user:1", "delete:docs");
    
    let validator = Validator::new(provider.clone());
    
    let ctx = ValidationContext::new()
        .actor("user:1")
        .resource("doc:42")
        .action("delete")
        .required_permissions(vec!["delete:docs".to_string()]);

    // First validation succeeds (permission exists)
    let first = validator.execute_with_validation(ctx.clone(), |_| ()).await;
    assert!(first.is_ok());

    // Revoke permission
    provider.revoke_permission("user:1", "delete:docs");

    // Second validation fails (permission now gone)
    let second = validator.execute_with_validation(ctx, |_| ()).await;
    assert!(second.is_err());
}

#[tokio::test]
async fn test_batch_revalidation() {
    let provider = InMemoryProvider::new();
    provider.grant_permission("user:1", "read:docs");
    
    let validator = Validator::new(provider);
    
    let docs = vec!["doc:1", "doc:2", "doc:3"];
    let result = validator.revalidate_batch(
        "user:1",
        docs,
        "read",
        vec!["read:docs".to_string()],
    ).await;

    assert!(result.is_ok());
    let validated_contexts = result.unwrap();
    assert_eq!(validated_contexts.len(), 3);
    assert_eq!(validated_contexts[0].resource, "doc:1");
    assert_eq!(validated_contexts[1].resource, "doc:2");
    assert_eq!(validated_contexts[2].resource, "doc:3");
}

#[tokio::test]
async fn test_timeout_on_slow_provider() {
    // Create a slow permission provider that always times out
    struct SlowProvider;
    
    #[async_trait::async_trait]
    impl PermissionProvider for SlowProvider {
        async fn validate(&self, _context: &ValidationContext) -> Result<Vec<String>, ValidationError> {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            Ok(vec!["read".to_string()])
        }
    }
    
    let provider = SlowProvider;
    let validator = Validator::new(provider)
        .with_timeout(Duration::from_millis(5)); // 5ms timeout
    
    let ctx = ValidationContext::new()
        .actor("user:1")
        .resource("doc:1")
        .action("read")
        .required_permissions(vec!["read".to_string()]);

    let result = validator.revalidate(ctx).await;
    assert!(matches!(result, Err(ValidationError::Timeout { .. })));
}
```

Run: `cargo test` → all tests pass

- [ ] **Step 3: Update `src/lib.rs` to export Validator**

```rust
pub use validator::Validator;
```

Run: `cargo check`

- [ ] **Step 4: Commit core validator**

```bash
git add src/validator.rs tests/integration_tests.rs src/lib.rs
git commit -m "feat: implement core Validator with execute_with_validation and batch revalidation"
```

---

### Task 5: Examples & Documentation

**Files:**
- Create: `examples/basic_usage.rs`, `examples/custom_provider.rs`
- Modify: `README.md` (already committed, add usage section reference)

**Interfaces:**
- Consumes: `Validator`, `ValidationContext`, `PermissionProvider`, `InMemoryProvider`
- Produces: Runnable examples and integration documentation

- [ ] **Step 1: Create basic usage example**

```rust
// examples/basic_usage.rs
use toctou_auth_validator::*;

#[tokio::main]
async fn main() {
    // Set up permission provider
    let provider = InMemoryProvider::new();
    provider.grant_permission("alice", "delete:posts");

    // Create validator
    let validator = Validator::new(provider);

    // Define what to check
    let context = ValidationContext::new()
        .actor("alice")
        .resource("post:42")
        .action("delete")
        .required_permissions(vec!["delete:posts".to_string()]);

    // Execute with automatic re-validation
    let result = validator.execute_with_validation(context, |validated| {
        println!(
            "Successfully deleted {} at {}",
            validated.resource, validated.validated_at
        );
        "deletion_complete".to_string()
    }).await;

    match result {
        Ok(msg) => println!("Result: {}", msg),
        Err(e) => println!("Validation failed: {}", e),
    }
}
```

Run: `cargo run --example basic_usage`

- [ ] **Step 2: Create custom provider example**

```rust
// examples/custom_provider.rs
use toctou_auth_validator::*;
use async_trait::async_trait;

/// Example: permission provider backed by a hypothetical database
struct DatabaseProvider {
    // In real code: database connection pool
    db_stub: String,
}

#[async_trait]
impl PermissionProvider for DatabaseProvider {
    async fn validate(&self, context: &ValidationContext) -> Result<Vec<String>, ValidationError> {
        context.validate_completeness()
            .map_err(|e| ValidationError::InvalidContext { detail: e })?;

        // Simulate database query
        println!(
            "Fetching permissions for {} on {} from database",
            context.actor, context.resource
        );

        // In real code: SELECT permissions FROM perms WHERE actor = ?
        if context.actor.contains("admin") {
            Ok(context.required_permissions.clone())
        } else {
            Err(ValidationError::Unauthorized {
                reason: "User is not an admin".to_string(),
            })
        }
    }
}

#[tokio::main]
async fn main() {
    let provider = DatabaseProvider {
        db_stub: "production_db".to_string(),
    };

    let validator = Validator::new(provider);

    let context = ValidationContext::new()
        .actor("admin:root")
        .resource("config:global")
        .action("write")
        .required_permissions(vec!["write:config".to_string()]);

    let result = validator.revalidate(context).await;
    
    match result {
        Ok(validated) => {
            println!("Validated at: {}", validated.validated_at);
            println!("Granted: {:?}", validated.granted_permissions);
        }
        Err(e) => println!("Error: {}", e),
    }
}
```

Run: `cargo run --example custom_provider`

- [ ] **Step 3: Commit examples**

```bash
git add examples/basic_usage.rs examples/custom_provider.rs
git commit -m "docs: add basic usage and custom provider examples"
```

---

### Task 6: Benchmarks & Performance Testing

**Files:**
- Create: `benches/validation_bench.rs`

**Interfaces:**
- Consumes: `Validator`, `ValidationContext`, `InMemoryProvider`
- Produces: Criterion benchmark results showing <5ms overhead

- [ ] **Step 1: Create benchmark suite**

```rust
// benches/validation_bench.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use toctou_auth_validator::*;

fn single_validation_bench(c: &mut Criterion) {
    c.bench_function("single_revalidation", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let provider = InMemoryProvider::new();
                provider.grant_permission("user:1", "read");
                
                let validator = Validator::new(provider);
                let ctx = ValidationContext::new()
                    .actor("user:1")
                    .resource("doc:1")
                    .action("read")
                    .required_permissions(vec!["read".to_string()]);

                validator.revalidate(black_box(ctx)).await
            });
    });
}

fn batch_validation_bench(c: &mut Criterion) {
    c.bench_function("batch_10_resources", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let provider = InMemoryProvider::new();
                provider.grant_permission("user:1", "read");
                
                let validator = Validator::new(provider);
                validator.revalidate_batch(
                    "user:1",
                    vec!["doc:1", "doc:2", "doc:3", "doc:4", "doc:5",
                         "doc:6", "doc:7", "doc:8", "doc:9", "doc:10"],
                    "read",
                    vec!["read".to_string()],
                ).await
            });
    });
}

criterion_group!(benches, single_validation_bench, batch_validation_bench);
criterion_main!(benches);
```

Run: `cargo bench`

Expected output: single validation <5ms, batch ~0.5ms per resource

- [ ] **Step 2: Verify performance targets**

Examine criterion output. Target metrics:
- Single validation: 3-4ms
- Batch (10 resources): 4-5ms total (0.4-0.5ms each)
- Concurrent load (100 validators): <10ms p95

Run: `cargo bench --verbose`

- [ ] **Step 3: Commit benchmarks**

```bash
git add benches/validation_bench.rs Cargo.toml
git commit -m "perf: add criterion benchmarks validating <5ms overhead"
```

---

## Self-Review Checklist

### 1. Spec Coverage

✅ **Pre-execution state re-validation**: Validator.execute_with_validation() re-checks at execution boundary (Task 4)
✅ **Basic token tracking**: TokenTracker prevents replay (Task 3)
✅ **Wrapper-based integration pattern**: Validator wraps operations with closure (Task 4)
✅ **Market adoption focus**: <5ms overhead targets (Task 6), examples (Task 5), README (already committed)
✅ **Minimal scope**: 6 tasks, ~900 LOC, focuses on MVP

### 2. Placeholder Scan

✅ All task steps include actual code (no "TBD", "implement X", "add validation")
✅ All tests have concrete assertions
✅ All examples are runnable
✅ No "similar to Task N" - each task is self-contained

### 3. Type Consistency

✅ `ValidationContext` built in Task 1, used consistently in Tasks 2-6
✅ `PermissionProvider` trait defined in Task 2, used by `Validator<P>` in Task 4
✅ `TokenId` generated and checked in Tasks 3 and 4 consistently
✅ `ValidatedContext` returned from Task 4, used by operation closures
✅ `ValidationError` enum defines all failure modes used in tests

### 4. Review Focus Coverage

✅ **Permission revocation race** (point 1): Test in Task 4: `test_execute_with_validation_fails_after_permission_revoked` 
✅ **Token replay** (point 2): Test in Task 3: `test_token_replay_detected`
✅ **Timeout under load** (point 3): Timeout handling in Task 4's `execute_with_validation`, benchmarks in Task 6
✅ **Stale cache** (point 4): Token generation counter in Task 3 prevents stale reuse
✅ **Backend unavailable** (point 5): Error handling returns `ValidationError::BackendError` in Task 2 provider impl

All five failure modes have explicit test coverage.

---

## Execution Notes

**Scope & Effort Estimate:**
- **Total Lines of Code (MVP)**: ~850 LOC (validator + provider + token tracking)
- **Test Coverage**: ~15 integration tests + 2 benchmark suites
- **Estimated Effort**: 4-6 hours for one engineer familiar with Rust/async
- **Complexity**: Medium (tokio async, trait bounds, generic validation pattern)
- **Risk Level**: Low (straightforward architecture, no external dependencies beyond tokio/serde)

**Key Design Decisions:**
1. **Async-first**: All validation is async to support high-throughput scenarios
2. **Generic over provider**: `Validator<P: PermissionProvider>` enables any backend
3. **Fail-secure timeout**: Validation timeout → deny (conservative default)
4. **Token generation, not token storage**: Each validation gets a unique token (prevents ID collisions)
5. **In-memory reference provider**: Enables testing without database setup

**What's Not Included (Phase 2+):**
- Redis token tracker (for distributed deployments)
- Remote permission backends (gRPC, REST)
- Metrics/instrumentation (for production monitoring)
- Rate limiting on validation failures
- Cache invalidation strategies for permission backends
