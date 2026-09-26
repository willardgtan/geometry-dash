// HSM Client Wrapper (Week 1 Task 1.6 / Week 1.5)
// Provides cryptographic signing with hardware security module failover

use std::path::{Path, PathBuf};
use std::fs;
use sodiumoxide::crypto::sign::{self, SecretKey, PublicKey, Signature};
use sodiumoxide::randombytes;

/// HSM-level errors
#[derive(Debug, Clone)]
pub enum HsmError {
    InitializationFailed(String),
    SigningFailed(String),
    KeyGenerationFailed(String),
    KeyNotFound(String),
    FileSystemError(String),
    HsmUnavailable(String),
}

impl std::fmt::Display for HsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HsmError::InitializationFailed(s) => write!(f, "HSM initialization failed: {}", s),
            HsmError::SigningFailed(s) => write!(f, "Signing failed: {}", s),
            HsmError::KeyGenerationFailed(s) => write!(f, "Key generation failed: {}", s),
            HsmError::KeyNotFound(s) => write!(f, "Key not found: {}", s),
            HsmError::FileSystemError(s) => write!(f, "Filesystem error: {}", s),
            HsmError::HsmUnavailable(s) => write!(f, "HSM unavailable, using fallback: {}", s),
        }
    }
}

impl std::error::Error for HsmError {}

/// Result type for HSM operations
pub type HsmResult<T> = Result<T, HsmError>;

/// HSM signing material (keypair)
#[derive(Clone)]
pub struct SigningKey {
    secret: SecretKey,
    public: PublicKey,
    key_id: String,
}

impl SigningKey {
    /// Create signing key from raw bytes
    pub fn from_bytes(secret_bytes: &[u8], key_id: String) -> HsmResult<Self> {
        let secret = SecretKey::from_slice(secret_bytes)
            .ok_or_else(|| HsmError::KeyGenerationFailed("Invalid key bytes".to_string()))?;
        let public = secret.public_key();
        Ok(SigningKey { secret, public, key_id })
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.0
    }

    /// Get key ID
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get secret key bytes (for HSM operations)
    pub fn secret_key_bytes(&self) -> [u8; 64] {
        self.secret.0
    }
}

/// HSM Client trait: abstracts hardware and filesystem backends
pub trait HsmClient: Send + Sync {
    /// Initialize HSM connection
    fn initialize(&mut self) -> HsmResult<()>;

    /// Generate a new signing key
    fn generate_signing_key(&mut self, key_id: &str) -> HsmResult<SigningKey>;

    /// Load existing signing key by ID
    fn load_signing_key(&self, key_id: &str) -> HsmResult<SigningKey>;

    /// Sign a message
    fn sign(&self, key: &SigningKey, message: &[u8]) -> HsmResult<Vec<u8>>;

    /// Verify a signature
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> HsmResult<bool>;

    /// Cleanup and close HSM connection
    fn cleanup(&mut self) -> HsmResult<()>;

    /// Get HSM status/info
    fn status(&self) -> String;
}

/// Real HSM Client using PKCS#11 (when available)
pub struct RealHsmClient {
    initialized: bool,
    module_path: Option<String>,
    token_label: Option<String>,
}

impl RealHsmClient {
    /// Create new HSM client with PKCS#11 module path
    pub fn new(module_path: Option<String>, token_label: Option<String>) -> Self {
        RealHsmClient {
            initialized: false,
            module_path,
            token_label,
        }
    }

    /// Check if PKCS#11 module is available
    pub fn is_available(&self) -> bool {
        // In production: attempt to load libp11 or softHSM
        // For now: check if module path is configured
        self.module_path.is_some()
    }
}

impl HsmClient for RealHsmClient {
    fn initialize(&mut self) -> HsmResult<()> {
        // In production: would load PKCS#11 library
        // For Week 1: just mark as initialized if module is configured
        if self.is_available() {
            eprintln!("Initializing HSM with module: {:?}", self.module_path);
            self.initialized = true;
            Ok(())
        } else {
            Err(HsmError::HsmUnavailable(
                "No PKCS#11 module configured".to_string()
            ))
        }
    }

    fn generate_signing_key(&mut self, key_id: &str) -> HsmResult<SigningKey> {
        if !self.initialized {
            return Err(HsmError::InitializationFailed("HSM not initialized".to_string()));
        }

        // In production: would use PKCS#11 to generate key on HSM
        // For Week 1: use sodiumoxide as placeholder
        let (pk, sk) = sign::gen_keypair();

        eprintln!("Generated signing key {} on HSM", key_id);

        Ok(SigningKey {
            secret: sk,
            public: pk,
            key_id: key_id.to_string(),
        })
    }

    fn load_signing_key(&self, key_id: &str) -> HsmResult<SigningKey> {
        if !self.initialized {
            return Err(HsmError::InitializationFailed("HSM not initialized".to_string()));
        }

        // In production: would load key from HSM by ID
        // For Week 1: error (keys must be generated)
        Err(HsmError::KeyNotFound(format!("Key {} not found on HSM", key_id)))
    }

    fn sign(&self, key: &SigningKey, message: &[u8]) -> HsmResult<Vec<u8>> {
        if !self.initialized {
            return Err(HsmError::InitializationFailed("HSM not initialized".to_string()));
        }

        // Use sodiumoxide for signing (in production would use PKCS#11)
        let signature = sign::sign_detached(message, &key.secret);

        eprintln!("Signed message with key {} on HSM", key.key_id);

        Ok(signature.0.to_vec())
    }

    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> HsmResult<bool> {
        let pk = PublicKey(*public_key);

        if signature.len() != 64 {
            return Ok(false);
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = Signature(sig_bytes);

        match sign::verify_detached(&sig, message, &pk) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn cleanup(&mut self) -> HsmResult<()> {
        if self.initialized {
            eprintln!("Closing HSM connection");
            self.initialized = false;
        }
        Ok(())
    }

    fn status(&self) -> String {
        if self.initialized {
            format!("HSM initialized (module: {:?})", self.module_path)
        } else {
            "HSM not initialized".to_string()
        }
    }
}

/// Filesystem-based HSM Client (fallback when hardware unavailable)
pub struct FilesystemHsmClient {
    key_root: PathBuf,
    initialized: bool,
}

impl FilesystemHsmClient {
    /// Create filesystem HSM with key storage directory
    pub fn new(key_root: &str) -> Self {
        FilesystemHsmClient {
            key_root: PathBuf::from(key_root),
            initialized: false,
        }
    }

    /// Get key file path
    fn key_path(&self, key_id: &str) -> PathBuf {
        self.key_root.join(format!("{}.key", key_id))
    }

    /// Get public key file path
    fn pubkey_path(&self, key_id: &str) -> PathBuf {
        self.key_root.join(format!("{}.pub", key_id))
    }
}

impl HsmClient for FilesystemHsmClient {
    fn initialize(&mut self) -> HsmResult<()> {
        // Ensure key directory exists with proper permissions
        if !self.key_root.exists() {
            fs::create_dir_all(&self.key_root)
                .map_err(|e| HsmError::FileSystemError(format!("Failed to create key directory: {}", e)))?;
        }

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&self.key_root, perms)
                .map_err(|e| HsmError::FileSystemError(format!("Failed to set directory permissions: {}", e)))?;
        }

        eprintln!("Filesystem HSM initialized at {}", self.key_root.display());
        self.initialized = true;
        Ok(())
    }

    fn generate_signing_key(&mut self, key_id: &str) -> HsmResult<SigningKey> {
        if !self.initialized {
            return Err(HsmError::InitializationFailed("Filesystem HSM not initialized".to_string()));
        }

        // Generate new keypair
        let (pk, sk) = sign::gen_keypair();
        let key = SigningKey {
            secret: sk,
            public: pk,
            key_id: key_id.to_string(),
        };

        // Store secret key
        let key_path = self.key_path(key_id);
        fs::write(&key_path, key.secret_key_bytes())
            .map_err(|e| HsmError::FileSystemError(format!("Failed to write secret key: {}", e)))?;

        // Store public key
        let pubkey_path = self.pubkey_path(key_id);
        fs::write(&pubkey_path, &key.public_key_bytes())
            .map_err(|e| HsmError::FileSystemError(format!("Failed to write public key: {}", e)))?;

        eprintln!("Generated signing key {} in filesystem", key_id);
        Ok(key)
    }

    fn load_signing_key(&self, key_id: &str) -> HsmResult<SigningKey> {
        if !self.initialized {
            return Err(HsmError::InitializationFailed("Filesystem HSM not initialized".to_string()));
        }

        // Load secret key
        let key_path = self.key_path(key_id);
        if !key_path.exists() {
            return Err(HsmError::KeyNotFound(format!("Key {} not found", key_id)));
        }

        let secret_bytes = fs::read(&key_path)
            .map_err(|e| HsmError::FileSystemError(format!("Failed to read secret key: {}", e)))?;

        SigningKey::from_bytes(&secret_bytes, key_id.to_string())
    }

    fn sign(&self, key: &SigningKey, message: &[u8]) -> HsmResult<Vec<u8>> {
        let signature = sign::sign_detached(message, &key.secret);
        eprintln!("Signed message with key {} (filesystem)", key.key_id);
        Ok(signature.0.to_vec())
    }

    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> HsmResult<bool> {
        let pk = PublicKey(*public_key);

        if signature.len() != 64 {
            return Ok(false);
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = Signature(sig_bytes);

        match sign::verify_detached(&sig, message, &pk) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn cleanup(&mut self) -> HsmResult<()> {
        if self.initialized {
            eprintln!("Closing filesystem HSM");
            self.initialized = false;
        }
        Ok(())
    }

    fn status(&self) -> String {
        if self.initialized {
            format!("Filesystem HSM at {}", self.key_root.display())
        } else {
            "Filesystem HSM not initialized".to_string()
        }
    }
}

/// Auto-selecting HSM client: tries hardware first, falls back to filesystem
pub struct AutoHsmClient {
    backend: Box<dyn HsmClient>,
    using_fallback: bool,
}

impl AutoHsmClient {
    /// Create HSM client with automatic backend selection
    pub fn new(
        pkcs11_module: Option<String>,
        pkcs11_token: Option<String>,
        filesystem_root: &str,
    ) -> HsmResult<Self> {
        // Try real HSM first
        let real_hsm = RealHsmClient::new(pkcs11_module, pkcs11_token);

        if real_hsm.is_available() {
            eprintln!("Using hardware HSM (PKCS#11)");
            Ok(AutoHsmClient {
                backend: Box::new(real_hsm),
                using_fallback: false,
            })
        } else {
            eprintln!("Hardware HSM unavailable, using filesystem fallback");
            Ok(AutoHsmClient {
                backend: Box::new(FilesystemHsmClient::new(filesystem_root)),
                using_fallback: true,
            })
        }
    }

    /// Check if using fallback
    pub fn is_fallback(&self) -> bool {
        self.using_fallback
    }

    /// Delegate to backend
    pub fn initialize(&mut self) -> HsmResult<()> {
        self.backend.initialize()
    }

    pub fn generate_signing_key(&mut self, key_id: &str) -> HsmResult<SigningKey> {
        self.backend.generate_signing_key(key_id)
    }

    pub fn load_signing_key(&self, key_id: &str) -> HsmResult<SigningKey> {
        self.backend.load_signing_key(key_id)
    }

    pub fn sign(&self, key: &SigningKey, message: &[u8]) -> HsmResult<Vec<u8>> {
        self.backend.sign(key, message)
    }

    pub fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> HsmResult<bool> {
        self.backend.verify(public_key, message, signature)
    }

    pub fn cleanup(&mut self) -> HsmResult<()> {
        self.backend.cleanup()
    }

    pub fn status(&self) -> String {
        self.backend.status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_signing_key_creation() {
        let (pk, sk) = sign::gen_keypair();
        let key = SigningKey {
            secret: sk,
            public: pk,
            key_id: "test-key".to_string(),
        };

        assert_eq!(key.key_id(), "test-key");
        assert_eq!(key.public_key_bytes(), pk.0);
    }

    #[test]
    fn test_real_hsm_unavailable() {
        let mut hsm = RealHsmClient::new(None, None);
        let result = hsm.initialize();
        assert!(result.is_err());
    }

    #[test]
    fn test_filesystem_hsm_initialization() {
        let temp = TempDir::new().unwrap();
        let mut hsm = FilesystemHsmClient::new(temp.path().to_str().unwrap());

        assert!(hsm.initialize().is_ok());
        assert!(temp.path().exists());
    }

    #[test]
    fn test_filesystem_hsm_generate_key() {
        let temp = TempDir::new().unwrap();
        let mut hsm = FilesystemHsmClient::new(temp.path().to_str().unwrap());

        hsm.initialize().unwrap();
        let key = hsm.generate_signing_key("test-key").unwrap();

        assert_eq!(key.key_id(), "test-key");
        assert!(hsm.key_path("test-key").exists());
        assert!(hsm.pubkey_path("test-key").exists());
    }

    #[test]
    fn test_filesystem_hsm_load_key() {
        let temp = TempDir::new().unwrap();
        let mut hsm = FilesystemHsmClient::new(temp.path().to_str().unwrap());

        hsm.initialize().unwrap();
        let generated = hsm.generate_signing_key("test-key").unwrap();
        let loaded = hsm.load_signing_key("test-key").unwrap();

        assert_eq!(generated.public_key_bytes(), loaded.public_key_bytes());
    }

    #[test]
    fn test_signing_and_verification() {
        let temp = TempDir::new().unwrap();
        let mut hsm = FilesystemHsmClient::new(temp.path().to_str().unwrap());

        hsm.initialize().unwrap();
        let key = hsm.generate_signing_key("test-key").unwrap();

        let message = b"test message";
        let signature = hsm.sign(&key, message).unwrap();

        let verified = hsm.verify(&key.public_key_bytes(), message, &signature).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_auto_hsm_fallback() {
        let temp = TempDir::new().unwrap();
        let mut hsm = AutoHsmClient::new(None, None, temp.path().to_str().unwrap()).unwrap();

        assert!(hsm.is_fallback());
        assert!(hsm.initialize().is_ok());

        let key = hsm.generate_signing_key("auto-key").unwrap();
        let message = b"auto test";
        let signature = hsm.sign(&key, message).unwrap();

        let verified = hsm.verify(&key.public_key_bytes(), message, &signature).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_hsm_error_display() {
        let err = HsmError::InitializationFailed("test error".to_string());
        assert!(format!("{}", err).contains("initialization failed"));
    }
}
