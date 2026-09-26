// Named Pipe Management for IPC (Week 1 Task 1.4)
// Creates and manages 22 named pipes (FIFOs) for inter-principal communication
// One bidirectional pipe per interface pair (IF-001 through IF-022)

use std::fs;
use std::path::{Path, PathBuf};
use std::os::unix::fs::DirBuilder;
use crate::types::InterfaceId;
use crate::ipc::IpcError;

/// Pipe metadata and state
#[derive(Debug, Clone)]
pub struct PipeInfo {
    pub interface_id: u32,
    pub pipe_path: PathBuf,
    pub created_at: u64,
}

/// Named pipe manager: creates and tracks FIFO pipes for all interfaces
pub struct PipeManager {
    pipe_root: PathBuf,
    pipes: std::collections::HashMap<u32, PipeInfo>,
}

impl PipeManager {
    /// Create a new pipe manager with given root directory
    pub fn new(pipe_root: &str) -> Result<Self, IpcError> {
        let root_path = PathBuf::from(pipe_root);

        // Ensure root directory exists with proper permissions (0o750)
        if !root_path.exists() {
            DirBuilder::new()
                .mode(0o750)
                .create(&root_path)
                .map_err(|e| IpcError::FileSystemError(
                    format!("Failed to create pipe root directory: {}", e)
                ))?;
        }

        Ok(PipeManager {
            pipe_root: root_path,
            pipes: std::collections::HashMap::new(),
        })
    }

    /// Create named pipes for all 22 interfaces
    pub fn create_all_pipes(&mut self) -> Result<(), IpcError> {
        // Create FIFO for each interface (IF-001 through IF-022)
        for if_id in 1..=22 {
            self.create_pipe(if_id)?;
        }
        Ok(())
    }

    /// Create a single named pipe for an interface
    pub fn create_pipe(&mut self, if_id: u32) -> Result<(), IpcError> {
        if if_id < 1 || if_id > 22 {
            return Err(IpcError::PipeCreationFailed(
                format!("Invalid interface ID: {}", if_id)
            ));
        }

        let pipe_name = format!("if-{:03d}.pipe", if_id);
        let pipe_path = self.pipe_root.join(&pipe_name);

        // Remove old pipe if it exists (from previous crashed session)
        if pipe_path.exists() {
            fs::remove_file(&pipe_path)
                .map_err(|e| IpcError::FileSystemError(
                    format!("Failed to remove old pipe {}: {}", pipe_name, e)
                ))?;
        }

        // Create FIFO using nix crate
        #[cfg(target_os = "linux")]
        {
            use nix::unistd::mkfifo;
            use nix::sys::stat::Mode;

            mkfifo(&pipe_path, Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IWGRP)
                .map_err(|e| IpcError::PipeCreationFailed(
                    format!("mkfifo failed for {}: {}", pipe_name, e)
                ))?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Fallback for non-Linux systems: create a regular file (testing only)
            fs::File::create(&pipe_path)
                .map_err(|e| IpcError::PipeCreationFailed(
                    format!("Failed to create pipe file for testing: {}", e)
                ))?;
        }

        // Record pipe info
        let now_ns = crate::ipc::current_timestamp_ns();
        self.pipes.insert(if_id, PipeInfo {
            interface_id: if_id,
            pipe_path: pipe_path.clone(),
            created_at: now_ns,
        });

        Ok(())
    }

    /// Get pipe info for an interface
    pub fn get_pipe(&self, if_id: u32) -> Option<&PipeInfo> {
        self.pipes.get(&if_id)
    }

    /// List all created pipes
    pub fn all_pipes(&self) -> Vec<&PipeInfo> {
        self.pipes.values().collect()
    }

    /// Cleanup: remove all pipes (typically on shutdown)
    pub fn cleanup_all(&mut self) -> Result<(), IpcError> {
        let mut errors = Vec::new();

        for (_if_id, pipe_info) in self.pipes.iter() {
            if pipe_info.pipe_path.exists() {
                if let Err(e) = fs::remove_file(&pipe_info.pipe_path) {
                    errors.push(format!("Failed to remove {}: {}",
                        pipe_info.pipe_path.display(), e));
                }
            }
        }

        self.pipes.clear();

        if !errors.is_empty() {
            return Err(IpcError::FileSystemError(
                format!("Cleanup errors: {}", errors.join("; "))
            ));
        }

        Ok(())
    }

    /// Remove a single pipe
    pub fn cleanup_pipe(&mut self, if_id: u32) -> Result<(), IpcError> {
        if let Some(pipe_info) = self.pipes.remove(&if_id) {
            if pipe_info.pipe_path.exists() {
                fs::remove_file(&pipe_info.pipe_path)
                    .map_err(|e| IpcError::FileSystemError(
                        format!("Failed to remove pipe for IF-{:03d}: {}", if_id, e)
                    ))?;
            }
        }
        Ok(())
    }

    /// Get pipe root directory path
    pub fn pipe_root(&self) -> &Path {
        &self.pipe_root
    }

    /// Get number of created pipes
    pub fn pipe_count(&self) -> usize {
        self.pipes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_pipe_manager_new() {
        let temp_dir = TempDir::new().unwrap();
        let pipe_path = temp_dir.path().join("pipes");

        let manager = PipeManager::new(pipe_path.to_str().unwrap());
        assert!(manager.is_ok());
        assert!(pipe_path.exists());
    }

    #[test]
    fn test_pipe_manager_create_single_pipe() {
        let temp_dir = TempDir::new().unwrap();
        let pipe_path = temp_dir.path().join("pipes");

        let mut manager = PipeManager::new(pipe_path.to_str().unwrap()).unwrap();
        let result = manager.create_pipe(1);

        assert!(result.is_ok());
        assert!(manager.get_pipe(1).is_some());
        assert_eq!(manager.pipe_count(), 1);
    }

    #[test]
    fn test_pipe_manager_create_all_pipes() {
        let temp_dir = TempDir::new().unwrap();
        let pipe_path = temp_dir.path().join("pipes");

        let mut manager = PipeManager::new(pipe_path.to_str().unwrap()).unwrap();
        let result = manager.create_all_pipes();

        assert!(result.is_ok());
        assert_eq!(manager.pipe_count(), 22);

        for if_id in 1..=22 {
            assert!(manager.get_pipe(if_id).is_some());
        }
    }

    #[test]
    fn test_pipe_manager_invalid_interface_id() {
        let temp_dir = TempDir::new().unwrap();
        let pipe_path = temp_dir.path().join("pipes");

        let mut manager = PipeManager::new(pipe_path.to_str().unwrap()).unwrap();
        let result = manager.create_pipe(0);  // Invalid: must be 1-22

        assert!(result.is_err());
    }

    #[test]
    fn test_pipe_manager_get_pipe() {
        let temp_dir = TempDir::new().unwrap();
        let pipe_path = temp_dir.path().join("pipes");

        let mut manager = PipeManager::new(pipe_path.to_str().unwrap()).unwrap();
        manager.create_pipe(5).unwrap();

        let pipe_info = manager.get_pipe(5);
        assert!(pipe_info.is_some());
        assert_eq!(pipe_info.unwrap().interface_id, 5);
    }

    #[test]
    fn test_pipe_manager_all_pipes() {
        let temp_dir = TempDir::new().unwrap();
        let pipe_path = temp_dir.path().join("pipes");

        let mut manager = PipeManager::new(pipe_path.to_str().unwrap()).unwrap();
        manager.create_pipe(1).unwrap();
        manager.create_pipe(2).unwrap();
        manager.create_pipe(3).unwrap();

        let all_pipes = manager.all_pipes();
        assert_eq!(all_pipes.len(), 3);
    }

    #[test]
    fn test_pipe_manager_cleanup_single() {
        let temp_dir = TempDir::new().unwrap();
        let pipe_path = temp_dir.path().join("pipes");

        let mut manager = PipeManager::new(pipe_path.to_str().unwrap()).unwrap();
        manager.create_pipe(1).unwrap();
        assert_eq!(manager.pipe_count(), 1);

        manager.cleanup_pipe(1).unwrap();
        assert_eq!(manager.pipe_count(), 0);
    }

    #[test]
    fn test_pipe_manager_cleanup_all() {
        let temp_dir = TempDir::new().unwrap();
        let pipe_path = temp_dir.path().join("pipes");

        let mut manager = PipeManager::new(pipe_path.to_str().unwrap()).unwrap();
        manager.create_all_pipes().unwrap();
        assert_eq!(manager.pipe_count(), 22);

        manager.cleanup_all().unwrap();
        assert_eq!(manager.pipe_count(), 0);
    }

    #[test]
    fn test_pipe_manager_recreate_existing_pipe() {
        let temp_dir = TempDir::new().unwrap();
        let pipe_path = temp_dir.path().join("pipes");

        let mut manager = PipeManager::new(pipe_path.to_str().unwrap()).unwrap();
        manager.create_pipe(1).unwrap();

        // Creating the same pipe again should work (removes old one first)
        let result = manager.create_pipe(1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pipe_info_timestamp() {
        let temp_dir = TempDir::new().unwrap();
        let pipe_path = temp_dir.path().join("pipes");

        let mut manager = PipeManager::new(pipe_path.to_str().unwrap()).unwrap();
        manager.create_pipe(1).unwrap();

        let pipe_info = manager.get_pipe(1).unwrap();
        assert!(pipe_info.created_at > 0);
    }
}
