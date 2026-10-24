//! cgroup v2 CPU throttling enforcer for sloth-daemon.
//!
//! Handles safe, reversible cgroup v2 CPU throttling under `/sys/fs/cgroup/sloth-daemon/`.
//! Adheres strictly to safety rules: no signals, no nice/priority manipulation,
//! reversible cgroup assignment, protected process immunity, and dry-run safety.

use std::collections::HashMap as StdHashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use tracing::{debug, info, warn};

use crate::Config;

/// Default filesystem path where cgroup v2 unified hierarchy is mounted.
pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Subdirectory name under the cgroup root dedicated to sloth-daemon.
pub const DAEMON_CGROUP_NAME: &str = "sloth-daemon";

/// Minimum quota floor percentage of one CPU core (5%).
pub const MIN_QUOTA_FLOOR_PCT: u8 = 5;

/// Default cgroup CPU measurement period in microseconds (100 ms).
pub const DEFAULT_PERIOD_US: u64 = 100_000;

/// Default built-in set of protected process names (exact or prefix with `*`).
pub const BUILTIN_PROTECTED_NAMES: &[&str] = &[
    "systemd",
    "systemd-*",
    "sshd",
    "dbus-daemon",
    "Xorg",
    "Xwayland",
    "gnome-shell",
    "kwin_*",
    "pipewire",
    "pulseaudio",
    "NetworkManager",
    "ollama",
];

// ============================================================================
// Types & Errors
// ============================================================================

/// Reasons why a process is protected from CPU throttling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectedReason {
    /// PID 0 or PID 1 (init / systemd).
    InitProcess,
    /// sloth-daemon process itself.
    DaemonProcess,
    /// Direct parent of the daemon process.
    DaemonParent,
    /// Kernel worker thread.
    KernelThread,
    /// Matches a built-in or configured protected process name.
    ProtectedName(String),
    /// Belongs to a core protected systemd slice.
    SystemSlice(String),
}

impl std::fmt::Display for ProtectedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitProcess => write!(f, "PID <= 1 (init / systemd) is protected"),
            Self::DaemonProcess => write!(f, "sloth-daemon process itself is protected"),
            Self::DaemonParent => write!(f, "sloth-daemon parent process is protected"),
            Self::KernelThread => write!(f, "kernel thread is protected"),
            Self::ProtectedName(name) => write!(f, "process name '{name}' is in protected list"),
            Self::SystemSlice(path) => write!(f, "cgroup '{path}' is in protected system slice"),
        }
    }
}

/// Errors returned by the cgroup enforcement manager.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnforceError {
    /// Target process is protected and cannot be throttled.
    #[error("process is protected: {0}")]
    Protected(ProtectedReason),

    /// Concurrency cap of throttled processes reached.
    #[error("concurrency cap reached ({current}/{max})")]
    CapReached { current: usize, max: usize },

    /// Requested quota percentage is invalid or below the safety floor.
    #[error("invalid quota percentage: {quota_pct}% (must be between {min}% and 100%)")]
    QuotaInvalid { quota_pct: u8, min: u8 },

    /// Process is no longer running or PID has been reused.
    #[error("process {pid} exited or comm changed")]
    ProcessExited { pid: u32 },

    /// The target path is outside the allowed cgroup hierarchy.
    #[error("path traversal or invalid path: {0}")]
    PathEscape(String),

    /// Filesystem error during a cgroup operation.
    #[error("cgroup operation failed on {path}: {message}")]
    CgroupIo { path: PathBuf, message: String },
}

/// Record of an actively throttled process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThrottleRecord {
    /// Target process ID.
    pub pid: u32,
    /// Process name at the time of throttle decision.
    pub comm: String,
    /// Original cgroup path recorded before moving the process.
    pub original_cgroup: PathBuf,
    /// Applied CPU quota percentage of one core.
    pub quota_pct: u8,
    /// Timestamp when throttling started.
    pub started_at: Instant,
}

// ============================================================================
// Pure Helper Functions
// ============================================================================

/// Formats the string to write to `cpu.max` (`"$QUOTA_US $PERIOD_US\n"`).
///
/// Ensures quota percentage is clamped between `MIN_QUOTA_FLOOR_PCT` (5%) and 100%.
pub fn format_cpu_max(quota_pct: u8, period_us: u64) -> Result<String, EnforceError> {
    if !(MIN_QUOTA_FLOOR_PCT..=100).contains(&quota_pct) {
        return Err(EnforceError::QuotaInvalid {
            quota_pct,
            min: MIN_QUOTA_FLOOR_PCT,
        });
    }
    let quota_us = (period_us * quota_pct as u64) / 100;
    Ok(format!("{quota_us} {period_us}\n"))
}

/// Parses the relative cgroup path from `/proc/<pid>/cgroup` contents.
///
/// Under cgroup v2 (unified hierarchy), the line starts with `0::`.
pub fn parse_proc_cgroup(content: &str) -> Option<PathBuf> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let trimmed = rest.trim();
            let relative = trimmed.strip_prefix('/').unwrap_or(trimmed);
            return Some(PathBuf::from(relative));
        }
    }
    None
}

/// Checks whether a process name matches any protected pattern (exact match or prefix wildcard).
pub fn matches_protected_name(comm: &str, protected_names: &[String]) -> bool {
    for pattern in protected_names {
        if let Some(prefix) = pattern.strip_suffix('*') {
            if comm.starts_with(prefix) {
                return true;
            }
        } else if comm == pattern {
            return true;
        }
    }
    false
}

/// Validates that `target` is within `base_dir` and does not contain `..` or path escapes.
pub fn validate_safe_path(base_dir: &Path, target: &Path) -> Result<(), EnforceError> {
    for comp in target.components() {
        if let std::path::Component::ParentDir = comp {
            return Err(EnforceError::PathEscape(format!(
                "path '{}' contains '..'",
                target.display()
            )));
        }
    }
    if !target.starts_with(base_dir) {
        return Err(EnforceError::PathEscape(format!(
            "path '{}' is not under '{}'",
            target.display(),
            base_dir.display()
        )));
    }
    Ok(())
}

/// Reads parent PID of a given process from `/proc/<pid>/status`.
pub fn get_parent_pid(pid: u32) -> Option<u32> {
    let path = format!("/proc/{pid}/status");
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

// ============================================================================
// CgroupManager Implementation
// ============================================================================

/// Manager responsible for reversible cgroup v2 throttling operations.
#[derive(Debug)]
pub struct CgroupManager {
    root_path: PathBuf,
    parent_path: PathBuf,
    dry_run: bool,
    max_concurrent: usize,
    default_quota_pct: u8,
    extra_protected_names: Vec<String>,
    active_throttles: StdHashMap<u32, ThrottleRecord>,
}

impl CgroupManager {
    /// Creates a new CgroupManager instance connected to the system `/sys/fs/cgroup`.
    pub fn new(config: &Config) -> Result<Self, EnforceError> {
        Self::with_root(config, PathBuf::from(DEFAULT_CGROUP_ROOT))
    }

    /// Creates a CgroupManager with a custom cgroup root (useful for tests).
    pub fn with_root(config: &Config, root_path: PathBuf) -> Result<Self, EnforceError> {
        let parent_path = root_path.join(DAEMON_CGROUP_NAME);
        let mut mgr = Self {
            root_path,
            parent_path,
            dry_run: config.dry_run,
            max_concurrent: config.throttle.max_concurrent,
            default_quota_pct: config.throttle.quota_pct,
            extra_protected_names: config.protected.extra_names.clone(),
            active_throttles: StdHashMap::new(),
        };

        if !mgr.dry_run {
            mgr.ensure_parent_cgroup()?;
            let cleaned = mgr.startup_cleanup()?;
            if cleaned > 0 {
                info!(
                    cleaned_cgroups = cleaned,
                    "Startup cgroup cleanup completed"
                );
            }
        }

        Ok(mgr)
    }

    /// Ensures the parent cgroup `/sys/fs/cgroup/sloth-daemon/` exists and enables `+cpu`.
    pub fn ensure_parent_cgroup(&self) -> Result<(), EnforceError> {
        if self.dry_run {
            return Ok(());
        }

        validate_safe_path(&self.root_path, &self.parent_path)?;

        if !self.parent_path.exists() {
            fs::create_dir_all(&self.parent_path).map_err(|e| EnforceError::CgroupIo {
                path: self.parent_path.clone(),
                message: format!("failed to create parent cgroup directory: {e}"),
            })?;
        }

        // Enable +cpu in subtree_control so child cgroups can enforce cpu.max
        let subtree_file = self.parent_path.join("cgroup.subtree_control");
        if subtree_file.exists() {
            let current = fs::read_to_string(&subtree_file).unwrap_or_default();
            if !current.split_whitespace().any(|c| c == "cpu") {
                fs::write(&subtree_file, "+cpu\n").map_err(|e| EnforceError::CgroupIo {
                    path: subtree_file,
                    message: format!("failed to write '+cpu' to subtree_control: {e}"),
                })?;
            }
        }

        Ok(())
    }

    /// Scans the daemon parent cgroup on startup and cleans up lingering leftover cgroups.
    pub fn startup_cleanup(&mut self) -> Result<usize, EnforceError> {
        if self.dry_run || !self.parent_path.exists() {
            return Ok(0);
        }

        let mut cleaned = 0;
        let entries = match fs::read_dir(&self.parent_path) {
            Ok(e) => e,
            Err(_) => return Ok(0),
        };

        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if name_str.starts_with("pid-") && entry.path().is_dir() {
                let leaf_path = entry.path();
                let procs_file = leaf_path.join("cgroup.procs");

                // Move any lingering processes back to root cgroup
                if let Ok(content) = fs::read_to_string(&procs_file) {
                    for line in content.lines() {
                        if let Ok(pid) = line.trim().parse::<u32>() {
                            let root_procs = self.root_path.join("cgroup.procs");
                            let _ = fs::write(&root_procs, format!("{pid}\n"));
                            warn!(pid = pid, "Restored leftover process to root cgroup");
                        }
                    }
                }

                if fs::remove_dir(&leaf_path).is_ok() {
                    cleaned += 1;
                    debug!(path = %leaf_path.display(), "Removed stale cgroup from previous run");
                }
            }
        }

        Ok(cleaned)
    }

    /// Determines if a target process is protected from CPU throttling.
    pub fn is_protected(&self, pid: u32, comm: &str) -> Option<ProtectedReason> {
        // 1. PID 0 or PID 1
        if pid <= 1 {
            return Some(ProtectedReason::InitProcess);
        }

        // 2. The daemon itself
        let my_pid = std::process::id();
        if pid == my_pid {
            return Some(ProtectedReason::DaemonProcess);
        }

        // 3. The daemon's parent PID
        if let Some(parent_pid) = get_parent_pid(my_pid) {
            if pid == parent_pid {
                return Some(ProtectedReason::DaemonParent);
            }
        }

        // 4. Protected process name (built-in + extra)
        let mut all_protected: Vec<String> = BUILTIN_PROTECTED_NAMES
            .iter()
            .map(|&s| s.to_string())
            .collect();
        all_protected.extend(self.extra_protected_names.iter().cloned());

        if matches_protected_name(comm, &all_protected) {
            return Some(ProtectedReason::ProtectedName(comm.to_string()));
        }

        // 5. Kernel thread (only applies if process actually exists in /proc)
        if crate::is_kernel_thread(pid) {
            return Some(ProtectedReason::KernelThread);
        }

        // 6. Privileged system slice (under system.slice for systemd-managed services)
        if let Ok(content) = fs::read_to_string(format!("/proc/{pid}/cgroup")) {
            if let Some(cgroup_path) = parse_proc_cgroup(&content) {
                let path_str = cgroup_path.to_string_lossy();
                if path_str.starts_with("system.slice/") && !path_str.contains("user@") {
                    // Check if it's a critical system service
                    if path_str.contains("sshd")
                        || path_str.contains("systemd")
                        || path_str.contains("dbus")
                    {
                        return Some(ProtectedReason::SystemSlice(path_str.to_string()));
                    }
                }
            }
        }

        None
    }

    /// Throttles a target process by moving it into a child cgroup with `cpu.max` quota applied.
    pub fn throttle(
        &mut self,
        pid: u32,
        comm: &str,
        quota_pct: Option<u8>,
    ) -> Result<(), EnforceError> {
        let quota = quota_pct.unwrap_or(self.default_quota_pct);

        // 1. Validate quota
        let cpu_max_str = format_cpu_max(quota, DEFAULT_PERIOD_US)?;

        // 2. Protected check
        if let Some(reason) = self.is_protected(pid, comm) {
            debug!(pid = pid, comm = comm, reason = %reason, "Throttle skipped: target is protected");
            return Err(EnforceError::Protected(reason));
        }

        // 3. Concurrency cap check
        if !self.active_throttles.contains_key(&pid)
            && self.active_throttles.len() >= self.max_concurrent
        {
            warn!(
                current = self.active_throttles.len(),
                max = self.max_concurrent,
                "Throttle rejected: concurrency cap reached"
            );
            return Err(EnforceError::CapReached {
                current: self.active_throttles.len(),
                max: self.max_concurrent,
            });
        }

        // 4. Re-verify the target is alive and comm matches
        let proc_path = format!("/proc/{pid}");
        if !Path::new(&proc_path).exists() {
            return Err(EnforceError::ProcessExited { pid });
        }
        if let Ok(live_comm) = fs::read_to_string(format!("/proc/{pid}/comm")) {
            if live_comm.trim() != comm {
                return Err(EnforceError::ProcessExited { pid });
            }
        }

        // 5. Record original cgroup path BEFORE moving
        let cgroup_content = fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .map_err(|_| EnforceError::ProcessExited { pid })?;
        let original_cgroup =
            parse_proc_cgroup(&cgroup_content).ok_or(EnforceError::ProcessExited { pid })?;

        // 6. Dry run check: log what would be done and return without filesystem writes
        if self.dry_run {
            info!(
                pid = pid,
                comm = comm,
                quota_pct = quota,
                dry_run = true,
                "DRY-RUN: would throttle process to cgroup cpu.max"
            );
            self.active_throttles.insert(
                pid,
                ThrottleRecord {
                    pid,
                    comm: comm.to_string(),
                    original_cgroup,
                    quota_pct: quota,
                    started_at: Instant::now(),
                },
            );
            return Ok(());
        }

        // 7. Ensure parent cgroup exists and +cpu enabled
        self.ensure_parent_cgroup()?;

        // 8. Create leaf directory
        let leaf_name = format!("pid-{pid}");
        let leaf_path = self.parent_path.join(leaf_name);
        validate_safe_path(&self.parent_path, &leaf_path)?;

        if !leaf_path.exists() {
            fs::create_dir(&leaf_path).map_err(|e| EnforceError::CgroupIo {
                path: leaf_path.clone(),
                message: format!("failed to create leaf cgroup directory: {e}"),
            })?;
        }

        // 9. Write cpu.max FIRST, before moving the process into the cgroup
        let cpu_max_file = leaf_path.join("cpu.max");
        if let Err(e) = fs::write(&cpu_max_file, &cpu_max_str) {
            let _ = fs::remove_dir(&leaf_path);
            return Err(EnforceError::CgroupIo {
                path: cpu_max_file,
                message: format!("failed to write cpu.max: {e}"),
            });
        }

        // 10. Write PID to cgroup.procs
        let procs_file = leaf_path.join("cgroup.procs");
        let pid_str = format!("{pid}\n");
        if let Err(e) = fs::write(&procs_file, &pid_str) {
            let _ = fs::remove_dir(&leaf_path);
            return Err(EnforceError::CgroupIo {
                path: procs_file,
                message: format!("failed to move PID into cgroup: {e}"),
            });
        }

        // 11. Store throttle record
        info!(
            pid = pid,
            comm = comm,
            quota_pct = quota,
            leaf = %leaf_path.display(),
            "Process throttled successfully"
        );

        self.active_throttles.insert(
            pid,
            ThrottleRecord {
                pid,
                comm: comm.to_string(),
                original_cgroup,
                quota_pct: quota,
                started_at: Instant::now(),
            },
        );

        Ok(())
    }

    /// Releases a throttled process back to its original cgroup and removes the leaf directory.
    pub fn release(&mut self, pid: u32) -> Result<(), EnforceError> {
        let record = match self.active_throttles.remove(&pid) {
            Some(r) => r,
            None => return Ok(()),
        };

        if self.dry_run {
            info!(
                pid = pid,
                comm = %record.comm,
                dry_run = true,
                "DRY-RUN: would release process back to original cgroup"
            );
            return Ok(());
        }

        let leaf_path = self.parent_path.join(format!("pid-{pid}"));

        // If the process is still alive, move it back to its recorded original cgroup
        if Path::new(&format!("/proc/{pid}")).exists() {
            let target_cgroup = self.root_path.join(&record.original_cgroup);
            let target_procs = target_cgroup.join("cgroup.procs");

            let target_file = if target_procs.exists() {
                target_procs
            } else {
                warn!(
                    pid = pid,
                    original = %record.original_cgroup.display(),
                    "Original cgroup no longer exists; falling back to root cgroup"
                );
                self.root_path.join("cgroup.procs")
            };

            if let Err(e) = fs::write(&target_file, format!("{pid}\n")) {
                warn!(
                    pid = pid,
                    error = %e,
                    "Failed to move process back during release (may have already exited)"
                );
            }
        }

        // Remove the empty child cgroup directory
        if leaf_path.exists() {
            if let Err(e) = fs::remove_dir(&leaf_path) {
                debug!(
                    leaf = %leaf_path.display(),
                    error = %e,
                    "Failed to remove cgroup leaf directory (may still have transient tasks)"
                );
            }
        }

        info!(pid = pid, comm = %record.comm, "Process released from throttle");
        Ok(())
    }

    /// Releases all currently throttled processes. Idempotent and never panics.
    pub fn release_all(&mut self) {
        let pids: Vec<u32> = self.active_throttles.keys().copied().collect();
        for pid in pids {
            let _ = self.release(pid);
        }
    }

    /// Returns a map of all currently active throttle records.
    pub fn active_records(&self) -> &StdHashMap<u32, ThrottleRecord> {
        &self.active_throttles
    }

    /// Checks if a given PID is currently recorded as throttled.
    pub fn is_throttled(&self, pid: u32) -> bool {
        self.active_throttles.contains_key(&pid)
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        self.release_all();
    }
}

// ============================================================================
// Unit Tests (no root required)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_cpu_max() {
        // Standard valid quotas
        assert_eq!(
            format_cpu_max(5, 100_000).unwrap(),
            "5000 100000\n" // 5% of one core (quota floor)
        );
        assert_eq!(
            format_cpu_max(20, 100_000).unwrap(),
            "20000 100000\n" // 20%
        );
        assert_eq!(
            format_cpu_max(50, 100_000).unwrap(),
            "50000 100000\n" // 50%
        );
        assert_eq!(
            format_cpu_max(100, 100_000).unwrap(),
            "100000 100000\n" // 100% (one full core)
        );

        // Invalid quotas below floor or above 100%
        assert_eq!(
            format_cpu_max(0, 100_000),
            Err(EnforceError::QuotaInvalid {
                quota_pct: 0,
                min: 5
            })
        );
        assert_eq!(
            format_cpu_max(4, 100_000),
            Err(EnforceError::QuotaInvalid {
                quota_pct: 4,
                min: 5
            })
        );
        assert_eq!(
            format_cpu_max(101, 100_000),
            Err(EnforceError::QuotaInvalid {
                quota_pct: 101,
                min: 5
            })
        );
    }

    #[test]
    fn test_parse_proc_cgroup() {
        // Normal cgroup v2 entry
        let v2_content = "0::/user.slice/user-1000.slice/session-1.scope\n";
        assert_eq!(
            parse_proc_cgroup(v2_content),
            Some(PathBuf::from("user.slice/user-1000.slice/session-1.scope"))
        );

        // Hybrid / multi-controller lines
        let hybrid = "2:cpu,cpuacct:/docker/123\n1:memory:/\n0::/system.slice/service.service\n";
        assert_eq!(
            parse_proc_cgroup(hybrid),
            Some(PathBuf::from("system.slice/service.service"))
        );

        // Root cgroup
        let root = "0::/\n";
        assert_eq!(parse_proc_cgroup(root), Some(PathBuf::from("")));

        // Empty or malformed
        assert_eq!(parse_proc_cgroup(""), None);
        assert_eq!(parse_proc_cgroup("1:cpu:/\n"), None);
    }

    #[test]
    fn test_matches_protected_name() {
        let protected: Vec<String> = BUILTIN_PROTECTED_NAMES
            .iter()
            .map(|&s| s.to_string())
            .collect();

        // Exact matches
        assert!(matches_protected_name("systemd", &protected));
        assert!(matches_protected_name("sshd", &protected));
        assert!(matches_protected_name("ollama", &protected));

        // Prefix wildcard matches
        assert!(matches_protected_name("systemd-journald", &protected));
        assert!(matches_protected_name("systemd-resolved", &protected));
        assert!(matches_protected_name("kwin_wayland", &protected));
        assert!(matches_protected_name("kwin_x11", &protected));

        // Unprotected processes
        assert!(!matches_protected_name("yes", &protected));
        assert!(!matches_protected_name("python", &protected));
        assert!(!matches_protected_name("stress-ng", &protected));
    }

    #[test]
    fn test_validate_safe_path() {
        let base = Path::new("/sys/fs/cgroup/sloth-daemon");

        // Valid leaf path
        let valid = base.join("pid-1234");
        assert_eq!(validate_safe_path(base, &valid), Ok(()));

        // Path traversal with ..
        let traversal = base.join("../escaped");
        assert!(validate_safe_path(base, &traversal).is_err());

        // Completely outside base
        let outside = Path::new("/etc/shadow");
        assert!(validate_safe_path(base, outside).is_err());
    }

    #[test]
    fn test_dry_run_workflow() {
        let config = Config {
            dry_run: true,
            ..Config::default()
        };

        // Create manager in a mock directory
        let temp_dir = std::env::temp_dir().join("sloth_test_cgroup");
        let mut mgr = CgroupManager::with_root(&config, temp_dir.clone()).unwrap();

        // PID 1 must be refused
        assert_eq!(
            mgr.throttle(1, "systemd", None),
            Err(EnforceError::Protected(ProtectedReason::InitProcess))
        );

        // Daemon PID itself must be refused
        assert_eq!(
            mgr.throttle(std::process::id(), "sloth-daemon", None),
            Err(EnforceError::Protected(ProtectedReason::DaemonProcess))
        );

        // Protected process names must be refused
        assert_eq!(
            mgr.throttle(9999, "sshd", None),
            Err(EnforceError::Protected(ProtectedReason::ProtectedName(
                "sshd".to_string()
            )))
        );
        assert_eq!(
            mgr.throttle(9999, "systemd-journald", None),
            Err(EnforceError::Protected(ProtectedReason::ProtectedName(
                "systemd-journald".to_string()
            )))
        );
        assert_eq!(
            mgr.throttle(9999, "kwin_wayland", None),
            Err(EnforceError::Protected(ProtectedReason::ProtectedName(
                "kwin_wayland".to_string()
            )))
        );

        // Active records initial state
        assert_eq!(mgr.active_records().len(), 0);
        assert!(!mgr.is_throttled(9999));
    }

    #[test]
    fn test_concurrency_cap() {
        let config = Config {
            dry_run: true,
            throttle: crate::ThrottleConfig {
                max_concurrent: 2,
                ..crate::ThrottleConfig::default()
            },
            ..Config::default()
        };

        let temp_dir = std::env::temp_dir().join("sloth_test_cgroup_cap");
        let mut mgr = CgroupManager::with_root(&config, temp_dir).unwrap();

        // Simulate two throttled records
        mgr.active_throttles.insert(
            100,
            ThrottleRecord {
                pid: 100,
                comm: "proc1".to_string(),
                original_cgroup: PathBuf::from(""),
                quota_pct: 20,
                started_at: Instant::now(),
            },
        );
        mgr.active_throttles.insert(
            200,
            ThrottleRecord {
                pid: 200,
                comm: "proc2".to_string(),
                original_cgroup: PathBuf::from(""),
                quota_pct: 20,
                started_at: Instant::now(),
            },
        );

        // Attempting to throttle a 3rd process must fail with CapReached
        assert_eq!(
            mgr.throttle(300, "proc3", None),
            Err(EnforceError::CapReached { current: 2, max: 2 })
        );

        // Releasing one must free up the slot
        assert_eq!(mgr.release(100), Ok(()));
        assert_eq!(mgr.active_records().len(), 1);

        // release_all empties all active records
        mgr.release_all();
        assert_eq!(mgr.active_records().len(), 0);
    }

    #[test]
    fn test_dry_run_throttle_and_release_live_process() {
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("failed to spawn sleep");
        let pid = child.id();

        let config = Config {
            dry_run: true,
            ..Config::default()
        };
        let temp_dir = std::env::temp_dir().join("sloth_test_dry_run_live");
        let mut mgr = CgroupManager::with_root(&config, temp_dir).unwrap();

        // Throttle the running process in dry_run mode
        assert_eq!(mgr.throttle(pid, "sleep", None), Ok(()));
        assert!(mgr.is_throttled(pid));
        assert_eq!(mgr.active_records().len(), 1);

        // Record verification
        let record = mgr.active_records().get(&pid).unwrap();
        assert_eq!(record.pid, pid);
        assert_eq!(record.comm, "sleep");
        assert_eq!(record.quota_pct, 20);

        // Release the process in dry_run mode
        assert_eq!(mgr.release(pid), Ok(()));
        assert!(!mgr.is_throttled(pid));
        assert_eq!(mgr.active_records().len(), 0);

        let _ = child.kill();
        let _ = child.wait();
    }
}
