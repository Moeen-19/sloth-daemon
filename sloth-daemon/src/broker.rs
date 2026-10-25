//! Deterministic Evidence Broker for sloth-daemon (Phase 4.5).
//!
//! Gathers local facts from kernel metrics history and `/proc` files, deriving a
//! compact, privacy-safe `ProcessBrief`. This allows tiny local models (e.g. 0.5B-3B)
//! to judge quickly and accurately, and provides a pure deterministic "rules" mode.
//!
//! Privacy rules enforced here:
//! - Name is sanitized (`[A-Za-z0-9._+-]`, max 32 chars).
//! - All features are derived summaries (categories, buckets, trends).
//! - NEVER includes command-line arguments, environment variables, raw file paths,
//!   usernames, or raw cgroup paths.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ai_classifier::{Class, Verdict};
use crate::{AiConfig, ProcessSample};

// ============================================================================
// Data Contracts
// ============================================================================

/// Broad workload category derived from process or parent comm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameCategory {
    Compiler,
    Encoder,
    Database,
    BrowserHelper,
    Interpreter,
    Shell,
    DesktopService,
    Unknown,
}

/// CPU usage direction over the measurement history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuTrend {
    Rising,
    Flat,
    Falling,
}

/// CPU usage pattern over the measurement history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Burstiness {
    Steady,
    Spiky,
}

/// Coarse resident set size bucket (prevents leaking exact memory sizes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RssBucket {
    Small,
    Medium,
    Large,
}

/// Execution session context derived from cgroup (never exposes the raw cgroup path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    UserApp,
    SystemService,
    Unknown,
}

/// Deterministic preliminary verdict computed from rules before any LLM call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RulePreliminary {
    pub class: Class,
    pub confidence: f32,
    pub reasons: Vec<String>,
}

impl RulePreliminary {
    /// Converts the preliminary rule assessment into a standard `Verdict`.
    pub fn to_verdict(&self) -> Verdict {
        let throttle_recommended = match self.class {
            Class::Essential | Class::Interactive | Class::Unknown => false,
            Class::Runaway | Class::Background => self.confidence >= 0.8,
        };
        let reason = if self.reasons.is_empty() {
            "preliminary rule match".to_string()
        } else {
            self.reasons.join("; ")
        };
        Verdict {
            classification: self.class,
            confidence: self.confidence,
            throttle_recommended,
            reason,
        }
    }
}

/// Compact evidence package derived deterministically for local classification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessBrief {
    /// Sanitized process name.
    pub name: String,
    /// Category derived from process name.
    pub name_category: NameCategory,
    /// Category derived from parent process name.
    pub parent_category: NameCategory,
    /// Instantaneous CPU percentage (100.0 = one full core).
    pub cpu_now: f32,
    /// 60-second moving average CPU percentage.
    pub cpu_avg_60s: f32,
    /// Peak CPU percentage in recent history.
    pub cpu_peak: f32,
    /// CPU usage trend (rising, flat, or falling).
    pub trend: CpuTrend,
    /// CPU usage burstiness (steady or spiky).
    pub burstiness: Burstiness,
    /// Seconds continuously sustained above throttle threshold.
    pub sustained_secs: u32,
    /// Process age in seconds.
    pub age_secs: u64,
    /// Thread count.
    pub thread_count: u32,
    /// Coarse memory RSS bucket (small, medium, large).
    pub rss_bucket: RssBucket,
    /// Coarse session kind (user_app, system_service, unknown).
    pub session_kind: SessionKind,
    /// Whether the process has a controlling terminal.
    pub has_tty: bool,
    /// System CPU pressure avg10 from /proc/pressure/cpu (if available).
    pub psi_cpu_avg10: Option<f32>,
    /// CPU consumption rank (1 = highest CPU consumer among active samples).
    pub cpu_rank: u32,
    /// Number of logical CPU cores on the host.
    pub num_cores: u32,
    /// Deterministic preliminary verdict from rule evaluation.
    pub rule_preliminary: RulePreliminary,
}

impl ProcessBrief {
    /// Returns true if the workload qualifies as never-throttle per rules.
    pub fn is_never_throttle(&self) -> bool {
        matches!(
            self.name_category,
            NameCategory::Compiler
                | NameCategory::Encoder
                | NameCategory::Database
                | NameCategory::DesktopService
        ) || matches!(self.parent_category, NameCategory::Compiler)
            || (self.rule_preliminary.class == Class::Essential
                && self.rule_preliminary.confidence >= 0.9)
    }
}

// ============================================================================
// History Ring Buffer
// ============================================================================

/// Number of samples retained in the ring buffer (~60s at 2s intervals).
pub const RING_BUFFER_CAPACITY: usize = 30;

/// Ring buffer storing recent CPU percentages for a single PID.
#[derive(Debug, Clone, Default)]
pub struct PidCpuRingBuffer {
    samples: VecDeque<f32>,
}

impl PidCpuRingBuffer {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(RING_BUFFER_CAPACITY),
        }
    }

    pub fn push(&mut self, cpu_pct: f32) {
        if self.samples.len() >= RING_BUFFER_CAPACITY {
            self.samples.pop_front();
        }
        self.samples.push_back(cpu_pct);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn cpu_now(&self) -> f32 {
        self.samples.back().copied().unwrap_or(0.0)
    }

    pub fn cpu_avg_60s(&self) -> f32 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let sum: f32 = self.samples.iter().sum();
        sum / self.samples.len() as f32
    }

    pub fn cpu_peak(&self) -> f32 {
        self.samples.iter().copied().fold(0.0, f32::max)
    }

    pub fn trend(&self) -> CpuTrend {
        calculate_trend(&self.samples)
    }

    pub fn burstiness(&self) -> Burstiness {
        calculate_burstiness(&self.samples)
    }
}

/// Computes the CPU trend by comparing the newer half to the older half.
pub fn calculate_trend(samples: &VecDeque<f32>) -> CpuTrend {
    if samples.len() < 4 {
        return CpuTrend::Flat;
    }
    let half = samples.len() / 2;
    let first_half_sum: f32 = samples.iter().take(half).sum();
    let second_half_sum: f32 = samples.iter().skip(samples.len() - half).sum();
    let first_avg = first_half_sum / half as f32;
    let second_avg = second_half_sum / half as f32;

    let delta = second_avg - first_avg;
    if delta > 5.0 {
        CpuTrend::Rising
    } else if delta < -5.0 {
        CpuTrend::Falling
    } else {
        CpuTrend::Flat
    }
}

/// Computes whether CPU consumption is steady or spiky via standard deviation.
pub fn calculate_burstiness(samples: &VecDeque<f32>) -> Burstiness {
    if samples.len() < 4 {
        return Burstiness::Steady;
    }
    let n = samples.len() as f32;
    let mean: f32 = samples.iter().sum::<f32>() / n;
    let variance: f32 = samples
        .iter()
        .map(|&val| {
            let diff = val - mean;
            diff * diff
        })
        .sum::<f32>()
        / n;
    let std_dev = variance.sqrt();

    if std_dev > 15.0 {
        Burstiness::Spiky
    } else {
        Burstiness::Steady
    }
}

/// Global tracker retaining per-PID CPU history ring buffers.
#[derive(Debug, Default)]
pub struct SamplerHistory {
    pids: HashMap<u32, PidCpuRingBuffer>,
}

impl SamplerHistory {
    pub fn new() -> Self {
        Self {
            pids: HashMap::new(),
        }
    }

    pub fn record(&mut self, pid: u32, cpu_pct: f32) {
        self.pids.entry(pid).or_default().push(cpu_pct);
    }

    pub fn get(&self, pid: u32) -> Option<&PidCpuRingBuffer> {
        self.pids.get(&pid)
    }

    pub fn retain_active(&mut self, active_pids: &[u32]) {
        self.pids.retain(|pid, _| active_pids.contains(pid));
    }
}

// ============================================================================
// Pure /proc Parsers
// ============================================================================

/// Parsed fields from `/proc/<pid>/stat`.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedStat {
    pub comm: String,
    pub ppid: u32,
    pub tty_nr: i32,
    pub num_threads: u32,
    pub starttime: u64,
}

/// Parses the contents of `/proc/<pid>/stat`.
///
/// Handles executable names with embedded spaces and parentheses by scanning from
/// the first '(' to the last ')'.
pub fn parse_stat(stat_text: &str) -> Option<ParsedStat> {
    let open_paren = stat_text.find('(')?;
    let close_paren = stat_text.rfind(')')?;
    if close_paren <= open_paren {
        return None;
    }
    let comm = stat_text[open_paren + 1..close_paren].to_string();
    let rest = stat_text[close_paren + 1..].trim();
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // rest starts from field 3 (state) at index 0.
    // Index 1: ppid (field 4)
    // Index 4: tty_nr (field 7)
    // Index 17: num_threads (field 20)
    // Index 19: starttime (field 22)
    if fields.len() < 20 {
        return None;
    }
    let ppid: u32 = fields[1].parse().ok()?;
    let tty_nr: i32 = fields[4].parse().ok()?;
    let num_threads: u32 = fields[17].parse().ok()?;
    let starttime: u64 = fields[19].parse().ok()?;

    Some(ParsedStat {
        comm,
        ppid,
        tty_nr,
        num_threads,
        starttime,
    })
}

/// Computes process age in seconds from starttime ticks, uptime, and clock tick frequency.
pub fn calculate_age_secs(starttime_ticks: u64, uptime_secs: f64, clk_tck: u64) -> u64 {
    let start_secs = starttime_ticks as f64 / clk_tck.max(1) as f64;
    if uptime_secs >= start_secs {
        (uptime_secs - start_secs) as u64
    } else {
        0
    }
}

/// Parses system uptime from `/proc/uptime`.
pub fn parse_uptime(uptime_text: &str) -> Option<f64> {
    uptime_text.split_whitespace().next()?.parse::<f64>().ok()
}

/// Parses VmRSS in kilobytes from `/proc/<pid>/status`.
pub fn parse_status_rss_kb(status_text: &str) -> Option<u64> {
    for line in status_text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let part = rest.split_whitespace().next()?;
            return part.parse::<u64>().ok();
        }
    }
    None
}

/// Maps RSS in kilobytes to a coarse `RssBucket`.
pub fn rss_bucket_from_kb(kb: u64) -> RssBucket {
    if kb < 100 * 1024 {
        RssBucket::Small
    } else if kb < 1024 * 1024 {
        RssBucket::Medium
    } else {
        RssBucket::Large
    }
}

/// Derives `SessionKind` from `/proc/<pid>/cgroup` lines without leaking paths.
pub fn parse_cgroup_session_kind(cgroup_text: &str) -> SessionKind {
    for line in cgroup_text.lines() {
        if line.contains("user.slice") || line.contains("/session-") || line.contains("user@") {
            return SessionKind::UserApp;
        }
        if line.contains("system.slice") || line.contains(".service") {
            return SessionKind::SystemService;
        }
    }
    SessionKind::Unknown
}

/// Parses 10-second CPU pressure (some avg10) from `/proc/pressure/cpu`.
pub fn parse_psi_cpu_avg10(pressure_text: &str) -> Option<f32> {
    for line in pressure_text.lines() {
        if line.starts_with("some ") {
            for token in line.split_whitespace() {
                if let Some(val) = token.strip_prefix("avg10=") {
                    return val.parse::<f32>().ok();
                }
            }
        }
    }
    None
}

// ============================================================================
// Workload Categorization & Preliminary Rules
// ============================================================================

/// Categorizes a process executable name into a known workload category.
pub fn categorize_comm(comm: &str) -> NameCategory {
    let lower = comm.to_ascii_lowercase();

    // Compilers & build tools
    if lower == "rustc"
        || lower == "cargo"
        || lower == "gcc"
        || lower == "g++"
        || lower == "cc1"
        || lower == "cc1plus"
        || lower == "clang"
        || lower == "clang++"
        || lower == "as"
        || lower == "ld"
        || lower == "lld"
        || lower == "ar"
        || lower == "make"
        || lower == "ninja"
        || lower == "fpm"
        || lower.starts_with("rustc")
        || lower.starts_with("gcc-")
        || lower.starts_with("clang-")
    {
        return NameCategory::Compiler;
    }

    // Encoders & transcoders
    if lower == "ffmpeg"
        || lower == "handbrake"
        || lower == "av1enc"
        || lower == "x264"
        || lower == "x265"
        || lower == "flac"
        || lower == "lame"
        || lower == "optipng"
        || lower == "cwebp"
    {
        return NameCategory::Encoder;
    }

    // Databases
    if lower == "postgres"
        || lower == "mysqld"
        || lower == "mariadbd"
        || lower == "mongod"
        || lower == "redis-server"
        || lower == "clickhouse"
        || lower == "sqlite3"
    {
        return NameCategory::Database;
    }

    // Browser helpers & renderers
    if lower.contains("isolated-web-co")
        || lower.contains("web content")
        || lower.contains("utility process")
        || lower.contains("renderer")
        || lower == "chrome"
        || lower == "chromium"
        || lower == "firefox"
        || lower == "brave"
        || lower == "edge"
    {
        return NameCategory::BrowserHelper;
    }

    // Interpreters & runtime hosts
    if lower == "python"
        || lower == "python3"
        || lower.starts_with("python3.")
        || lower == "node"
        || lower == "ruby"
        || lower == "perl"
        || lower == "php"
        || lower == "lua"
        || lower == "julia"
        || lower == "r"
    {
        return NameCategory::Interpreter;
    }

    // Shells
    if lower == "bash"
        || lower == "zsh"
        || lower == "sh"
        || lower == "fish"
        || lower == "dash"
        || lower == "csh"
        || lower == "tcsh"
    {
        return NameCategory::Shell;
    }

    // Desktop & core system services
    if lower == "gnome-shell"
        || lower == "kwin"
        || lower == "kwin_wayland"
        || lower == "kwin_x11"
        || lower == "pipewire"
        || lower == "pulseaudio"
        || lower == "xorg"
        || lower == "xwayland"
        || lower == "wireplumber"
        || lower == "dbus-daemon"
        || lower == "systemd"
        || lower == "ollama"
    {
        return NameCategory::DesktopService;
    }

    NameCategory::Unknown
}

/// Evaluates deterministic preliminary rules for a workload.
pub fn evaluate_preliminary_rules(
    name: &str,
    name_cat: NameCategory,
    parent_cat: NameCategory,
    sustained_secs: u32,
    config: &AiConfig,
) -> RulePreliminary {
    // 1. Configured never_throttle list
    if config
        .never_throttle
        .iter()
        .any(|p| name.eq_ignore_ascii_case(p) || name.starts_with(p))
    {
        return RulePreliminary {
            class: Class::Essential,
            confidence: 0.99,
            reasons: vec!["configured never throttle match".to_string()],
        };
    }

    // 2. Heavy legitimate workload categories
    match name_cat {
        NameCategory::Compiler => {
            return RulePreliminary {
                class: Class::Essential,
                confidence: 0.95,
                reasons: vec!["compiler workload never throttled".to_string()],
            };
        }
        NameCategory::Encoder => {
            return RulePreliminary {
                class: Class::Essential,
                confidence: 0.90,
                reasons: vec!["encoder workload never throttled".to_string()],
            };
        }
        NameCategory::Database => {
            return RulePreliminary {
                class: Class::Essential,
                confidence: 0.95,
                reasons: vec!["database workload never throttled".to_string()],
            };
        }
        NameCategory::DesktopService => {
            return RulePreliminary {
                class: Class::Essential,
                confidence: 0.99,
                reasons: vec!["desktop service never throttled".to_string()],
            };
        }
        _ => {}
    }

    // 3. Child of compiler (e.g. cc1 spawned by gcc)
    if parent_cat == NameCategory::Compiler {
        return RulePreliminary {
            class: Class::Essential,
            confidence: 0.90,
            reasons: vec!["child of compiler never throttled".to_string()],
        };
    }

    // 4. Configured throttle candidates
    if config
        .throttle_candidates
        .iter()
        .any(|p| name.eq_ignore_ascii_case(p) || name.starts_with(p))
    {
        return if sustained_secs >= 30 {
            RulePreliminary {
                class: Class::Runaway,
                confidence: config.candidates_confidence,
                reasons: vec!["configured throttle candidate high sustained cpu".to_string()],
            }
        } else {
            RulePreliminary {
                class: Class::Background,
                confidence: config.candidates_confidence,
                reasons: vec!["configured throttle candidate busy".to_string()],
            }
        };
    }

    // 5. Candidate categories (browser helpers and interpreters)
    match name_cat {
        NameCategory::BrowserHelper => {
            if sustained_secs >= 30 {
                RulePreliminary {
                    class: Class::Runaway,
                    confidence: 0.85,
                    reasons: vec!["browser helper high sustained cpu".to_string()],
                }
            } else {
                RulePreliminary {
                    class: Class::Background,
                    confidence: 0.70,
                    reasons: vec!["browser helper busy".to_string()],
                }
            }
        }
        NameCategory::Interpreter => {
            if sustained_secs >= 30 {
                RulePreliminary {
                    class: Class::Runaway,
                    confidence: 0.85,
                    reasons: vec!["interpreter high sustained cpu".to_string()],
                }
            } else {
                RulePreliminary {
                    class: Class::Background,
                    confidence: 0.70,
                    reasons: vec!["interpreter busy".to_string()],
                }
            }
        }
        _ => RulePreliminary {
            class: Class::Unknown,
            confidence: 0.50,
            reasons: vec!["no specific rule match".to_string()],
        },
    }
}

// ============================================================================
// ProcessBrief Builder
// ============================================================================

/// Host and system execution context passed to the brief builder.
#[derive(Debug, Clone, Copy)]
pub struct SystemContext<'a> {
    pub cpu_rank: u32,
    pub num_cores: u32,
    pub proc_root: &'a Path,
    pub pressure_path: &'a Path,
    pub uptime_secs: f64,
}

/// Builds a `ProcessBrief` from sample, history, system context, and `/proc`.
///
/// Returns `None` ("no brief") without panicking if the process terminates mid-read.
pub fn build_brief(
    sample: &ProcessSample,
    history: Option<&PidCpuRingBuffer>,
    sys_ctx: &SystemContext,
    config: &AiConfig,
) -> Option<ProcessBrief> {
    // 1. Read /proc/<pid>/stat
    let stat_path = sys_ctx.proc_root.join(format!("{}/stat", sample.pid));
    let stat_text = fs::read_to_string(&stat_path).ok()?;
    let stat = parse_stat(&stat_text)?;

    // 2. Read parent /proc/<ppid>/stat if available
    let parent_category = if stat.ppid > 0 {
        let parent_stat_path = sys_ctx.proc_root.join(format!("{}/stat", stat.ppid));
        if let Ok(p_text) = fs::read_to_string(&parent_stat_path) {
            parse_stat(&p_text)
                .map(|p| categorize_comm(&p.comm))
                .unwrap_or(NameCategory::Unknown)
        } else {
            NameCategory::Unknown
        }
    } else {
        NameCategory::Unknown
    };

    // 3. Read /proc/<pid>/status for RSS
    let status_path = sys_ctx.proc_root.join(format!("{}/status", sample.pid));
    let rss_bucket = if let Ok(status_text) = fs::read_to_string(&status_path) {
        parse_status_rss_kb(&status_text)
            .map(rss_bucket_from_kb)
            .unwrap_or(RssBucket::Small)
    } else {
        RssBucket::Small
    };

    // 4. Read /proc/<pid>/cgroup for session kind
    let cgroup_path = sys_ctx.proc_root.join(format!("{}/cgroup", sample.pid));
    let session_kind = if let Ok(cgroup_text) = fs::read_to_string(&cgroup_path) {
        parse_cgroup_session_kind(&cgroup_text)
    } else {
        SessionKind::Unknown
    };

    // 5. Read system CPU pressure if available
    let psi_cpu_avg10 = fs::read_to_string(sys_ctx.pressure_path)
        .ok()
        .and_then(|t| parse_psi_cpu_avg10(&t));

    // 6. Metrics and trends
    let (cpu_avg_60s, cpu_peak, trend, burstiness) = match history {
        Some(h) => (h.cpu_avg_60s(), h.cpu_peak(), h.trend(), h.burstiness()),
        None => (
            sample.cpu_percent,
            sample.cpu_percent,
            CpuTrend::Flat,
            Burstiness::Steady,
        ),
    };

    let safe_name = crate::ai_classifier::sanitize_comm(&sample.comm);
    let name_category = categorize_comm(&sample.comm);
    let age_secs = calculate_age_secs(stat.starttime, sys_ctx.uptime_secs, 100);
    let has_tty = stat.tty_nr != 0;

    let rule_preliminary = evaluate_preliminary_rules(
        &safe_name,
        name_category,
        parent_category,
        sample.sustained_secs,
        config,
    );

    Some(ProcessBrief {
        name: safe_name,
        name_category,
        parent_category,
        cpu_now: sample.cpu_percent,
        cpu_avg_60s,
        cpu_peak,
        trend,
        burstiness,
        sustained_secs: sample.sustained_secs,
        age_secs,
        thread_count: stat.num_threads,
        rss_bucket,
        session_kind,
        has_tty,
        psi_cpu_avg10,
        cpu_rank: sys_ctx.cpu_rank,
        num_cores: sys_ctx.num_cores,
        rule_preliminary,
    })
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_driven_category_rules() {
        let cases = vec![
            ("gcc", NameCategory::Compiler),
            ("gcc-13", NameCategory::Compiler),
            ("g++", NameCategory::Compiler),
            ("clang", NameCategory::Compiler),
            ("clang++", NameCategory::Compiler),
            ("rustc", NameCategory::Compiler),
            ("cargo", NameCategory::Compiler),
            ("make", NameCategory::Compiler),
            ("ninja", NameCategory::Compiler),
            ("ffmpeg", NameCategory::Encoder),
            ("av1enc", NameCategory::Encoder),
            ("x264", NameCategory::Encoder),
            ("postgres", NameCategory::Database),
            ("mysqld", NameCategory::Database),
            ("redis-server", NameCategory::Database),
            ("isolated-web-co", NameCategory::BrowserHelper),
            ("Web Content", NameCategory::BrowserHelper),
            ("chrome", NameCategory::BrowserHelper),
            ("firefox", NameCategory::BrowserHelper),
            ("python", NameCategory::Interpreter),
            ("python3", NameCategory::Interpreter),
            ("python3.11", NameCategory::Interpreter),
            ("node", NameCategory::Interpreter),
            ("ruby", NameCategory::Interpreter),
            ("bash", NameCategory::Shell),
            ("zsh", NameCategory::Shell),
            ("gnome-shell", NameCategory::DesktopService),
            ("pipewire", NameCategory::DesktopService),
            ("Xorg", NameCategory::DesktopService),
            ("systemd", NameCategory::DesktopService),
            ("ollama", NameCategory::DesktopService),
            ("my-custom-app", NameCategory::Unknown),
        ];

        for (comm, expected) in cases {
            assert_eq!(
                categorize_comm(comm),
                expected,
                "failed categorization for comm: {comm}"
            );
        }
    }

    #[test]
    fn test_table_driven_trend() {
        let mut rising = VecDeque::new();
        for &v in &[10.0, 12.0, 15.0, 80.0, 85.0, 90.0] {
            rising.push_back(v);
        }
        assert_eq!(calculate_trend(&rising), CpuTrend::Rising);

        let mut falling = VecDeque::new();
        for &v in &[90.0, 88.0, 85.0, 20.0, 15.0, 10.0] {
            falling.push_back(v);
        }
        assert_eq!(calculate_trend(&falling), CpuTrend::Falling);

        let mut flat = VecDeque::new();
        for &v in &[50.0, 52.0, 48.0, 50.0, 51.0, 49.0] {
            flat.push_back(v);
        }
        assert_eq!(calculate_trend(&flat), CpuTrend::Flat);
    }

    #[test]
    fn test_table_driven_burstiness() {
        let mut steady = VecDeque::new();
        for &v in &[90.0, 91.0, 90.5, 89.5, 90.0, 90.2] {
            steady.push_back(v);
        }
        assert_eq!(calculate_burstiness(&steady), Burstiness::Steady);

        let mut spiky = VecDeque::new();
        for &v in &[10.0, 95.0, 15.0, 90.0, 12.0, 98.0] {
            spiky.push_back(v);
        }
        assert_eq!(calculate_burstiness(&spiky), Burstiness::Spiky);
    }

    #[test]
    fn test_table_driven_bucketing_and_proc_parsers() {
        // 1. Stat parsing
        let stat_fixture = "1234 (python3) S 1000 1234 1234 34816 1234 4194304 100 0 0 0 10 20 0 0 20 0 4 0 50000 1234567 890 18446744073709551615";
        let parsed_stat = parse_stat(stat_fixture).expect("valid stat line should parse");
        assert_eq!(parsed_stat.comm, "python3");
        assert_eq!(parsed_stat.ppid, 1000);
        assert_ne!(parsed_stat.tty_nr, 0);
        assert_eq!(parsed_stat.num_threads, 4);
        assert_eq!(parsed_stat.starttime, 50000);

        // 2. Age calculation
        let age = calculate_age_secs(parsed_stat.starttime, 600.0, 100);
        assert_eq!(age, 100); // 600 - 500 = 100

        // 3. Status RSS parsing & bucketing
        let small_status = "Name:\tsmall\nVmRSS:\t 50000 kB\n";
        let med_status = "Name:\tmed\nVmRSS:\t 500000 kB\n";
        let large_status = "Name:\tlarge\nVmRSS:\t 2000000 kB\n";

        assert_eq!(
            rss_bucket_from_kb(parse_status_rss_kb(small_status).unwrap()),
            RssBucket::Small
        );
        assert_eq!(
            rss_bucket_from_kb(parse_status_rss_kb(med_status).unwrap()),
            RssBucket::Medium
        );
        assert_eq!(
            rss_bucket_from_kb(parse_status_rss_kb(large_status).unwrap()),
            RssBucket::Large
        );

        // 4. Cgroup session parsing
        let user_cgroup = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app.scope\n";
        let sys_cgroup = "0::/system.slice/docker.service\n";
        let unknown_cgroup = "0::/\n";

        assert_eq!(parse_cgroup_session_kind(user_cgroup), SessionKind::UserApp);
        assert_eq!(
            parse_cgroup_session_kind(sys_cgroup),
            SessionKind::SystemService
        );
        assert_eq!(
            parse_cgroup_session_kind(unknown_cgroup),
            SessionKind::Unknown
        );

        // 5. PSI cpu parsing
        let psi_fixture = "some avg10=12.34 avg60=5.67 avg300=1.23 total=123456\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        assert_eq!(parse_psi_cpu_avg10(psi_fixture), Some(12.34));
    }

    #[test]
    fn test_privacy_serialized_prompt_contains_no_sensitive_data() {
        let brief = ProcessBrief {
            name: "python3".to_string(),
            name_category: NameCategory::Interpreter,
            parent_category: NameCategory::Shell,
            cpu_now: 98.0,
            cpu_avg_60s: 95.0,
            cpu_peak: 99.0,
            trend: CpuTrend::Flat,
            burstiness: Burstiness::Steady,
            sustained_secs: 45,
            age_secs: 120,
            thread_count: 2,
            rss_bucket: RssBucket::Medium,
            session_kind: SessionKind::UserApp,
            has_tty: true,
            psi_cpu_avg10: Some(10.5),
            cpu_rank: 1,
            num_cores: 8,
            rule_preliminary: RulePreliminary {
                class: Class::Runaway,
                confidence: 0.85,
                reasons: vec!["interpreter high sustained cpu".to_string()],
            },
        };

        let serialized = serde_json::to_string(&brief).expect("should serialize");

        // 1. Must never contain a slash '/' (no file paths or cgroup paths)
        assert!(
            !serialized.contains('/'),
            "serialized brief contains slash '/': {serialized}"
        );

        // 2. Must never contain cmdline or environment references
        let lower = serialized.to_ascii_lowercase();
        assert!(
            !lower.contains("cmdline"),
            "serialized brief contains cmdline: {serialized}"
        );
        assert!(
            !lower.contains("environ"),
            "serialized brief contains environ: {serialized}"
        );

        // 3. Must never contain current username
        if let Ok(user) = std::env::var("USER") {
            if !user.is_empty() {
                assert!(
                    !serialized.contains(&user),
                    "serialized brief contains username '{user}': {serialized}"
                );
            }
        }
    }

    #[test]
    fn test_missing_process_returns_no_brief_without_panic() {
        let sample = ProcessSample {
            pid: 99999999, // Non-existent PID
            comm: "defunct".to_string(),
            cpu_percent: 100.0,
            window_secs: 2,
            sustained_secs: 10,
        };
        let cfg = AiConfig::default();
        let sys_ctx = SystemContext {
            cpu_rank: 1,
            num_cores: 4,
            proc_root: Path::new("/nonexistent_proc_path"),
            pressure_path: Path::new("/nonexistent_pressure_path"),
            uptime_secs: 1000.0,
        };
        let brief = build_brief(&sample, None, &sys_ctx, &cfg);
        assert!(
            brief.is_none(),
            "non-existent PID must yield None ('no brief')"
        );
    }
}
