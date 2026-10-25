//! Policy Gate for sloth-daemon (Phase 5).
//!
//! Evaluates CPU samples, evidence briefs, AI verdicts, and current system state
//! to make deterministic decisions: `Throttle`, `Release`, or `None`.
//!
//! Golden rule:
//! - The AI proposes, the policy gate disposes.
//! - The AI verdict can only lower the chance of throttling or confirm a throttle
//!   justified by hard thresholds.
//! - The AI can NEVER bypass the protected list or never-throttle rules.
//! - Hysteresis: a throttled process is calm when its CPU stays below 50% of its
//!   quota for a configurable number of consecutive samples (`cool_down_samples`,
//!   default 5).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::ai_classifier::{Class, Verdict};
use crate::broker::ProcessBrief;
use crate::cgroup_manager::{matches_protected_name, BUILTIN_PROTECTED_NAMES};
use crate::{Config, ProcessSample, ThrottleAction};

/// Checks if a process is immune to throttling based on PID or protected name lists.
pub fn is_protected_process(pid: u32, comm: &str, extra_protected: &[String]) -> bool {
    if pid <= 1 {
        return true;
    }
    let mut all_patterns: Vec<String> = BUILTIN_PROTECTED_NAMES
        .iter()
        .map(|s| s.to_string())
        .collect();
    all_patterns.extend_from_slice(extra_protected);
    matches_protected_name(comm, &all_patterns)
}

// ============================================================================
// Policy State
// ============================================================================

/// State record for an actively throttled process.
#[derive(Debug, Clone, PartialEq)]
pub struct ThrottledProcess {
    pub pid: u32,
    pub comm: String,
    pub throttled_at: Instant,
    pub quota_pct: u8,
    /// Number of consecutive sample windows where CPU usage was below 50% of quota.
    pub calm_samples: u32,
}

/// In-memory policy state tracking active throttles and cool-down progression.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PolicyState {
    pub throttled: HashMap<u32, ThrottledProcess>,
}

impl PolicyState {
    pub fn new() -> Self {
        Self {
            throttled: HashMap::new(),
        }
    }

    pub fn is_throttled(&self, pid: u32) -> bool {
        self.throttled.contains_key(&pid)
    }

    pub fn throttled_count(&self) -> usize {
        self.throttled.len()
    }

    pub fn record_throttle(&mut self, pid: u32, comm: String, quota_pct: u8, now: Instant) {
        self.throttled.insert(
            pid,
            ThrottledProcess {
                pid,
                comm,
                throttled_at: now,
                quota_pct,
                calm_samples: 0,
            },
        );
    }

    pub fn record_release(&mut self, pid: u32) {
        self.throttled.remove(&pid);
    }

    /// Updates the calm sample counter for an existing throttle.
    pub fn update_calm(&mut self, pid: u32, is_below_calm_threshold: bool) {
        if let Some(record) = self.throttled.get_mut(&pid) {
            if is_below_calm_threshold {
                record.calm_samples = record.calm_samples.saturating_add(1);
            } else {
                record.calm_samples = 0;
            }
        }
    }

    /// Identifies throttled processes that have exited (no longer present in active samples).
    /// Removes them from the policy state and returns their PIDs.
    pub fn check_exited(&mut self, active_pids: &[u32]) -> Vec<(u32, &'static str)> {
        let mut exited = Vec::new();
        let throttled_pids: Vec<u32> = self.throttled.keys().copied().collect();
        for pid in throttled_pids {
            if !active_pids.contains(&pid) {
                self.throttled.remove(&pid);
                exited.push((pid, "process exited while throttled"));
            }
        }
        exited
    }
}

// ============================================================================
// Policy Decision Function
// ============================================================================

/// Evaluates a process sample and verdict against policy rules, returning
/// `ThrottleAction` and an explanatory reason string for structured logging.
pub fn decide_with_reason(
    sample: &ProcessSample,
    brief: Option<&ProcessBrief>,
    verdict: &Verdict,
    state: &PolicyState,
    config: &Config,
    now: Instant,
) -> (ThrottleAction, &'static str) {
    // ------------------------------------------------------------------------
    // CASE A: The process is CURRENTLY THROTTLED -> Evaluate Release
    // ------------------------------------------------------------------------
    if let Some(th) = state.throttled.get(&sample.pid) {
        // 1. Release if process became protected or matches never_throttle
        let is_protected =
            is_protected_process(sample.pid, &sample.comm, &config.protected.extra_names)
                || config
                    .ai
                    .never_throttle
                    .iter()
                    .any(|p| sample.comm == *p || sample.comm.starts_with(p))
                || brief.map(|b| b.is_never_throttle()).unwrap_or(false);

        if is_protected {
            return (
                ThrottleAction::Release { pid: sample.pid },
                "process became protected",
            );
        }

        // 2. Release if TTL expired
        let elapsed = now.duration_since(th.throttled_at);
        if elapsed >= Duration::from_secs(config.throttle.ttl_secs) {
            return (
                ThrottleAction::Release { pid: sample.pid },
                "throttle TTL expired",
            );
        }

        // 3. Hysteresis: calm threshold is 50% of assigned quota
        // E.g., if quota is 20%, calm threshold is 10.0% CPU.
        let calm_threshold = (th.quota_pct as f32) * 0.5;
        let is_calm_sample = sample.cpu_percent < calm_threshold;

        if is_calm_sample {
            // Check if this sample completes the cool-down requirement
            if th.calm_samples + 1 >= config.throttle.cool_down_samples {
                return (
                    ThrottleAction::Release { pid: sample.pid },
                    "calm for cool-down period below 50% quota",
                );
            } else {
                return (
                    ThrottleAction::None,
                    "calming down but cool-down incomplete",
                );
            }
        } else {
            // Process is still busy near or above quota
            return (ThrottleAction::None, "active at or near quota");
        }
    }

    // ------------------------------------------------------------------------
    // CASE B: The process is NOT THROTTLED -> Evaluate Throttle
    // ------------------------------------------------------------------------

    // 1. Safety Boundary: never throttle protected processes or never_throttle matches
    let is_protected =
        is_protected_process(sample.pid, &sample.comm, &config.protected.extra_names)
            || config
                .ai
                .never_throttle
                .iter()
                .any(|p| sample.comm == *p || sample.comm.starts_with(p))
            || brief.map(|b| b.is_never_throttle()).unwrap_or(false);

    if is_protected {
        return (
            ThrottleAction::None,
            "process is protected or never_throttle",
        );
    }

    // 2. Threshold check: CPU percentage must be above threshold
    if sample.cpu_percent < config.sampling.cpu_threshold_pct {
        return (ThrottleAction::None, "cpu below threshold");
    }

    // 3. Duration check: must be sustained above threshold long enough
    if sample.sustained_secs < config.sampling.sustained_secs {
        return (ThrottleAction::None, "cpu not sustained long enough");
    }

    // 4. AI Verdict checks:
    //    - verdict must recommend throttle
    //    - classification must be Runaway or Background
    //    - confidence must meet or exceed minimum threshold
    if !verdict.throttle_recommended {
        return (ThrottleAction::None, "ai does not recommend throttle");
    }

    let is_candidate_class = matches!(verdict.classification, Class::Runaway | Class::Background);
    if !is_candidate_class {
        return (
            ThrottleAction::None,
            "ai classification not runaway or background",
        );
    }

    if verdict.confidence < config.ai.min_confidence {
        return (ThrottleAction::None, "ai confidence below minimum");
    }

    // 5. Concurrency cap check
    if state.throttled_count() >= config.throttle.max_concurrent {
        return (ThrottleAction::None, "concurrency cap reached");
    }

    // 6. All conditions met: throttle the process (quota clamped to at least 5%)
    let quota_pct = config.throttle.quota_pct.max(5);
    (
        ThrottleAction::Throttle {
            pid: sample.pid,
            quota_pct,
        },
        "valid runaway workload justifies throttle",
    )
}

/// Pure policy gate entrypoint returning `ThrottleAction`.
pub fn decide(
    sample: &ProcessSample,
    brief: Option<&ProcessBrief>,
    verdict: &Verdict,
    state: &PolicyState,
    config: &Config,
    now: Instant,
) -> ThrottleAction {
    decide_with_reason(sample, brief, verdict, state, config, now).0
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::{
        Burstiness, CpuTrend, NameCategory, RssBucket, RulePreliminary, SessionKind,
    };

    fn test_config() -> Config {
        Config {
            dry_run: true,
            sampling: crate::SamplingConfig {
                interval_secs: 2,
                cpu_threshold_pct: 90.0,
                sustained_secs: 30,
            },
            throttle: crate::ThrottleConfig {
                quota_pct: 20,
                max_concurrent: 3,
                ttl_secs: 600,
                cool_down_samples: 5,
            },
            ai: crate::AiConfig {
                provider: "rules".to_string(),
                fallback_to_rules: false,
                ollama_url: "http://localhost:11434".to_string(),
                model: "llama3.2:3b".to_string(),
                timeout_secs: 10,
                min_confidence: 0.8,
                allow_remote_ollama: false,
                never_throttle: vec!["custom_compiler".to_string()],
                throttle_candidates: vec!["stress-ng".to_string()],
                candidates_confidence: 0.85,
            },
            protected: crate::ProtectedConfig {
                extra_names: vec!["critical_daemon".to_string()],
            },
        }
    }

    fn sample_hot() -> ProcessSample {
        ProcessSample {
            pid: 12345,
            comm: "stress-ng".to_string(),
            cpu_percent: 98.0,
            window_secs: 2,
            sustained_secs: 35,
        }
    }

    fn brief_for(sample: &ProcessSample, name_cat: NameCategory) -> ProcessBrief {
        ProcessBrief {
            name: sample.comm.clone(),
            name_category: name_cat,
            parent_category: NameCategory::Unknown,
            cpu_now: sample.cpu_percent,
            cpu_avg_60s: sample.cpu_percent,
            cpu_peak: sample.cpu_percent,
            trend: CpuTrend::Flat,
            burstiness: Burstiness::Steady,
            sustained_secs: sample.sustained_secs,
            age_secs: 100,
            thread_count: 1,
            rss_bucket: RssBucket::Small,
            session_kind: SessionKind::UserApp,
            has_tty: false,
            psi_cpu_avg10: None,
            cpu_rank: 1,
            num_cores: 4,
            rule_preliminary: RulePreliminary {
                class: Class::Runaway,
                confidence: 0.9,
                reasons: vec!["candidate runaway".to_string()],
            },
        }
    }

    fn verdict_runaway() -> Verdict {
        Verdict {
            classification: Class::Runaway,
            confidence: 0.9,
            throttle_recommended: true,
            reason: "runaway process".to_string(),
        }
    }

    #[test]
    fn test_table_driven_policy_decisions() {
        let config = test_config();
        let now = Instant::now();

        struct TestCase {
            name: &'static str,
            sample: ProcessSample,
            brief: Option<ProcessBrief>,
            verdict: Verdict,
            state: PolicyState,
            expected_action: ThrottleAction,
            expected_reason_substr: &'static str,
        }

        let cases = vec![
            // 1. Protected by PID 1
            TestCase {
                name: "PID 1 is never throttled",
                sample: ProcessSample {
                    pid: 1,
                    comm: "systemd".to_string(),
                    cpu_percent: 100.0,
                    sustained_secs: 60,
                    window_secs: 2,
                },
                brief: None,
                verdict: verdict_runaway(),
                state: PolicyState::new(),
                expected_action: ThrottleAction::None,
                expected_reason_substr: "protected",
            },
            // 2. Protected by system name (e.g. sshd)
            TestCase {
                name: "sshd is protected by default name list",
                sample: ProcessSample {
                    pid: 2222,
                    comm: "sshd".to_string(),
                    cpu_percent: 99.0,
                    sustained_secs: 60,
                    window_secs: 2,
                },
                brief: None,
                verdict: verdict_runaway(),
                state: PolicyState::new(),
                expected_action: ThrottleAction::None,
                expected_reason_substr: "protected",
            },
            // 3. Protected by extra_names config
            TestCase {
                name: "extra_names match is protected",
                sample: ProcessSample {
                    pid: 3333,
                    comm: "critical_daemon".to_string(),
                    cpu_percent: 99.0,
                    sustained_secs: 60,
                    window_secs: 2,
                },
                brief: None,
                verdict: verdict_runaway(),
                state: PolicyState::new(),
                expected_action: ThrottleAction::None,
                expected_reason_substr: "protected",
            },
            // 4. Protected by never_throttle config
            TestCase {
                name: "never_throttle match is protected",
                sample: ProcessSample {
                    pid: 4444,
                    comm: "custom_compiler".to_string(),
                    cpu_percent: 99.0,
                    sustained_secs: 60,
                    window_secs: 2,
                },
                brief: None,
                verdict: verdict_runaway(),
                state: PolicyState::new(),
                expected_action: ThrottleAction::None,
                expected_reason_substr: "protected",
            },
            // 5. Workload category is compiler in brief -> never_throttle
            TestCase {
                name: "compiler category is never throttled",
                sample: ProcessSample {
                    pid: 5555,
                    comm: "rustc".to_string(),
                    cpu_percent: 99.0,
                    sustained_secs: 60,
                    window_secs: 2,
                },
                brief: Some(brief_for(&sample_hot(), NameCategory::Compiler)),
                verdict: verdict_runaway(),
                state: PolicyState::new(),
                expected_action: ThrottleAction::None,
                expected_reason_substr: "never_throttle",
            },
            // 6. Below CPU threshold
            TestCase {
                name: "CPU below threshold is not throttled",
                sample: ProcessSample {
                    pid: 6666,
                    comm: "stress-ng".to_string(),
                    cpu_percent: 85.0, // below 90.0
                    sustained_secs: 60,
                    window_secs: 2,
                },
                brief: None,
                verdict: verdict_runaway(),
                state: PolicyState::new(),
                expected_action: ThrottleAction::None,
                expected_reason_substr: "below threshold",
            },
            // 7. Not sustained long enough
            TestCase {
                name: "Sustained seconds below config is not throttled",
                sample: ProcessSample {
                    pid: 7777,
                    comm: "stress-ng".to_string(),
                    cpu_percent: 99.0,
                    sustained_secs: 20, // below 30
                    window_secs: 2,
                },
                brief: None,
                verdict: verdict_runaway(),
                state: PolicyState::new(),
                expected_action: ThrottleAction::None,
                expected_reason_substr: "not sustained long enough",
            },
            // 8. Low AI confidence
            TestCase {
                name: "Low AI confidence is rejected",
                sample: sample_hot(),
                brief: None,
                verdict: Verdict {
                    classification: Class::Runaway,
                    confidence: 0.70, // below 0.8
                    throttle_recommended: true,
                    reason: "uncertain".to_string(),
                },
                state: PolicyState::new(),
                expected_action: ThrottleAction::None,
                expected_reason_substr: "confidence below minimum",
            },
            // 9. AI says do not throttle
            TestCase {
                name: "AI says throttle_recommended = false",
                sample: sample_hot(),
                brief: None,
                verdict: Verdict {
                    classification: Class::Runaway,
                    confidence: 0.95,
                    throttle_recommended: false,
                    reason: "skip".to_string(),
                },
                state: PolicyState::new(),
                expected_action: ThrottleAction::None,
                expected_reason_substr: "does not recommend throttle",
            },
            // 10. AI returns Essential
            TestCase {
                name: "AI classification is essential",
                sample: sample_hot(),
                brief: None,
                verdict: Verdict {
                    classification: Class::Essential,
                    confidence: 0.95,
                    throttle_recommended: false,
                    reason: "essential".to_string(),
                },
                state: PolicyState::new(),
                expected_action: ThrottleAction::None,
                expected_reason_substr: "does not recommend throttle",
            },
            // 11. Concurrency cap reached
            TestCase {
                name: "Concurrency cap reached prevents new throttle",
                sample: sample_hot(),
                brief: None,
                verdict: verdict_runaway(),
                state: {
                    let mut s = PolicyState::new();
                    s.record_throttle(101, "proc1".to_string(), 20, now);
                    s.record_throttle(102, "proc2".to_string(), 20, now);
                    s.record_throttle(103, "proc3".to_string(), 20, now);
                    s
                },
                expected_action: ThrottleAction::None,
                expected_reason_substr: "concurrency cap reached",
            },
            // 12. Valid throttle decision
            TestCase {
                name: "Valid runaway workload triggers throttle",
                sample: sample_hot(),
                brief: None,
                verdict: verdict_runaway(),
                state: PolicyState::new(),
                expected_action: ThrottleAction::Throttle {
                    pid: 12345,
                    quota_pct: 20,
                },
                expected_reason_substr: "justifies throttle",
            },
        ];

        for tc in cases {
            let (action, reason) = decide_with_reason(
                &tc.sample,
                tc.brief.as_ref(),
                &tc.verdict,
                &tc.state,
                &config,
                now,
            );
            assert_eq!(
                action, tc.expected_action,
                "Test '{}' failed: expected action {:?}, got {:?}",
                tc.name, tc.expected_action, action
            );
            assert!(
                reason.contains(tc.expected_reason_substr),
                "Test '{}' failed: reason '{}' does not contain '{}'",
                tc.name,
                reason,
                tc.expected_reason_substr
            );
        }
    }

    #[test]
    fn test_hysteresis_no_flapping_at_quota() {
        let config = test_config();
        let now = Instant::now();

        // Process is throttled to 20% quota
        let mut state = PolicyState::new();
        state.record_throttle(999, "stuck_worker".to_string(), 20, now);

        // When pinned at quota (e.g. 19.5% or 20.0% CPU):
        // 50% of 20% quota is 10.0%. CPU is 19.5% >= 10.0%.
        // It must NOT be released! Action must be None (no flapping).
        let pinned_sample = ProcessSample {
            pid: 999,
            comm: "stuck_worker".to_string(),
            cpu_percent: 19.5,
            sustained_secs: 60,
            window_secs: 2,
        };

        for _ in 0..10 {
            let (action, reason) = decide_with_reason(
                &pinned_sample,
                None,
                &verdict_runaway(),
                &state,
                &config,
                now,
            );
            assert_eq!(
                action,
                ThrottleAction::None,
                "Process pinned at quota must not flap into release"
            );
            assert_eq!(reason, "active at or near quota");
            state.update_calm(999, pinned_sample.cpu_percent < 10.0);
        }

        // Calm samples counter should remain 0
        assert_eq!(state.throttled.get(&999).unwrap().calm_samples, 0);
    }

    #[test]
    fn test_hysteresis_release_after_cool_down() {
        let config = test_config(); // cool_down_samples = 5, quota = 20% -> calm threshold = 10%
        let now = Instant::now();

        let mut state = PolicyState::new();
        state.record_throttle(999, "stuck_worker".to_string(), 20, now);

        let calm_sample = ProcessSample {
            pid: 999,
            comm: "stuck_worker".to_string(),
            cpu_percent: 5.0, // < 10.0%
            sustained_secs: 60,
            window_secs: 2,
        };

        // Samples 1 through 4: cool-down in progress, must NOT release yet
        for i in 1..=4 {
            let (action, reason) =
                decide_with_reason(&calm_sample, None, &verdict_runaway(), &state, &config, now);
            assert_eq!(
                action,
                ThrottleAction::None,
                "Sample {i}: should not release before cool-down completes"
            );
            assert_eq!(reason, "calming down but cool-down incomplete");
            state.update_calm(999, true);
            assert_eq!(state.throttled.get(&999).unwrap().calm_samples, i);
        }

        // Sample 5: completes cool_down_samples (5) -> triggers Release!
        let (action, reason) =
            decide_with_reason(&calm_sample, None, &verdict_runaway(), &state, &config, now);
        assert_eq!(
            action,
            ThrottleAction::Release { pid: 999 },
            "Sample 5: should trigger Release after 5 calm samples"
        );
        assert!(reason.contains("cool-down period"));
    }

    #[test]
    fn test_hysteresis_spike_resets_calm_counter() {
        let config = test_config();
        let now = Instant::now();

        let mut state = PolicyState::new();
        state.record_throttle(999, "stuck_worker".to_string(), 20, now);

        // 3 calm samples
        for _ in 0..3 {
            state.update_calm(999, true);
        }
        assert_eq!(state.throttled.get(&999).unwrap().calm_samples, 3);

        // A spike near quota (18% CPU >= 10%)
        let spike_sample = ProcessSample {
            pid: 999,
            comm: "stuck_worker".to_string(),
            cpu_percent: 18.0,
            sustained_secs: 60,
            window_secs: 2,
        };
        let (action, _) = decide_with_reason(
            &spike_sample,
            None,
            &verdict_runaway(),
            &state,
            &config,
            now,
        );
        assert_eq!(action, ThrottleAction::None);
        state.update_calm(999, false);

        // Counter reset to 0
        assert_eq!(state.throttled.get(&999).unwrap().calm_samples, 0);
    }

    #[test]
    fn test_ttl_expiry_releases_throttle() {
        let config = test_config(); // ttl_secs = 600
        let past = Instant::now();
        let future = past + Duration::from_secs(601);

        let mut state = PolicyState::new();
        state.record_throttle(999, "stuck_worker".to_string(), 20, past);

        let busy_sample = ProcessSample {
            pid: 999,
            comm: "stuck_worker".to_string(),
            cpu_percent: 20.0,
            sustained_secs: 650,
            window_secs: 2,
        };

        let (action, reason) = decide_with_reason(
            &busy_sample,
            None,
            &verdict_runaway(),
            &state,
            &config,
            future,
        );
        assert_eq!(action, ThrottleAction::Release { pid: 999 });
        assert_eq!(reason, "throttle TTL expired");
    }

    #[test]
    fn test_becoming_protected_releases_throttle() {
        let config = test_config();
        let now = Instant::now();

        let mut state = PolicyState::new();
        // Was throttled under an unknown name
        state.record_throttle(999, "custom_compiler".to_string(), 20, now);

        // Process comm matches never_throttle list in config
        let sample = ProcessSample {
            pid: 999,
            comm: "custom_compiler".to_string(),
            cpu_percent: 20.0,
            sustained_secs: 50,
            window_secs: 2,
        };

        let (action, reason) =
            decide_with_reason(&sample, None, &verdict_runaway(), &state, &config, now);
        assert_eq!(action, ThrottleAction::Release { pid: 999 });
        assert_eq!(reason, "process became protected");
    }

    #[test]
    fn test_check_exited_removes_dead_processes() {
        let mut state = PolicyState::new();
        let now = Instant::now();
        state.record_throttle(1001, "proc1".to_string(), 20, now);
        state.record_throttle(1002, "proc2".to_string(), 20, now);

        // Only 1001 is still active
        let active = vec![1001, 1003];
        let exited = state.check_exited(&active);

        assert_eq!(exited.len(), 1);
        assert_eq!(exited[0].0, 1002);
        assert!(!state.is_throttled(1002));
        assert!(state.is_throttled(1001));
    }
}
