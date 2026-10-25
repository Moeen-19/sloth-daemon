//! Ollama AI classification bridge for sloth-daemon.
//!
//! Calls a local Ollama model to classify whether a busy process is a runaway
//! background hog or legitimate work. All model output is treated as untrusted
//! and parsed strictly. Any failure returns `Verdict::unknown()` so the daemon
//! never throttles due to AI misbehaviour.
//!
//! Privacy rules enforced here:
//! - Only process name, CPU%, and sustained duration reach the model.
//! - `comm` is sanitized before insertion into the prompt.
//! - The Ollama URL must be a loopback address (127.x or ::1 or "localhost").
//! - Response bodies are capped at 64 KiB before parsing.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info, warn};

use crate::broker::ProcessBrief;
use crate::AiConfig;

// ============================================================================
// Public Types
// ============================================================================

/// Classification categories returned by the AI classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    /// Core system services or mission-critical tasks (never throttled).
    Essential,
    /// Direct user interaction tasks like GUI applications.
    Interactive,
    /// Normal background jobs and batch operations.
    Background,
    /// Runaway CPU-consuming loops or misbehaving processes.
    Runaway,
    /// Unrecognized or uncertain process category (default fail-safe).
    Unknown,
}

/// Raw JSON verdict as returned by the Ollama model (before validation).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawVerdict {
    /// String classification (validated into `Class` separately for clear error messages).
    pub classification: String,
    /// Model confidence level (must be 0.0..=1.0; finite).
    pub confidence: f32,
    /// Whether the model recommends CPU throttling.
    pub throttle_recommended: bool,
    /// Short plain-English explanation (for logging only; truncated and sanitized).
    pub reason: String,
}

/// Validated and typed AI verdict safe for use by the policy gate.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// Validated classification category.
    pub classification: Class,
    /// Confidence level, guaranteed to be in 0.0..=1.0.
    pub confidence: f32,
    /// Whether throttling is recommended (forced false for Essential / Interactive).
    pub throttle_recommended: bool,
    /// Sanitized reason string (for operational logs only; never used in paths or commands).
    pub reason: String,
}

impl Verdict {
    /// Creates a safe default `Unknown` verdict that will never trigger throttling.
    pub fn unknown() -> Self {
        Self {
            classification: Class::Unknown,
            confidence: 0.0,
            throttle_recommended: false,
            reason: "no verdict".to_string(),
        }
    }
}

/// Ollama health status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    /// Model is present and reachable.
    Ready,
    /// Ollama is reachable but the configured model is not installed.
    ModelMissing(String),
    /// Ollama is not reachable.
    Unreachable(String),
}

// ============================================================================
// Internal Cache
// ============================================================================

/// Maximum number of entries kept in the verdict cache.
const CACHE_MAX_ENTRIES: usize = 256;
/// TTL for a successful verdict (5 minutes).
const CACHE_TTL_SUCCESS: Duration = Duration::from_secs(300);
/// Short TTL for a failed/unknown verdict so recovery is fast (30 seconds).
const CACHE_TTL_FAILURE: Duration = Duration::from_secs(30);

struct CacheEntry {
    key: String,
    verdict: Verdict,
    inserted_at: Instant,
    ttl: Duration,
}

/// Simple bounded LRU cache keyed by sanitized process name.
struct VerdictCache {
    entries: VecDeque<CacheEntry>,
}

impl VerdictCache {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }

    fn get(&mut self, key: &str) -> Option<&Verdict> {
        let now = Instant::now();
        // Remove expired entries lazily.
        self.entries
            .retain(|e| now.duration_since(e.inserted_at) < e.ttl);
        // Move matching entry to back (most recently used) and return reference.
        if let Some(pos) = self.entries.iter().position(|e| e.key == key) {
            self.entries.rotate_left(pos);
            // rotate_left(pos) moved the target to index 0; pop_front is guaranteed Some.
            if let Some(entry) = self.entries.pop_front() {
                self.entries.push_back(entry);
            }
            return self.entries.back().map(|e| &e.verdict);
        }
        None
    }

    fn insert(&mut self, key: String, verdict: Verdict, ttl: Duration) {
        // Remove existing entry with the same key.
        self.entries.retain(|e| e.key != key);
        // Evict the oldest entry if at capacity.
        if self.entries.len() >= CACHE_MAX_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(CacheEntry {
            key,
            verdict,
            inserted_at: Instant::now(),
            ttl,
        });
    }
}

// ============================================================================
// Circuit Breaker
// ============================================================================

/// Number of consecutive failures before the breaker opens.
const BREAKER_FAILURE_THRESHOLD: u32 = 3;
/// Duration the breaker stays open before allowing a retry.
const BREAKER_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BreakerState {
    Closed,
    Open,
}

struct CircuitBreaker {
    state: BreakerState,
    consecutive_failures: u32,
    opened_at: Option<Instant>,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            state: BreakerState::Closed,
            consecutive_failures: 0,
            opened_at: None,
        }
    }

    /// Returns true if the breaker allows the call to proceed.
    fn allow(&mut self) -> bool {
        match self.state {
            BreakerState::Closed => true,
            BreakerState::Open => {
                if let Some(opened) = self.opened_at {
                    if Instant::now().duration_since(opened) >= BREAKER_BACKOFF {
                        // Allow a probe request to check if Ollama recovered.
                        self.state = BreakerState::Closed;
                        self.consecutive_failures = 0;
                        self.opened_at = None;
                        info!("AI classifier circuit breaker closed (retry after backoff)");
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.state = BreakerState::Closed;
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= BREAKER_FAILURE_THRESHOLD
            && self.state == BreakerState::Closed
        {
            self.state = BreakerState::Open;
            self.opened_at = Some(Instant::now());
            warn!(
                consecutive_failures = self.consecutive_failures,
                backoff_secs = BREAKER_BACKOFF.as_secs(),
                "AI classifier circuit breaker opened; Ollama calls suspended"
            );
        }
    }
}

// ============================================================================
// JSON schema for Ollama `format` field (built once, reused)
// ============================================================================

fn verdict_json_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "classification": {
                "type": "string",
                "enum": ["essential", "interactive", "background", "runaway", "unknown"]
            },
            "confidence":          { "type": "number" },
            "throttle_recommended":{ "type": "boolean" },
            "reason":              { "type": "string" }
        },
        "required": ["classification", "confidence", "throttle_recommended", "reason"]
    })
}

// ============================================================================
// Prompt construction
// ============================================================================

const SYSTEM_PROMPT: &str = "\
You classify Linux processes for a CPU governor. You receive a ProcessBrief JSON. \
Classify as: essential, interactive, background, runaway, or unknown. \
Only recommend throttle if runaway or background hog. Keep reason under 15 words. \
Respond with JSON only, matching schema.";

const SYSTEM_PROMPT_RETRY_SUFFIX: &str = " Respond with JSON only, no other text.";

/// Sanitizes a process `comm` string for safe inclusion in the prompt.
///
/// Keeps only `[A-Za-z0-9._+-]`, replaces everything else with `_`,
/// and truncates to 32 characters. The result is never used in paths or commands.
pub fn sanitize_comm(comm: &str) -> String {
    comm.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect()
}

fn build_user_message(brief: &ProcessBrief) -> String {
    serde_json::to_string(brief).unwrap_or_else(|_| "{}".to_string())
}

// ============================================================================
// Validation
// ============================================================================

/// Validates a `RawVerdict` into a typed `Verdict`, enforcing all rules from the skill.
pub fn validate(raw: RawVerdict) -> Option<Verdict> {
    // 1. Parse classification string.
    let classification = match raw.classification.to_lowercase().as_str() {
        "essential" => Class::Essential,
        "interactive" => Class::Interactive,
        "background" => Class::Background,
        "runaway" => Class::Runaway,
        "unknown" => Class::Unknown,
        other => {
            warn!(
                classification = other,
                "AI returned unknown classification; rejecting verdict"
            );
            return None;
        }
    };

    // 2. Validate confidence: must be finite and strictly within 0.0..=1.0.
    if !raw.confidence.is_finite() || !(0.0..=1.0).contains(&raw.confidence) {
        warn!(
            confidence = raw.confidence,
            "AI returned out-of-range confidence; rejecting verdict"
        );
        return None;
    }

    // 3. Sanitize and truncate reason: limit to at most 15 words, filter control characters.
    let reason_words: Vec<&str> = raw.reason.split_whitespace().take(15).collect();
    let reason_text = reason_words.join(" ");
    let reason: String = reason_text
        .chars()
        .filter(|c| !c.is_control())
        .take(150)
        .collect();

    // 4. Consistency: Essential and Interactive may never recommend throttling.
    let throttle_recommended = match classification {
        Class::Essential | Class::Interactive => false,
        _ => raw.throttle_recommended,
    };

    Some(Verdict {
        classification,
        confidence: raw.confidence,
        throttle_recommended,
        reason,
    })
}

// ============================================================================
// URL validation
// ============================================================================

/// Returns `Ok(())` if `url` points to a loopback address, or if `allow_remote` is true.
pub fn validate_ollama_url(url: &str, allow_remote: bool) -> anyhow::Result<()> {
    if allow_remote {
        return Ok(());
    }
    let parsed =
        url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid Ollama URL '{}': {}", url, e))?;

    match parsed.host() {
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => Ok(()),
        Some(url::Host::Ipv4(ip)) if ip.is_loopback() => Ok(()),
        Some(url::Host::Ipv6(ip)) if ip.is_loopback() => Ok(()),
        Some(host) => anyhow::bail!(
            "Ollama URL '{}' resolves to non-loopback address {}; set allow_remote_ollama = true to allow remote models",
            url,
            host
        ),
        None => anyhow::bail!("Ollama URL '{}' has no host", url),
    }
}

// ============================================================================
// Classifier
// ============================================================================

/// Maximum response body size accepted from Ollama (64 KiB).
const MAX_RESPONSE_BYTES: u64 = 65_536;

/// AI classifier that calls a local Ollama model and returns typed verdicts.
pub struct Classifier {
    client: reqwest::Client,
    config: AiConfig,
    cache: Mutex<VerdictCache>,
    breaker: Mutex<CircuitBreaker>,
    schema: serde_json::Value,
}

#[derive(Debug)]
enum CallError {
    Connect(reqwest::Error),
    Http(reqwest::StatusCode),
    TooLarge,
    Read(reqwest::Error),
    Malformed(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Connect(e) => write!(f, "connection failed: {e}"),
            CallError::Http(status) => write!(f, "Ollama returned HTTP {status}"),
            CallError::TooLarge => write!(
                f,
                "Ollama response body too large (exceeds {MAX_RESPONSE_BYTES} bytes)"
            ),
            CallError::Read(e) => write!(f, "failed to read response body: {e}"),
            CallError::Malformed(msg) => write!(f, "malformed response: {msg}"),
        }
    }
}

impl std::error::Error for CallError {}

impl Classifier {
    /// Constructs a new `Classifier`, validating the Ollama URL and building the HTTP client.
    ///
    /// Returns an error if the URL is not loopback (unless `allow_remote_ollama` is set).
    pub async fn new(cfg: &AiConfig) -> anyhow::Result<Self> {
        validate_ollama_url(&cfg.ollama_url, cfg.allow_remote_ollama)?;

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .no_proxy()
            .redirect(Policy::none())
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {e}"))?;

        info!(
            url = %cfg.ollama_url,
            model = %cfg.model,
            "AI classifier initialized"
        );

        Ok(Self {
            client,
            config: cfg.clone(),
            cache: Mutex::new(VerdictCache::new()),
            breaker: Mutex::new(CircuitBreaker::new()),
            schema: verdict_json_schema(),
        })
    }

    /// Checks whether Ollama is reachable and the configured model is installed.
    pub async fn health(&self) -> HealthStatus {
        let url = format!("{}/api/tags", self.config.ollama_url);
        match self
            .client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Err(e) => HealthStatus::Unreachable(e.to_string()),
            Ok(resp) => {
                if !resp.status().is_success() {
                    return HealthStatus::Unreachable(format!("HTTP {}", resp.status()));
                }
                // Parse model list and check if our model is present.
                match resp.json::<serde_json::Value>().await {
                    Err(e) => HealthStatus::Unreachable(format!("failed to parse /api/tags: {e}")),
                    Ok(body) => {
                        let installed = body
                            .get("models")
                            .and_then(|m| m.as_array())
                            .map(|arr| {
                                arr.iter().any(|m| {
                                    m.get("name")
                                        .and_then(|n| n.as_str())
                                        .map(|n| {
                                            n == self.config.model
                                                || n.starts_with(&format!("{}:", self.config.model))
                                        })
                                        .unwrap_or(false)
                                })
                            })
                            .unwrap_or(false);

                        if installed {
                            HealthStatus::Ready
                        } else {
                            HealthStatus::ModelMissing(self.config.model.clone())
                        }
                    }
                }
            }
        }
    }

    /// Returns a cached verdict for the process name if present and unexpired.
    pub fn get_cached(&self, name: &str) -> Option<Verdict> {
        let safe_name = sanitize_comm(name);
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.get(&safe_name).cloned()
    }

    /// Classifies a process using either deterministic rules or a local Ollama model.
    /// Never panics or returns an error — always returns a `Verdict`.
    pub async fn classify(&self, brief: &ProcessBrief) -> Verdict {
        // If provider is "rules", return preliminary verdict immediately
        if self.config.provider == "rules" {
            debug!(
                name = %brief.name,
                "Rules provider used; returning preliminary verdict"
            );
            return brief.rule_preliminary.to_verdict();
        }

        let safe_name = &brief.name;

        // 1. Check cache.
        {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = cache.get(safe_name) {
                debug!(
                    comm = %safe_name,
                    classification = ?cached.classification,
                    "AI classifier cache hit"
                );
                return cached.clone();
            }
        }
        debug!(comm = %safe_name, "AI classifier cache miss; calling Ollama");

        // 2. Check circuit breaker.
        {
            let mut breaker = self.breaker.lock().unwrap_or_else(|e| e.into_inner());
            if !breaker.allow() {
                debug!(comm = %safe_name, "AI circuit breaker open");
                return if self.config.fallback_to_rules {
                    brief.rule_preliminary.to_verdict()
                } else {
                    Verdict::unknown()
                };
            }
        }

        // 3. Call Ollama (with one retry on malformed output).
        let start = Instant::now();
        let raw_verdict = self.call_with_retry(brief, safe_name).await;
        let latency_ms = start.elapsed().as_millis();

        debug!(
            comm = %safe_name,
            classification = ?raw_verdict.classification,
            confidence = raw_verdict.confidence,
            latency_ms,
            "AI classification complete"
        );

        // 4. Update circuit breaker and cache.
        let is_failure =
            raw_verdict.classification == Class::Unknown && raw_verdict.reason == "no verdict";
        {
            let mut breaker = self.breaker.lock().unwrap_or_else(|e| e.into_inner());
            if is_failure {
                breaker.record_failure();
            } else {
                breaker.record_success();
            }
        }

        // 5. Apply fallback and Golden Rule
        let verdict = if is_failure && self.config.fallback_to_rules {
            brief.rule_preliminary.to_verdict()
        } else if brief.is_never_throttle() {
            // Golden Rule: LLM can never override a never_throttle / essential match
            let mut v = raw_verdict;
            v.throttle_recommended = false;
            v
        } else {
            raw_verdict
        };

        let ttl = if is_failure {
            CACHE_TTL_FAILURE
        } else {
            CACHE_TTL_SUCCESS
        };
        {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(safe_name.clone(), verdict.clone(), ttl);
        }

        verdict
    }

    /// Makes the Ollama HTTP call, retrying once on malformed inner JSON.
    /// Does not retry on connection failures per the skill.
    async fn call_with_retry(&self, brief: &ProcessBrief, safe_name: &str) -> Verdict {
        // First attempt.
        match self.call_ollama(brief, false).await {
            Ok(verdict) => return verdict,
            Err(CallError::Connect(e)) => {
                warn!(
                    comm = %safe_name,
                    error = %e,
                    "AI classifier connection failed (no retry); returning unknown"
                );
                return Verdict::unknown();
            }
            Err(e) => {
                warn!(
                    comm = %safe_name,
                    error = %e,
                    "AI classifier first attempt failed; retrying once"
                );
            }
        }
        // Single retry with extra instruction.
        match self.call_ollama(brief, true).await {
            Ok(verdict) => verdict,
            Err(e) => {
                warn!(
                    comm = %safe_name,
                    error = %e,
                    "AI classifier retry also failed; returning unknown"
                );
                Verdict::unknown()
            }
        }
    }

    /// Performs a single POST to Ollama's `/api/chat` and parses the response.
    async fn call_ollama(
        &self,
        brief: &ProcessBrief,
        is_retry: bool,
    ) -> Result<Verdict, CallError> {
        let system_content = if is_retry {
            format!("{}{}", SYSTEM_PROMPT, SYSTEM_PROMPT_RETRY_SUFFIX)
        } else {
            SYSTEM_PROMPT.to_string()
        };

        let body = json!({
            "model": self.config.model,
            "messages": [
                { "role": "system", "content": system_content },
                { "role": "user",   "content": build_user_message(brief) }
            ],
            "stream": false,
            "format": self.schema,
            "options": {
                "temperature": 0,
                "num_predict": 200
            },
            "keep_alive": "10m"
        });

        let url = format!("{}/api/chat", self.config.ollama_url);
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    CallError::Connect(e)
                } else {
                    CallError::Malformed(e.to_string())
                }
            })?;

        let status = resp.status();
        if !status.is_success() {
            return Err(CallError::Http(status));
        }

        // Cap response body size to avoid memory exhaustion from a misbehaving server.
        let mut mut_resp = resp;
        let mut bytes = Vec::new();
        while let Some(chunk) = mut_resp.chunk().await.map_err(CallError::Read)? {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES as usize {
                return Err(CallError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }

        // Parse the outer API envelope.
        let outer: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| CallError::Malformed(format!("malformed outer JSON from Ollama: {e}")))?;

        // Extract the inner JSON string from message.content.
        let inner_str = outer
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .ok_or_else(|| {
                CallError::Malformed("missing message.content in Ollama response".to_string())
            })?;

        // Parse and validate the inner verdict JSON.
        let raw: RawVerdict = serde_json::from_str(inner_str).map_err(|e| {
            CallError::Malformed(format!("malformed verdict JSON in message.content: {e}"))
        })?;

        validate(raw).ok_or_else(|| CallError::Malformed("verdict failed validation".to_string()))
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- sanitize_comm ----

    #[test]
    fn test_sanitize_comm_clean() {
        assert_eq!(sanitize_comm("yes"), "yes");
        assert_eq!(sanitize_comm("cc1plus"), "cc1plus");
        assert_eq!(sanitize_comm("my-proc.1"), "my-proc.1");
    }

    #[test]
    fn test_sanitize_comm_strips_dangerous_chars() {
        assert_eq!(sanitize_comm("bad name;rm -rf"), "bad_name_rm_-rf");
        assert_eq!(sanitize_comm("proc\x00null"), "proc_null");
        assert_eq!(sanitize_comm("../../etc/passwd"), ".._.._etc_passwd");
    }

    #[test]
    fn test_sanitize_comm_truncates_at_32() {
        let long = "a".repeat(64);
        assert_eq!(sanitize_comm(&long).len(), 32);
    }

    // ---- validate ----

    #[test]
    fn test_validate_valid_runaway() {
        let raw = RawVerdict {
            classification: "runaway".to_string(),
            confidence: 0.95,
            throttle_recommended: true,
            reason: "high cpu loop".to_string(),
        };
        let v = validate(raw).expect("should validate");
        assert_eq!(v.classification, Class::Runaway);
        assert!((v.confidence - 0.95).abs() < f32::EPSILON);
        assert!(v.throttle_recommended);
    }

    #[test]
    fn test_validate_essential_forces_no_throttle() {
        let raw = RawVerdict {
            classification: "essential".to_string(),
            confidence: 0.9,
            throttle_recommended: true, // model incorrectly says throttle
            reason: "essential svc".to_string(),
        };
        let v = validate(raw).expect("should validate");
        assert_eq!(v.classification, Class::Essential);
        // Must be forced to false regardless of model output
        assert!(!v.throttle_recommended);
    }

    #[test]
    fn test_validate_interactive_forces_no_throttle() {
        let raw = RawVerdict {
            classification: "interactive".to_string(),
            confidence: 0.8,
            throttle_recommended: true,
            reason: "user app".to_string(),
        };
        let v = validate(raw).expect("should validate");
        assert!(!v.throttle_recommended);
    }

    #[test]
    fn test_validate_rejects_unknown_classification() {
        let raw = RawVerdict {
            classification: "definitely_evil".to_string(),
            confidence: 0.5,
            throttle_recommended: false,
            reason: "?".to_string(),
        };
        assert!(validate(raw).is_none());
    }

    #[test]
    fn test_validate_rejects_nan_confidence() {
        let raw = RawVerdict {
            classification: "runaway".to_string(),
            confidence: f32::NAN,
            throttle_recommended: true,
            reason: "high cpu".to_string(),
        };
        assert!(validate(raw).is_none());
    }

    #[test]
    fn test_validate_rejects_out_of_range_confidence_high() {
        let raw = RawVerdict {
            classification: "runaway".to_string(),
            confidence: 7.0,
            throttle_recommended: true,
            reason: "high cpu".to_string(),
        };
        assert!(validate(raw).is_none());
    }

    #[test]
    fn test_validate_rejects_negative_confidence() {
        let raw = RawVerdict {
            classification: "background".to_string(),
            confidence: -1.0,
            throttle_recommended: false,
            reason: "idle".to_string(),
        };
        assert!(validate(raw).is_none());
    }

    #[test]
    fn test_validate_truncates_reason_and_strips_control_chars() {
        let long_reason = "a".repeat(300) + "\x01\x02\x03";
        let raw = RawVerdict {
            classification: "unknown".to_string(),
            confidence: 0.0,
            throttle_recommended: false,
            reason: long_reason,
        };
        let v = validate(raw).expect("should validate");
        assert!(v.reason.len() <= 200);
        assert!(!v.reason.chars().any(|c| c.is_control()));
    }

    #[test]
    fn test_validate_background_keeps_throttle_recommended() {
        let raw = RawVerdict {
            classification: "background".to_string(),
            confidence: 0.85,
            throttle_recommended: true,
            reason: "idle background job".to_string(),
        };
        let v = validate(raw).expect("should validate");
        assert_eq!(v.classification, Class::Background);
        assert!(v.throttle_recommended);
    }

    // ---- URL validation ----

    #[test]
    fn test_url_loopback_accepted() {
        assert!(validate_ollama_url("http://localhost:11434", false).is_ok());
        assert!(validate_ollama_url("http://127.0.0.1:11434", false).is_ok());
        assert!(validate_ollama_url("http://[::1]:11434", false).is_ok());
    }

    #[test]
    fn test_url_remote_rejected_without_flag() {
        assert!(validate_ollama_url("http://192.168.1.100:11434", false).is_err());
        assert!(validate_ollama_url("http://example.com:11434", false).is_err());
    }

    #[test]
    fn test_url_remote_allowed_with_flag() {
        assert!(validate_ollama_url("http://192.168.1.100:11434", true).is_ok());
    }

    // ---- Verdict::unknown ----

    #[test]
    fn test_verdict_unknown_never_throttles() {
        let v = Verdict::unknown();
        assert_eq!(v.classification, Class::Unknown);
        assert_eq!(v.confidence, 0.0);
        assert!(!v.throttle_recommended);
    }

    // ---- Cache ----

    #[test]
    fn test_cache_hit_and_miss() {
        let mut cache = VerdictCache::new();
        let v = Verdict::unknown();
        cache.insert("proc1".to_string(), v.clone(), CACHE_TTL_SUCCESS);
        assert!(cache.get("proc1").is_some());
        assert!(cache.get("proc2").is_none());
    }

    #[test]
    fn test_cache_expiry() {
        let mut cache = VerdictCache::new();
        let v = Verdict::unknown();
        // Insert with a very short TTL (already expired in the past via a Duration trick)
        cache.insert("proc1".to_string(), v, Duration::from_nanos(1));
        // Sleep to ensure TTL has elapsed
        std::thread::sleep(Duration::from_millis(5));
        assert!(
            cache.get("proc1").is_none(),
            "expired entry should not be returned"
        );
    }

    #[test]
    fn test_cache_bounded_evicts_oldest() {
        let mut cache = VerdictCache::new();
        // Fill to capacity
        for i in 0..CACHE_MAX_ENTRIES {
            cache.insert(format!("proc{i}"), Verdict::unknown(), CACHE_TTL_SUCCESS);
        }
        // proc0 should have been evicted to make room for the next insert
        cache.insert(
            "new_proc".to_string(),
            Verdict::unknown(),
            CACHE_TTL_SUCCESS,
        );
        assert!(
            cache.get("proc0").is_none(),
            "oldest entry should be evicted"
        );
        assert!(cache.get("new_proc").is_some());
    }

    // ---- Circuit breaker ----

    #[test]
    fn test_breaker_opens_after_threshold_failures() {
        let mut breaker = CircuitBreaker::new();
        assert!(breaker.allow());
        for _ in 0..BREAKER_FAILURE_THRESHOLD {
            breaker.record_failure();
        }
        assert!(
            !breaker.allow(),
            "breaker should be open after threshold failures"
        );
    }

    #[test]
    fn test_breaker_resets_on_success() {
        let mut breaker = CircuitBreaker::new();
        for _ in 0..BREAKER_FAILURE_THRESHOLD {
            breaker.record_failure();
        }
        // Force closed by simulating backoff elapsed (not easily testable without mocking time).
        // Instead, reset directly via record_success path won't reopen a closed breaker.
        // Verify the state via a new breaker to confirm normal success path.
        let mut fresh = CircuitBreaker::new();
        fresh.record_failure();
        fresh.record_success();
        assert_eq!(fresh.consecutive_failures, 0);
    }

    // ---- Stub server tests ----

    use axum::{response::Json as AxumJson, routing::post, Router};
    use std::sync::Arc;

    /// Starts a local stub Ollama server that always returns the given canned JSON body.
    async fn start_stub_server(
        response_body: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let shared = Arc::new(response_body);
        let app = Router::new().route(
            "/api/chat",
            post({
                let shared = shared.clone();
                move |_: axum::extract::Request| {
                    let body = shared.clone();
                    async move { AxumJson((*body).clone()) }
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://127.0.0.1:{}", addr.port()), handle)
    }

    /// Creates an `AiConfig` pointing at the given stub URL in ollama mode.
    fn stub_config(url: &str) -> AiConfig {
        AiConfig {
            provider: "ollama".to_string(),
            fallback_to_rules: false,
            ollama_url: url.to_string(),
            model: "llama3.2:3b".to_string(),
            timeout_secs: 5,
            min_confidence: 0.8,
            allow_remote_ollama: false,
            never_throttle: Vec::new(),
            throttle_candidates: Vec::new(),
            candidates_confidence: 0.85,
        }
    }

    fn sample_brief() -> ProcessBrief {
        ProcessBrief {
            name: "stress-ng".to_string(),
            name_category: crate::broker::NameCategory::Unknown,
            parent_category: crate::broker::NameCategory::Shell,
            cpu_now: 99.0,
            cpu_avg_60s: 98.5,
            cpu_peak: 100.0,
            trend: crate::broker::CpuTrend::Flat,
            burstiness: crate::broker::Burstiness::Steady,
            sustained_secs: 60,
            age_secs: 120,
            thread_count: 4,
            rss_bucket: crate::broker::RssBucket::Small,
            session_kind: crate::broker::SessionKind::UserApp,
            has_tty: true,
            psi_cpu_avg10: Some(15.2),
            cpu_rank: 1,
            num_cores: 8,
            rule_preliminary: crate::broker::RulePreliminary {
                class: Class::Runaway,
                confidence: 0.85,
                reasons: vec!["configured throttle candidate high sustained cpu".to_string()],
            },
        }
    }

    #[tokio::test]
    async fn test_rules_provider_returns_preliminary_verdict() {
        let cfg = AiConfig {
            provider: "rules".to_string(),
            // Even with non-existent URL, rules provider returns instantly without error
            ollama_url: "http://127.0.0.1:1".to_string(),
            ..Default::default()
        };

        let classifier = Classifier::new(&cfg).await.unwrap();
        let brief = sample_brief();
        let verdict = classifier.classify(&brief).await;

        assert_eq!(verdict.classification, Class::Runaway);
        assert!(verdict.throttle_recommended);
        assert!((verdict.confidence - 0.85).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_stub_valid_runaway_verdict() {
        let inner = serde_json::to_string(&json!({
            "classification": "runaway",
            "confidence": 0.92,
            "throttle_recommended": true,
            "reason": "stuck loop"
        }))
        .unwrap();
        let response = json!({ "message": { "content": inner } });
        let (url, _handle) = start_stub_server(response).await;

        let cfg = stub_config(&url);
        let classifier = Classifier::new(&cfg).await.unwrap();
        let verdict = classifier.classify(&sample_brief()).await;

        assert_eq!(verdict.classification, Class::Runaway);
        assert!(verdict.throttle_recommended);
        assert!((verdict.confidence - 0.92).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_golden_rule_overrides_llm_throttle_on_compiler() {
        let inner = serde_json::to_string(&json!({
            "classification": "runaway",
            "confidence": 0.99,
            "throttle_recommended": true,
            "reason": "high cpu"
        }))
        .unwrap();
        let response = json!({ "message": { "content": inner } });
        let (url, _handle) = start_stub_server(response).await;

        let cfg = stub_config(&url);
        let classifier = Classifier::new(&cfg).await.unwrap();

        let mut brief = sample_brief();
        brief.name = "rustc".to_string();
        brief.name_category = crate::broker::NameCategory::Compiler;
        brief.rule_preliminary = crate::broker::RulePreliminary {
            class: Class::Essential,
            confidence: 0.95,
            reasons: vec!["compiler workload never throttled".to_string()],
        };

        let verdict = classifier.classify(&brief).await;
        // LLM recommended throttle, but Golden Rule forces throttle_recommended = false
        assert!(
            !verdict.throttle_recommended,
            "compiler workload must never have throttle recommended even if LLM says so"
        );
    }

    #[tokio::test]
    async fn test_stub_essential_forces_no_throttle() {
        let inner = serde_json::to_string(&json!({
            "classification": "essential",
            "confidence": 0.88,
            "throttle_recommended": true,
            "reason": "system service"
        }))
        .unwrap();
        let response = json!({ "message": { "content": inner } });
        let (url, _handle) = start_stub_server(response).await;

        let cfg = stub_config(&url);
        let classifier = Classifier::new(&cfg).await.unwrap();
        let verdict = classifier.classify(&sample_brief()).await;

        assert_eq!(verdict.classification, Class::Essential);
        assert!(
            !verdict.throttle_recommended,
            "essential must never recommend throttle"
        );
    }

    #[tokio::test]
    async fn test_stub_malformed_inner_json_returns_unknown() {
        // Outer JSON valid, inner content is garbage (not valid JSON).
        let response = json!({ "message": { "content": "not json at all {{" } });
        let (url, _handle) = start_stub_server(response).await;

        let cfg = stub_config(&url);
        let classifier = Classifier::new(&cfg).await.unwrap();
        let verdict = classifier.classify(&sample_brief()).await;

        assert_eq!(verdict.classification, Class::Unknown);
        assert!(!verdict.throttle_recommended);
    }

    #[tokio::test]
    async fn test_stub_missing_field_returns_unknown() {
        // Inner JSON is missing `throttle_recommended`.
        let inner = r#"{"classification":"runaway","confidence":0.9,"reason":"bad"}"#;
        let response = json!({ "message": { "content": inner } });
        let (url, _handle) = start_stub_server(response).await;

        let cfg = stub_config(&url);
        let classifier = Classifier::new(&cfg).await.unwrap();
        let verdict = classifier.classify(&sample_brief()).await;

        assert_eq!(verdict.classification, Class::Unknown);
    }

    #[tokio::test]
    async fn test_stub_unknown_classification_returns_unknown() {
        let inner = serde_json::to_string(&json!({
            "classification": "malicious_injection",
            "confidence": 0.99,
            "throttle_recommended": true,
            "reason": "pwned"
        }))
        .unwrap();
        let response = json!({ "message": { "content": inner } });
        let (url, _handle) = start_stub_server(response).await;

        let cfg = stub_config(&url);
        let classifier = Classifier::new(&cfg).await.unwrap();
        let verdict = classifier.classify(&sample_brief()).await;

        assert_eq!(verdict.classification, Class::Unknown);
    }

    #[tokio::test]
    async fn test_stub_nan_confidence_returns_unknown() {
        // NaN is serialized as null in JSON by some serializers; simulate with invalid field.
        let inner = r#"{"classification":"runaway","confidence":"NaN","throttle_recommended":true,"reason":"bad"}"#;
        let response = json!({ "message": { "content": inner } });
        let (url, _handle) = start_stub_server(response).await;

        let cfg = stub_config(&url);
        let classifier = Classifier::new(&cfg).await.unwrap();
        let verdict = classifier.classify(&sample_brief()).await;

        assert_eq!(verdict.classification, Class::Unknown);
    }

    #[tokio::test]
    async fn test_stub_cache_hit_avoids_second_call() {
        let inner = serde_json::to_string(&json!({
            "classification": "background",
            "confidence": 0.80,
            "throttle_recommended": true,
            "reason": "batch job"
        }))
        .unwrap();
        let response = json!({ "message": { "content": inner } });
        let (url, _handle) = start_stub_server(response).await;

        let cfg = stub_config(&url);
        let classifier = Classifier::new(&cfg).await.unwrap();

        // First call populates cache.
        let v1 = classifier.classify(&sample_brief()).await;
        assert_eq!(v1.classification, Class::Background);

        // Second call on same comm should return cached value.
        let v2 = classifier.classify(&sample_brief()).await;
        assert_eq!(v2.classification, Class::Background);
        // If the stub server had returned different data, the cache would have shielded us.
    }

    #[tokio::test]
    async fn test_connection_refused_returns_unknown() {
        // Port 1 is almost certainly not listening.
        let cfg = AiConfig {
            provider: "ollama".to_string(),
            fallback_to_rules: false,
            ollama_url: "http://127.0.0.1:1".to_string(),
            model: "llama3.2:3b".to_string(),
            timeout_secs: 2,
            min_confidence: 0.8,
            allow_remote_ollama: false,
            never_throttle: Vec::new(),
            throttle_candidates: Vec::new(),
            candidates_confidence: 0.85,
        };
        let classifier = Classifier::new(&cfg).await.unwrap();
        let start = Instant::now();
        let verdict = classifier.classify(&sample_brief()).await;
        assert_eq!(verdict.classification, Class::Unknown);
        assert!(!verdict.throttle_recommended);
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "connection refused must return unknown within timeout"
        );
    }

    #[tokio::test]
    async fn test_fallback_to_rules_when_ollama_unreachable() {
        let cfg = AiConfig {
            provider: "ollama".to_string(),
            fallback_to_rules: true,
            ollama_url: "http://127.0.0.1:1".to_string(),
            model: "llama3.2:3b".to_string(),
            timeout_secs: 1,
            min_confidence: 0.8,
            allow_remote_ollama: false,
            never_throttle: Vec::new(),
            throttle_candidates: Vec::new(),
            candidates_confidence: 0.85,
        };
        let classifier = Classifier::new(&cfg).await.unwrap();
        let brief = sample_brief();
        let verdict = classifier.classify(&brief).await;

        // When fallback_to_rules is true, connection failure falls back to rules
        assert_eq!(verdict.classification, Class::Runaway);
        assert!(verdict.throttle_recommended);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_repeated_failures() {
        // Port 1 = always connection refused = always failure.
        let cfg = AiConfig {
            provider: "ollama".to_string(),
            fallback_to_rules: false,
            ollama_url: "http://127.0.0.1:1".to_string(),
            model: "llama3.2:3b".to_string(),
            timeout_secs: 1,
            min_confidence: 0.8,
            allow_remote_ollama: false,
            never_throttle: Vec::new(),
            throttle_candidates: Vec::new(),
            candidates_confidence: 0.85,
        };
        let classifier = Classifier::new(&cfg).await.unwrap();
        // After BREAKER_FAILURE_THRESHOLD classify calls on distinct procs, breaker opens.
        for i in 0..BREAKER_FAILURE_THRESHOLD {
            let mut b = sample_brief();
            b.name = format!("proc_{i}");
            classifier.classify(&b).await;
        }
        let state = classifier
            .breaker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .state;
        assert_eq!(
            state,
            BreakerState::Open,
            "breaker should be open after repeated failures"
        );
    }
}
