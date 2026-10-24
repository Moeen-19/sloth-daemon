---
name: ollama-bridge
description: Handling local Ollama HTTP requests, structured JSON output, strict parsing, caching and safe fallbacks for sloth-daemon's AI classifier.
---

# Skill: Ollama Bridge

Use this skill whenever you write or change `sloth-daemon/src/ai_classifier.rs` or anything that calls Ollama.

## Mission

Turn a small, privacy-safe `ProcessSample` into a validated `Verdict` using a **local** Ollama model. The model is advisory. Bad, slow, or missing output must degrade to `unknown`, which means "do not throttle".

## Ground Rules

1. **Local only.** The only host the daemon may contact is the configured Ollama URL (default `http://localhost:11434`). Refuse to start the classifier if the configured URL is not a loopback address, unless the user explicitly sets an `allow_remote_ollama = true` flag. Never contact any other host.
2. **Minimal prompt.** Include only: process name (`comm`), CPU percent, and how long it has been busy. Never include command-line arguments, environment variables, file paths, usernames, hostnames, or anything read from `/proc/<pid>/cmdline|environ|cwd`.
3. **Sanitize the name.** `comm` is at most 15 bytes but is attacker-controlled. Before putting it in the prompt, keep only `[A-Za-z0-9._+-]`, replace everything else with `_`, and truncate to 32 characters. Never put it anywhere except inside the prompt's data section.
4. **Treat the model's output as untrusted.** Parse strictly, validate ranges, and never use any model text to build a path, command, or cgroup write. Only the `Verdict` enum and numbers leave this module.
5. **Never block the control loop.** Classification is async with a hard timeout. A slow model must not stop sampling.
6. **Fail closed.** Any error returns `Verdict::unknown()`.

## Ollama API Facts

Verify field names against the Ollama docs and the installed version before relying on them. These are the ones this project uses:

- Base URL: `http://localhost:11434`
- Health and model list: `GET /api/tags` (returns installed models). Use it at startup to check that the configured model is installed.
- Chat endpoint (preferred): `POST /api/chat`

  ```json
  {
    "model": "llama3.2:3b",
    "messages": [
      { "role": "system", "content": "..." },
      { "role": "user", "content": "..." }
    ],
    "stream": false,
    "format": { "type": "object", "properties": { "...": {} }, "required": ["..."] },
    "options": { "temperature": 0, "num_predict": 200 },
    "keep_alive": "10m"
  }
  ```

- With `"stream": false`, the response is a single JSON object. The model's text is in `message.content` (for `/api/chat`) or `response` (for `/api/generate`). **That text is itself a JSON string** that you must parse a second time.
- `"format"` accepts either the string `"json"` or a JSON schema object for structured outputs. Prefer the schema. It constrains the model to the right shape but does **not** guarantee sensible values, so you still validate.
- `temperature: 0` for repeatable classification. `num_predict` caps output length so a runaway generation cannot stall the daemon.
- `keep_alive` keeps the model loaded between calls to avoid cold-start latency. Choose a sensible default and make it configurable.
- Error cases to handle: connection refused (Ollama not running), HTTP 404 (model not pulled), HTTP 5xx, timeouts, and a body that is not valid JSON.

## Data Types

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Class { Essential, Interactive, Background, Runaway, Unknown }

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawVerdict {
    pub classification: String,   // validated into Class manually for clear errors
    pub confidence: f32,
    pub throttle_recommended: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub classification: Class,
    pub confidence: f32,          // clamped to 0.0..=1.0 after validation
    pub throttle_recommended: bool,
    pub reason: String,           // truncated, sanitized, for logs only
}

impl Verdict { pub fn unknown() -> Self { /* Unknown, 0.0, false, "no verdict" */ } }
```

**Validation rules** (`validate(raw) -> Option<Verdict>`):

- `classification` must be one of the five allowed values; otherwise reject.
- `confidence` must be finite and within `0.0..=1.0`; otherwise reject (do not silently clamp bad values like `NaN` or `7.0`).
- `reason` is truncated to a fixed length (for example 200 chars), stripped of control characters and newlines, and used only for logging.
- Consistency check: if `classification` is `Essential` or `Interactive`, force `throttle_recommended = false` regardless of what the model said.
- Cap trust: the policy gate, not this module, decides whether a verdict is acted on.

## JSON Schema for `format`

```json
{
  "type": "object",
  "properties": {
    "classification": { "type": "string", "enum": ["essential", "interactive", "background", "runaway", "unknown"] },
    "confidence": { "type": "number" },
    "throttle_recommended": { "type": "boolean" },
    "reason": { "type": "string" }
  },
  "required": ["classification", "confidence", "throttle_recommended", "reason"]
}
```

Build it once with `serde_json::json!` and reuse it.

## Prompt Template

System message (fixed text, no user data):

```
You classify Linux processes for a CPU governor. You are given only a process name,
its recent CPU usage, and how long it has been busy. Decide if it is a runaway
process that should be slowed down, or legitimate work that should be left alone.

Rules:
- Compilers, build tools, video encoders, databases, package managers, test runners
  and scientific workloads are legitimate heavy work: do not recommend throttling.
- Desktop, audio, network and system services are essential: never recommend throttling.
- Recommend throttling only when the name suggests a non-essential background task
  or an interpreter/browser helper that has been pinned at high CPU for a long time.
- If unsure, answer "unknown" with throttle_recommended false.
Respond with JSON only, matching the provided schema.
```

User message (the only place data appears):

```
process_name: {sanitized_comm}
cpu_percent: {cpu:.0} (100 = one full core)
busy_for_seconds: {sustained_secs}
```

Keep the system text as a constant. Because the process name is untrusted, it appears only in the user message and only after sanitization. The model must not be able to change the schema or the rules by naming a process cleverly; the strict output validation and the deterministic policy gate are the real defence, and prompt wording is secondary.

## HTTP Client Rules (`reqwest`)

- One shared `reqwest::Client` built at startup with:
  - `connect_timeout` (for example 1 s) and overall `timeout` from config (default around 20 s; first call after a cold model load can be slow, so allow a larger first-call timeout or a warm-up request).
  - `no_proxy()` so localhost traffic never goes through a proxy.
  - Redirects disabled (`redirect(Policy::none())`).
- Limit response size (read with a cap, for example 64 KB) before parsing.
- No retries on connection-refused. Retry **once** on a malformed model response (temperature 0 means retrying is only useful if you tweak the prompt, so on the retry add a short reminder "Respond with JSON only"), then give up with `unknown`.
- Use a circuit breaker: after N consecutive failures (for example 3), stop calling Ollama for a backoff period (for example 60 s) and return `unknown` immediately. Log once at `warn` when the breaker opens and once when it closes.

## Caching

- Cache `Verdict` by sanitized process name with a TTL (for example 5 minutes), bounded in size (for example 256 entries, evict oldest).
- A cached `unknown` produced by a failure should have a **short** TTL so recovery is quick.
- Cache keys must not include PIDs; two instances of the same program share a verdict. Different CPU levels still go through the policy gate separately.

## Fallback Behaviour

When Ollama is unreachable, the model is missing, the breaker is open, or parsing fails twice:

- Return `Verdict::unknown()`.
- The deterministic fallback may **not** invent a throttle recommendation. `unknown` means "do nothing".

## Public API

```rust
pub struct Classifier { /* client, config, cache, breaker */ }

impl Classifier {
    pub async fn new(cfg: &AiConfig) -> anyhow::Result<Self>;   // builds client, checks loopback
    pub async fn health(&self) -> HealthStatus;                  // GET /api/tags, model installed?
    pub async fn classify(&self, sample: &ProcessSample) -> Verdict; // never errors, never panics
}
```

`classify` returns a `Verdict`, not a `Result`. All failures are logged inside and turned into `unknown`.

## Logging

- `info`: classifier ready (model name, URL host), breaker open/close.
- `debug`: per-call latency, cache hit/miss, sanitized name, resulting class and confidence.
- `warn`: Ollama unreachable, model not installed, malformed output.
- Never log the full request or response bodies at `info` or above.

## Tests (no real model needed)

Use a small local stub HTTP server (for example `axum` or `wiremock` in dev-dependencies only, with approval) that returns canned responses:

- Valid response with nested JSON string in `message.content` → correct `Verdict`.
- Malformed outer JSON, malformed inner JSON, missing field, extra field, unknown classification, `confidence` of `NaN`/`-1`/`7` → `unknown`.
- `essential` classification with `throttle_recommended: true` → forced to `false`.
- HTTP 404 (model missing), HTTP 500, connection refused, slow response beyond the timeout → `unknown` within the timeout.
- Circuit breaker opens after repeated failures and closes after the backoff.
- Cache hit avoids a second HTTP call; TTL expiry triggers a new call.
- Name sanitization turns `bad name;rm -rf` into a safe string.
- Non-loopback URL is rejected unless `allow_remote_ollama` is set.

## Manual Verification (give to the user)

```bash
ollama serve &                # if not already running
ollama pull llama3.2:3b       # or the model named in sloth.toml
curl -s http://localhost:11434/api/tags | head
# Then run the daemon in dry-run mode and watch the logs for verdicts.
# Stop Ollama and confirm the daemon logs a warning and throttles nothing.
```

## Do Not

- Do not call any cloud AI service.
- Do not send command lines, paths, environment, usernames, or any file contents to the model.
- Do not stream responses; use `"stream": false`.
- Do not let model text influence file paths, shell commands, or cgroup writes.
- Do not panic or return an error from `classify`; return `Verdict::unknown()`.
- Do not hard-code a model name. Read it from config and verify it is installed at startup.