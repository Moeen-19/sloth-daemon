# Sloth Daemon: AI-Assisted eBPF CPU Governor - Execution Blueprint

We are building **sloth-daemon**, a Linux system daemon written in Rust. It watches per-process CPU consumption using an eBPF program in the kernel (aya framework), asks a **local Ollama model** to classify which processes are runaway background hogs versus essential workloads, and then gently slows the hogs down with **cgroup v2 CPU throttling**. It never kills anything. The name is the policy: make greedy processes *sloth-like*, not dead.

Read `instructions.md` before touching any file. This blueprint says **what** to build and in **what order**; `instructions.md` says **how** to behave while building it. Skill files in `.agents/skills/` say how to do each specialised piece of work.

---

## Objectives

1. **Observe** CPU usage per PID with near-zero overhead using an eBPF tracepoint probe, not `/proc` polling.
2. **Classify** processes with a local LLM (Ollama) or deterministic rules so that a compiler, a video encode, or a database is not throttled by mistake while a runaway browser tab or stuck loop is.
3. **Enforce** throttling through cgroup v2 `cpu.max`, reversibly, with strict safety rails.
4. **Fail safe.** If the AI is down, the kernel probe fails to load, or anything is uncertain, the daemon does nothing to processes.
5. **Stay private and local.** No process data leaves the machine. The only network call is to `localhost` Ollama.
6. **Broker evidence deterministically.** Before any LLM call, derive a compact `ProcessBrief` from local facts (metrics, category rules, system context) so small (0.5B) models classify reliably and rules-only mode works without a model.

### Non-Goals

- No killing, signalling, or `nice`-ing processes.
- No cloud AI providers.
- No GUI. CLI plus logs only.
- No support for cgroup v1 or non-Linux systems.
- No throttling of memory, disk, or network (CPU only).

---

## Architecture

```
 ┌────────────────────────── KERNEL SPACE ──────────────────────────┐
 │  tracepoint: sched:sched_switch  ──►  sloth-ebpf (aya-ebpf)      │
 │      per-CPU start timestamps  ──►  BPF map PID_CPU_NS (LRU)     │
 │      process exit tracepoint   ──►  cleans map entries           │
 └───────────────────────────────┬──────────────────────────────────┘
                                 │ map reads every sample interval
 ┌───────────────────────────────▼──────────────────────────────────┐
 │                     USER SPACE: sloth-daemon                     │
 │                                                                  │
 │  main.rs ── load probe, config, main loop, graceful shutdown     │
 │     │                                                            │
 │     ├─► sampler:  map deltas ─► CPU% per PID over a window       │
 │     │                                                            │
 │     ├─► broker.rs ─► history, /proc metrics ─► ProcessBrief      │
 │     │        (deterministic preliminary rules verdict)           │
 │     │                                                            │
 │     ├─► ai_classifier.rs ─► Ollama (localhost:11434) ─► verdict  │
 │     │        (AI is ADVISORY, output is validated JSON)          │
 │     │                                                            │
 │     ├─► policy gate (deterministic, in main.rs or policy mod):   │
 │     │        protected list, thresholds, hysteresis, dry-run     │
 │     │                                                            │
 │     └─► cgroup_manager.rs ─► /sys/fs/cgroup/sloth-daemon/<id>    │
 │              cpu.max write, cgroup.procs move, release, cleanup  │
 └──────────────────────────────────────────────────────────────────┘
```

**Golden rule of the design:** the AI proposes, the deterministic policy gate disposes. The model's output can only *lower* the chance of throttling or confirm a throttle that the hard thresholds already justify. It can never bypass the protected list.

---

## Directory Structure

```
sloth-daemon/
├── README.md                 # Human-facing overview and quickstart
├── blueprint.md              # This file
├── instructions.md           # Agent operating rules
├── sloth-daemon.service      # Systemd unit example (minimal capabilities)
├── sloth.toml                # Example configuration
├── scripts/
│   ├── e2e-phase5.sh         # End-to-end Phase 5 test (root required)
│   └── crash-recovery.sh     # Crash-recovery integration test (root required)
│   └── llm-check.sh          # Ollama integration test (root required)
├── .agents/skills/
│   ├── ebpf-probe-builder.md
│   ├── cgroup-enforcer.md
│   └── ollama-bridge.md
├── Cargo.toml                # Workspace: sloth-ebpf + sloth-daemon
├── sloth-ebpf/               # no_std kernel program (aya-ebpf)
│   └── src/main.rs
└── sloth-daemon/             # user-space daemon (tokio)
    └── src/
        ├── main.rs
        ├── broker.rs
        ├── policy.rs
        ├── ai_classifier.rs
        └── cgroup_manager.rs
```

Do not add new top-level crates or directories without recording the reason in `blueprint.md` first.

---

## Shared Data Contracts

Define these early (Phase 1) and keep them stable. All phases rely on them.

**`ProcessSample`** (user-space):

| Field | Type | Meaning |
|:--|:--|:--|
| `pid` | `u32` | Process ID |
| `comm` | `String` | Executable name (max 16 bytes from kernel) |
| `cpu_percent` | `f32` | CPU use over the last window, 100.0 = one full core |
| `window_secs` | `u32` | Length of the measurement window |
| `sustained_secs` | `u32` | How long it has stayed above the threshold |

**`ProcessBrief`** (evidence broker output, compact derived facts):

| Field | Type | Meaning |
|:--|:--|:--|
| `name` | `String` | Sanitized process name |
| `name_category` | `NameCategory` | Category derived from name rules (`compiler`, `encoder`, `database`, `browser_helper`, `interpreter`, `shell`, `desktop_service`, `unknown`) |
| `parent_category` | `NameCategory` | Category derived from parent process comm |
| `cpu_now` | `f32` | Instantaneous CPU% |
| `cpu_avg_60s` | `f32` | 60-second moving average CPU% |
| `cpu_peak` | `f32` | Peak CPU% over history |
| `trend` | `CpuTrend` | `rising`, `flat`, or `falling` |
| `burstiness` | `Burstiness` | `steady` or `spiky` |
| `sustained_secs` | `u32` | Seconds continuously above threshold |
| `age_secs` | `u64` | Process age in seconds |
| `thread_count` | `u32` | Number of threads |
| `rss_bucket` | `RssBucket` | `small`, `medium`, or `large` |
| `session_kind` | `SessionKind` | `user_app`, `system_service`, or `unknown` (never the raw cgroup path) |
| `has_tty` | `bool` | Whether process has a controlling terminal |
| `psi_cpu_avg10` | `Option<f32>` | System CPU pressure avg10 from `/proc/pressure/cpu` |
| `cpu_rank` | `u32` | Process rank among CPU consumers |
| `num_cores` | `u32` | Number of logical cores |
| `rule_preliminary` | `RulePreliminary` | Deterministic `{ class, confidence, reasons }` from rule lists |

**`Verdict`** (from the AI, strict JSON):

```json
{
  "classification": "essential | interactive | background | runaway | unknown",
  "confidence": 0.0,
  "throttle_recommended": false,
  "reason": "short plain-English explanation"
}
```

**`ThrottleAction`** (from the policy gate): `None`, `Throttle { pid, quota_pct }`, `Release { pid }`.

**Config** (`sloth.toml`, with defaults in code): sample interval, CPU threshold percent, sustained seconds before action, throttle quota percent, Ollama URL and model, AI timeout, protected process names, `dry_run` (default `true`), maximum concurrent throttled PIDs.

---

## Phased Execution Roadmap

Complete phases **in order**. Do not start a phase until the previous phase's checklist passes. After each phase, stop, summarise what was done, and wait for the user's go-ahead if the instructions say a checkpoint is required.

### Phase 1: Workspace Scaffolding and Toolchain

- **Goal:** A compiling, empty workspace where both crates build, with logging and config in place.
- **Tasks:**
  1. Create the root `Cargo.toml` workspace. Include `sloth-daemon` as a default member. Treat `sloth-ebpf` specially (it targets `bpfel-unknown-none` and needs nightly with `build-std=core`), so it must not break a plain `cargo build` of the daemon.
  2. Scaffold `sloth-ebpf/src/main.rs` as a `#![no_std]` `#![no_main]` aya-ebpf program with a panic handler and a license section, and nothing else yet.
  3. Scaffold `sloth-daemon` with `tokio`, `anyhow`, `tracing` and `tracing-subscriber`, `serde` and `toml`, `clap`. Create empty modules `ai_classifier` and `cgroup_manager`.
  4. Add the data contracts above as Rust types.
  5. Implement config loading with sane defaults and **`dry_run = true` by default**.
  6. Add a `build.rs` or documented command sequence in `instructions.md` that builds the eBPF object and embeds it with `include_bytes_aligned!`.
  7. Add a startup preflight that checks: running on Linux, cgroup v2 mounted at `/sys/fs/cgroup`, sufficient privileges, kernel BTF available. Print clear errors and exit non-zero if not met.
- **Exit check:** `cargo build -p sloth-daemon` succeeds, the eBPF crate builds with the documented nightly command, and `sloth-daemon --help` and `--check` work.

### Phase 2: eBPF CPU Observation Probe

- **Goal:** Kernel-side per-PID CPU accounting that user space can read cheaply.
- **Tasks:**
  1. Load the `ebpf-probe-builder` skill and follow it.
  2. In `sloth-ebpf`, attach to the `sched:sched_switch` tracepoint. Keep a per-CPU timestamp of when the current task started running. On each switch, add the elapsed time to the outgoing PID's total in `PID_CPU_NS` (an LRU hash map keyed by `u32` PID, value `u64` nanoseconds).
  3. Attach a second tracepoint on process exit to delete the PID's entry, so the map cannot leak.
  4. Ignore PID 0 (idle) and handle the verifier limits: bounded loops, no unbounded stack, checked map access.
  5. In `sloth-daemon/src/main.rs`, load the object with aya, attach the programs, and read `PID_CPU_NS` on a timer. Convert deltas between samples into `cpu_percent`.
  6. Resolve `comm` from the kernel (or `/proc/<pid>/comm` as a fallback) and filter out kernel threads.
  7. Print a top-N table of busiest processes at each interval in debug mode.
- **Exit check:** Running a synthetic busy loop (`yes > /dev/null`) shows up at about 100% in the daemon output within two sample windows, and disappears from the map after it exits.

### Phase 3: Cgroup v2 Enforcement Engine

- **Goal:** Safely and reversibly limit a process's CPU with cgroup v2, with no AI involved yet.
- **Tasks:**
  1. Load the `cgroup-enforcer` skill and follow it.
  2. In `cgroup_manager.rs`, implement: ensure the daemon's parent cgroup exists and has the `cpu` controller enabled; create a per-target child cgroup; write `cpu.max`; move the PID with `cgroup.procs`; release by moving the PID back to its original cgroup and removing the empty child.
  3. Record each PID's **original cgroup path** before moving it so release is exact.
  4. Implement the **protected list**: PID 1, the daemon itself and its parent, kernel threads, anything whose `comm` is in the configured protected set (for example `systemd`, `sshd`, `Xorg`, `gnome-shell`, `pipewire`, `dbus-daemon`), and any process in a privileged system slice.
  5. Implement `dry_run`: log what would be written, write nothing.
  6. Implement a global `release_all()` used on graceful shutdown, on panic hook, and on startup to clean up leftovers from a previous crash.
  7. Add a hard cap on concurrently throttled PIDs and a minimum quota floor (never below 5% of one core).
- **Exit check:** With `dry_run = false` in a test run, a busy-loop PID is throttled to the configured quota (confirm with `top` and by reading `cpu.max`), is restored on release, and `/sys/fs/cgroup/sloth-daemon/` is empty after shutdown. Attempting to throttle PID 1 or the daemon is refused and logged.

### Phase 4: Local AI Classifier (Ollama Bridge)

- **Goal:** Ask a local model whether a busy process is a genuine runaway, returning validated, typed verdicts.
- **Tasks:**
  1. Load the `ollama-bridge` skill and follow it.
  2. In `ai_classifier.rs`, build an HTTP client for `http://localhost:11434` (configurable) using `reqwest` with hard timeouts.
  3. Build a minimal, privacy-safe prompt from a `ProcessSample`: process name, CPU%, sustained duration, and nothing else. **Never** include command-line arguments, environment variables, file paths, or usernames.
  4. Request JSON output with `"stream": false` and `"format"` set to a JSON schema matching `Verdict`. Parse the inner JSON strictly. On any parse failure, retry once, then return `Verdict::unknown()`.
  5. Add a verdict cache keyed by process name (and short TTL) so the same program is not re-classified every window.
  6. Add a **deterministic fallback classifier** used when Ollama is unreachable. The fallback may only return `unknown`, which means "do not throttle".
  7. Expose a clean async API: `classify(&ProcessSample) -> Verdict`.
- **Exit check:** With Ollama running, a mock sample for a name like `cc1plus` is classified as non-runaway and one like a stuck `python` loop at 100% for a long time can be classified as runaway. With Ollama stopped, `classify` returns `unknown` quickly (within the timeout) without panicking.

### Phase 4.5: Evidence Broker (ProcessBrief)

- **Goal:** Build a deterministic evidence broker that computes a compact `ProcessBrief` from local metrics, rules, and system context before calling any model, enabling fast classification with tiny models and pure rules-only operation.
- **Tasks:**
  1. Create `sloth-daemon/src/broker.rs` with `ProcessBrief`, ring-buffer CPU sampler history per PID (~30 samples), `/proc` metrics readers, category matching rules, and preliminary verdict generation.
  2. Implement pure `/proc` parsing functions for stat (age, threads, tty), status (RSS bucket), cgroup (session kind), and pressure (PSI cpu avg10). Return `None` ("no brief") if a process disappears mid-read.
  3. Ensure `ProcessBrief` contains only derived features: sanitized name, name and parent categories, CPU metrics (current, avg_60s, peak, trend, burstiness), sustained duration, age, thread count, RSS bucket, session kind, tty presence, system context (PSI, rank, cores), and preliminary rule verdict.
  4. Never include raw cmdline, environment, file paths, usernames, or raw cgroup paths in `ProcessBrief`.
  5. Add config support for `ai.provider` (`"rules"` default, `"ollama"`), `fallback_to_rules`, `never_throttle`, and `throttle_candidates`.
  6. Update `ai_classifier.rs` to consume `ProcessBrief`. In `"rules"` mode, return the preliminary rule verdict directly. In `"ollama"` mode, supply compact JSON brief to the model. Fall back to rules verdict only if `fallback_to_rules = true`.
- **Exit check:** Table-driven tests for categories, trend, burstiness, and bucketing pass using fixtures; prompt serialization test asserts absence of cmdline, env, slashes, or usernames; mock-server tests pass with the new brief prompt; `cargo fmt`, `clippy -D warnings`, and `cargo test` pass.

### Phase 5: Orchestration and Policy Gate

- **Goal:** Wire sampler, AI and enforcer into one safe control loop.
- **Tasks:**
  1. Implement the policy gate in `policy.rs` as a pure, unit-testable function: `decide(sample, brief, verdict, state, config) -> ThrottleAction`.
  2. Rules, all required for a throttle: CPU above the threshold for at least `sustained_secs`; not protected; AI verdict is `runaway` or `background` with `confidence >= 0.8` and `throttle_recommended = true`; under the concurrency cap.
  3. Add **hysteresis**: a throttled PID is considered "calm" when its CPU stays below 50% of its quota for `cool_down_samples` consecutive samples (default 5); release on calm to avoid flapping at quota.
  4. Add automatic **release TTL**: every throttle expires after a maximum duration unless re-justified.
  5. Release immediately if the PID exits or if the process becomes protected.
  6. Run AI classification asynchronously so a slow model never blocks the sampling loop.
  7. Handle `SIGINT` and `SIGTERM`: stop the loop, call `release_all()`, exit cleanly.
  8. Emit structured `tracing` logs for every decision: pid, comm, cpu%, verdict, action, and reason.
- **Exit check:** An end-to-end test where a CPU hog is detected, classified, throttled, observed at reduced CPU, then released after it calms down or the TTL expires. `Ctrl+C` leaves no residual cgroups.

### Phase 6: Hardening, Tests and Docs

- **Goal:** Make it trustworthy enough to run unattended.
- **Tasks:**
  1. Unit tests for the policy gate (table-driven), config parsing, verdict parsing (valid, malformed, out-of-range confidence), and the protected-list matcher.
  2. Integration test scripts (shell or Rust, root-required, clearly marked) for the throttle and release cycle.
  3. Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` and fix everything.
  4. Write a `sloth-daemon.service` systemd unit example with the minimal capabilities needed (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_SYS_ADMIN` only if unavoidable) and note it in the README.
  5. Update `README.md` with install, run, dry-run, and safety notes.
  6. Final review pass against `instructions.md`, checking that no forbidden action exists in the code (no `kill`, no `SIGSTOP`, no writes outside `/sys/fs/cgroup/sloth-daemon/` and moving PIDs).
- **Exit check:** All checks green, README accurate, definition of done met.

---

## Definition of Done

The project is done when **every** box below is true and has been verified by running the command or test, not assumed.

### Build and Quality
- [x] `cargo build --release -p sloth-daemon` succeeds with the eBPF object embedded.
- [x] The eBPF crate builds with the documented nightly `bpfel-unknown-none` command.
- [x] `cargo fmt --check` passes.
- [x] `cargo clippy --all-targets -- -D warnings` passes.
- [x] `cargo test` passes, including policy gate and verdict parsing tests.
- [x] No `unwrap()` or `expect()` on runtime paths in user space (tests excepted).

### Observation
- [x] The eBPF probe loads and attaches on the target kernel without verifier errors.
- [x] CPU% for a known busy process is within about 10% of what `top` reports.
- [x] Exited processes are removed from the BPF map.

### Classification
- [x] Ollama verdicts are parsed into typed `Verdict` values using JSON-schema-constrained output.
- [x] Malformed or missing model output yields `unknown`, never a crash or a throttle.
- [x] With Ollama offline, the daemon keeps running and throttles nothing.
- [x] Prompts contain only process name, CPU%, and duration.

### Enforcement and Safety
- [x] Throttling uses cgroup v2 `cpu.max` and is confirmed effective on a test process.
- [x] PID 1, the daemon itself, kernel threads, and all protected names can never be throttled.
- [x] `dry_run = true` is the default and performs zero writes to `/sys/fs/cgroup`.
- [x] Every throttle has a TTL, a floor quota, and counts against a concurrency cap.
- [x] `SIGINT` and `SIGTERM` release all throttles and remove all child cgroups.
- [x] Leftover cgroups from a prior crash are cleaned on startup.
- [x] No code path kills, stops, or re-prioritises a process by any other means.

### Documentation
- [x] `README.md` explains installation, privileges, dry-run, and configuration.
- [x] A systemd unit example is included.
- [x] Every decision the daemon makes is explained in its logs.