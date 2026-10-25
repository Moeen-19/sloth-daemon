# Instructions for the Coding Agent (agy) - sloth-daemon

You are building **sloth-daemon**: a Rust Linux daemon that uses an eBPF probe (aya) to watch per-process CPU use, a local Ollama model to classify runaway processes, and cgroup v2 `cpu.max` to throttle them. You are working on a real machine, with real kernel interfaces. Follow these rules exactly. When a rule conflicts with a shortcut, the rule wins.

---

## 1. Source of Truth and Order of Reading

1. Read `blueprint.md` first. It defines the objectives, architecture, data contracts, phases, and Definition of Done.
2. Read this file second.
3. Before doing specialised work, read the matching skill in `.agents/skills/`:
   - Writing or changing anything in `sloth-ebpf/` → `ebpf-probe-builder.md`
   - Writing or changing `cgroup_manager.rs` or anything touching `/sys/fs/cgroup` → `cgroup-enforcer.md`
   - Writing or changing `ai_classifier.rs` or anything calling Ollama → `ollama-bridge.md`
4. If the blueprint, these instructions, and a skill disagree, stop and ask the user. Do not choose silently.

## 2. Working Style

- **Work one phase at a time**, in blueprint order. Do not start Phase N+1 until Phase N's exit check passes.
- **Stay in scope.** Do only what the current phase's tasks say. No bonus features, no speculative abstractions, no extra crates "for later".
- **Do not deviate from the plan.** If you think the plan is wrong, say so, explain why, propose a change to `blueprint.md`, and wait for approval.
- **Small, verifiable steps.** After each meaningful change, build or test it. Never stack up large unverified changes.
- **Do not invent facts.** If you are not sure of an aya API, a cgroup file name, or an Ollama field, check the crate docs or kernel docs, or ask. Do not guess signatures from memory. aya's API has changed between versions, so read the version pinned in `Cargo.lock`.
- **Report honestly.** If a test fails, say it failed. Never claim something works unless you ran it.
- **Be brief.** Credits are limited and this is a small project. Keep every message short: no essays, no restating the blueprint, no per-subtask reports, and no listing of files or checks that went fine. Report problems in detail and successes in a line.
- **At the end of each phase**, reply with at most about 10 lines: what works, anything that failed or deviated from the blueprint, and any exact command the user must run (for example, one that needs root). **Then stop and wait for the user's go-ahead before starting the next phase.** This checkpoint is required after every phase.
- **Checks the user can do themselves** (running sudo tests, reading logs, comparing against `top`): give the exact command in one line and say "you run this". Do not try to substitute for them with long analysis.

## 3. Tech Stack (Fixed)

| Area | Choice |
|:--|:--|
| Language | Rust, 2021 edition or later |
| Kernel program | `aya-ebpf`, `#![no_std]`, target `bpfel-unknown-none` |
| User-space loader | `aya` |
| Async runtime | `tokio` |
| HTTP client | `reqwest` (with `json`), talking to Ollama only |
| Serialization | `serde`, `serde_json`, `toml` |
| Errors | `anyhow` in the binary, `thiserror` for module error types |
| Logging | `tracing` and `tracing-subscriber` (never `println!` for operational output) |
| CLI | `clap` |

Do not add dependencies outside this list without asking. When you add one, state why in one sentence.

## 4. Build and Test Commands

Run from the repository root. These are the canonical commands. If one fails because of the environment, tell the user rather than inventing a workaround.

```bash
# One-time toolchain setup
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

# Build the eBPF program (kernel side)
cargo +nightly build --package sloth-ebpf \
  --target bpfel-unknown-none -Z build-std=core --release

# Build the daemon (embeds the eBPF object)
cargo build --release -p sloth-daemon

# Quality gates (run before declaring any phase done)
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test

# Run (needs privileges to load eBPF and write cgroups)
sudo ./target/release/sloth-daemon --config sloth.toml
```

Notes:
- Loading eBPF and writing to `/sys/fs/cgroup` requires root or the capabilities `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` (and `CAP_SYS_ADMIN` where unavoidable). **Do not run the daemon with `sudo` yourself unless the user has approved it for this session.** Prefer to give the user the exact command to run.
- If a build step needs the network (crates, toolchain), that is allowed. Do not download or run anything else from the internet.

## 5. Safety Boundaries (Hard Rules)

These are non-negotiable. Violating any of them is a failure even if the code works.

### 5.1 What the daemon is allowed to do to processes
- **Allowed:** create child cgroups under `/sys/fs/cgroup/sloth-daemon/`, write `cpu.max` in those cgroups, move a PID into one of them, move it back, and remove the empty child cgroups.
- **Forbidden:** sending any signal to a process (`kill`, `SIGSTOP`, `SIGKILL`, `SIGTERM` to targets), calling `nice` or `setpriority`, changing CPU affinity, ptrace, writing to any `/proc/<pid>/` file, or touching any cgroup path outside `/sys/fs/cgroup/sloth-daemon/` except to move a PID back to its recorded original cgroup.

### 5.2 Never throttle these
PID 1, the daemon itself and its parent, kernel threads (no `/proc/<pid>/exe`, or parent is PID 2), and all names in the protected list (at minimum: `systemd`, `systemd-*`, `sshd`, `dbus-daemon`, `Xorg`, `Xwayland`, `gnome-shell`, `kwin_*`, `pipewire`, `pulseaudio`, `NetworkManager`, `ollama`). The protected check lives in code, and **the AI can never override it**.

### 5.3 Fail safe
- On any error, uncertainty, timeout, malformed model output, or missing data, the correct action is **do nothing** to the process.
- `dry_run = true` is the default. A real write only happens when the config explicitly sets `dry_run = false`.
- Every throttle must have a quota floor (not below 5% of one core), a TTL, and count against a maximum concurrency cap.
- On exit, panic, `SIGINT`, or `SIGTERM`, release everything. On startup, clean up leftovers from a previous run.

### 5.4 The AI is advisory only
- The LLM returns a verdict. A deterministic policy function decides the action.
- Treat all model output as **untrusted input**: parse strictly, validate ranges, ignore unknown fields, and never use any model text to build a file path, shell command, or cgroup write.
- The prompt contains only the compact derived features of `ProcessBrief`: sanitized name, categories, CPU history & trends, duration, age, thread count, RSS bucket, session kind, tty flag, system context, and preliminary rule verdict. Never include command-line arguments, environment variables, file paths, usernames, hostnames, or raw cgroup paths. Never send data anywhere except the local Ollama URL from the config.

### 5.5 Dangerous operations need the user
Stop and ask before: running anything with `sudo`, running the daemon with `dry_run = false`, deleting files outside `target/`, modifying anything outside the repo directory, changing kernel parameters (`sysctl`), or loading or unloading kernel modules.

## 6. Rust Code Standards

- No `unwrap()` or `expect()` on runtime paths in user space. Use `?` with context (`anyhow::Context`). Tests may unwrap.
- No `unsafe` in user space unless unavoidable. In the eBPF crate `unsafe` is normal (helpers, map access), but each `unsafe` block gets a one-line `// SAFETY:` comment.
- No panics in the kernel program. The eBPF verifier rejects them; use early returns and error codes.
- Keep the kernel program tiny: it counts, it does not decide. All policy lives in user space.
- Public functions and types get doc comments. Modules get a short top-of-file comment explaining their job.
- Pure logic (policy decisions, parsing, protected-list matching) must be separated from I/O so it is unit-testable.
- Constants, not magic numbers: put thresholds and paths in named constants or config.
- Keep functions short. If a function needs a long comment to explain, split it.
- Formatting and lints must pass (`cargo fmt`, `cargo clippy -D warnings`) before you report completion.

## 7. File Ownership and Layout

| File | Responsibility | Must not contain |
|:--|:--|:--|
| `sloth-ebpf/src/main.rs` | Tracepoint programs and BPF maps | Policy, thresholds, string handling |
| `sloth-daemon/src/main.rs` | Config, preflight, loading the probe, sampling, control loop, signal handling | Raw HTTP calls, raw cgroup file writes, policy logic |
| `sloth-daemon/src/broker.rs` | Evidence Broker: `ProcessBrief`, /proc metrics, sampler history ring buffer, category rules, preliminary verdict | Raw HTTP calls, cgroup manipulation |
| `sloth-daemon/src/policy.rs` | Policy Gate: deterministic decisions (`decide`), `PolicyState`, hysteresis, TTL | Raw HTTP calls, raw cgroup file writes |
| `sloth-daemon/src/ai_classifier.rs` | Ollama HTTP, prompt, parsing, cache, fallback | Cgroup logic, process killing |
| `sloth-daemon/src/cgroup_manager.rs` | All `/sys/fs/cgroup` access, protected list enforcement, release logic | HTTP, AI logic |

If `main.rs` grows too large, ask before adding new modules. Do not move files without approval.

## 8. Logging and Observability

- Use `tracing` levels: `error` for failures, `warn` for degraded operation (for example Ollama down), `info` for decisions (throttle, release), `debug` for per-sample detail.
- Every throttle or release log line includes `pid`, `comm`, `cpu_percent`, `classification`, `confidence`, `action`, `dry_run`, and `reason`.
- Never log secrets, command lines, or environment contents.

## 9. Testing Rules

- Every new pure function gets a unit test in the same change.
- Policy gate tests are table-driven and cover: protected process, below threshold, not sustained long enough, low-confidence verdict, AI says do not throttle, concurrency cap reached, valid throttle, hysteresis release.
- Tests that need root or touch real cgroups go in a clearly marked integration area and must be skipped (not failed) when not run as root.
- Mock Ollama in tests with a local stub server. Tests must not need a real model.

## 10. Git and Housekeeping

- Make one logical change per commit, only if the user asks you to commit. Never force-push, rewrite history, or touch other branches.
- Never commit `target/`, config files containing local paths, or logs.
- Keep `README.md` accurate: if behaviour or commands change, update it in the same change.

## 11. When to Stop and Ask

Stop and ask the user, with a specific question and a recommended default, if:
- A required kernel feature is missing (no cgroup v2, no BTF, tracepoint not available).
- The pinned aya version's API does not match the skill or blueprint.
- A phase's exit check cannot be run without privileges you do not have.
- You are tempted to add scope, a dependency, or a new file not in the blueprint.
- Anything in this file or the blueprint is ambiguous.

## 12. Definition of "Finished" for Any Task

A task is finished only when: it compiles, `cargo fmt` and `clippy` are clean, relevant tests pass, the behaviour was actually exercised (or you clearly state it needs the user to run it with privileges), and your summary says exactly what was and was not verified.