# Sloth Daemon: The AI-Assisted CPU Governor

Make greedy processes sloth-like, not dead. Sloth Daemon watches CPU usage with an eBPF probe, asks a local Ollama model whether a busy process is a genuine runaway, and gently slows it down with cgroup v2 CPU limits. It never kills anything.

> **Status:** In development. The project is built phase by phase following `blueprint.md`. Check the Definition of Done in that file for what is complete.

## What is Sloth Daemon

A runaway browser helper, a stuck script, or a forgotten background job can pin a CPU core and make your machine crawl. Sloth Daemon observes per-process CPU time directly in the kernel, uses a small local language model to tell runaway processes apart from legitimate heavy work like compiles and video encodes, and then caps the offender's CPU share. When the process calms down or a time limit expires, the cap is lifted.

Everything runs on your machine. No process data leaves it, and the only network call is to your local Ollama server.

## How It Works

1. **Observe:** an eBPF program (aya) attached to the `sched:sched_switch` tracepoint accumulates on-CPU time per process in a kernel map.
2. **Sample:** the user-space daemon reads that map on an interval and turns the deltas into CPU percentages.
3. **Classify:** for processes that stay busy past a threshold, the daemon asks a local Ollama model for a structured verdict (`essential`, `interactive`, `background`, `runaway`, or `unknown`).
4. **Decide:** a deterministic policy gate makes the final call. The AI is advisory only and can never override the protected list.
5. **Enforce:** approved targets are moved into a child cgroup under `/sys/fs/cgroup/sloth-daemon/` with a `cpu.max` quota, and released later.

## Architecture and Tech Stack

| Component | Technology | Purpose |
|:--|:--|:--|
| Kernel probe | Rust, `aya-ebpf` | Per-process CPU accounting with minimal overhead |
| Daemon | Rust, `aya`, `tokio` | Loading the probe, sampling, control loop, policy gate |
| AI classifier | Ollama (local HTTP API), `reqwest` | Structured JSON verdicts on runaway processes |
| Enforcement | cgroup v2 (`cpu.max`, `cgroup.procs`) | Reversible CPU throttling |
| Observability | `tracing` | Structured logs explaining every decision |
| Agent workflow | `agy` with `.agents/skills/` | Guided, rule-bound development |

## Safety Model

- **Dry run by default.** Nothing is written to `/sys/fs/cgroup` unless `dry_run = false` is set explicitly.
- **No killing.** No signals, no `nice`, no CPU affinity changes. Only cgroup `cpu.max` and moving PIDs between cgroups.
- **Protected processes.** PID 1, the daemon itself, kernel threads, and core services (for example `systemd`, `sshd`, display servers, audio, and `ollama`) are never throttled.
- **Limits on every throttle.** A minimum quota of 5% of one core, a cap on how many processes can be throttled at once, and an automatic expiry time.
- **Fail safe.** If Ollama is down or returns bad output, the verdict is `unknown` and nothing is throttled.
- **Clean exit.** On shutdown, `SIGINT`, or `SIGTERM`, every throttle is released and the daemon's cgroups are removed. Leftovers from a crash are cleaned on the next start.
- **Private by design.** Prompts contain only the process name, CPU percentage, and how long it has been busy. Never command lines, paths, or environment.

## Requirements

- Linux with **cgroup v2** (unified hierarchy) mounted at `/sys/fs/cgroup`
- A kernel with BTF (`/sys/kernel/btf/vmlinux` exists) and the `sched_switch` tracepoint
- Root, or the capabilities `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` (and `CAP_SYS_ADMIN` only if needed)
- Rust stable plus a **nightly** toolchain with `rust-src` for the eBPF crate
- `bpf-linker`
- [Ollama](https://ollama.com) running locally with at least one model pulled

Check cgroup v2 and BTF quickly:

```bash
stat -fc %T /sys/fs/cgroup        # expect: cgroup2fs
ls /sys/kernel/btf/vmlinux        # expect: the file exists
```

## Quick Start and Installation

1. **Clone the repository:**

   ```bash
   git clone <your-repo-url> sloth-daemon
   cd sloth-daemon
   ```

2. **Install the toolchain (one time):**

   ```bash
   rustup toolchain install nightly --component rust-src
   cargo install bpf-linker
   ```

3. **Build:**

   ```bash
   # Kernel-side eBPF program
   cargo +nightly build --package sloth-ebpf \
     --target bpfel-unknown-none -Z build-std=core --release

   # Daemon (embeds the eBPF object)
   cargo build --release -p sloth-daemon
   ```

4. **Prepare Ollama:**

   ```bash
   ollama serve &                  # if it is not already running
   ollama pull llama3.2:3b         # or any model you set in sloth.toml
   ```

5. **Check your system, then run in dry-run mode first:**

   ```bash
   sudo ./target/release/sloth-daemon --check
   sudo ./target/release/sloth-daemon --config sloth.toml
   ```

   In dry-run mode the daemon logs what it *would* throttle and writes nothing. Watch the logs for a while and make sure the decisions look right.

6. **Enable real throttling** only when you are happy with the dry-run output: set `dry_run = false` in `sloth.toml` and restart.

## Configuration

Settings live in `sloth.toml`. Every value has a default in code.

```toml
dry_run = true                 # keep true until you trust the decisions

[sampling]
interval_secs = 2              # how often CPU is measured
cpu_threshold_pct = 90         # a process must exceed this...
sustained_secs = 30            # ...for this long before it is considered

[throttle]
quota_pct = 20                 # CPU cap applied, in % of one core (minimum 5)
max_concurrent = 5             # most processes throttled at once
ttl_secs = 600                 # automatic release after this long
release_below_pct = 50         # calm-down level for early release

[ai]
ollama_url = "http://localhost:11434"
model = "llama3.2:3b"
timeout_secs = 20
min_confidence = 0.8           # verdicts below this are ignored

[protected]
extra_names = []               # added to the built-in protected list
```

Exact keys may change while the project is in development. `blueprint.md` defines the configuration contract.

## Verifying It Works

Start a harmless CPU hog in a second terminal:

```bash
yes > /dev/null &
echo $!                         # note the PID
```

With `dry_run = false` and a hog that stays busy past the threshold, you should see:

```bash
cat /sys/fs/cgroup/sloth-daemon/pid-<PID>/cpu.max   # e.g. "20000 100000"
top -p <PID>                                         # roughly 20% CPU
```

Stop the daemon with `Ctrl+C`, then confirm cleanup:

```bash
ls /sys/fs/cgroup/sloth-daemon/                      # empty
kill <PID>                                           # stop your test process
```

## Running as a Service

A systemd unit example (`sloth-daemon.service`) is planned for the final phase. It will run the daemon with the minimum capabilities needed instead of full root. Until then, run it manually with `sudo` as shown above.

## Project Structure

```
sloth-daemon/
├── README.md                 # This file
├── blueprint.md              # Architecture, phases, Definition of Done
├── instructions.md           # Operating rules for the coding agent
├── .agents/skills/           # Skill files used by the coding agent
│   ├── ebpf-probe-builder.md
│   ├── cgroup-enforcer.md
│   └── ollama-bridge.md
├── Cargo.toml                # Workspace: sloth-ebpf + sloth-daemon
├── sloth-ebpf/               # Kernel-space eBPF program (aya-ebpf)
│   └── src/main.rs
└── sloth-daemon/             # User-space daemon
    └── src/
        ├── main.rs           # Config, sampling, control loop, policy gate
        ├── ai_classifier.rs  # Ollama bridge
        └── cgroup_manager.rs # cgroup v2 enforcement
```

## Documentation

- Architectural Blueprint and phase plan: `blueprint.md`
- Agent operating rules: `instructions.md`
- Agent skills: `.agents/skills/`

## Troubleshooting

| Symptom | What to check |
|:--|:--|
| "cgroup v2 not found" | Run `stat -fc %T /sys/fs/cgroup`. It must print `cgroup2fs`. Hybrid or v1 systems are not supported. |
| eBPF fails to load | Run as root or grant the capabilities. Check `/sys/kernel/btf/vmlinux` exists and `ls /sys/kernel/tracing/events/sched/`. |
| No verdicts, only warnings | Ollama is not running or the model is not pulled. Run `curl http://localhost:11434/api/tags`. The daemon throttles nothing in this state. |
| Nothing gets throttled | Check that the process exceeds the threshold for the full sustained time, is not on the protected list, and that `dry_run` is `false`. |
| Leftover `sloth-daemon` cgroups | Restart the daemon. It cleans up leftovers on startup. |

## Contributing

Development follows the phased plan in `blueprint.md` and the rules in `instructions.md`. If you use a coding agent, point it at those two files first.

## License

Distributed under the MIT License. (Change this line if you choose a different license.)