# Sloth Daemon: The AI-Assisted CPU Governor

Make greedy processes sloth-like, not dead. Sloth Daemon watches CPU usage with an eBPF probe, gathers local evidence about each busy process, optionally asks a small local LLM (Ollama) to judge it, and gently slows genuine runaways with cgroup v2 CPU limits. It never kills anything.

## What is Sloth Daemon

A runaway browser helper, a stuck script, or a forgotten background job can pin a CPU core and make your machine crawl. Sloth Daemon observes per-process CPU time directly in the kernel (no `/proc` polling), builds a compact evidence brief for every process that stays busy, and decides whether it is a runaway or legitimate heavy work like a compile or a video encode. Runaways get a CPU cap. When the process calms down or a time limit expires, the cap is lifted.

Everything runs on your machine. In the default mode there is no network access at all. In the optional LLM mode the only network call is to your local Ollama server.

## How It Works

1. **Observe:** an eBPF program (aya) attached to the `sched:sched_switch` tracepoint accumulates on-CPU time per task in a kernel map.
2. **Sample:** the user-space daemon reads that map on an interval and turns the deltas into CPU percentages per process.
3. **Gather evidence:** a deterministic broker compiles derived local facts into a `ProcessBrief`: CPU trend and burstiness, how long the process has been busy, name and parent category, thread count, memory size bucket, session kind, system CPU pressure, and a preliminary rule verdict. Command lines, environment variables, paths and usernames are never included.
4. **Classify:** the brief is turned into a typed verdict (`essential`, `interactive`, `background`, `runaway`, or `unknown`) either by the rules alone or by a local LLM reading the brief (see the two modes below).
5. **Decide:** a deterministic policy gate makes the final call. The AI is advisory only and can never override the protected list or the never-throttle list.
6. **Enforce:** approved targets are moved into a child cgroup under `/sys/fs/cgroup/sloth-daemon/` with a `cpu.max` quota, then released later.

### Two classification modes

| Mode | Setting | Needs | What decides |
|:--|:--|:--|:--|
| Rules (default) | `provider = "rules"` | Nothing | The evidence broker's preliminary verdict, built from your `never_throttle` and `throttle_candidates` lists plus the process evidence |
| Local LLM | `provider = "ollama"` | Ollama and a small model | A local model reads the `ProcessBrief` and returns a typed verdict. It can confirm or lower a throttle, never override the protected list |

If Ollama is unreachable or returns bad output, the verdict is `unknown` and nothing is throttled, unless you set `fallback_to_rules = true`.

**Default behaviour:** in rules mode, nothing is throttled until you add program names to `throttle_candidates`. A busy process that isn't on that list is classified `unknown` and left alone, so a fresh install is safe even with `dry_run = false`.

## Architecture and Tech Stack

| Component | Technology | Purpose |
|:--|:--|:--|
| Kernel probe | Rust, `aya-ebpf` | Per-process CPU accounting with minimal overhead |
| Daemon | Rust, `aya`, `tokio` | Loading the probe, sampling, control loop |
| Evidence broker | Rust (`broker.rs`) | Derived `ProcessBrief`, metric history, deterministic category rules |
| Policy gate | Rust (`policy.rs`) | Pure, table-tested decision function with hysteresis and expiry |
| AI classifier | Ollama (local HTTP API), `reqwest` | Structured JSON verdicts from the evidence brief (optional) |
| Enforcement | cgroup v2 (`cpu.max`, `cgroup.procs`) | Reversible CPU throttling |
| Observability | `tracing` | Structured logs explaining every decision |
| Agent workflow | `agy` with `.agents/skills/` | Guided, rule-bound development |

## Safety Model

- **Dry run by default.** Nothing is written to `/sys/fs/cgroup` unless `dry_run = false` is set explicitly.
- **No killing.** No signals, no `nice`, no CPU affinity changes. Only cgroup `cpu.max` and moving PIDs between cgroups.
- **Protected processes.** PID 1, the daemon itself, kernel threads, and core services (for example `systemd`, `sshd`, display servers, audio, and `ollama`) are never throttled.
- **Limits on every throttle.** A minimum quota of 5% of one core, a cap on how many processes can be throttled at once, and an automatic expiry time.
- **No flapping.** A throttled process is released only after it stays calm (well below its quota) for a cool-down period, so the cap itself cannot trigger an immediate release.
- **Fail safe.** Errors, timeouts, malformed model output or missing data mean the process is left alone.
- **Clean exit.** On shutdown, `SIGINT` or `SIGTERM`, every throttle is released and the daemon's cgroups are removed.
- **Crash recovery.** If the daemon is killed, leftover cgroups are cleaned on the next start. Because the original cgroup is only remembered in memory, recovered processes are moved to the root cgroup.
- **Private by design.** Prompts contain only derived `ProcessBrief` facts. Never command lines, environments, raw paths, or usernames.

## Requirements

- Linux with **cgroup v2** (unified hierarchy) mounted at `/sys/fs/cgroup`
- A kernel with BTF (`/sys/kernel/btf/vmlinux` exists) and the `sched_switch` tracepoint
- Root, or the capabilities `CAP_BPF` and `CAP_PERFMON` (the systemd unit runs as root with only these two)
- Rust stable plus a **nightly** toolchain with `rust-src` for the eBPF crate
- `bpf-linker`
- *Optional, LLM mode only:* [Ollama](https://ollama.com) with a small model. The daemon speaks Ollama's HTTP API; other backends (llama.cpp server, vLLM) are not supported. The recommended minimum model is `qwen2.5:0.5b` (roughly 400 MB).

Check cgroup v2 and BTF quickly:

```bash
stat -fc %T /sys/fs/cgroup        # expect: cgroup2fs
ls /sys/kernel/btf/vmlinux        # expect: the file exists
```

## Quick Start and Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Moeen-19/sloth-daemon.git
   cd sloth-daemon
   ```

2. **Install the toolchain (one time):**

   ```bash
   rustup toolchain install nightly --component rust-src
   cargo install bpf-linker
   ```

3. **Build (as your normal user, not root):**

   ```bash
   # Kernel-side eBPF program
   cargo +nightly build --package sloth-ebpf \
     --target bpfel-unknown-none -Z build-std=core --release

   # Daemon (embeds the eBPF object)
   cargo build --release -p sloth-daemon
   ```

4. **Check your system, then run in dry-run mode first:**

   ```bash
   sudo ./target/release/sloth-daemon --check
   sudo ./target/release/sloth-daemon --config sloth.toml --debug
   ```

   In dry-run mode the daemon logs what it *would* throttle and writes nothing. Watch the logs for a while and make sure the decisions look right.

5. **Enable real throttling** only when you are happy with the dry-run output: set `dry_run = false` in `sloth.toml`, add the programs you are happy to slow down to `throttle_candidates`, and restart.

6. **Optional, LLM mode:** install Ollama, pull the small recommended model, and set `provider = "ollama"`:

   ```bash
   # Arch Linux (CPU build). On other distros use the installer from ollama.com
   sudo pacman -S ollama
   sudo systemctl enable --now ollama
   ollama pull qwen2.5:0.5b
   curl -s http://localhost:11434/api/tags      # should list the model
   ```

   Then set `provider = "ollama"`, `model = "qwen2.5:0.5b"` and `timeout_secs = 60` in `sloth.toml`. The first request after a cold start can take a while on old CPUs, so keep the timeout generous. Bigger models work too but are slow on old hardware. In LLM mode the model reads the evidence brief and can confirm or lower a throttle. It cannot raise one: a process must also be allowed by the rules (for example listed in `throttle_candidates`).

   To try LLM mode safely (dry run only, one test process), run `./scripts/llm-check.sh`. Stop Ollama afterwards with `sudo systemctl stop ollama` to free memory.

## Configuration

Settings live in `sloth.toml`. Every value has a default in code.

```toml
dry_run = true                 # keep true until you trust the decisions

[sampling]
interval_secs = 2              # how often CPU is measured
cpu_threshold_pct = 90.0       # a process must exceed this (% of one core)...
sustained_secs = 30            # ...for this long before it is considered

[throttle]
quota_pct = 20                 # CPU cap applied, in % of one core (minimum 5)
max_concurrent = 5             # most processes throttled at once
ttl_secs = 600                 # automatic release after this long
cool_down_samples = 5          # release after this many calm samples in a row
                               # (calm = CPU below 50% of the quota)

[ai]
provider = "rules"             # "rules" (no Ollama needed) or "ollama"
fallback_to_rules = false      # if true, fall back to the rules verdict when Ollama fails
ollama_url = "http://localhost:11434"
model = "qwen2.5:0.5b"         # recommended minimum model for LLM mode
timeout_secs = 60              # generous: a cold first request can be slow on old CPUs
min_confidence = 0.8           # verdicts below this are ignored
never_throttle = []            # extra names that are NEVER throttled
throttle_candidates = []       # rules mode: names it may throttle. Empty = nothing is throttled

[protected]
extra_names = []               # added to the built-in protected list
```

**Built-in always-protected names:** `systemd`, `systemd-*`, `sshd`, `dbus-daemon`, `Xorg`, `Xwayland`, `gnome-shell`, `kwin_*`, `pipewire`, `pulseaudio`, `NetworkManager`, `ollama`.

## Verifying It Works

Two scripts run the full checks in one terminal. They need sudo, start a harmless `yes` busy loop, and only ever throttle that one process:

```bash
./scripts/e2e-phase5.sh --build      # throttle, CPU drop, release, cleanup
sudo ./scripts/crash-recovery.sh     # SIGKILL the daemon, restart, check cleanup
```

Build as your normal user first (`cargo build --release -p sloth-daemon`) before running `crash-recovery.sh`, since it runs as root and root usually has no Rust toolchain.

To check by hand, start a hog and wait for it to stay busy past `sustained_secs`:

```bash
yes > /dev/null &
pgrep -n yes                                           # note the PID
cat /sys/fs/cgroup/sloth-daemon/pid-<PID>/cpu.max      # e.g. "20000 100000"
top -b -n 2 -d 2 -p <PID> | tail -2                    # roughly 20% CPU
```

After stopping the daemon with `Ctrl+C`, confirm cleanup:

```bash
ls -d /sys/fs/cgroup/sloth-daemon/pid-*                # expect: no matches
kill <PID>                                             # stop your test process
```

## Running as a Service

A systemd unit file is provided at [`sloth-daemon.service`](sloth-daemon.service). It has been tested as a running service (throttle, release, SIGTERM shutdown and cleanup) with only `CAP_BPF` and `CAP_PERFMON`.

```bash
sudo cp target/release/sloth-daemon /usr/local/bin/
sudo mkdir -p /etc/sloth-daemon
sudo cp sloth.toml /etc/sloth-daemon/sloth.toml
sudo cp sloth-daemon.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now sloth-daemon
journalctl -u sloth-daemon -f
```

Capabilities set in the unit: `CAP_BPF` and `CAP_PERFMON`, for loading eBPF and attaching tracepoints. All other capabilities are dropped. The cgroup operations (create directory, write `cpu.max`, move PIDs) need no capability because the service runs as root and they are checked by file permissions. If your system behaves differently, permission errors in `journalctl -u sloth-daemon` will say which operation failed. Note that the unit does not set `ProtectKernelTunables` or `ReadWritePaths`, because the daemon must write under `/sys/fs/cgroup` to release processes back to their original cgroup.

## Tested On

- Arch Linux, cgroup v2, kernel `7.2.11-arch1-1` (unit tests, live throttle/release, crash recovery)
- systemd service: tested live (throttle, release, SIGTERM, no leftovers)
- Rules mode: tested live. LLM mode: tested live in dry-run with `qwen2.5:0.5b, gemma3:1b` on Ollama (about 10 s per verdict on an old laptop CPU) and against a mock Ollama server.

## Limitations

- CPU only. No memory, disk or network throttling.
- Linux with pure cgroup v2 only. No cgroup v1 or hybrid setups.
- The LLM sees only derived facts about a process, so it can misjudge unusual workloads. The policy gate, protected list and dry-run mode are the safety net.
- Small local models are weak. The evidence brief is what makes them usable.

## Project Structure

```
sloth-daemon/
├── README.md                 # This file
├── blueprint.md              # Architecture, phases, Definition of Done
├── instructions.md           # Operating rules for the coding agent
├── sloth-daemon.service      # Systemd unit example
├── sloth.toml                # Example configuration
├── scripts/
│   ├── e2e-phase5.sh         # End-to-end throttle test (needs sudo)
│   ├── crash-recovery.sh     # Crash-recovery integration test (root required)
│   └── llm-check.sh          # Live Ollama check, dry run only (needs sudo and Ollama)
├── .agents/skills/           # Skill files used by the coding agent
│   ├── ebpf-probe-builder.md
│   ├── cgroup-enforcer.md
│   └── ollama-bridge.md
├── Cargo.toml                # Workspace: sloth-ebpf + sloth-daemon
├── sloth-ebpf/               # Kernel-space eBPF program (aya-ebpf)
│   └── src/main.rs
└── sloth-daemon/             # User-space daemon
    └── src/
        ├── main.rs           # Config, sampling, control loop, signals
        ├── broker.rs         # Evidence broker: ProcessBrief, metric history, rules
        ├── policy.rs         # Deterministic policy gate
        ├── ai_classifier.rs  # Ollama bridge (optional; rules mode needs no Ollama)
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
| Ollama warnings in LLM mode | Ollama is not running or the model is not pulled. Run `curl http://localhost:11434/api/tags`. The daemon throttles nothing in this state unless `fallback_to_rules = true`. |
| Nothing gets throttled | Check that the process stays above the threshold for the full sustained time, is not protected, is allowed by your `throttle_candidates` / `never_throttle` lists (an empty `throttle_candidates` means nothing is throttled in rules mode), and that `dry_run` is `false`. |
| `cargo` fails under sudo | Root has no default toolchain. Build as your normal user, then run only the binary or scripts with sudo. |
| Leftover `sloth-daemon` cgroups | Restart the daemon. It cleans up leftovers on startup. |

## Contributing

Development follows the phased plan in `blueprint.md` and the rules in `instructions.md`. If you use a coding agent, point it at those two files first.

## License

Distributed under the AGPL-3.0 License. See [`LICENSE`](LICENSE).