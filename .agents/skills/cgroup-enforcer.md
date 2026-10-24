---
name: cgroup-enforcer
description: Logic for safe, reversible cgroup v2 CPU throttling in sloth-daemon (cpu.max, cgroup.procs, protected list, release and cleanup).
---

# Skill: Cgroup v2 Enforcer

Use this skill whenever you write or change `sloth-daemon/src/cgroup_manager.rs` or anything that touches `/sys/fs/cgroup`.

## Mission

Slow a chosen process down by capping its CPU with cgroup v2, and be able to **undo it exactly**. Nothing else. No signals, no `nice`, no affinity, no killing.

## Cgroup v2 Facts You Must Respect

- The unified hierarchy is normally mounted at `/sys/fs/cgroup`. Verify with the filesystem type (`cgroup2`) in `/proc/self/mountinfo` or `statfs`; do not assume.
- A process belongs to exactly one cgroup. Move it by writing its PID (as text, plus newline) to the target cgroup's `cgroup.procs`. Moving a PID moves the whole process (all threads).
- `cpu.max` has the format `"$MAX $PERIOD"` in microseconds. Examples:
  - `"20000 100000"` means 20 ms of CPU per 100 ms period, i.e. 20% of one core.
  - `"max 100000"` means no limit (the default).
- Quota percent to `cpu.max`: `quota_us = period_us * pct / 100`. With a 100000 µs period, `pct = 20` gives `20000`. Values above 100% (multiple cores) are valid but this daemon only throttles *down*, so it clamps `pct` between the floor (5) and a configured ceiling (default 100 or less).
- A child cgroup only has `cpu.max` if the **parent's `cgroup.subtree_control` lists `cpu`**. Enable it by writing `+cpu` to the parent's `cgroup.subtree_control`. Check `cgroup.controllers` of the parent first to make sure `cpu` is available there. On systemd systems the root usually already offers it.
- **No-internal-process rule:** a non-root cgroup that has controllers enabled for its children cannot also contain processes directly. So the daemon's own parent cgroup (`/sys/fs/cgroup/sloth-daemon/`) must hold **no processes** when `+cpu` is enabled in its `subtree_control`. Put throttled processes only in *leaf children* (`/sys/fs/cgroup/sloth-daemon/<id>/`). The daemon process itself stays where it is.
- Under systemd, writing outside your delegated subtree can conflict with systemd's management. Using a top-level directory under the root cgroup works for a root daemon, but if the user runs the daemon as a systemd service, mention that a unit with `Delegate=yes` is the cleaner approach and ask before choosing.
- Removing a cgroup is done with `rmdir`, and only succeeds if it has no processes and no child cgroups. Do not try to delete files inside a cgroup directory.

## Layout

```
/sys/fs/cgroup/
└── sloth-daemon/                 # parent, created by the daemon, cpu enabled in subtree_control
    ├── pid-12345/                # one leaf per throttled process
    │   ├── cpu.max
    │   └── cgroup.procs
    └── pid-67890/
```

Child directory names are built **only from the numeric PID** (`pid-<u32>`). Never build a path from a process name or any text that did not come from a parsed integer.

## Module API (suggested shape)

```rust
pub struct CgroupManager { /* config, root path, state map, dry_run */ }

pub enum EnforceError { Protected(Reason), CapReached, QuotaInvalid, Io(std::io::Error), NotSupported }

impl CgroupManager {
    pub fn new(cfg: &Config) -> anyhow::Result<Self>;       // preflight + startup cleanup
    pub fn throttle(&mut self, pid: u32, quota_pct: u8) -> Result<(), EnforceError>;
    pub fn release(&mut self, pid: u32) -> Result<(), EnforceError>;
    pub fn release_all(&mut self);                           // idempotent, never panics
    pub fn is_protected(&self, pid: u32) -> Option<Reason>;
    pub fn active(&self) -> impl Iterator<Item = &ThrottleRecord>;
}

pub struct ThrottleRecord {
    pub pid: u32,
    pub comm: String,
    pub original_cgroup: PathBuf,   // recorded BEFORE moving
    pub quota_pct: u8,
    pub started_at: Instant,
}
```

Keep the pure parts (quota math, protected-list matching, `cpu.max` string building, cgroup path parsing) in small free functions so they can be unit-tested without root.

## Throttle Procedure (in this exact order)

1. **Validate input:** quota within `[FLOOR_PCT, ceiling]`; `pid > 1`.
2. **Protected check** (see below). If protected, return `EnforceError::Protected` and log. No writes.
3. **Concurrency cap check.** If at the cap, return `CapReached`.
4. **Re-verify the target:** confirm `/proc/<pid>` still exists and its `comm` still matches what the decision was based on (PIDs can be reused). If not, abort.
5. **Record the original cgroup:** parse `/proc/<pid>/cgroup`. On cgroup v2 the line looks like `0::/user.slice/user-1000.slice/...`. Store the path after `0::`. If the file cannot be parsed, abort rather than guess.
6. **If `dry_run`:** log exactly what would be created and written, then return `Ok`. **Zero filesystem writes.**
7. Ensure the parent cgroup exists and `+cpu` is enabled in its `subtree_control` (idempotent).
8. Create the leaf directory `pid-<pid>` (ignore "already exists").
9. Write `cpu.max` in the leaf **first**, *before* moving the process, so there is never a moment where the process is in the leaf unthrottled.
10. Write the PID to the leaf's `cgroup.procs`.
11. Store the `ThrottleRecord`. If any step after creating the leaf fails, roll back (move PID back if it was moved, `rmdir` the leaf) and return the error.

## Release Procedure

1. Look up the record. If the PID is gone (`/proc/<pid>` missing), just remove the leaf if empty and drop the record.
2. Write the PID to the **recorded original** cgroup's `cgroup.procs`. If the original no longer exists, fall back to the root `cgroup.procs` (`/sys/fs/cgroup/cgroup.procs`) and log a warning.
3. Optionally reset `cpu.max` to `max 100000` in the leaf (harmless; it is about to be removed).
4. `rmdir` the leaf. If it fails because it is busy, log and retry on the next tick. Do not loop forever.
5. Drop the record.

Releasing must be safe to call twice and for PIDs that no longer exist.

## Protected List (Hard Rules)

`is_protected(pid)` returns `Some(reason)` if **any** of these hold:

- `pid == 1`, or `pid == std::process::id()`, or `pid` is the daemon's parent.
- Kernel thread: `/proc/<pid>/exe` cannot be read (readlink fails), or the parent PID is 2, or `/proc/<pid>/cmdline` is empty. Use at least two signals if possible.
- `comm` matches the protected set. Support exact names and simple glob suffixes such as `systemd-*` and `kwin_*`. Default set: `systemd`, `systemd-*`, `sshd`, `dbus-daemon`, `Xorg`, `Xwayland`, `gnome-shell`, `kwin_*`, `pipewire`, `pulseaudio`, `NetworkManager`, `ollama`. The config may **add** names; it may not remove the built-in minimum.
- The process is in a cgroup under `system.slice` that belongs to a core service, or is otherwise in the user's configured protected cgroup prefixes. Keep this check conservative.
- The PID is already throttled and the record says another quota (avoid double-handling; update instead).

The AI verdict is never consulted here. This function is deterministic and has unit tests.

## Safety Rails

- **Quota floor:** never below 5% of one core. A process at 0% can deadlock others that wait on it.
- **Concurrency cap:** configurable (default small, for example 5).
- **TTL:** every record has a start time; the control loop in `main.rs` calls `release` when the TTL expires. The manager exposes `started_at` so the loop can enforce it.
- **Startup cleanup:** on `new()`, list `/sys/fs/cgroup/sloth-daemon/pid-*`. For each, move any remaining PIDs back to the root cgroup (`/sys/fs/cgroup/cgroup.procs`) since the original is unknown after a crash, then `rmdir`. Log what was cleaned.
- **Shutdown cleanup:** `release_all()` is called on graceful exit, from a signal handler task, and from a panic hook. It must never panic and must continue past individual failures.
- **No other process control:** no signals, `nice`, affinity changes, or `/proc/<pid>` writes. Only the cgroup files named above.
- **Permissions errors:** if a write fails with `EACCES`/`EPERM`, stop throttling entirely, log a clear `error`, and surface it to the control loop so it can exit or stay in observe-only mode. Do not retry in a tight loop.
- **Path safety:** every path written must start with `/sys/fs/cgroup/` and, for creates and `cpu.max`, with `/sys/fs/cgroup/sloth-daemon/`. Add a small helper that asserts this and use it for all writes.

## Writing Control Files Correctly

- Open with write-only, no create, no truncate semantics assumptions; cgroup files are special. Write the whole string in a single `write` call (for example `std::fs::write(path, "20000 100000\n")`).
- Include a trailing newline for PIDs and `cpu.max`.
- Map `ESRCH`/`ENOENT` on `cgroup.procs` to "process already exited" (not an error). Map `EBUSY` and `EINVAL` to descriptive errors.

## Unit Tests to Write (no root needed)

- `cpu_max_string(pct, period)` for 5, 20, 50, 100 and invalid values (0, 4, 101).
- Protected matching: exact names, `systemd-*`, `kwin_*`, case sensitivity, names near the 16-byte comm limit.
- Parsing `/proc/<pid>/cgroup` content: normal v2 line, hybrid v1+v2 lines (pick the `0::` entry), empty, malformed.
- Path guard rejects `..`, absolute escapes, and anything outside the allowed prefixes.
- Dry run performs no writes (use a temp directory as a fake cgroup root, injected via the manager's root path field).

## Manual Verification (give these to the user; they need privileges)

```bash
# Start a victim
yes > /dev/null &  echo $!

# After the daemon throttles it:
cat /sys/fs/cgroup/sloth-daemon/pid-<PID>/cpu.max      # expect e.g. "20000 100000"
cat /proc/<PID>/cgroup                                  # expect .../sloth-daemon/pid-<PID>
top -p <PID>                                            # expect ~20% CPU

# After shutdown:
ls /sys/fs/cgroup/sloth-daemon/                         # expect empty
cat /proc/<PID>/cgroup                                  # expect original path again
kill <PID>                                              # the user cleans up the victim
```

## Do Not

- Do not write to `cpu.weight`, `cpu.uclamp.*`, `cgroup.freeze`, `cgroup.kill`, or any file other than `cpu.max`, `cgroup.procs`, and `cgroup.subtree_control` (parent only).
- Do not use `cgroup.kill` or `cgroup.freeze`. They kill or stop processes.
- Do not shell out to `cgcreate`, `cgset`, `systemctl`, or `systemd-run`.
- Do not throttle without recording the original cgroup.
- Do not assume cgroup v1 or a hybrid setup. If the preflight finds anything but pure v2 at `/sys/fs/cgroup`, refuse to enforce and tell the user.