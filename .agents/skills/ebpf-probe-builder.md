---
name: ebpf-probe-builder
description: Guidelines for writing safe, verifier-friendly aya eBPF kernel probes for sloth-daemon (per-PID CPU accounting via tracepoints).
---

# Skill: eBPF Probe Builder (aya)

Use this skill whenever you create or modify anything in `sloth-ebpf/` or the user-space code that loads and reads from it.

## When to Use

- Writing or changing tracepoint programs or BPF maps.
- Changing how `sloth-daemon/src/main.rs` loads, attaches, or reads the probe.
- Debugging a verifier rejection or a load error.

## Core Principles

1. **The kernel program counts; user space decides.** The probe only records raw CPU time per PID. No thresholds, no string handling, no policy.
2. **Keep it tiny.** Fewer instructions means fewer verifier problems and lower overhead on the scheduler hot path.
3. **Never block, never panic.** Every failure path returns early.
4. **Verify the API for the pinned version.** aya's macros, map types, and attach APIs have changed between releases. Check `Cargo.lock` and the docs for that exact version before writing code. Do not rely on memory of older examples.

## Probe Design for sloth-daemon

**Goal:** Accumulate on-CPU nanoseconds per PID.

**Mechanism:** Attach to the `sched:sched_switch` tracepoint.

- Keep a per-CPU record of `(pid, start_timestamp_ns)` for the task currently running on that CPU. A `PerCpuArray` with one slot is the usual choice.
- On each switch event:
  1. Read the current time with `bpf_ktime_get_ns()`.
  2. If the per-CPU slot holds a previous task with a valid start time, compute `delta = now - start` and add it to that task's total in `PID_CPU_NS`.
  3. Record the incoming task's PID and `now` into the per-CPU slot.
- Skip PID 0 (idle).
- **Key choice (thread id vs process id):** `sched_switch` exposes `prev_pid` and `next_pid`, which are kernel task ids (thread ids). Getting the tgid of `prev` from the tracepoint alone is not reliable. The simplest correct approach is to key by task id in the kernel and aggregate threads into processes in user space (via `/proc/<pid>/status` `Tgid:` field). State this tradeoff to the user in your phase summary and record the final choice in a code comment.

**Maps:**

| Map | Type | Key | Value | Notes |
|:--|:--|:--|:--|:--|
| `PID_CPU_NS` | LRU hash map | `u32` task id | `u64` ns | Bounded size (for example 16384). LRU so it self-trims if exit events are missed |
| `CPU_START` | per-CPU array | `u32` (index 0) | struct `{ pid: u32, start_ns: u64 }` | One slot per CPU |

Do not add more maps without asking.

**Cleanup:** attach a second tracepoint on `sched:sched_process_exit` that removes the exiting task's entry from `PID_CPU_NS`. Without it, dead PIDs linger until LRU eviction.

## Reading Tracepoint Fields Safely

- Do **not** hard-code field offsets from memory. Tracepoint layouts are kernel-specific.
- Read the real layout on the target machine from `/sys/kernel/tracing/events/sched/sched_switch/format` (or `/sys/kernel/debug/tracing/events/sched/sched_switch/format`) and encode the offsets of `prev_pid` and `next_pid` as named constants with a comment pointing at that file.
- Use aya's safe read helpers on the `TracePointContext` (for example `ctx.read_at::<T>(offset)`); confirm the exact method name in the pinned version.

## Verifier Rules of Thumb

- Bounded loops only. Prefer no loops.
- Stack is 512 bytes maximum. Keep structs small.
- Check every map lookup result for `None` before use.
- Use wrapping or saturating arithmetic for counters.
- No function calls except `#[inline(always)]` helpers and BPF helpers.
- No floating point in the kernel program.
- Never index with an unchecked variable.
- Include a GPL-compatible license section so GPL-only helpers are allowed. aya templates provide this; verify the exact form for the pinned version.

## Shape Guide (verify every name against the pinned aya version before using)

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray},
    programs::TracePointContext,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuStart {
    pub pid: u32,
    pub start_ns: u64,
}

#[map]
static PID_CPU_NS: LruHashMap<u32, u64> = LruHashMap::with_max_entries(16384, 0);

#[map]
static CPU_START: PerCpuArray<CpuStart> = PerCpuArray::with_max_entries(1, 0);

// Offsets come from /sys/kernel/tracing/events/sched/sched_switch/format
const PREV_PID_OFFSET: usize = 0; // TODO: replace with the real offset
const NEXT_PID_OFFSET: usize = 0; // TODO: replace with the real offset

#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    // Never fail loudly in the scheduler path.
    let _ = try_sched_switch(&ctx);
    0
}

fn try_sched_switch(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: bpf_ktime_get_ns has no preconditions.
    let now = unsafe { bpf_ktime_get_ns() };
    // 1. Read prev_pid / next_pid with ctx.read_at at the offsets above.
    // 2. Look up CPU_START slot 0; if it holds a running task (pid != 0),
    //    add (now - start_ns) to PID_CPU_NS[pid].
    // 3. Store next_pid and `now` into CPU_START slot 0.
    let _ = (ctx, now);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

This is a shape guide, not final code. Fill in the real reads and map updates, and confirm every import, macro, and constructor name against the aya version in `Cargo.lock`.

## User-Space Loading Checklist

1. Embed the compiled object with aya's `include_bytes_aligned!` (see how `build.rs` or the documented build sequence produces it).
2. Load it (`Ebpf::load` on current aya; `Bpf::load` on older versions. Check the pinned version).
3. Optionally initialise `aya_log` so kernel logs surface in `tracing`. Keep logging out of the hot path in the final build.
4. For each program: get by name, convert to the tracepoint type, `load()`, then `attach("sched", "sched_switch")` (and `"sched_process_exit"` for the cleanup program).
5. Take the map by name and wrap it in its typed user-space map. LRU hash maps have their own type in aya; check the docs.
6. On each sample interval read all entries, compute `delta_ns / window_ns * 100.0` as CPU percent (100.0 = one core), and keep the new totals for the next window.
7. Handle counter resets (new total smaller than old): treat as a restarted PID and skip that sample.
8. Keep the `Ebpf` handle alive for the whole program lifetime. Dropping it detaches the probes.

## Building

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo +nightly build --package sloth-ebpf \
  --target bpfel-unknown-none -Z build-std=core --release
```

## Debugging Playbook

| Symptom | Likely cause | What to do |
|:--|:--|:--|
| Verifier: invalid memory access / register errors | Unchecked map lookup or wrong offset | Add the `None` check, re-read the tracefs format file |
| `bpf-linker` or link errors | Missing `bpf-linker`, wrong target, missing `-Z build-std=core` | Re-run the build command above |
| Load fails with a permission error | Missing capabilities | Ask the user to run with the needed privileges |
| Load fails with BTF or tracepoint-not-found | Kernel lacks the feature or the name differs | Check `ls /sys/kernel/tracing/events/sched/` and `/sys/kernel/btf/vmlinux`, then ask the user |
| Map has no entries | Program not attached, or handle dropped | Check attach return values and handle lifetime |
| CPU% wildly off | Wrong time units, or thread-id vs process-id mix-up | Print raw deltas and compare to `top` |

Useful read-only host commands to suggest to the user: `bpftool prog show`, `bpftool map dump name PID_CPU_NS`, `cat /sys/kernel/tracing/events/sched/sched_switch/format`.

## Do Not

- Do not add kprobes, uprobes, or other attach points without asking.
- Do not send per-event data to user space (ring buffer or perf array) for every context switch. It is far too hot. Aggregate in the kernel map.
- Do not store process names in the kernel map.
- Do not make decisions in the kernel program.
- Do not use `unsafe` without a `// SAFETY:` comment.
- Do not leave debug logging enabled in the hot path of the final build.