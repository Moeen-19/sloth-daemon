#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray},
    programs::TracePointContext,
};

// Field offset verified from /sys/kernel/tracing/events/sched/sched_switch/format
const SCHED_SWITCH_PREV_PID_OFFSET: usize = 24;
// Field offset verified from /sys/kernel/tracing/events/sched/sched_switch/format
const SCHED_SWITCH_NEXT_PID_OFFSET: usize = 56;

// Field offset verified from /sys/kernel/tracing/events/sched/sched_process_exit/format
const SCHED_PROCESS_EXIT_PID_OFFSET: usize = 24;

/// Per-CPU tracking of the currently running task.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuStart {
    pub pid: u32,
    pub start_ns: u64,
}

/// Map of accumulated on-CPU nanoseconds keyed by kernel task/thread ID.
/// LRU ensures that stale entries are evicted if process exit tracepoint is missed.
#[map]
static PID_CPU_NS: LruHashMap<u32, u64> = LruHashMap::with_max_entries(16384, 0);

/// Per-CPU array tracking the start timestamp of the active task on each CPU.
#[map]
static CPU_START: PerCpuArray<CpuStart> = PerCpuArray::with_max_entries(1, 0);

/// Handles sched_switch tracepoints to record on-CPU time deltas.
#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    let _ = try_sched_switch(&ctx);
    0
}

fn try_sched_switch(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: bpf_ktime_get_ns has no preconditions and never fails.
    let now = unsafe { bpf_ktime_get_ns() };

    // Read prev_pid and next_pid from the tracepoint context (i32 per kernel format).
    // SAFETY: read_at reads kernel memory within verified tracepoint bounds.
    let _prev_pid =
        unsafe { ctx.read_at::<i32>(SCHED_SWITCH_PREV_PID_OFFSET) }.map_err(|e| e as i64)? as u32;

    // SAFETY: read_at reads kernel memory within verified tracepoint bounds.
    let next_pid =
        unsafe { ctx.read_at::<i32>(SCHED_SWITCH_NEXT_PID_OFFSET) }.map_err(|e| e as i64)? as u32;

    // Charge the elapsed time to the task stored in CPU_START, not just prev_pid.
    // Skip if slot has pid == 0 (idle) or start_ns == 0 (probe attached mid-run).
    if let Some(slot) = CPU_START.get(0) {
        if slot.pid != 0 && slot.start_ns != 0 && now >= slot.start_ns {
            let delta = now - slot.start_ns;
            // SAFETY: get_ptr_mut safely queries the BPF map with checked Option result.
            let current_total =
                unsafe { PID_CPU_NS.get_ptr_mut(slot.pid).map(|p| *p).unwrap_or(0) };
            let new_total = current_total.wrapping_add(delta);
            let _ = PID_CPU_NS.insert(slot.pid, new_total, 0);
        }
    }

    // Record incoming task and timestamp into CPU_START slot 0.
    let next_slot = CpuStart {
        pid: next_pid,
        start_ns: now,
    };
    let _ = CPU_START.set(0, next_slot, 0);

    Ok(())
}

/// Handles sched_process_exit tracepoints to clean up exiting tasks from the map.
#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    let _ = try_sched_process_exit(&ctx);
    0
}

fn try_sched_process_exit(ctx: &TracePointContext) -> Result<(), i64> {
    // Read exiting pid from tracepoint context (i32 per kernel format).
    // SAFETY: read_at reads kernel memory within verified tracepoint bounds.
    let pid =
        unsafe { ctx.read_at::<i32>(SCHED_PROCESS_EXIT_PID_OFFSET) }.map_err(|e| e as i64)? as u32;

    if pid != 0 {
        let _ = PID_CPU_NS.remove(pid);
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static _license: [u8; 4] = *b"GPL\0";
