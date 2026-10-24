use std::env;
use std::fs;
use std::path::PathBuf;

/// Magic byte sequence for the non-loadable eBPF placeholder.
pub const EBPF_PLACEHOLDER_MAGIC: &[u8] = b"SLOTH_EBPF_NOT_BUILT_PLACEHOLDER\0";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let dest_path = out_dir.join("sloth-ebpf.bin");

    println!("cargo:rerun-if-env-changed=SLOTH_EBPF_PATH");
    println!("cargo:rerun-if-env-changed=SLOTH_FORCE_PLACEHOLDER");

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir.parent().unwrap_or(&manifest_dir);

    let force_placeholder = env::var("SLOTH_FORCE_PLACEHOLDER").as_deref() == Ok("1");

    let candidates = if let Ok(custom_path) = env::var("SLOTH_EBPF_PATH") {
        vec![PathBuf::from(custom_path)]
    } else {
        vec![
            workspace_root.join("target/bpfel-unknown-none/release/sloth-ebpf"),
            workspace_root.join("target/bpfel-unknown-none/debug/sloth-ebpf"),
        ]
    };

    let mut found = false;
    if !force_placeholder {
        for candidate in candidates {
            println!("cargo:rerun-if-changed={}", candidate.display());
            if candidate.exists() {
                if let Ok(bytes) = fs::read(&candidate) {
                    if bytes.starts_with(b"\x7fELF") && fs::copy(&candidate, &dest_path).is_ok() {
                        found = true;
                        break;
                    }
                }
            }
        }
    }

    if !found {
        fs::write(&dest_path, EBPF_PLACEHOLDER_MAGIC).expect("failed to write eBPF placeholder");
    }
}
