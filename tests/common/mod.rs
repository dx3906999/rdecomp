//! Shared helpers for integration tests.
//!
//! This module lives in `tests/common/mod.rs` so Cargo does NOT treat it as
//! an independent test crate.  Other `tests/*.rs` files pull it in with:
//!
//! ```ignore
//! mod common;
//! ```

use rdecomp::analysis;
use rdecomp::arch::x86::{X86Disasm, X86Lifter};
use rdecomp::arch::{ArchDisasm, ArchLifter};
use rdecomp::cfg::Cfg;
use rdecomp::codegen::CodeGenerator;
use rdecomp::ir::{CallingConv, Function};
use rdecomp::loader::Binary;
use rdecomp::pass::PassContext;
use std::collections::HashSet;
use std::path::Path;

/// Load a test binary from `test_file/bin/wsl/`.
pub fn load_wsl_binary(name: &str) -> Binary {
    let path = Path::new("test_file/bin/wsl").join(name);
    assert!(path.exists(), "test binary not found: {}", path.display());
    let mut binary = Binary::from_path(&path).expect("failed to load binary");
    binary.discover_functions();
    binary
}

/// Full pipeline: disasm → cfg → lift → optimize → codegen for a single function.
pub fn decompile_function(binary: &Binary, func_name: &str) -> String {
    let func_sym = binary
        .functions
        .iter()
        .find(|f| f.name == func_name)
        .unwrap_or_else(|| panic!("function '{}' not found in binary", func_name));

    let addr = func_sym.addr;
    let size = infer_function_size(binary, func_sym);

    let disasm: Box<dyn ArchDisasm> = Box::new(X86Disasm);
    let instructions = disasm
        .disassemble_function(binary, addr, size)
        .expect("disassembly failed");

    let cfg = Cfg::build(&instructions);

    let mut lifter: Box<dyn ArchLifter> = Box::new(X86Lifter::new(binary.arch));
    apply_calling_conv(binary, &mut *lifter);

    let mut func = lifter.lift_function(&func_sym.name, addr, &cfg, binary);

    let ctx = build_pass_context(binary);
    let pm = analysis::default_pass_manager();
    pm.run_all(&mut func, &ctx);

    let mut codegen = CodeGenerator::new(&binary.functions, binary);
    codegen.generate(&mut func, &cfg)
}

/// Lift a function to IR (without codegen).
pub fn lift_function(binary: &Binary, func_name: &str) -> Function {
    let func_sym = binary
        .functions
        .iter()
        .find(|f| f.name == func_name)
        .unwrap_or_else(|| panic!("function '{}' not found in binary", func_name));

    let addr = func_sym.addr;
    let size = infer_function_size(binary, func_sym);

    let disasm: Box<dyn ArchDisasm> = Box::new(X86Disasm);
    let instructions = disasm
        .disassemble_function(binary, addr, size)
        .expect("disassembly failed");

    let cfg = Cfg::build(&instructions);

    let mut lifter: Box<dyn ArchLifter> = Box::new(X86Lifter::new(binary.arch));
    apply_calling_conv(binary, &mut *lifter);

    let mut func = lifter.lift_function(&func_sym.name, addr, &cfg, binary);

    let ctx = build_pass_context(binary);
    let pm = analysis::default_pass_manager();
    pm.run_all(&mut func, &ctx);
    func
}

// ── private helpers ─────────────────────────────────────────────

fn infer_function_size(binary: &Binary, func_sym: &rdecomp::loader::FunctionSymbol) -> u64 {
    if func_sym.size > 0 {
        func_sym.size
    } else {
        binary
            .functions
            .iter()
            .map(|f| f.addr)
            .filter(|&a| a > func_sym.addr)
            .min()
            .map(|next| next - func_sym.addr)
            .unwrap_or(65536)
    }
}

fn apply_calling_conv(binary: &Binary, lifter: &mut dyn ArchLifter) {
    match (binary.arch, binary.format) {
        (rdecomp::loader::Arch::X86, _) => lifter.set_calling_conv(CallingConv::Cdecl),
        (_, rdecomp::loader::BinaryFormat::Pe) => lifter.set_calling_conv(CallingConv::Win64),
        _ => {}
    }
}

fn build_pass_context(binary: &Binary) -> PassContext {
    let noreturn_addrs: HashSet<u64> = binary
        .plt_map
        .iter()
        .filter(|(_, name)| rdecomp::ir::is_noreturn_name(name))
        .map(|(addr, _)| *addr)
        .collect();

    PassContext { noreturn_addrs }
}
