//! CFG construction tests.

mod common;

use rdecomp::arch::x86::X86Disasm;
use rdecomp::arch::ArchDisasm;
use rdecomp::cfg::Cfg;

#[test]
fn cfg_builds_for_classify() {
    let binary = common::load_wsl_binary("case1_control");
    let func_sym = binary.functions.iter().find(|f| f.name == "classify").unwrap();
    let disasm = X86Disasm;
    let instructions = disasm
        .disassemble_function(&binary, func_sym.addr, func_sym.size)
        .unwrap();
    let cfg = Cfg::build(&instructions);
    assert!(!cfg.blocks.is_empty(), "CFG should have blocks");
    // classify has 4 branches → should have multiple blocks
    assert!(
        cfg.blocks.len() >= 4,
        "classify CFG should have >=4 blocks, got {}",
        cfg.blocks.len()
    );
}
