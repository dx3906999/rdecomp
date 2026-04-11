//! x86/x86-64 architecture backend.
//!
//! Wraps the existing `disasm` and `lift` modules behind the `ArchDisasm` and
//! `ArchLifter` traits so that the main pipeline can work architecture-generically.

use super::{ArchDisasm, ArchLifter};
use crate::cfg::Cfg;
use crate::disasm::{self, DisasmInsn};
use crate::error::Result;
use crate::ir::{CallingConv, Function};
use crate::lift::Lifter;
use crate::loader::{Arch, Binary};

/// x86/x86-64 disassembler (delegates to `disasm::disassemble_function`).
pub struct X86Disasm;

impl ArchDisasm for X86Disasm {
    fn disassemble_function(
        &self,
        binary: &Binary,
        addr: u64,
        size: u64,
    ) -> Result<Vec<DisasmInsn>> {
        disasm::disassemble_function(binary, addr, size)
    }
}

/// x86/x86-64 IR lifter (wraps `lift::Lifter`).
pub struct X86Lifter {
    inner: Lifter,
}

impl X86Lifter {
    pub fn new(arch: Arch) -> Self {
        Self {
            inner: Lifter::new(arch),
        }
    }
}

impl ArchLifter for X86Lifter {
    fn set_calling_conv(&mut self, cc: CallingConv) {
        self.inner.set_calling_conv(cc);
    }

    fn calling_conv(&self) -> CallingConv {
        self.inner.calling_conv()
    }

    fn lift_function(
        &mut self,
        name: &str,
        addr: u64,
        cfg: &Cfg,
        binary: &Binary,
    ) -> Function {
        self.inner.lift_function(name, addr, cfg, binary)
    }
}
