//! Architecture abstraction layer.
//!
//! Defines traits for disassembly and IR lifting so that new architectures
//! (ARM64, RISC-V, …) can be added without modifying core analysis/codegen.

pub mod x86;

use crate::cfg::Cfg;
use crate::disasm::DisasmInsn;
use crate::error::Result;
use crate::ir::{CallingConv, Function};
use crate::loader::Binary;

/// Architecture-specific disassembler.
pub trait ArchDisasm {
    /// Disassemble a function-sized region starting at `addr`.
    fn disassemble_function(
        &self,
        binary: &Binary,
        addr: u64,
        size: u64,
    ) -> Result<Vec<DisasmInsn>>;
}

/// Architecture-specific IR lifter.
pub trait ArchLifter {
    /// Set the calling convention for subsequent lift operations.
    fn set_calling_conv(&mut self, cc: CallingConv);

    /// Get the current calling convention.
    fn calling_conv(&self) -> CallingConv;

    /// Lift a function's CFG into IR.
    fn lift_function(
        &mut self,
        name: &str,
        addr: u64,
        cfg: &Cfg,
        binary: &Binary,
    ) -> Function;
}
