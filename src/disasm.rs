use crate::error::Result;
use crate::loader::{Arch, Binary};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, Mnemonic};

/// A disassembled instruction with its address and raw bytes.
#[derive(Debug, Clone)]
pub struct DisasmInsn {
    pub addr: u64,
    pub len: usize,
    pub mnemonic: Mnemonic,
    pub insn: Instruction,
    pub text: String,
}

impl DisasmInsn {
    /// Whether this instruction is a branch (conditional or unconditional).
    pub fn is_branch(&self) -> bool {
        self.insn.flow_control() == iced_x86::FlowControl::ConditionalBranch
            || self.insn.flow_control() == iced_x86::FlowControl::UnconditionalBranch
    }

    /// Whether this is a call instruction.
    pub fn is_call(&self) -> bool {
        self.insn.flow_control() == iced_x86::FlowControl::Call
            || self.insn.flow_control() == iced_x86::FlowControl::IndirectCall
    }

    /// Whether this is a return instruction.
    pub fn is_return(&self) -> bool {
        self.insn.flow_control() == iced_x86::FlowControl::Return
    }

    /// Whether this instruction terminates a basic block.
    pub fn is_terminator(&self) -> bool {
        matches!(
            self.insn.flow_control(),
            iced_x86::FlowControl::ConditionalBranch
                | iced_x86::FlowControl::UnconditionalBranch
                | iced_x86::FlowControl::Return
                | iced_x86::FlowControl::IndirectBranch
        )
    }

    /// Get the branch/jump target address if it's a direct branch.
    pub fn branch_target(&self) -> Option<u64> {
        if (self.insn.flow_control() == iced_x86::FlowControl::ConditionalBranch
            || self.insn.flow_control() == iced_x86::FlowControl::UnconditionalBranch
            || self.insn.flow_control() == iced_x86::FlowControl::Call)
            && (self.insn.op0_kind() == iced_x86::OpKind::NearBranch16
                || self.insn.op0_kind() == iced_x86::OpKind::NearBranch32
                || self.insn.op0_kind() == iced_x86::OpKind::NearBranch64)
            {
                return Some(self.insn.near_branch_target());
            }
        None
    }
}

/// Disassemble a range of bytes starting at the given virtual address.
pub fn disassemble(binary: &Binary, start_addr: u64, max_bytes: usize) -> Result<Vec<DisasmInsn>> {
    let bitness = match binary.arch {
        Arch::X86 => 32,
        Arch::X86_64 => 64,
    };

    let sec = binary
        .section_at(start_addr)
        .ok_or(crate::error::DecompError::DisassemblyError(format!(
            "no section at 0x{start_addr:x}"
        )))?;

    let offset = (start_addr - sec.vaddr) as usize;
    let available = sec.data.len() - offset;
    let len = max_bytes.min(available);
    let code = &sec.data[offset..offset + len];

    let mut decoder = Decoder::with_ip(bitness, code, start_addr, DecoderOptions::NONE);
    let mut formatter = iced_x86::IntelFormatter::new();
    let mut output = String::new();
    let mut instructions = Vec::new();

    let mut insn = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        output.clear();
        formatter.format(&insn, &mut output);

        instructions.push(DisasmInsn {
            addr: insn.ip(),
            len: insn.len(),
            mnemonic: insn.mnemonic(),
            insn,
            text: output.clone(),
        });

        // Stop at return
        if insn.flow_control() == iced_x86::FlowControl::Return {
            break;
        }
    }

    Ok(instructions)
}

/// Disassemble a function-sized region. If function size is unknown, disassemble
/// until a return instruction or max limit.
pub fn disassemble_function(
    binary: &Binary,
    func_addr: u64,
    func_size: u64,
) -> Result<Vec<DisasmInsn>> {
    let bitness = match binary.arch {
        Arch::X86 => 32,
        Arch::X86_64 => 64,
    };

    let sec = binary
        .section_at(func_addr)
        .ok_or(crate::error::DecompError::DisassemblyError(format!(
            "no section at 0x{func_addr:x}"
        )))?;

    let offset = (func_addr - sec.vaddr) as usize;
    let available = sec.data.len() - offset;

    let size = if func_size > 0 {
        (func_size as usize).min(available)
    } else {
        available.min(0x10000) // 64K max for unknown size
    };

    let code = &sec.data[offset..offset + size];
    let mut decoder = Decoder::with_ip(bitness, code, func_addr, DecoderOptions::NONE);
    let mut formatter = iced_x86::IntelFormatter::new();
    let mut output = String::new();
    let mut instructions = Vec::new();
    let mut insn = Instruction::default();

    // Track depth of ret discovery for multi-return functions
    let end_addr = func_addr + size as u64;

    while decoder.can_decode() {
        decoder.decode_out(&mut insn);

        if insn.ip() >= end_addr && func_size > 0 {
            break;
        }

        output.clear();
        formatter.format(&insn, &mut output);

        let is_ret = insn.flow_control() == iced_x86::FlowControl::Return;

        instructions.push(DisasmInsn {
            addr: insn.ip(),
            len: insn.len(),
            mnemonic: insn.mnemonic(),
            insn,
            text: output.clone(),
        });

        // Stop after hlt (e.g. _start ends with hlt)
        if insn.mnemonic() == Mnemonic::Hlt {
            break;
        }

        // For unknown-size functions, stop after first ret not followed by known code
        if is_ret && func_size == 0 {
            break;
        }
    }

    Ok(instructions)
}
