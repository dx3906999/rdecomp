use crate::cfg::Cfg;
use crate::disasm::DisasmInsn;
use crate::ir::*;
use crate::loader::{Arch, Binary};
use iced_x86::{Mnemonic, OpKind, Register};
use iced_x86::ConditionCode as IcedCC;
use std::collections::BTreeMap;

/// Sentinel addresses for synthetic library calls.
pub const SYNTHETIC_MEMCPY: u64 = u64::MAX - 1;
pub const SYNTHETIC_MEMSET: u64 = u64::MAX - 2;

/// Get the memory displacement as a correctly sign-extended i64.
/// For 32-bit address modes the displacement is only 32 bits; using
/// `memory_displacement64()` zero-extends it, so e.g. `[ebp-0x10]`
/// yields `0x00000000FFFFFFF0` instead of `-16`.  We use the displacement
/// size to decide how to sign-extend.
fn mem_disp_signed(insn: &iced_x86::Instruction) -> i64 {
    let ds = insn.memory_displ_size();
    if ds <= 4 {
        insn.memory_displacement32() as i32 as i64
    } else {
        insn.memory_displacement64() as i64
    }
}

/// Tracks the last CMP/TEST operands for condition fusion.
#[derive(Debug, Clone)]
struct FlagState {
    kind: FlagKind,
    lhs: Expr,
    rhs: Expr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlagKind {
    Cmp,
    Test,
    Arith,
}

/// Lifts x86/x64 machine code to IR.
pub struct Lifter {
    next_temp: u32,
    flag_state: Option<FlagState>,
    calling_conv: CallingConv,
    in_prologue: bool,
    frame_size: u64,
    has_frame_pointer: bool,
    saw_push_rbp: bool,
    /// True when the function writes to XMM0 (float/SSE return value).
    writes_xmm0: bool,
    /// True when the function writes to RAX/EAX via non-call instructions.
    writes_rax_noncall: bool,
    /// True when the last seen write was to XMM0 (vs RAX).
    last_write_is_xmm0: bool,
}

impl Lifter {
    pub fn new(arch: Arch) -> Self {
        let _ = arch;
        Self {
            next_temp: 0,
            flag_state: None,
            calling_conv: CallingConv::SystemV,
            in_prologue: true,
            frame_size: 0,
            has_frame_pointer: false,
            saw_push_rbp: false,
            writes_xmm0: false,
            writes_rax_noncall: false,
            last_write_is_xmm0: false,
        }
    }

    pub fn set_calling_conv(&mut self, cc: CallingConv) {
        self.calling_conv = cc;
    }

    pub fn calling_conv(&self) -> CallingConv {
        self.calling_conv
    }

    /// Pointer width for the current architecture.
    fn ptr_width(&self) -> BitWidth {
        if self.calling_conv.is_32bit() { BitWidth::Bit32 } else { BitWidth::Bit64 }
    }

    /// Pointer size in bytes.
    fn ptr_size(&self) -> u64 {
        if self.calling_conv.is_32bit() { 4 } else { 8 }
    }

    fn new_temp(&mut self, width: BitWidth) -> Var {
        let id = self.next_temp;
        self.next_temp += 1;
        Var::Temp(id, width)
    }

    // ── public entry ─────────────────────────────────────────────

    pub fn lift_function(&mut self, name: &str, addr: u64, cfg: &Cfg, binary: &Binary) -> Function {
        let mut func = Function::new(name.to_string(), addr);
        func.entry = cfg.blocks.get(&cfg.entry).map_or(BlockId(0), |b| b.block_id);
        func.calling_conv = self.calling_conv;

        self.flag_state = None;
        self.in_prologue = true;
        self.frame_size = 0;
        self.has_frame_pointer = false;
        self.saw_push_rbp = false;
        self.writes_xmm0 = false;
        self.writes_rax_noncall = false;
        self.last_write_is_xmm0 = false;

        let addr_to_block: BTreeMap<u64, BlockId> = cfg
            .blocks
            .iter()
            .map(|(&a, blk)| (a, blk.block_id))
            .collect();

        let rpo = cfg.reverse_postorder();

        // Track the flag state at the end of each block, keyed by block address.
        // This allows successor blocks that consist of only a conditional branch
        // (no flag-setting instructions of their own) to inherit the correct
        // flag context from their predecessor.
        let mut block_end_flags: BTreeMap<u64, Option<FlagState>> = BTreeMap::new();

        for &block_addr in &rpo {
            let cfg_block = match cfg.blocks.get(&block_addr) {
                Some(b) => b,
                None => continue,
            };

            // Reset flag state at block boundaries.  For blocks whose body
            // contains no flag-setting instructions (e.g. a bare conditional
            // jump that tests flags from the preceding block), try to inherit
            // the flag state from a predecessor that has already been lifted.
            // Reset per-block state
            self.flag_state = None;
            self.last_write_is_xmm0 = false;
            {
                // Build a set of predecessor addresses for this block
                let preds: Vec<u64> = cfg.blocks.iter()
                    .filter(|(_, blk)| blk.successors.contains(&block_addr))
                    .map(|(&addr, _)| addr)
                    .collect();
                // Check whether this block body contains any instruction that
                // overwrites the condition flags.  If not, a trailing Jcc may
                // still be testing flags produced by a predecessor.
                let has_flag_writers = cfg_block.instructions
                    .iter()
                    .filter(|insn| !insn.is_terminator())
                    .any(|insn| Self::mnemonic_sets_flags(insn.mnemonic));
                if !has_flag_writers {
                    // No body instructions — inherit flag state from a predecessor
                    for &pred_addr in &preds {
                        if let Some(Some(fs)) = block_end_flags.get(&pred_addr) {
                            self.flag_state = Some(fs.clone());
                            break;
                        }
                    }
                }
            }

            let mut stmts = Vec::new();
            let last_idx = cfg_block.instructions.len().saturating_sub(1);

            for (i, insn) in cfg_block.instructions.iter().enumerate() {
                if i == last_idx && insn.is_terminator() {
                    continue;
                }
                let mut lifted = self.lift_instruction(insn);
                // Track writes to XMM0/RAX for return detection
                for s in &lifted {
                    match s {
                        Stmt::Assign(Var::Reg(RegId::Xmm0, _), _) => {
                            self.writes_xmm0 = true;
                            self.last_write_is_xmm0 = true;
                        }
                        Stmt::Assign(Var::Reg(RegId::Rax, _), _) => {
                            self.writes_rax_noncall = true;
                            self.last_write_is_xmm0 = false;
                        }
                        Stmt::Call(Some(Var::Reg(RegId::Rax, _)), _, _) => {
                            // Call clobbers rax but doesn't count as intentional rax return
                            self.last_write_is_xmm0 = false;
                        }
                        _ => {}
                    }
                }
                stmts.append(&mut lifted);
            }

            let terminator = if let Some(last_insn) = cfg_block.instructions.last() {
                self.lift_terminator(last_insn, &addr_to_block, cfg_block, binary)
            } else {
                Terminator::Unreachable
            };

            // Save the flag state at the end of this block for successors
            block_end_flags.insert(block_addr, self.flag_state.clone());

            func.blocks.push(BasicBlock {
                id: cfg_block.block_id,
                addr: block_addr,
                stmts,
                terminator,
            });
        }

        func.next_temp = self.next_temp;
        func.next_block = cfg.blocks.len() as u32;
        func.has_frame_pointer = self.has_frame_pointer;
        func.frame_size = self.frame_size;
        func
    }

    // ── instruction dispatch ─────────────────────────────────────

    fn lift_instruction(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        if self.in_prologue
            && let Some(s) = self.try_lift_prologue(insn) {
                return s;
            }

        // Suppress callee-save push/pop
        if insn.mnemonic == Mnemonic::Push && self.is_callee_save(insn) {
            return vec![];
        }
        if insn.mnemonic == Mnemonic::Pop && self.is_callee_save(insn) {
            return vec![];
        }

        match insn.mnemonic {
            Mnemonic::Push => self.lift_push(insn),
            Mnemonic::Pop => self.lift_pop(insn),
            Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd
            => self.lift_mov(insn),
            Mnemonic::Cmove | Mnemonic::Cmovne | Mnemonic::Cmovl | Mnemonic::Cmovle
            | Mnemonic::Cmovg | Mnemonic::Cmovge | Mnemonic::Cmovb | Mnemonic::Cmovbe
            | Mnemonic::Cmova | Mnemonic::Cmovae | Mnemonic::Cmovs | Mnemonic::Cmovns => {
                self.lift_cmov(insn)
            }
            Mnemonic::Lea => self.lift_lea(insn),
            Mnemonic::Add => self.lift_arith(insn, BinOp::Add),
            Mnemonic::Sub => self.lift_sub(insn),
            Mnemonic::Sbb => self.lift_sbb(insn),
            Mnemonic::Adc => self.lift_adc(insn),
            Mnemonic::Imul => self.lift_imul(insn),
            Mnemonic::Mul => self.lift_binop(insn, BinOp::Mul),
            Mnemonic::Idiv => self.lift_div(insn, true),
            Mnemonic::Div => self.lift_div(insn, false),
            Mnemonic::And => self.lift_arith(insn, BinOp::And),
            Mnemonic::Or => self.lift_arith(insn, BinOp::Or),
            Mnemonic::Xor => self.lift_xor(insn),
            Mnemonic::Shl => self.lift_arith(insn, BinOp::Shl),
            Mnemonic::Shr => self.lift_arith(insn, BinOp::Shr),
            Mnemonic::Sar => self.lift_arith(insn, BinOp::Sar),
            Mnemonic::Rol => self.lift_arith(insn, BinOp::Rol),
            Mnemonic::Ror => self.lift_arith(insn, BinOp::Ror),
            Mnemonic::Neg => self.lift_unary(insn, UnaryOp::Neg),
            Mnemonic::Not => self.lift_unary(insn, UnaryOp::Not),
            Mnemonic::Inc => self.lift_inc_dec(insn, BinOp::Add),
            Mnemonic::Dec => self.lift_inc_dec(insn, BinOp::Sub),
            Mnemonic::Cmp => self.lift_cmp(insn),
            Mnemonic::Test => self.lift_test(insn),
            Mnemonic::Call => self.lift_call(insn),
            Mnemonic::Sete | Mnemonic::Setne | Mnemonic::Setl | Mnemonic::Setle
            | Mnemonic::Setg | Mnemonic::Setge | Mnemonic::Setb | Mnemonic::Setbe
            | Mnemonic::Seta | Mnemonic::Setae | Mnemonic::Sets | Mnemonic::Setns => {
                self.lift_setcc(insn)
            }
            Mnemonic::Cdqe => self.lift_cdqe(),
            Mnemonic::Cdq => self.lift_cdq_cqo(BitWidth::Bit32, 31),
            Mnemonic::Cqo => self.lift_cdq_cqo(BitWidth::Bit64, 63),
            Mnemonic::Xchg => self.lift_xchg(insn),
            // REP string operations → library calls
            Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq
                if insn.insn.has_rep_prefix() || insn.insn.has_repe_prefix() =>
            {
                self.lift_rep_movs()
            }
            Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq
                if insn.insn.has_rep_prefix() || insn.insn.has_repe_prefix() =>
            {
                self.lift_rep_stos()
            }
            // Non-REP string ops — just skip
            Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsq
            | Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq => vec![Stmt::Nop],
            // SSE scalar move/arithmetic (Movsd is also used for SSE scalar double)
            Mnemonic::Movss | Mnemonic::Movsd | Mnemonic::Movaps | Mnemonic::Movups
            | Mnemonic::Movapd | Mnemonic::Movupd => self.lift_mov(insn),
            Mnemonic::Addss | Mnemonic::Addsd => self.lift_float_arith(insn, "add"),
            Mnemonic::Subss | Mnemonic::Subsd => self.lift_float_arith(insn, "sub"),
            Mnemonic::Mulss | Mnemonic::Mulsd => self.lift_float_arith(insn, "mul"),
            Mnemonic::Divss | Mnemonic::Divsd => self.lift_float_arith(insn, "div"),
            // Scalar float comparison
            Mnemonic::Ucomiss | Mnemonic::Ucomisd
            | Mnemonic::Comiss | Mnemonic::Comisd => self.lift_float_cmp(insn),
            // SSE XOR (zero-init pattern: xorps xmm0, xmm0)
            Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Pxor => self.lift_xor(insn),
            // CVTSI2SS/SD (int → float)
            Mnemonic::Cvtsi2ss | Mnemonic::Cvtsi2sd => self.lift_cvtsi2f(insn),
            // CVTTSS2SI/CVTTSD2SI (float → int truncation)
            Mnemonic::Cvttss2si | Mnemonic::Cvttsd2si => self.lift_cvtf2si(insn),
            // CVTSS2SD / CVTSD2SS (float precision conversion)
            Mnemonic::Cvtss2sd | Mnemonic::Cvtsd2ss => self.lift_mov(insn),
            // MOVD/MOVQ — XMM ↔ GPR bitcast or 32/64-bit move
            Mnemonic::Movd | Mnemonic::Movq => self.lift_movd(insn),
            // ── SSE2 packed integer instructions (IDA-style intrinsics) ──
            Mnemonic::Movdqa | Mnemonic::Movdqu => self.lift_simd_mov(insn),
            Mnemonic::Pcmpeqb => self.lift_simd_binop(insn, "_mm_cmpeq_epi8"),
            Mnemonic::Pcmpeqw => self.lift_simd_binop(insn, "_mm_cmpeq_epi16"),
            Mnemonic::Pcmpeqd => self.lift_simd_binop(insn, "_mm_cmpeq_epi32"),
            Mnemonic::Pcmpgtb => self.lift_simd_binop(insn, "_mm_cmpgt_epi8"),
            Mnemonic::Pcmpgtw => self.lift_simd_binop(insn, "_mm_cmpgt_epi16"),
            Mnemonic::Pcmpgtd => self.lift_simd_binop(insn, "_mm_cmpgt_epi32"),
            Mnemonic::Paddb => self.lift_simd_binop(insn, "_mm_add_epi8"),
            Mnemonic::Paddw => self.lift_simd_binop(insn, "_mm_add_epi16"),
            Mnemonic::Paddd => self.lift_simd_binop(insn, "_mm_add_epi32"),
            Mnemonic::Paddq => self.lift_simd_binop(insn, "_mm_add_epi64"),
            Mnemonic::Psubb => self.lift_simd_binop(insn, "_mm_sub_epi8"),
            Mnemonic::Psubw => self.lift_simd_binop(insn, "_mm_sub_epi16"),
            Mnemonic::Psubd => self.lift_simd_binop(insn, "_mm_sub_epi32"),
            Mnemonic::Psubq => self.lift_simd_binop(insn, "_mm_sub_epi64"),
            Mnemonic::Pmullw => self.lift_simd_binop(insn, "_mm_mullo_epi16"),
            Mnemonic::Pmulld => self.lift_simd_binop(insn, "_mm_mullo_epi32"),
            Mnemonic::Pand => self.lift_simd_binop(insn, "_mm_and_si128"),
            Mnemonic::Pandn => self.lift_simd_binop(insn, "_mm_andnot_si128"),
            Mnemonic::Por => self.lift_simd_binop(insn, "_mm_or_si128"),
            Mnemonic::Punpcklbw => self.lift_simd_binop(insn, "_mm_unpacklo_epi8"),
            Mnemonic::Punpckhbw => self.lift_simd_binop(insn, "_mm_unpackhi_epi8"),
            Mnemonic::Punpcklwd => self.lift_simd_binop(insn, "_mm_unpacklo_epi16"),
            Mnemonic::Punpckhwd => self.lift_simd_binop(insn, "_mm_unpackhi_epi16"),
            Mnemonic::Punpckldq => self.lift_simd_binop(insn, "_mm_unpacklo_epi32"),
            Mnemonic::Punpckhdq => self.lift_simd_binop(insn, "_mm_unpackhi_epi32"),
            Mnemonic::Punpcklqdq => self.lift_simd_binop(insn, "_mm_unpacklo_epi64"),
            Mnemonic::Punpckhqdq => self.lift_simd_binop(insn, "_mm_unpackhi_epi64"),
            Mnemonic::Packuswb => self.lift_simd_binop(insn, "_mm_packus_epi16"),
            Mnemonic::Packsswb => self.lift_simd_binop(insn, "_mm_packs_epi16"),
            Mnemonic::Packssdw => self.lift_simd_binop(insn, "_mm_packs_epi32"),
            // Shift by immediate
            Mnemonic::Psraw => self.lift_simd_shift(insn, "_mm_srai_epi16"),
            Mnemonic::Psrad => self.lift_simd_shift(insn, "_mm_srai_epi32"),
            Mnemonic::Psrlw => self.lift_simd_shift(insn, "_mm_srli_epi16"),
            Mnemonic::Psrld => self.lift_simd_shift(insn, "_mm_srli_epi32"),
            Mnemonic::Psrlq => self.lift_simd_shift(insn, "_mm_srli_epi64"),
            Mnemonic::Psllw => self.lift_simd_shift(insn, "_mm_slli_epi16"),
            Mnemonic::Pslld => self.lift_simd_shift(insn, "_mm_slli_epi32"),
            Mnemonic::Psllq => self.lift_simd_shift(insn, "_mm_slli_epi64"),
            // Byte-level shift of entire 128-bit register
            Mnemonic::Psrldq => self.lift_simd_shift(insn, "_mm_srli_si128"),
            Mnemonic::Pslldq => self.lift_simd_shift(insn, "_mm_slli_si128"),
            // Shuffle
            Mnemonic::Pshufd => self.lift_simd_shuffle(insn, "_mm_shuffle_epi32"),
            Mnemonic::Pshufhw => self.lift_simd_shuffle(insn, "_mm_shufflehi_epi16"),
            Mnemonic::Pshuflw => self.lift_simd_shuffle(insn, "_mm_shufflelo_epi16"),
            Mnemonic::Shufps => self.lift_simd_shuffle(insn, "_mm_shuffle_ps"),
            Mnemonic::Shufpd => self.lift_simd_shuffle(insn, "_mm_shuffle_pd"),
            // Min/Max
            Mnemonic::Pminsb => self.lift_simd_binop(insn, "_mm_min_epi8"),
            Mnemonic::Pminub => self.lift_simd_binop(insn, "_mm_min_epu8"),
            Mnemonic::Pminsw => self.lift_simd_binop(insn, "_mm_min_epi16"),
            Mnemonic::Pminsd => self.lift_simd_binop(insn, "_mm_min_epi32"),
            Mnemonic::Pmaxsb => self.lift_simd_binop(insn, "_mm_max_epi8"),
            Mnemonic::Pmaxub => self.lift_simd_binop(insn, "_mm_max_epu8"),
            Mnemonic::Pmaxsw => self.lift_simd_binop(insn, "_mm_max_epi16"),
            Mnemonic::Pmaxsd => self.lift_simd_binop(insn, "_mm_max_epi32"),
            // Extract/insert
            Mnemonic::Pextrb | Mnemonic::Pextrw | Mnemonic::Pextrd | Mnemonic::Pextrq
                => self.lift_simd_extract(insn),
            Mnemonic::Pmovmskb => self.lift_pmovmskb(insn),
            // Floating-point packed ops (pass through as intrinsic)
            Mnemonic::Addps => self.lift_simd_binop(insn, "_mm_add_ps"),
            Mnemonic::Subps => self.lift_simd_binop(insn, "_mm_sub_ps"),
            Mnemonic::Mulps => self.lift_simd_binop(insn, "_mm_mul_ps"),
            Mnemonic::Divps => self.lift_simd_binop(insn, "_mm_div_ps"),
            Mnemonic::Addpd => self.lift_simd_binop(insn, "_mm_add_pd"),
            Mnemonic::Subpd => self.lift_simd_binop(insn, "_mm_sub_pd"),
            Mnemonic::Mulpd => self.lift_simd_binop(insn, "_mm_mul_pd"),
            Mnemonic::Divpd => self.lift_simd_binop(insn, "_mm_div_pd"),
            Mnemonic::Andps | Mnemonic::Andpd => self.lift_simd_binop(insn, "_mm_and_ps"),
            Mnemonic::Orps | Mnemonic::Orpd => self.lift_simd_binop(insn, "_mm_or_ps"),
            Mnemonic::Maxps => self.lift_simd_binop(insn, "_mm_max_ps"),
            Mnemonic::Minps => self.lift_simd_binop(insn, "_mm_min_ps"),
            Mnemonic::Maxpd => self.lift_simd_binop(insn, "_mm_max_pd"),
            Mnemonic::Minpd => self.lift_simd_binop(insn, "_mm_min_pd"),
            Mnemonic::Leave => vec![],
            Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32 | Mnemonic::Int3 => vec![],
            _ => vec![Stmt::Nop],
        }
    }

    /// Conservative check for instructions that update arithmetic/logic flags
    /// relevant for subsequent Jcc fusion.
    fn mnemonic_sets_flags(m: Mnemonic) -> bool {
        matches!(
            m,
            Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::Sbb
                | Mnemonic::Adc
                | Mnemonic::Imul
                | Mnemonic::Mul
                | Mnemonic::Idiv
                | Mnemonic::Div
                | Mnemonic::And
                | Mnemonic::Or
                | Mnemonic::Xor
                | Mnemonic::Shl
                | Mnemonic::Shr
                | Mnemonic::Sar
                | Mnemonic::Rol
                | Mnemonic::Ror
                | Mnemonic::Inc
                | Mnemonic::Dec
                | Mnemonic::Neg
                | Mnemonic::Cmp
                | Mnemonic::Test
        )
    }

    // ── prologue / epilogue ──────────────────────────────────────

    fn try_lift_prologue(&mut self, insn: &DisasmInsn) -> Option<Vec<Stmt>> {
        match insn.mnemonic {
            Mnemonic::Push
                if insn.insn.op0_kind() == OpKind::Register
                    && matches!(insn.insn.op0_register(), Register::RBP | Register::EBP) =>
            {
                // Don't set has_frame_pointer here — only set it when we also see
                // mov rbp, rsp (the canonical frame pointer setup).
                // A bare push rbp might just be saving a callee-saved register.
                self.saw_push_rbp = true;
                Some(vec![])
            }
            Mnemonic::Mov
                if insn.insn.op0_kind() == OpKind::Register
                    && insn.insn.op1_kind() == OpKind::Register
                    && matches!(insn.insn.op0_register(), Register::RBP | Register::EBP)
                    && matches!(insn.insn.op1_register(), Register::RSP | Register::ESP) =>
            {
                self.has_frame_pointer = true;
                Some(vec![])
            }
            Mnemonic::Sub
                if insn.insn.op0_kind() == OpKind::Register
                    && matches!(insn.insn.op0_register(), Register::RSP | Register::ESP) =>
            {
                self.frame_size = self.extract_imm(insn);
                self.in_prologue = false;
                Some(vec![])
            }
            _ => {
                self.in_prologue = false;
                None
            }
        }
    }

    fn is_callee_save(&self, insn: &DisasmInsn) -> bool {
        if insn.insn.op0_kind() != OpKind::Register {
            return false;
        }
        let (reg_id, _) = map_register(insn.insn.op0_register());
        self.calling_conv.callee_saved().contains(&reg_id)
    }

    fn extract_imm(&self, insn: &DisasmInsn) -> u64 {
        match insn.insn.op1_kind() {
            OpKind::Immediate8 => insn.insn.immediate8() as u64,
            OpKind::Immediate32 => insn.insn.immediate32() as u64,
            OpKind::Immediate8to32 => insn.insn.immediate8to32() as u32 as u64,
            OpKind::Immediate8to64 => insn.insn.immediate8to64() as u64,
            OpKind::Immediate32to64 => insn.insn.immediate32to64() as u64,
            _ => 0,
        }
    }

    // ── terminator ───────────────────────────────────────────────

    fn lift_terminator(
        &mut self,
        insn: &DisasmInsn,
        addr_to_block: &BTreeMap<u64, BlockId>,
        cfg_block: &crate::cfg::CfgBlock,
        binary: &Binary,
    ) -> Terminator {
        match insn.insn.flow_control() {
            iced_x86::FlowControl::Return => {
                // Float-returning: xmm0 is the return register when it was the
                // last value written (e.g. `movaps xmm0, xmm1; ret`).
                // Integer-returning: rax is used when rax was explicitly written.
                if self.writes_xmm0 && self.last_write_is_xmm0 {
                    Terminator::Return(Some(Expr::var(Var::Reg(RegId::Xmm0, BitWidth::Bit128))))
                } else {
                    let ret_w = if self.calling_conv.is_32bit() { BitWidth::Bit32 } else { BitWidth::Bit64 };
                    Terminator::Return(Some(Expr::var(Var::Reg(RegId::Rax, ret_w))))
                }
            }
            iced_x86::FlowControl::UnconditionalBranch => {
                if let Some(target) = insn.branch_target() {
                    addr_to_block
                        .get(&target)
                        .map_or(Terminator::Unreachable, |&id| Terminator::Jump(id))
                } else {
                    Terminator::IndirectJump(self.lift_operand(&insn.insn, 0))
                }
            }
            iced_x86::FlowControl::ConditionalBranch => {
                let cc = Self::map_condition_code(insn.insn.condition_code());
                let cond = self.fuse_condition(cc);

                let t = insn
                    .branch_target()
                    .and_then(|a| addr_to_block.get(&a).copied());
                let f = addr_to_block
                    .get(&(insn.addr + insn.len as u64))
                    .copied();

                match (t, f) {
                    (Some(tt), Some(ff)) => Terminator::Branch(cond, tt, ff),
                    (Some(tt), None) => Terminator::Jump(tt),
                    _ => Terminator::Unreachable,
                }
            }
            iced_x86::FlowControl::IndirectBranch => {
                if let Some(sw) = self.try_resolve_jump_table(insn, addr_to_block, binary) {
                    sw
                } else {
                    Terminator::IndirectJump(self.lift_operand(&insn.insn, 0))
                }
            }
            _ => {
                // fall-through (call at end of block, etc.)
                let next = insn.addr + insn.len as u64;
                if let Some(&id) = addr_to_block.get(&next) {
                    Terminator::Jump(id)
                } else if let Some(&succ) = cfg_block.successors.first() {
                    addr_to_block
                        .get(&succ)
                        .map_or(Terminator::Unreachable, |&id| Terminator::Jump(id))
                } else {
                    Terminator::Unreachable
                }
            }
        }
    }

    /// Try to resolve an indirect branch as a jump table (switch).
    ///
    /// Recognises `jmp [base + reg*scale]` where `base` is an absolute or
    /// RIP-relative address pointing into a read-only data section.  Entries
    /// are read until a target falls outside the set of known block addresses.
    fn try_resolve_jump_table(
        &self,
        insn: &DisasmInsn,
        addr_to_block: &BTreeMap<u64, BlockId>,
        binary: &Binary,
    ) -> Option<Terminator> {
        let ix = &insn.insn;

        // Must be a memory operand with an index register and scale ≥ 4
        if ix.op0_kind() != OpKind::Memory {
            return None;
        }
        let scale = ix.memory_index_scale();
        if scale < 4 {
            return None;
        }
        let index_reg = ix.memory_index();
        if index_reg == Register::None {
            return None;
        }

        // Compute the table base virtual address.
        let table_base = if ix.memory_base() == Register::RIP || ix.memory_base() == Register::EIP {
            // RIP-relative: RIP value at this point is insn.addr + insn.len
            (insn.addr + insn.len as u64).wrapping_add(ix.memory_displacement64())
        } else if ix.memory_base() == Register::None {
            // Absolute address
            ix.memory_displacement64()
        } else {
            // Has a base register we can't resolve statically
            return None;
        };

        let entry_size = scale as usize; // 4 or 8
        let max_cases: usize = 256; // safety bound

        let mut cases: Vec<(u64, BlockId)> = Vec::new();
        for i in 0..max_cases {
            let entry_addr = table_base + (i as u64) * (entry_size as u64);
            let target = binary.read_ptr(entry_addr, entry_size)?;
            if let Some(&bid) = addr_to_block.get(&target) {
                cases.push((i as u64, bid));
            } else {
                break;
            }
        }

        if cases.len() < 2 {
            return None;
        }

        let (reg_id, _) = map_register(index_reg);

        let val = Expr::var(Var::Reg(
            reg_id,
            if entry_size == 8 { BitWidth::Bit64 } else { BitWidth::Bit32 },
        ));

        Some(Terminator::Switch(val, cases, None))
    }

    // ── condition fusion ─────────────────────────────────────────

    fn fuse_condition(&mut self, cc: CondCode) -> Expr {
        let Some(st) = self.flag_state.clone() else {
            return Expr::Cond(cc);
        };
        match st.kind {
            FlagKind::Cmp => Expr::cmp(cc, st.lhs, st.rhs),
            FlagKind::Test => {
                if st.lhs == st.rhs {
                    let zero = Expr::const_val(0, st.rhs.width());
                    let cc2 = match cc {
                        CondCode::Sign => CondCode::Lt,
                        CondCode::NotSign => CondCode::Ge,
                        other => other,
                    };
                    Expr::cmp(cc2, st.lhs, zero)
                } else {
                    let anded = Expr::binop(BinOp::And, st.lhs, st.rhs);
                    Expr::cmp(cc, anded, Expr::const_val(0, BitWidth::Bit64))
                }
            }
            FlagKind::Arith => {
                let zero = Expr::const_val(0, st.rhs.width());
                Expr::cmp(cc, st.lhs, zero)
            }
        }
    }

    // ── individual lifters ───────────────────────────────────────

    fn lift_push(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let val = self.lift_operand(&insn.insn, 0);
        let pw = self.ptr_width();
        let ps = self.ptr_size();
        let rsp = Var::Reg(RegId::Rsp, pw);
        vec![
            Stmt::Assign(rsp.clone(), Expr::binop(BinOp::Sub, Expr::var(rsp.clone()), Expr::const_val(ps, pw))),
            Stmt::Store(Expr::var(rsp), val, pw),
        ]
    }

    fn lift_pop(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let pw = self.ptr_width();
        let ps = self.ptr_size();
        let rsp = Var::Reg(RegId::Rsp, pw);
        let mut stmts = Vec::new();
        if let Some(dst) = self.lift_operand_as_var(&insn.insn, 0) {
            stmts.push(Stmt::Assign(dst, Expr::load(Expr::var(rsp.clone()), pw)));
        }
        stmts.push(Stmt::Assign(rsp.clone(), Expr::binop(BinOp::Add, Expr::var(rsp), Expr::const_val(ps, pw))));
        stmts
    }

    fn lift_mov(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let src = self.lift_operand(&insn.insn, 1);

        let val = match insn.mnemonic {
            Mnemonic::Movzx => Expr::unaryop(UnaryOp::ZeroExt(operand_width(&insn.insn, 0)), src),
            Mnemonic::Movsx | Mnemonic::Movsxd => {
                Expr::unaryop(UnaryOp::SignExt(operand_width(&insn.insn, 0)), src)
            }
            _ => src,
        };

        match dst {
            Some(var) => vec![Stmt::Assign(var, val)],
            None => {
                let addr = self.lift_memory_operand(&insn.insn, 0);
                vec![Stmt::Store(addr, val, operand_width(&insn.insn, 0))]
            }
        }
    }

    fn lift_cmov(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let src = self.lift_operand(&insn.insn, 1);
        let cc = Self::map_condition_code(insn.insn.condition_code());
        let cond = self.fuse_condition(cc);

        match dst {
            Some(var) => {
                // Emit as: dst = cond ? src : dst
                let select = Expr::select(cond, src, Expr::var(var.clone()));
                vec![Stmt::Assign(var, select)]
            }
            None => vec![Stmt::Nop],
        }
    }

    fn lift_lea(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let addr = self.lift_memory_operand(&insn.insn, 1);
        match dst {
            Some(var) => vec![Stmt::Assign(var, addr)],
            None => vec![Stmt::Nop],
        }
    }

    fn lift_binop(&mut self, insn: &DisasmInsn, op: BinOp) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let lhs = self.lift_operand(&insn.insn, 0);
        let rhs = self.lift_operand(&insn.insn, 1);
        let result = Expr::binop(op, lhs, rhs);
        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => {
                let addr = self.lift_memory_operand(&insn.insn, 0);
                vec![Stmt::Store(addr, result, operand_width(&insn.insn, 0))]
            }
        }
    }

    /// Handle IMUL which can have 2 or 3 operands:
    ///   imul dst, src       → dst = dst * src
    ///   imul dst, src, imm  → dst = src * imm
    fn lift_imul(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let op_count = insn.insn.op_count();
        if op_count == 3 {
            // 3-operand form: imul dst, src, imm
            let dst = self.lift_operand_as_var(&insn.insn, 0);
            let src = self.lift_operand(&insn.insn, 1);
            let imm = self.lift_operand(&insn.insn, 2);
            let result = Expr::binop(BinOp::Mul, src, imm);
            match dst {
                Some(var) => vec![Stmt::Assign(var, result)],
                None => {
                    let addr = self.lift_memory_operand(&insn.insn, 0);
                    vec![Stmt::Store(addr, result, operand_width(&insn.insn, 0))]
                }
            }
        } else {
            self.lift_binop(insn, BinOp::Mul)
        }
    }

    fn lift_arith(&mut self, insn: &DisasmInsn, op: BinOp) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let lhs = self.lift_operand(&insn.insn, 0);
        let rhs = self.lift_operand(&insn.insn, 1);
        let result = Expr::binop(op, lhs.clone(), rhs);
        // Use the destination variable for flag conditions when available.
        // The assignment updates dst to the result value, so subsequent
        // flag checks (e.g. `jne` after `shr edi,1`) should reference the
        // already-updated variable (`edi != 0`) rather than re-evaluating
        // the expression (`(edi >> 1) != 0` which would double-apply).
        let flag_lhs = match &dst {
            Some(var) => Expr::var(var.clone()),
            None => result.clone(),
        };
        self.flag_state = Some(FlagState {
            kind: FlagKind::Arith,
            lhs: flag_lhs,
            rhs: Expr::const_val(0, lhs.width()),
        });
        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => {
                let addr = self.lift_memory_operand(&insn.insn, 0);
                vec![Stmt::Store(addr, result, operand_width(&insn.insn, 0))]
            }
        }
    }

    fn lift_sub(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        if insn.insn.op0_kind() == OpKind::Register
            && matches!(insn.insn.op0_register(), Register::RSP | Register::ESP)
        {
            return vec![]; // epilogue stack adjustment
        }
        self.lift_arith(insn, BinOp::Sub)
    }

    /// Lift `sbb dst, src` → `dst = dst - src - CF`
    /// CF is the carry flag from the previous cmp/sub/etc.
    fn lift_sbb(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let dst_val = self.lift_operand(&insn.insn, 0);
        let src = self.lift_operand(&insn.insn, 1);
        let w = operand_width(&insn.insn, 0);

        // Build the CF value as a 0/1 integer from the previous flag state
        let cf_val = if let Some(st) = self.flag_state.clone() {
            let cf_cond = match st.kind {
                FlagKind::Cmp => Expr::cmp(CondCode::Below, st.lhs, st.rhs),
                FlagKind::Arith => {
                    // After sub/add arith, CF is complex; approximate as 0
                    Expr::const_val(0, w)
                }
                FlagKind::Test => Expr::const_val(0, w), // TEST clears CF
            };
            Expr::select(cf_cond, Expr::const_val(1, w), Expr::const_val(0, w))
        } else {
            Expr::const_val(0, w)
        };

        // Idiom: sbb reg, reg → result = 0 - CF = -CF
        // This is a well-known x86 pattern: produces -1 if CF=1, 0 if CF=0.
        let result = if dst_val == src {
            Expr::unaryop(UnaryOp::Neg, cf_val)
        } else {
            let sub1 = Expr::binop(BinOp::Sub, dst_val, src);
            Expr::binop(BinOp::Sub, sub1, cf_val)
        };

        self.flag_state = Some(FlagState {
            kind: FlagKind::Arith,
            lhs: match &dst {
                Some(var) => Expr::var(var.clone()),
                None => result.clone(),
            },
            rhs: Expr::const_val(0, w),
        });

        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => {
                let addr = self.lift_memory_operand(&insn.insn, 0);
                vec![Stmt::Store(addr, result, w)]
            }
        }
    }

    /// Lift `adc dst, src` → `dst = dst + src + CF`
    fn lift_adc(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let dst_val = self.lift_operand(&insn.insn, 0);
        let src = self.lift_operand(&insn.insn, 1);
        let w = operand_width(&insn.insn, 0);

        let cf_val = if let Some(st) = self.flag_state.clone() {
            let cf_cond = match st.kind {
                FlagKind::Cmp => Expr::cmp(CondCode::Below, st.lhs, st.rhs),
                FlagKind::Arith => Expr::const_val(0, w),
                FlagKind::Test => Expr::const_val(0, w),
            };
            Expr::select(cf_cond, Expr::const_val(1, w), Expr::const_val(0, w))
        } else {
            Expr::const_val(0, w)
        };

        let add1 = Expr::binop(BinOp::Add, dst_val, src);
        let result = Expr::binop(BinOp::Add, add1, cf_val);

        self.flag_state = Some(FlagState {
            kind: FlagKind::Arith,
            lhs: match &dst {
                Some(var) => Expr::var(var.clone()),
                None => result.clone(),
            },
            rhs: Expr::const_val(0, w),
        });

        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => {
                let addr = self.lift_memory_operand(&insn.insn, 0);
                vec![Stmt::Store(addr, result, w)]
            }
        }
    }

    fn lift_div(&mut self, insn: &DisasmInsn, signed: bool) -> Vec<Stmt> {
        let divisor = self.lift_operand(&insn.insn, 0);
        let dividend = Expr::var(Var::Reg(RegId::Rax, BitWidth::Bit64));
        let (dop, mop) = if signed {
            (BinOp::SDiv, BinOp::SMod)
        } else {
            (BinOp::UDiv, BinOp::UMod)
        };
        vec![
            Stmt::Assign(Var::Reg(RegId::Rdx, BitWidth::Bit64), Expr::binop(mop, dividend.clone(), divisor.clone())),
            Stmt::Assign(Var::Reg(RegId::Rax, BitWidth::Bit64), Expr::binop(dop, dividend, divisor)),
        ]
    }

    fn lift_xor(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        if insn.insn.op0_kind() == OpKind::Register
            && insn.insn.op1_kind() == OpKind::Register
            && insn.insn.op0_register() == insn.insn.op1_register()
        {
            let dst = self.lift_operand_as_var(&insn.insn, 0);
            let w = operand_width(&insn.insn, 0);
            if let Some(var) = dst {
                self.flag_state = Some(FlagState {
                    kind: FlagKind::Arith,
                    lhs: Expr::const_val(0, w),
                    rhs: Expr::const_val(0, w),
                });
                return vec![Stmt::Assign(var, Expr::const_val(0, w))];
            }
        }
        self.lift_arith(insn, BinOp::Xor)
    }

    fn lift_unary(&mut self, insn: &DisasmInsn, op: UnaryOp) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let val = self.lift_operand(&insn.insn, 0);
        let w = operand_width(&insn.insn, 0);
        match dst {
            Some(var) => {
                // NEG sets flags like CMP 0, operand (i.e., SUB 0, operand).
                // We capture the pre-neg operand in a temp so that the flag
                // state references the ORIGINAL value, not the post-neg register.
                if op == UnaryOp::Neg {
                    let pre_neg = self.new_temp(w);
                    self.flag_state = Some(FlagState {
                        kind: FlagKind::Cmp,
                        lhs: Expr::const_val(0, w),
                        rhs: Expr::var(pre_neg.clone()),
                    });
                    return vec![
                        Stmt::Assign(pre_neg, val.clone()),
                        Stmt::Assign(var, Expr::unaryop(op, val)),
                    ];
                }
                vec![Stmt::Assign(var, Expr::unaryop(op, val))]
            }
            None => vec![Stmt::Nop],
        }
    }

    fn lift_inc_dec(&mut self, insn: &DisasmInsn, op: BinOp) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let val = self.lift_operand(&insn.insn, 0);
        let w = operand_width(&insn.insn, 0);
        let result = Expr::binop(op, val, Expr::const_val(1, w));
        let flag_lhs = match &dst {
            Some(var) => Expr::var(var.clone()),
            None => result.clone(),
        };
        self.flag_state = Some(FlagState {
            kind: FlagKind::Arith,
            lhs: flag_lhs,
            rhs: Expr::const_val(0, w),
        });
        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => {
                let addr = self.lift_memory_operand(&insn.insn, 0);
                vec![Stmt::Store(addr, result, w)]
            }
        }
    }

    fn lift_cmp(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let lhs = self.lift_operand(&insn.insn, 0);
        let rhs = self.lift_operand(&insn.insn, 1);
        self.flag_state = Some(FlagState { kind: FlagKind::Cmp, lhs, rhs });
        vec![] // suppressed — will be fused with Jcc
    }

    fn lift_test(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let lhs = self.lift_operand(&insn.insn, 0);
        let rhs = self.lift_operand(&insn.insn, 1);
        self.flag_state = Some(FlagState { kind: FlagKind::Test, lhs, rhs });
        vec![] // suppressed
    }

    fn lift_setcc(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let cc = Self::map_condition_code(insn.insn.condition_code());
        let cond = self.fuse_condition(cc);
        match self.lift_operand_as_var(&insn.insn, 0) {
            Some(var) => vec![Stmt::Assign(var, cond)],
            None => vec![Stmt::Nop],
        }
    }

    fn lift_call(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let target = if let Some(addr) = insn.branch_target() {
            Expr::const_val(addr, self.ptr_width())
        } else {
            self.lift_operand(&insn.insn, 0)
        };
        let ret_w = if self.calling_conv.is_32bit() { BitWidth::Bit32 } else { BitWidth::Bit64 };
        let ret = Var::Reg(RegId::Rax, ret_w);
        let args: Vec<Expr> = self
            .calling_conv
            .param_regs()
            .iter()
            .map(|&r| Expr::var(Var::Reg(r, BitWidth::Bit64)))
            .collect();
        self.flag_state = None;
        vec![Stmt::Call(Some(ret), target, args)]
    }

    fn lift_cdqe(&mut self) -> Vec<Stmt> {
        let eax = Expr::unaryop(UnaryOp::Trunc(BitWidth::Bit32), Expr::var(Var::Reg(RegId::Rax, BitWidth::Bit64)));
        vec![Stmt::Assign(Var::Reg(RegId::Rax, BitWidth::Bit64), Expr::unaryop(UnaryOp::SignExt(BitWidth::Bit64), eax))]
    }

    fn lift_cdq_cqo(&self, width: BitWidth, shift: u64) -> Vec<Stmt> {
        let ax = Expr::var(Var::Reg(RegId::Rax, width));
        vec![Stmt::Assign(
            Var::Reg(RegId::Rdx, width),
            Expr::binop(BinOp::Sar, ax, Expr::const_val(shift, BitWidth::Bit8)),
        )]
    }

    fn lift_xchg(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let a = self.lift_operand_as_var(&insn.insn, 0);
        let b = self.lift_operand_as_var(&insn.insn, 1);
        let w = operand_width(&insn.insn, 0);
        let tmp = self.new_temp(w);
        match (a, b) {
            (Some(va), Some(vb)) => vec![
                Stmt::Assign(tmp.clone(), Expr::var(va.clone())),
                Stmt::Assign(va, Expr::var(vb.clone())),
                Stmt::Assign(vb, Expr::var(tmp)),
            ],
            _ => vec![Stmt::Nop],
        }
    }

    /// REP MOVSB/MOVSW/MOVSD/MOVSQ → memcpy(rdi, rsi, rcx)
    fn lift_rep_movs(&self) -> Vec<Stmt> {
        let dst = Expr::var(Var::Reg(RegId::Rdi, BitWidth::Bit64));
        let src = Expr::var(Var::Reg(RegId::Rsi, BitWidth::Bit64));
        let cnt = Expr::var(Var::Reg(RegId::Rcx, BitWidth::Bit64));
        // Sentinel address for synthetic "memcpy"
        vec![Stmt::Call(
            None,
            Expr::Const(SYNTHETIC_MEMCPY, BitWidth::Bit64),
            vec![dst, src, cnt],
        )]
    }

    /// REP STOSB/STOSW/STOSD/STOSQ → memset(rdi, rax, rcx)
    fn lift_rep_stos(&self) -> Vec<Stmt> {
        let dst = Expr::var(Var::Reg(RegId::Rdi, BitWidth::Bit64));
        let val = Expr::var(Var::Reg(RegId::Rax, BitWidth::Bit64));
        let cnt = Expr::var(Var::Reg(RegId::Rcx, BitWidth::Bit64));
        vec![Stmt::Call(
            None,
            Expr::Const(SYNTHETIC_MEMSET, BitWidth::Bit64),
            vec![dst, val, cnt],
        )]
    }

    // ── SIMD / SSE lifting helpers ─────────────────────────────

    /// Lift MOVDQA/MOVDQU: 128-bit aligned/unaligned move.
    fn lift_simd_mov(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        // Same as regular mov, width is 128-bit from register/memory size
        self.lift_mov(insn)
    }

    /// Lift a packed SIMD binary op as `dst = intrinsic(dst, src)`.
    fn lift_simd_binop(&mut self, insn: &DisasmInsn, name: &str) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let lhs = self.lift_operand(&insn.insn, 0);
        let rhs = self.lift_operand(&insn.insn, 1);
        let result = Expr::intrinsic(name, vec![lhs, rhs]);
        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => {
                let addr = self.lift_memory_operand(&insn.insn, 0);
                vec![Stmt::Store(addr, result, BitWidth::Bit128)]
            }
        }
    }

    /// Lift packed shift: `dst = intrinsic(dst, imm)`.
    fn lift_simd_shift(&mut self, insn: &DisasmInsn, name: &str) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let src = self.lift_operand(&insn.insn, 0);
        let amt = self.lift_operand(&insn.insn, 1);
        let result = Expr::intrinsic(name, vec![src, amt]);
        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => vec![Stmt::Nop],
        }
    }

    /// Lift packed shuffle with immediate: `dst = intrinsic(src, imm8)`.
    fn lift_simd_shuffle(&mut self, insn: &DisasmInsn, name: &str) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let src = self.lift_operand(&insn.insn, 1);
        let imm = if insn.insn.op_count() >= 3 {
            self.lift_operand(&insn.insn, 2)
        } else {
            Expr::const_val(0, BitWidth::Bit8)
        };
        let result = Expr::intrinsic(name, vec![src, imm]);
        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => vec![Stmt::Nop],
        }
    }

    /// Lift PEXTRB/W/D/Q: extract element from XMM to GPR.
    fn lift_simd_extract(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let src = self.lift_operand(&insn.insn, 1);
        let idx = self.lift_operand(&insn.insn, 2);
        let name = match insn.mnemonic {
            Mnemonic::Pextrb => "_mm_extract_epi8",
            Mnemonic::Pextrw => "_mm_extract_epi16",
            Mnemonic::Pextrd => "_mm_extract_epi32",
            Mnemonic::Pextrq => "_mm_extract_epi64",
            _ => "_mm_extract_epi32",
        };
        let result = Expr::intrinsic(name, vec![src, idx]);
        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => {
                let addr = self.lift_memory_operand(&insn.insn, 0);
                vec![Stmt::Store(addr, result, operand_width(&insn.insn, 0))]
            }
        }
    }

    /// Lift PMOVMSKB: extract byte mask from XMM to GPR.
    fn lift_pmovmskb(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let src = self.lift_operand(&insn.insn, 1);
        let result = Expr::intrinsic("_mm_movemask_epi8", vec![src]);
        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => vec![Stmt::Nop],
        }
    }

    /// Lift MOVD/MOVQ: XMM ↔ GPR transfer (bitcast semantics).
    fn lift_movd(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let dst_is_xmm = insn.insn.op0_kind() == OpKind::Register
            && map_register(insn.insn.op0_register()).0.is_xmm();
        let src_is_xmm = insn.insn.op1_kind() == OpKind::Register
            && map_register(insn.insn.op1_register()).0.is_xmm();

        if dst_is_xmm && !src_is_xmm {
            // GPR/mem → XMM: _mm_cvtsi32_si128 or _mm_cvtsi64_si128
            let dst = self.lift_operand_as_var(&insn.insn, 0);
            let src = self.lift_operand(&insn.insn, 1);
            let name = if insn.mnemonic == Mnemonic::Movq { "_mm_cvtsi64_si128" } else { "_mm_cvtsi32_si128" };
            let result = Expr::intrinsic(name, vec![src]);
            match dst {
                Some(var) => vec![Stmt::Assign(var, result)],
                None => vec![Stmt::Nop],
            }
        } else if !dst_is_xmm && src_is_xmm {
            // XMM → GPR/mem: _mm_cvtsi128_si32 or _mm_cvtsi128_si64
            let dst = self.lift_operand_as_var(&insn.insn, 0);
            let src = self.lift_operand(&insn.insn, 1);
            let name = if insn.mnemonic == Mnemonic::Movq { "_mm_cvtsi128_si64" } else { "_mm_cvtsi128_si32" };
            let result = Expr::intrinsic(name, vec![src]);
            match dst {
                Some(var) => vec![Stmt::Assign(var, result)],
                None => {
                    let addr = self.lift_memory_operand(&insn.insn, 0);
                    let w = if insn.mnemonic == Mnemonic::Movq { BitWidth::Bit64 } else { BitWidth::Bit32 };
                    vec![Stmt::Store(addr, result, w)]
                }
            }
        } else {
            // XMM → XMM or mem → XMM without GPR: just move
            self.lift_mov(insn)
        }
    }

    /// Lift scalar float arithmetic: addss/subss/mulss/divss etc.
    /// Produces `xmm = xmm <op> src` directly (not intrinsic).
    fn lift_float_arith(&mut self, insn: &DisasmInsn, op: &str) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let lhs = self.lift_operand(&insn.insn, 0);
        let rhs = self.lift_operand(&insn.insn, 1);
        let binop = match op {
            "add" => BinOp::Add,
            "sub" => BinOp::Sub,
            "mul" => BinOp::Mul,
            "div" => BinOp::SDiv,
            _ => BinOp::Add,
        };
        let result = Expr::binop(binop, lhs, rhs);
        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => {
                let addr = self.lift_memory_operand(&insn.insn, 0);
                vec![Stmt::Store(addr, result, operand_width(&insn.insn, 0))]
            }
        }
    }

    /// Lift UCOMISS/UCOMISD: scalar float comparison → flags.
    fn lift_float_cmp(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let lhs = self.lift_operand(&insn.insn, 0);
        let rhs = self.lift_operand(&insn.insn, 1);
        self.flag_state = Some(FlagState { kind: FlagKind::Cmp, lhs, rhs });
        vec![]
    }

    /// Lift CVTSI2SS/CVTSI2SD: int → float conversion.
    fn lift_cvtsi2f(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let src = self.lift_operand(&insn.insn, 1);
        let name = if insn.mnemonic == Mnemonic::Cvtsi2sd { "_mm_cvtsi32_sd" } else { "_mm_cvtsi32_ss" };
        let result = Expr::intrinsic(name, vec![src]);
        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => vec![Stmt::Nop],
        }
    }

    /// Lift CVTTSS2SI/CVTTSD2SI: float → int truncation.
    fn lift_cvtf2si(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let src = self.lift_operand(&insn.insn, 1);
        let name = if insn.mnemonic == Mnemonic::Cvttsd2si { "_mm_cvttsd_si32" } else { "_mm_cvttss_si32" };
        let result = Expr::intrinsic(name, vec![src]);
        match dst {
            Some(var) => vec![Stmt::Assign(var, result)],
            None => vec![Stmt::Nop],
        }
    }

    // ── operand helpers ─────────────────────────────────────────

    fn lift_operand(&mut self, insn: &iced_x86::Instruction, op_idx: u32) -> Expr {
        match insn.op_kind(op_idx) {
            OpKind::Register => {
                let (r, w) = map_register(insn.op_register(op_idx));
                Expr::var(Var::Reg(r, w))
            }
            OpKind::Immediate8 => Expr::const_val(insn.immediate8() as u64, BitWidth::Bit8),
            OpKind::Immediate16 => Expr::const_val(insn.immediate16() as u64, BitWidth::Bit16),
            OpKind::Immediate32 => Expr::const_val(insn.immediate32() as u64, BitWidth::Bit32),
            OpKind::Immediate64 => Expr::const_val(insn.immediate64(), BitWidth::Bit64),
            OpKind::Immediate8to16 => Expr::const_val(insn.immediate8to16() as u16 as u64, BitWidth::Bit16),
            OpKind::Immediate8to32 => Expr::const_val(insn.immediate8to32() as u32 as u64, BitWidth::Bit32),
            OpKind::Immediate8to64 => Expr::const_val(insn.immediate8to64() as u64, BitWidth::Bit64),
            OpKind::Immediate32to64 => Expr::const_val(insn.immediate32to64() as u64, BitWidth::Bit64),
            OpKind::Memory => {
                let addr = self.lift_memory_operand(insn, op_idx);
                Expr::load(addr, operand_width(insn, op_idx))
            }
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Expr::const_val(insn.near_branch_target(), BitWidth::Bit64)
            }
            _ => Expr::const_val(0, BitWidth::Bit64),
        }
    }

    fn lift_operand_as_var(&self, insn: &iced_x86::Instruction, op_idx: u32) -> Option<Var> {
        match insn.op_kind(op_idx) {
            OpKind::Register => {
                let (r, w) = map_register(insn.op_register(op_idx));
                Some(Var::Reg(r, w))
            }
            OpKind::Memory => {
                let base = insn.memory_base();
                if self.has_frame_pointer && matches!(base, Register::RBP | Register::EBP) {
                    let disp = mem_disp_signed(insn);
                    Some(Var::Stack(disp, operand_width(insn, op_idx)))
                } else if matches!(base, Register::RSP | Register::ESP)
                    && insn.memory_index() == Register::None
                {
                    let disp = mem_disp_signed(insn);
                    Some(Var::Stack(-(self.frame_size as i64) + disp, operand_width(insn, op_idx)))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn lift_memory_operand(&self, insn: &iced_x86::Instruction, _op_idx: u32) -> Expr {
        // Handle segment-prefixed memory accesses (e.g. fs:0x28 for stack canary)
        let seg = insn.segment_prefix();
        if matches!(seg, Register::FS | Register::GS) {
            let disp = insn.memory_displacement64();
            // Use a high sentinel: 0xFFFF_FFFF_FFFF_E000 + disp
            // Easily recognizable in analysis passes.
            return Expr::const_val(0xFFFF_FFFF_FFFF_E000u64.wrapping_add(disp), BitWidth::Bit64);
        }

        let base = insn.memory_base();
        let index = insn.memory_index();
        let scale = insn.memory_index_scale();
        let pw = self.ptr_width();

        let mut addr: Option<Expr> = None;

        if base != Register::None {
            let (r, w) = map_register(base);
            addr = Some(Expr::var(Var::Reg(r, w)));
        }
        if index != Register::None {
            let (r, w) = map_register(index);
            let ix = if scale > 1 {
                Expr::binop(BinOp::Mul, Expr::var(Var::Reg(r, w)), Expr::const_val(scale as u64, pw))
            } else {
                Expr::var(Var::Reg(r, w))
            };
            addr = Some(match addr {
                Some(a) => Expr::binop(BinOp::Add, a, ix),
                None => ix,
            });
        }
        let disp_signed = mem_disp_signed(insn);
        if disp_signed != 0 {
            // For the Expr node, store the displacement as its unsigned representation
            // at the correct pointer width, so that extract_stack_offset can sign-extend
            // it properly.
            let (disp_val, disp_width) = if pw == BitWidth::Bit32 {
                ((disp_signed as i32 as u32) as u64, BitWidth::Bit32)
            } else {
                (disp_signed as u64, BitWidth::Bit64)
            };
            let d = Expr::const_val(disp_val, disp_width);
            addr = Some(match addr {
                Some(a) => {
                    if disp_signed < 0 {
                        // Represent as Sub for cleaner analysis
                        let abs_val = disp_signed.unsigned_abs();
                        Expr::binop(BinOp::Sub, a, Expr::const_val(abs_val, disp_width))
                    } else {
                        Expr::binop(BinOp::Add, a, d)
                    }
                }
                None => d,
            });
        }
        addr.unwrap_or_else(|| Expr::const_val(0, pw))
    }

    fn map_condition_code(cc: IcedCC) -> CondCode {
        match cc {
            IcedCC::e => CondCode::Eq,
            IcedCC::ne => CondCode::Ne,
            IcedCC::l => CondCode::Lt,
            IcedCC::le => CondCode::Le,
            IcedCC::g => CondCode::Gt,
            IcedCC::ge => CondCode::Ge,
            IcedCC::b => CondCode::Below,
            IcedCC::be => CondCode::BelowEq,
            IcedCC::a => CondCode::Above,
            IcedCC::ae => CondCode::AboveEq,
            IcedCC::s => CondCode::Sign,
            IcedCC::ns => CondCode::NotSign,
            _ => CondCode::Ne,
        }
    }
}

// ── register mapping ─────────────────────────────────────────────

fn map_register(reg: Register) -> (RegId, BitWidth) {
    match reg {
        Register::RAX => (RegId::Rax, BitWidth::Bit64),
        Register::RBX => (RegId::Rbx, BitWidth::Bit64),
        Register::RCX => (RegId::Rcx, BitWidth::Bit64),
        Register::RDX => (RegId::Rdx, BitWidth::Bit64),
        Register::RSI => (RegId::Rsi, BitWidth::Bit64),
        Register::RDI => (RegId::Rdi, BitWidth::Bit64),
        Register::RBP => (RegId::Rbp, BitWidth::Bit64),
        Register::RSP => (RegId::Rsp, BitWidth::Bit64),
        Register::R8  => (RegId::R8,  BitWidth::Bit64),
        Register::R9  => (RegId::R9,  BitWidth::Bit64),
        Register::R10 => (RegId::R10, BitWidth::Bit64),
        Register::R11 => (RegId::R11, BitWidth::Bit64),
        Register::R12 => (RegId::R12, BitWidth::Bit64),
        Register::R13 => (RegId::R13, BitWidth::Bit64),
        Register::R14 => (RegId::R14, BitWidth::Bit64),
        Register::R15 => (RegId::R15, BitWidth::Bit64),
        Register::RIP => (RegId::Rip, BitWidth::Bit64),
        Register::EAX  => (RegId::Rax, BitWidth::Bit32),
        Register::EBX  => (RegId::Rbx, BitWidth::Bit32),
        Register::ECX  => (RegId::Rcx, BitWidth::Bit32),
        Register::EDX  => (RegId::Rdx, BitWidth::Bit32),
        Register::ESI  => (RegId::Rsi, BitWidth::Bit32),
        Register::EDI  => (RegId::Rdi, BitWidth::Bit32),
        Register::EBP  => (RegId::Rbp, BitWidth::Bit32),
        Register::ESP  => (RegId::Rsp, BitWidth::Bit32),
        Register::R8D  => (RegId::R8,  BitWidth::Bit32),
        Register::R9D  => (RegId::R9,  BitWidth::Bit32),
        Register::R10D => (RegId::R10, BitWidth::Bit32),
        Register::R11D => (RegId::R11, BitWidth::Bit32),
        Register::R12D => (RegId::R12, BitWidth::Bit32),
        Register::R13D => (RegId::R13, BitWidth::Bit32),
        Register::R14D => (RegId::R14, BitWidth::Bit32),
        Register::R15D => (RegId::R15, BitWidth::Bit32),
        Register::AX => (RegId::Rax, BitWidth::Bit16),
        Register::BX => (RegId::Rbx, BitWidth::Bit16),
        Register::CX => (RegId::Rcx, BitWidth::Bit16),
        Register::DX => (RegId::Rdx, BitWidth::Bit16),
        Register::SI => (RegId::Rsi, BitWidth::Bit16),
        Register::DI => (RegId::Rdi, BitWidth::Bit16),
        Register::BP => (RegId::Rbp, BitWidth::Bit16),
        Register::SP => (RegId::Rsp, BitWidth::Bit16),
        Register::AL  => (RegId::Rax, BitWidth::Bit8),
        Register::BL  => (RegId::Rbx, BitWidth::Bit8),
        Register::CL  => (RegId::Rcx, BitWidth::Bit8),
        Register::DL  => (RegId::Rdx, BitWidth::Bit8),
        Register::SIL => (RegId::Rsi, BitWidth::Bit8),
        Register::DIL => (RegId::Rdi, BitWidth::Bit8),
        Register::BPL => (RegId::Rbp, BitWidth::Bit8),
        Register::SPL => (RegId::Rsp, BitWidth::Bit8),
        Register::R8L  => (RegId::R8,  BitWidth::Bit8),
        Register::R9L  => (RegId::R9,  BitWidth::Bit8),
        Register::R10L => (RegId::R10, BitWidth::Bit8),
        Register::R11L => (RegId::R11, BitWidth::Bit8),
        Register::R12L => (RegId::R12, BitWidth::Bit8),
        Register::R13L => (RegId::R13, BitWidth::Bit8),
        Register::R14L => (RegId::R14, BitWidth::Bit8),
        Register::R15L => (RegId::R15, BitWidth::Bit8),
        Register::AH => (RegId::Rax, BitWidth::Bit8),
        Register::BH => (RegId::Rbx, BitWidth::Bit8),
        Register::CH => (RegId::Rcx, BitWidth::Bit8),
        Register::DH => (RegId::Rdx, BitWidth::Bit8),
        // SSE registers (XMM0–XMM15) — 128-bit
        Register::XMM0  => (RegId::Xmm0,  BitWidth::Bit128),
        Register::XMM1  => (RegId::Xmm1,  BitWidth::Bit128),
        Register::XMM2  => (RegId::Xmm2,  BitWidth::Bit128),
        Register::XMM3  => (RegId::Xmm3,  BitWidth::Bit128),
        Register::XMM4  => (RegId::Xmm4,  BitWidth::Bit128),
        Register::XMM5  => (RegId::Xmm5,  BitWidth::Bit128),
        Register::XMM6  => (RegId::Xmm6,  BitWidth::Bit128),
        Register::XMM7  => (RegId::Xmm7,  BitWidth::Bit128),
        Register::XMM8  => (RegId::Xmm8,  BitWidth::Bit128),
        Register::XMM9  => (RegId::Xmm9,  BitWidth::Bit128),
        Register::XMM10 => (RegId::Xmm10, BitWidth::Bit128),
        Register::XMM11 => (RegId::Xmm11, BitWidth::Bit128),
        Register::XMM12 => (RegId::Xmm12, BitWidth::Bit128),
        Register::XMM13 => (RegId::Xmm13, BitWidth::Bit128),
        Register::XMM14 => (RegId::Xmm14, BitWidth::Bit128),
        Register::XMM15 => (RegId::Xmm15, BitWidth::Bit128),
        _ => (RegId::Rax, BitWidth::Bit64),
    }
}

fn operand_width(insn: &iced_x86::Instruction, op_idx: u32) -> BitWidth {
    match insn.op_kind(op_idx) {
        OpKind::Register => map_register(insn.op_register(op_idx)).1,
        OpKind::Memory => match insn.memory_size() {
            iced_x86::MemorySize::UInt8  | iced_x86::MemorySize::Int8  => BitWidth::Bit8,
            iced_x86::MemorySize::UInt16 | iced_x86::MemorySize::Int16 => BitWidth::Bit16,
            iced_x86::MemorySize::UInt32 | iced_x86::MemorySize::Int32
            | iced_x86::MemorySize::Float32 => BitWidth::Bit32,
            iced_x86::MemorySize::UInt64 | iced_x86::MemorySize::Int64
            | iced_x86::MemorySize::Float64 => BitWidth::Bit64,
            iced_x86::MemorySize::UInt128 | iced_x86::MemorySize::Int128
            | iced_x86::MemorySize::Packed128_Float32 | iced_x86::MemorySize::Packed128_Float64 => BitWidth::Bit128,
            _ => BitWidth::Bit64,
        },
        _ => BitWidth::Bit64,
    }
}
