use crate::cfg::Cfg;
use crate::disasm::DisasmInsn;
use crate::ir::*;
use crate::loader::Arch;
use iced_x86::{Mnemonic, OpKind, Register};
use iced_x86::ConditionCode as IcedCC;
use std::collections::BTreeMap;

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
        }
    }

    pub fn set_calling_conv(&mut self, cc: CallingConv) {
        self.calling_conv = cc;
    }

    fn new_temp(&mut self, width: BitWidth) -> Var {
        let id = self.next_temp;
        self.next_temp += 1;
        Var::Temp(id, width)
    }

    // ── public entry ─────────────────────────────────────────────

    pub fn lift_function(&mut self, name: &str, addr: u64, cfg: &Cfg) -> Function {
        let mut func = Function::new(name.to_string(), addr);
        func.entry = cfg.blocks.get(&cfg.entry).map_or(BlockId(0), |b| b.block_id);
        func.calling_conv = self.calling_conv;

        self.flag_state = None;
        self.in_prologue = true;
        self.frame_size = 0;
        self.has_frame_pointer = false;

        let addr_to_block: BTreeMap<u64, BlockId> = cfg
            .blocks
            .iter()
            .map(|(&a, blk)| (a, blk.block_id))
            .collect();

        let rpo = cfg.reverse_postorder();

        for &block_addr in &rpo {
            let cfg_block = match cfg.blocks.get(&block_addr) {
                Some(b) => b,
                None => continue,
            };

            let mut stmts = Vec::new();
            let last_idx = cfg_block.instructions.len().saturating_sub(1);

            for (i, insn) in cfg_block.instructions.iter().enumerate() {
                if i == last_idx && insn.is_terminator() {
                    continue;
                }
                let mut lifted = self.lift_instruction(insn);
                stmts.append(&mut lifted);
            }

            let terminator = if let Some(last_insn) = cfg_block.instructions.last() {
                self.lift_terminator(last_insn, &addr_to_block, cfg_block)
            } else {
                Terminator::Unreachable
            };

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
        if self.in_prologue {
            if let Some(s) = self.try_lift_prologue(insn) {
                return s;
            }
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
            Mnemonic::Leave => vec![],
            Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32 | Mnemonic::Int3 => vec![],
            _ => vec![Stmt::Nop],
        }
    }

    // ── prologue / epilogue ──────────────────────────────────────

    fn try_lift_prologue(&mut self, insn: &DisasmInsn) -> Option<Vec<Stmt>> {
        match insn.mnemonic {
            Mnemonic::Push
                if insn.insn.op0_kind() == OpKind::Register
                    && matches!(insn.insn.op0_register(), Register::RBP | Register::EBP) =>
            {
                self.has_frame_pointer = true;
                Some(vec![])
            }
            Mnemonic::Mov
                if insn.insn.op0_kind() == OpKind::Register
                    && insn.insn.op1_kind() == OpKind::Register
                    && matches!(insn.insn.op0_register(), Register::RBP | Register::EBP)
                    && matches!(insn.insn.op1_register(), Register::RSP | Register::ESP) =>
            {
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
    ) -> Terminator {
        match insn.insn.flow_control() {
            iced_x86::FlowControl::Return => {
                Terminator::Return(Some(Expr::var(Var::Reg(RegId::Rax, BitWidth::Bit64))))
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
                Terminator::IndirectJump(self.lift_operand(&insn.insn, 0))
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

    // ── condition fusion ─────────────────────────────────────────

    fn fuse_condition(&mut self, cc: CondCode) -> Expr {
        let Some(st) = self.flag_state.take() else {
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
        let rsp = Var::Reg(RegId::Rsp, BitWidth::Bit64);
        vec![
            Stmt::Assign(rsp.clone(), Expr::binop(BinOp::Sub, Expr::var(rsp.clone()), Expr::const_val(8, BitWidth::Bit64))),
            Stmt::Store(Expr::var(rsp), val, BitWidth::Bit64),
        ]
    }

    fn lift_pop(&mut self, insn: &DisasmInsn) -> Vec<Stmt> {
        let rsp = Var::Reg(RegId::Rsp, BitWidth::Bit64);
        let mut stmts = Vec::new();
        if let Some(dst) = self.lift_operand_as_var(&insn.insn, 0) {
            stmts.push(Stmt::Assign(dst, Expr::load(Expr::var(rsp.clone()), BitWidth::Bit64)));
        }
        stmts.push(Stmt::Assign(rsp.clone(), Expr::binop(BinOp::Add, Expr::var(rsp), Expr::const_val(8, BitWidth::Bit64))));
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
        let _cond = self.fuse_condition(cc);

        match dst {
            Some(var) => {
                // Emit as conditional assignment; codegen will handle
                let _tmp = self.new_temp(var.width());
                vec![Stmt::Assign(var, src)] // simplified
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
        self.flag_state = Some(FlagState {
            kind: FlagKind::Arith,
            lhs: result.clone(),
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
        match dst {
            Some(var) => vec![Stmt::Assign(var, Expr::unaryop(op, val))],
            None => vec![Stmt::Nop],
        }
    }

    fn lift_inc_dec(&mut self, insn: &DisasmInsn, op: BinOp) -> Vec<Stmt> {
        let dst = self.lift_operand_as_var(&insn.insn, 0);
        let val = self.lift_operand(&insn.insn, 0);
        let w = operand_width(&insn.insn, 0);
        let result = Expr::binop(op, val, Expr::const_val(1, w));
        self.flag_state = Some(FlagState {
            kind: FlagKind::Arith,
            lhs: result.clone(),
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
            Expr::const_val(addr, BitWidth::Bit64)
        } else {
            self.lift_operand(&insn.insn, 0)
        };
        let ret = Var::Reg(RegId::Rax, BitWidth::Bit64);
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
                if matches!(base, Register::RBP | Register::EBP) {
                    let disp = insn.memory_displacement64() as i64;
                    Some(Var::Stack(disp, operand_width(insn, op_idx)))
                } else if matches!(base, Register::RSP | Register::ESP)
                    && insn.memory_index() == Register::None
                {
                    let disp = insn.memory_displacement64() as i64;
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
        let disp = insn.memory_displacement64();

        let mut addr: Option<Expr> = None;

        if base != Register::None {
            let (r, w) = map_register(base);
            addr = Some(Expr::var(Var::Reg(r, w)));
        }
        if index != Register::None {
            let (r, w) = map_register(index);
            let ix = if scale > 1 {
                Expr::binop(BinOp::Mul, Expr::var(Var::Reg(r, w)), Expr::const_val(scale as u64, BitWidth::Bit64))
            } else {
                Expr::var(Var::Reg(r, w))
            };
            addr = Some(match addr {
                Some(a) => Expr::binop(BinOp::Add, a, ix),
                None => ix,
            });
        }
        if disp != 0 {
            let d = Expr::const_val(disp, BitWidth::Bit64);
            addr = Some(match addr {
                Some(a) => Expr::binop(BinOp::Add, a, d),
                None => d,
            });
        }
        addr.unwrap_or_else(|| Expr::const_val(0, BitWidth::Bit64))
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
        _ => (RegId::Rax, BitWidth::Bit64),
    }
}

fn operand_width(insn: &iced_x86::Instruction, op_idx: u32) -> BitWidth {
    match insn.op_kind(op_idx) {
        OpKind::Register => map_register(insn.op_register(op_idx)).1,
        OpKind::Memory => match insn.memory_size() {
            iced_x86::MemorySize::UInt8  | iced_x86::MemorySize::Int8  => BitWidth::Bit8,
            iced_x86::MemorySize::UInt16 | iced_x86::MemorySize::Int16 => BitWidth::Bit16,
            iced_x86::MemorySize::UInt32 | iced_x86::MemorySize::Int32 => BitWidth::Bit32,
            iced_x86::MemorySize::UInt64 | iced_x86::MemorySize::Int64 => BitWidth::Bit64,
            _ => BitWidth::Bit64,
        },
        _ => BitWidth::Bit64,
    }
}
