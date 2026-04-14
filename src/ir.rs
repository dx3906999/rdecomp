use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Well-known functions that never return.
pub const NORETURN_NAMES: &[&str] = &["exit", "_exit", "abort", "_Exit", "__assert_fail", "__stack_chk_fail"];

/// Check if a function name is a known noreturn function.
pub fn is_noreturn_name(name: &str) -> bool {
    NORETURN_NAMES.contains(&name)
}

/// Signedness of an integer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Signedness {
    Unsigned,
    Signed,
    Unknown,
}

/// High-level C-like type for decompiled output.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CType {
    /// Integer: width + signedness.
    Int(BitWidth, Signedness),
    /// Pointer to another type.
    Ptr(Box<CType>),
    /// Character (int8 used as char).
    Char,
    /// Boolean (result of comparison).
    Bool,
    /// Void (for return types).
    Void,
    /// Unknown / not yet inferred.
    Unknown,
}

impl CType {
    /// Produce a C type string for declarations.
    pub fn to_c_str(&self) -> &'static str {
        match self {
            CType::Int(BitWidth::Bit8, Signedness::Signed) => "int8_t",
            CType::Int(BitWidth::Bit8, _) => "uint8_t",
            CType::Int(BitWidth::Bit16, Signedness::Signed) => "int16_t",
            CType::Int(BitWidth::Bit16, _) => "uint16_t",
            CType::Int(BitWidth::Bit32, Signedness::Signed) => "int32_t",
            CType::Int(BitWidth::Bit32, _) => "uint32_t",
            CType::Int(BitWidth::Bit64, Signedness::Signed) => "int64_t",
            CType::Int(BitWidth::Bit64, _) => "uint64_t",
            CType::Ptr(_) => "void*",
            CType::Char => "char",
            CType::Bool => "bool",
            CType::Void => "void",
            CType::Unknown => "uint64_t",
        }
    }
}

/// Bit width for values and operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BitWidth {
    Bit8,
    Bit16,
    Bit32,
    Bit64,
}

impl BitWidth {
    pub fn bytes(self) -> u32 {
        match self {
            Self::Bit8 => 1,
            Self::Bit16 => 2,
            Self::Bit32 => 4,
            Self::Bit64 => 8,
        }
    }

    pub fn bits(self) -> u32 {
        self.bytes() * 8
    }
}

impl fmt::Display for BitWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bit8 => write!(f, "u8"),
            Self::Bit16 => write!(f, "u16"),
            Self::Bit32 => write!(f, "u32"),
            Self::Bit64 => write!(f, "u64"),
        }
    }
}

/// CPU register identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegId {
    // General-purpose 64-bit
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rbp,
    Rsp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    // Instruction pointer
    Rip,
    // SSE registers
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Xmm8,
    Xmm9,
    Xmm10,
    Xmm11,
    Xmm12,
    Xmm13,
    Xmm14,
    Xmm15,
}

impl RegId {
    /// Returns true for SSE/XMM registers.
    pub fn is_xmm(self) -> bool {
        matches!(self,
            Self::Xmm0 | Self::Xmm1 | Self::Xmm2 | Self::Xmm3
            | Self::Xmm4 | Self::Xmm5 | Self::Xmm6 | Self::Xmm7
            | Self::Xmm8 | Self::Xmm9 | Self::Xmm10 | Self::Xmm11
            | Self::Xmm12 | Self::Xmm13 | Self::Xmm14 | Self::Xmm15
        )
    }
}

impl fmt::Display for RegId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Rax => "rax",
            Self::Rbx => "rbx",
            Self::Rcx => "rcx",
            Self::Rdx => "rdx",
            Self::Rsi => "rsi",
            Self::Rdi => "rdi",
            Self::Rbp => "rbp",
            Self::Rsp => "rsp",
            Self::R8 => "r8",
            Self::R9 => "r9",
            Self::R10 => "r10",
            Self::R11 => "r11",
            Self::R12 => "r12",
            Self::R13 => "r13",
            Self::R14 => "r14",
            Self::R15 => "r15",
            Self::Rip => "rip",
            Self::Xmm0 => "xmm0",
            Self::Xmm1 => "xmm1",
            Self::Xmm2 => "xmm2",
            Self::Xmm3 => "xmm3",
            Self::Xmm4 => "xmm4",
            Self::Xmm5 => "xmm5",
            Self::Xmm6 => "xmm6",
            Self::Xmm7 => "xmm7",
            Self::Xmm8 => "xmm8",
            Self::Xmm9 => "xmm9",
            Self::Xmm10 => "xmm10",
            Self::Xmm11 => "xmm11",
            Self::Xmm12 => "xmm12",
            Self::Xmm13 => "xmm13",
            Self::Xmm14 => "xmm14",
            Self::Xmm15 => "xmm15",
        };
        write!(f, "{s}")
    }
}

/// CPU flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Flag {
    Zf, // Zero flag
    Sf, // Sign flag
    Cf, // Carry flag
    Of, // Overflow flag
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zf => write!(f, "ZF"),
            Self::Sf => write!(f, "SF"),
            Self::Cf => write!(f, "CF"),
            Self::Of => write!(f, "OF"),
        }
    }
}

/// A variable in the IR.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Var {
    /// CPU register (possibly sub-register with a width).
    Reg(RegId, BitWidth),
    /// Stack variable at offset from RBP.
    Stack(i64, BitWidth),
    /// Temporary variable (SSA-like).
    Temp(u32, BitWidth),
    /// CPU flag.
    Flag(Flag),
}

impl Var {
    pub fn width(&self) -> BitWidth {
        match self {
            Self::Reg(_, w) | Self::Stack(_, w) | Self::Temp(_, w) => *w,
            Self::Flag(_) => BitWidth::Bit8,
        }
    }
}

impl fmt::Display for Var {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reg(r, _) => write!(f, "{r}"),
            Self::Stack(off, _) => {
                if *off >= 0 {
                    write!(f, "arg_{off:x}")
                } else {
                    write!(f, "var_{:x}", off.unsigned_abs())
                }
            }
            Self::Temp(id, _) => write!(f, "t{id}"),
            Self::Flag(fl) => write!(f, "{fl}"),
        }
    }
}

/// Binary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    UMod,
    SMod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar, // Arithmetic shift right
    Rol, // Rotate left
    Ror, // Rotate right
    Eq,
    Ne,
    Ult,  // Unsigned less than
    Ule,
    Slt,  // Signed less than
    Sle,
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::UDiv | Self::SDiv => "/",
            Self::UMod | Self::SMod => "%",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::Shr | Self::Sar => ">>",
            Self::Rol => "<<<",
            Self::Ror => ">>>",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Ult | Self::Slt => "<",
            Self::Ule | Self::Sle => "<=",
        };
        write!(f, "{s}")
    }
}

/// Unary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOp {
    Neg,
    Not,
    /// Zero-extend to wider type.
    ZeroExt(BitWidth),
    /// Sign-extend to wider type.
    SignExt(BitWidth),
    /// Truncate to narrower type.
    Trunc(BitWidth),
    /// Address-of operator (&).
    AddrOf,
}

impl fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Neg => write!(f, "-"),
            Self::Not => write!(f, "~"),
            Self::ZeroExt(w) => write!(f, "({})", w),
            Self::SignExt(w) => write!(f, "(signed {})", w),
            Self::Trunc(w) => write!(f, "({})", w),
            Self::AddrOf => write!(f, "&"),
        }
    }
}

/// An expression in the IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expr {
    /// A variable reference.
    Var(Var),
    /// A constant value.
    Const(u64, BitWidth),
    /// Binary operation.
    BinOp(BinOp, Box<Expr>, Box<Expr>),
    /// Unary operation.
    UnaryOp(UnaryOp, Box<Expr>),
    /// Memory load: Load(address, width).
    Load(Box<Expr>, BitWidth),
    /// Condition (used in branches): flag-based (legacy, before fusion).
    Cond(CondCode),
    /// Fused comparison: Cmp(cc, lhs, rhs) — e.g. `a == b`, `a < 0`.
    /// This is produced by fusing CMP/TEST + Jcc.
    Cmp(CondCode, Box<Expr>, Box<Expr>),
    /// Logical AND (short-circuit): `a && b`.
    LogicalAnd(Box<Expr>, Box<Expr>),
    /// Logical OR (short-circuit): `a || b`.
    LogicalOr(Box<Expr>, Box<Expr>),
    /// Ternary select: `cond ? true_val : false_val` (from CMOV).
    Select(Box<Expr>, Box<Expr>, Box<Expr>),
}

impl Expr {
    pub fn width(&self) -> BitWidth {
        match self {
            Self::Var(v) => v.width(),
            Self::Const(_, w) | Self::Load(_, w) => *w,
            Self::BinOp(op, lhs, _) => match op {
                BinOp::Eq | BinOp::Ne | BinOp::Ult | BinOp::Ule | BinOp::Slt | BinOp::Sle => {
                    BitWidth::Bit8
                }
                _ => lhs.width(),
            },
            Self::UnaryOp(op, inner) => match op {
                UnaryOp::ZeroExt(w) | UnaryOp::SignExt(w) | UnaryOp::Trunc(w) => *w,
                UnaryOp::AddrOf => BitWidth::Bit64,
                _ => inner.width(),
            },
            Self::Cond(_) | Self::Cmp(..) => BitWidth::Bit8,
            Self::LogicalAnd(..) | Self::LogicalOr(..) => BitWidth::Bit8,
            Self::Select(_, true_val, _) => true_val.width(),
        }
    }

    pub fn const_val(val: u64, width: BitWidth) -> Self {
        Self::Const(val, width)
    }

    pub fn var(v: Var) -> Self {
        Self::Var(v)
    }

    pub fn binop(op: BinOp, lhs: Expr, rhs: Expr) -> Self {
        Self::BinOp(op, Box::new(lhs), Box::new(rhs))
    }

    pub fn unaryop(op: UnaryOp, inner: Expr) -> Self {
        Self::UnaryOp(op, Box::new(inner))
    }

    pub fn load(addr: Expr, width: BitWidth) -> Self {
        Self::Load(Box::new(addr), width)
    }

    pub fn cmp(cc: CondCode, lhs: Expr, rhs: Expr) -> Self {
        Self::Cmp(cc, Box::new(lhs), Box::new(rhs))
    }

    pub fn select(cond: Expr, true_val: Expr, false_val: Expr) -> Self {
        Self::Select(Box::new(cond), Box::new(true_val), Box::new(false_val))
    }

    /// Returns true if this expression or any sub-expression satisfies the predicate.
    pub fn any(&self, pred: &dyn Fn(&Expr) -> bool) -> bool {
        if pred(self) {
            return true;
        }
        match self {
            Self::BinOp(_, l, r)
            | Self::Cmp(_, l, r)
            | Self::LogicalAnd(l, r)
            | Self::LogicalOr(l, r) => l.any(pred) || r.any(pred),
            Self::UnaryOp(_, inner) | Self::Load(inner, _) => inner.any(pred),
            Self::Select(c, t, f) => c.any(pred) || t.any(pred) || f.any(pred),
            _ => false,
        }
    }

    /// Calls `f` on this expression and all sub-expressions (pre-order).
    pub fn walk(&self, f: &mut dyn FnMut(&Expr)) {
        f(self);
        match self {
            Self::BinOp(_, l, r)
            | Self::Cmp(_, l, r)
            | Self::LogicalAnd(l, r)
            | Self::LogicalOr(l, r) => {
                l.walk(f);
                r.walk(f);
            }
            Self::UnaryOp(_, inner) | Self::Load(inner, _) => inner.walk(f),
            Self::Select(c, t, f_) => {
                c.walk(f);
                t.walk(f);
                f_.walk(f);
            }
            _ => {}
        }
    }

    /// Calls `f` on sub-expressions first (bottom-up), then on self.
    /// Safe for leaf replacement: replaced nodes' children are not revisited.
    pub fn walk_mut(&mut self, f: &mut dyn FnMut(&mut Expr)) {
        match self {
            Self::BinOp(_, l, r)
            | Self::Cmp(_, l, r)
            | Self::LogicalAnd(l, r)
            | Self::LogicalOr(l, r) => {
                l.walk_mut(f);
                r.walk_mut(f);
            }
            Self::UnaryOp(_, inner) | Self::Load(inner, _) => inner.walk_mut(f),
            Self::Select(c, t, e) => {
                c.walk_mut(f);
                t.walk_mut(f);
                e.walk_mut(f);
            }
            _ => {}
        }
        f(self);
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Var(v) => write!(f, "{v}"),
            Self::Const(val, _) => {
                if *val > 9 {
                    write!(f, "0x{val:x}")
                } else {
                    write!(f, "{val}")
                }
            }
            Self::BinOp(op, lhs, rhs) => write!(f, "({lhs} {op} {rhs})"),
            Self::UnaryOp(op, inner) => write!(f, "{op}{inner}"),
            Self::Load(addr, width) => write!(f, "*({width}*){addr}"),
            Self::Cond(cc) => write!(f, "{cc}"),
            Self::Cmp(cc, lhs, rhs) => write!(f, "({lhs} {cc} {rhs})"),
            Self::LogicalAnd(lhs, rhs) => write!(f, "({lhs} && {rhs})"),
            Self::LogicalOr(lhs, rhs) => write!(f, "({lhs} || {rhs})"),
            Self::Select(cond, t, e) => write!(f, "({cond} ? {t} : {e})"),
        }
    }
}

/// Condition codes for branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CondCode {
    Eq,   // ZF=1
    Ne,   // ZF=0
    Lt,   // SF!=OF (signed <)
    Le,   // ZF=1 || SF!=OF
    Gt,   // ZF=0 && SF==OF
    Ge,   // SF==OF
    Below, // CF=1 (unsigned <)
    BelowEq, // CF=1 || ZF=1
    Above, // CF=0 && ZF=0
    AboveEq, // CF=0
    Sign,  // SF=1
    NotSign, // SF=0
}

impl CondCode {
    pub fn negate(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Lt => Self::Ge,
            Self::Le => Self::Gt,
            Self::Gt => Self::Le,
            Self::Ge => Self::Lt,
            Self::Below => Self::AboveEq,
            Self::BelowEq => Self::Above,
            Self::Above => Self::BelowEq,
            Self::AboveEq => Self::Below,
            Self::Sign => Self::NotSign,
            Self::NotSign => Self::Sign,
        }
    }
}

impl fmt::Display for CondCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eq => write!(f, "=="),
            Self::Ne => write!(f, "!="),
            Self::Lt => write!(f, "<"),
            Self::Le => write!(f, "<="),
            Self::Gt => write!(f, ">"),
            Self::Ge => write!(f, ">="),
            Self::Below => write!(f, "<u"),
            Self::BelowEq => write!(f, "<=u"),
            Self::Above => write!(f, ">u"),
            Self::AboveEq => write!(f, ">=u"),
            Self::Sign => write!(f, "< 0"),
            Self::NotSign => write!(f, ">= 0"),
        }
    }
}

/// A statement in the IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stmt {
    /// Assign a value to a variable.
    Assign(Var, Expr),
    /// Store a value to memory: Store(addr, value, width).
    Store(Expr, Expr, BitWidth),
    /// Function call: Call(return_var, target, args).
    Call(Option<Var>, Expr, Vec<Expr>),
    /// No effect (placeholder or removed instruction).
    Nop,
}

impl fmt::Display for Stmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Assign(var, expr) => write!(f, "{var} = {expr}"),
            Self::Store(addr, val, width) => write!(f, "*({width}*){addr} = {val}"),
            Self::Call(ret, target, args) => {
                if let Some(r) = ret {
                    write!(f, "{r} = ")?;
                }
                write!(f, "call {target}(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{arg}")?;
                }
                write!(f, ")")
            }
            Self::Nop => write!(f, "nop"),
        }
    }
}

/// Terminator of a basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Terminator {
    /// Unconditional jump to a block.
    Jump(BlockId),
    /// Conditional branch: if cond goto true_block else goto false_block.
    Branch(Expr, BlockId, BlockId),
    /// Return from function with optional value.
    Return(Option<Expr>),
    /// Switch/jump table: Switch(value, cases, default).
    /// Each case maps a constant value to a target block.
    Switch(Expr, Vec<(u64, BlockId)>, Option<BlockId>),
    /// Indirect jump (computed goto, unresolved switch).
    IndirectJump(Expr),
    /// Unreachable/undefined.
    Unreachable,
}

impl fmt::Display for Terminator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jump(target) => write!(f, "goto {target}"),
            Self::Branch(cond, t, e) => write!(f, "if {cond} goto {t} else {e}"),
            Self::Return(val) => {
                if let Some(v) = val {
                    write!(f, "return {v}")
                } else {
                    write!(f, "return")
                }
            }
            Self::Switch(val, cases, default) => {
                write!(f, "switch {val} [")?;
                for (i, (v, bid)) in cases.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{v} => {bid}")?;
                }
                if let Some(def) = default {
                    write!(f, ", default => {def}")?;
                }
                write!(f, "]")
            }
            Self::IndirectJump(target) => write!(f, "goto *{target}"),
            Self::Unreachable => write!(f, "unreachable"),
        }
    }
}

/// Block identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockId(pub u32);

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

/// Calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallingConv {
    /// System V AMD64 ABI (Linux/macOS): rdi, rsi, rdx, rcx, r8, r9.
    SystemV,
    /// Microsoft x64: rcx, rdx, r8, r9.
    Win64,
    /// x86 cdecl: all parameters on stack, return in eax.
    Cdecl,
}

impl CallingConv {
    /// Get parameter registers in order.
    pub fn param_regs(&self) -> &[RegId] {
        match self {
            Self::SystemV => &[RegId::Rdi, RegId::Rsi, RegId::Rdx, RegId::Rcx, RegId::R8, RegId::R9],
            Self::Win64 => &[RegId::Rcx, RegId::Rdx, RegId::R8, RegId::R9],
            Self::Cdecl => &[],
        }
    }

    /// Get callee-saved registers.
    pub fn callee_saved(&self) -> &[RegId] {
        match self {
            Self::SystemV => &[RegId::Rbx, RegId::Rbp, RegId::R12, RegId::R13, RegId::R14, RegId::R15],
            Self::Win64 => &[RegId::Rbx, RegId::Rbp, RegId::Rdi, RegId::Rsi, RegId::R12, RegId::R13, RegId::R14, RegId::R15],
            Self::Cdecl => &[RegId::Rbx, RegId::Rsi, RegId::Rdi, RegId::Rbp],
        }
    }

    /// Whether this is a 32-bit calling convention.
    pub fn is_32bit(&self) -> bool {
        matches!(self, Self::Cdecl)
    }
}

/// A basic block in the IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BlockId,
    /// Original address of the first instruction in this block.
    pub addr: u64,
    /// IR statements.
    pub stmts: Vec<Stmt>,
    /// Block terminator.
    pub terminator: Terminator,
}

impl fmt::Display for BasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}:  // 0x{:x}", self.id, self.addr)?;
        for stmt in &self.stmts {
            writeln!(f, "    {stmt}")?;
        }
        writeln!(f, "    {}", self.terminator)
    }
}

/// A function in the IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub addr: u64,
    pub entry: BlockId,
    pub blocks: Vec<BasicBlock>,
    pub next_temp: u32,
    pub next_block: u32,
    pub calling_conv: CallingConv,
    /// Number of parameters actually used (detected by analysis).
    pub param_count: usize,
    /// Whether this function has a standard frame pointer prologue.
    pub has_frame_pointer: bool,
    /// Stack frame size (sub rsp, N).
    pub frame_size: u64,
    /// Inferred buffer sizes: stack offset → byte count.
    /// Populated by `infer_buffer_sizes` analysis pass.
    #[serde(default)]
    pub buffer_sizes: HashMap<i64, u64>,
    /// Inferred types for variables: string key (e.g. "var_8", "arg_1", "t0") → CType.
    /// Populated by `typing::infer_types`.
    #[serde(default)]
    pub var_types: HashMap<String, CType>,
    /// Inferred return type.
    #[serde(default = "default_return_type")]
    pub return_type: CType,
}

fn default_return_type() -> CType {
    CType::Unknown
}

impl Function {
    pub fn new(name: String, addr: u64) -> Self {
        Self {
            name,
            addr,
            entry: BlockId(0),
            blocks: Vec::new(),
            next_temp: 0,
            next_block: 0,
            calling_conv: CallingConv::SystemV,
            param_count: 0,
            has_frame_pointer: false,
            frame_size: 0,
            buffer_sizes: HashMap::new(),
            var_types: HashMap::new(),
            return_type: CType::Unknown,
        }
    }

    /// Allocate a new temporary variable.
    pub fn new_temp(&mut self, width: BitWidth) -> Var {
        let id = self.next_temp;
        self.next_temp += 1;
        Var::Temp(id, width)
    }

    /// Allocate a new block ID.
    pub fn new_block_id(&mut self) -> BlockId {
        let id = self.next_block;
        self.next_block += 1;
        BlockId(id)
    }

    /// Find block by ID.
    pub fn block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Find block by ID (mutable).
    pub fn block_mut(&mut self, id: BlockId) -> Option<&mut BasicBlock> {
        self.blocks.iter_mut().find(|b| b.id == id)
    }

    /// Get successor block IDs for a block.
    pub fn successors(&self, id: BlockId) -> Vec<BlockId> {
        self.block(id)
            .map(|b| match &b.terminator {
                Terminator::Jump(target) => vec![*target],
                Terminator::Branch(_, t, f) => vec![*t, *f],
                Terminator::Switch(_, cases, default) => {
                    let mut succs: Vec<BlockId> = cases.iter().map(|(_, bid)| *bid).collect();
                    if let Some(def) = default {
                        succs.push(*def);
                    }
                    succs.sort();
                    succs.dedup();
                    succs
                }
                _ => vec![],
            })
            .unwrap_or_default()
    }

    /// Get predecessor block IDs for a block.
    pub fn predecessors(&self, id: BlockId) -> Vec<BlockId> {
        self.blocks
            .iter()
            .filter(|b| self.successors(b.id).contains(&id))
            .map(|b| b.id)
            .collect()
    }
}

impl fmt::Display for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "function {}() {{  // 0x{:x}", self.name, self.addr)?;
        for block in &self.blocks {
            write!(f, "{block}")?;
        }
        writeln!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── BitWidth ──────────────────────────────────────────────

    #[test]
    fn bitwidth_bytes_and_bits() {
        assert_eq!(BitWidth::Bit8.bytes(), 1);
        assert_eq!(BitWidth::Bit16.bytes(), 2);
        assert_eq!(BitWidth::Bit32.bytes(), 4);
        assert_eq!(BitWidth::Bit64.bytes(), 8);
        assert_eq!(BitWidth::Bit32.bits(), 32);
        assert_eq!(BitWidth::Bit64.bits(), 64);
    }

    #[test]
    fn bitwidth_ordering() {
        assert!(BitWidth::Bit8 < BitWidth::Bit16);
        assert!(BitWidth::Bit16 < BitWidth::Bit32);
        assert!(BitWidth::Bit32 < BitWidth::Bit64);
    }

    // ── Var ───────────────────────────────────────────────────

    #[test]
    fn var_width() {
        assert_eq!(Var::Reg(RegId::Rax, BitWidth::Bit64).width(), BitWidth::Bit64);
        assert_eq!(Var::Stack(-8, BitWidth::Bit32).width(), BitWidth::Bit32);
        assert_eq!(Var::Temp(0, BitWidth::Bit16).width(), BitWidth::Bit16);
        assert_eq!(Var::Flag(Flag::Zf).width(), BitWidth::Bit8);
    }

    #[test]
    fn var_display() {
        assert_eq!(format!("{}", Var::Reg(RegId::Rdi, BitWidth::Bit64)), "rdi");
        assert_eq!(format!("{}", Var::Stack(-8, BitWidth::Bit32)), "var_8");
        assert_eq!(format!("{}", Var::Stack(16, BitWidth::Bit64)), "arg_10");
        assert_eq!(format!("{}", Var::Temp(3, BitWidth::Bit32)), "t3");
        assert_eq!(format!("{}", Var::Flag(Flag::Cf)), "CF");
    }

    // ── CondCode ──────────────────────────────────────────────

    #[test]
    fn condcode_negate_roundtrip() {
        let codes = [
            CondCode::Eq, CondCode::Ne, CondCode::Lt, CondCode::Le,
            CondCode::Gt, CondCode::Ge, CondCode::Below, CondCode::BelowEq,
            CondCode::Above, CondCode::AboveEq, CondCode::Sign, CondCode::NotSign,
        ];
        for cc in &codes {
            assert_eq!(cc.negate().negate(), *cc, "double negate should be identity for {cc}");
        }
    }

    #[test]
    fn condcode_negate_pairs() {
        assert_eq!(CondCode::Eq.negate(), CondCode::Ne);
        assert_eq!(CondCode::Lt.negate(), CondCode::Ge);
        assert_eq!(CondCode::Below.negate(), CondCode::AboveEq);
    }

    // ── Expr ──────────────────────────────────────────────────

    #[test]
    fn expr_const_display() {
        assert_eq!(format!("{}", Expr::Const(0, BitWidth::Bit32)), "0");
        assert_eq!(format!("{}", Expr::Const(9, BitWidth::Bit32)), "9");
        assert_eq!(format!("{}", Expr::Const(10, BitWidth::Bit32)), "0xa");
        assert_eq!(format!("{}", Expr::Const(255, BitWidth::Bit8)), "0xff");
    }

    #[test]
    fn expr_binop_display() {
        let a = Expr::var(Var::Reg(RegId::Rax, BitWidth::Bit32));
        let b = Expr::const_val(5, BitWidth::Bit32);
        let add = Expr::binop(BinOp::Add, a, b);
        assert_eq!(format!("{add}"), "(rax + 5)");
    }

    #[test]
    fn expr_cmp_display() {
        let a = Expr::var(Var::Stack(-8, BitWidth::Bit32));
        let b = Expr::const_val(0, BitWidth::Bit32);
        let cmp = Expr::cmp(CondCode::Eq, a, b);
        assert_eq!(format!("{cmp}"), "(var_8 == 0)");
    }

    #[test]
    fn expr_logical_display() {
        let a = Expr::cmp(CondCode::Gt, Expr::var(Var::Stack(-4, BitWidth::Bit32)), Expr::const_val(0, BitWidth::Bit32));
        let b = Expr::cmp(CondCode::Lt, Expr::var(Var::Stack(-8, BitWidth::Bit32)), Expr::const_val(10, BitWidth::Bit32));
        let and = Expr::LogicalAnd(Box::new(a.clone()), Box::new(b.clone()));
        let or = Expr::LogicalOr(Box::new(a), Box::new(b));
        assert_eq!(format!("{and}"), "((var_4 > 0) && (var_8 < 0xa))");
        assert_eq!(format!("{or}"), "((var_4 > 0) || (var_8 < 0xa))");
    }

    #[test]
    fn expr_width() {
        assert_eq!(Expr::const_val(42, BitWidth::Bit32).width(), BitWidth::Bit32);
        assert_eq!(Expr::var(Var::Reg(RegId::Rax, BitWidth::Bit64)).width(), BitWidth::Bit64);
        // comparison result is always Bit8 (boolean)
        let cmp = Expr::cmp(CondCode::Eq, Expr::const_val(1, BitWidth::Bit32), Expr::const_val(1, BitWidth::Bit32));
        assert_eq!(cmp.width(), BitWidth::Bit8);
        // LogicalAnd/Or are boolean
        let la = Expr::LogicalAnd(Box::new(cmp.clone()), Box::new(cmp.clone()));
        assert_eq!(la.width(), BitWidth::Bit8);
    }

    #[test]
    fn expr_load_display() {
        let addr = Expr::var(Var::Reg(RegId::Rbx, BitWidth::Bit64));
        let load = Expr::load(addr, BitWidth::Bit32);
        assert_eq!(format!("{load}"), "*(u32*)rbx");
    }

    #[test]
    fn expr_unaryop_display() {
        let a = Expr::var(Var::Reg(RegId::Rax, BitWidth::Bit32));
        assert_eq!(format!("{}", Expr::unaryop(UnaryOp::Neg, a.clone())), "-rax");
        assert_eq!(format!("{}", Expr::unaryop(UnaryOp::Not, a.clone())), "~rax");
        assert_eq!(format!("{}", Expr::unaryop(UnaryOp::ZeroExt(BitWidth::Bit64), a.clone())), "(u64)rax");
        assert_eq!(format!("{}", Expr::unaryop(UnaryOp::SignExt(BitWidth::Bit64), a.clone())), "(signed u64)rax");
        assert_eq!(format!("{}", Expr::unaryop(UnaryOp::Trunc(BitWidth::Bit16), a.clone())), "(u16)rax");
    }

    // ── Stmt ──────────────────────────────────────────────────

    #[test]
    fn stmt_assign_display() {
        let s = Stmt::Assign(
            Var::Stack(-8, BitWidth::Bit32),
            Expr::const_val(42, BitWidth::Bit32),
        );
        assert_eq!(format!("{s}"), "var_8 = 0x2a");
    }

    #[test]
    fn stmt_store_display() {
        let s = Stmt::Store(
            Expr::var(Var::Reg(RegId::Rdi, BitWidth::Bit64)),
            Expr::const_val(0, BitWidth::Bit32),
            BitWidth::Bit32,
        );
        assert_eq!(format!("{s}"), "*(u32*)rdi = 0");
    }

    #[test]
    fn stmt_call_display() {
        let s = Stmt::Call(
            Some(Var::Reg(RegId::Rax, BitWidth::Bit64)),
            Expr::const_val(0x401000, BitWidth::Bit64),
            vec![Expr::var(Var::Reg(RegId::Rdi, BitWidth::Bit64))],
        );
        assert_eq!(format!("{s}"), "rax = call 0x401000(rdi)");
    }

    // ── Terminator ────────────────────────────────────────────

    #[test]
    fn terminator_display() {
        assert_eq!(format!("{}", Terminator::Jump(BlockId(1))), "goto bb1");
        assert_eq!(format!("{}", Terminator::Return(Some(Expr::const_val(0, BitWidth::Bit32)))), "return 0");
        assert_eq!(format!("{}", Terminator::Return(None)), "return");
        assert_eq!(format!("{}", Terminator::Unreachable), "unreachable");
    }

    #[test]
    fn terminator_branch_display() {
        let cond = Expr::cmp(CondCode::Ne, Expr::var(Var::Reg(RegId::Rax, BitWidth::Bit64)), Expr::const_val(0, BitWidth::Bit64));
        let t = Terminator::Branch(cond, BlockId(2), BlockId(3));
        assert_eq!(format!("{t}"), "if (rax != 0) goto bb2 else bb3");
    }

    // ── CallingConv ───────────────────────────────────────────

    #[test]
    fn calling_conv_param_regs() {
        assert_eq!(CallingConv::SystemV.param_regs().len(), 6);
        assert_eq!(CallingConv::Win64.param_regs().len(), 4);
        assert_eq!(CallingConv::Cdecl.param_regs().len(), 0);
    }

    #[test]
    fn calling_conv_32bit() {
        assert!(!CallingConv::SystemV.is_32bit());
        assert!(!CallingConv::Win64.is_32bit());
        assert!(CallingConv::Cdecl.is_32bit());
    }

    // ── Function ──────────────────────────────────────────────

    #[test]
    fn function_new_temp_and_block() {
        let mut f = Function::new("test".into(), 0x1000);
        let t0 = f.new_temp(BitWidth::Bit32);
        let t1 = f.new_temp(BitWidth::Bit64);
        assert_eq!(t0, Var::Temp(0, BitWidth::Bit32));
        assert_eq!(t1, Var::Temp(1, BitWidth::Bit64));

        let b0 = f.new_block_id();
        let b1 = f.new_block_id();
        assert_eq!(b0, BlockId(0));
        assert_eq!(b1, BlockId(1));
    }

    #[test]
    fn function_block_lookup() {
        let mut f = Function::new("test".into(), 0x1000);
        f.blocks.push(BasicBlock {
            id: BlockId(0),
            addr: 0x1000,
            stmts: vec![],
            terminator: Terminator::Return(None),
        });
        f.blocks.push(BasicBlock {
            id: BlockId(1),
            addr: 0x1010,
            stmts: vec![Stmt::Nop],
            terminator: Terminator::Jump(BlockId(0)),
        });

        assert!(f.block(BlockId(0)).is_some());
        assert!(f.block(BlockId(1)).is_some());
        assert!(f.block(BlockId(99)).is_none());
    }

    #[test]
    fn function_successors_and_predecessors() {
        let mut f = Function::new("test".into(), 0x1000);
        let cond = Expr::cmp(CondCode::Eq, Expr::const_val(0, BitWidth::Bit32), Expr::const_val(0, BitWidth::Bit32));
        f.blocks.push(BasicBlock {
            id: BlockId(0),
            addr: 0x1000,
            stmts: vec![],
            terminator: Terminator::Branch(cond, BlockId(1), BlockId(2)),
        });
        f.blocks.push(BasicBlock {
            id: BlockId(1),
            addr: 0x1010,
            stmts: vec![],
            terminator: Terminator::Return(Some(Expr::const_val(1, BitWidth::Bit32))),
        });
        f.blocks.push(BasicBlock {
            id: BlockId(2),
            addr: 0x1020,
            stmts: vec![],
            terminator: Terminator::Return(Some(Expr::const_val(0, BitWidth::Bit32))),
        });

        let succs = f.successors(BlockId(0));
        assert_eq!(succs, vec![BlockId(1), BlockId(2)]);

        let preds = f.predecessors(BlockId(1));
        assert_eq!(preds, vec![BlockId(0)]);
    }

    // ── noreturn ──────────────────────────────────────────────

    #[test]
    fn noreturn_names() {
        assert!(is_noreturn_name("exit"));
        assert!(is_noreturn_name("abort"));
        assert!(is_noreturn_name("__assert_fail"));
        assert!(!is_noreturn_name("printf"));
        assert!(!is_noreturn_name("main"));
    }

    // ── CType ─────────────────────────────────────────────────

    #[test]
    fn ctype_to_c_str() {
        assert_eq!(CType::Int(BitWidth::Bit32, Signedness::Signed).to_c_str(), "int32_t");
        assert_eq!(CType::Int(BitWidth::Bit64, Signedness::Unsigned).to_c_str(), "uint64_t");
        assert_eq!(CType::Bool.to_c_str(), "bool");
        assert_eq!(CType::Void.to_c_str(), "void");
        assert_eq!(CType::Char.to_c_str(), "char");
        assert_eq!(CType::Ptr(Box::new(CType::Int(BitWidth::Bit32, Signedness::Signed))).to_c_str(), "void*");
        assert_eq!(CType::Unknown.to_c_str(), "uint64_t");
    }

    // ── Switch terminator ─────────────────────────────────────

    #[test]
    fn terminator_switch_display() {
        let sw = Terminator::Switch(
            Expr::var(Var::Reg(RegId::Rax, BitWidth::Bit64)),
            vec![(0, BlockId(1)), (1, BlockId(2)), (2, BlockId(3))],
            Some(BlockId(4)),
        );
        assert_eq!(format!("{sw}"), "switch rax [0 => bb1, 1 => bb2, 2 => bb3, default => bb4]");
    }
}
