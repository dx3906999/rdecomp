use std::fmt;

/// Well-known functions that never return.
pub const NORETURN_NAMES: &[&str] = &["exit", "_exit", "abort", "_Exit", "__assert_fail", "__stack_chk_fail"];

/// Check if a function name is a known noreturn function.
pub fn is_noreturn_name(name: &str) -> bool {
    NORETURN_NAMES.contains(&name)
}

/// Bit width for values and operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        };
        write!(f, "{s}")
    }
}

/// CPU flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Ult | Self::Slt => "<",
            Self::Ule | Self::Sle => "<=",
        };
        write!(f, "{s}")
    }
}

/// Unary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
        }
    }
}

/// Condition codes for branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub enum Terminator {
    /// Unconditional jump to a block.
    Jump(BlockId),
    /// Conditional branch: if cond goto true_block else goto false_block.
    Branch(Expr, BlockId, BlockId),
    /// Return from function with optional value.
    Return(Option<Expr>),
    /// Indirect jump (switch/computed goto).
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
            Self::IndirectJump(target) => write!(f, "goto *{target}"),
            Self::Unreachable => write!(f, "unreachable"),
        }
    }
}

/// Block identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockId(pub u32);

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

/// Calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConv {
    /// System V AMD64 ABI (Linux/macOS): rdi, rsi, rdx, rcx, r8, r9.
    SystemV,
    /// Microsoft x64: rcx, rdx, r8, r9.
    Win64,
}

impl CallingConv {
    /// Get parameter registers in order.
    pub fn param_regs(&self) -> &[RegId] {
        match self {
            Self::SystemV => &[RegId::Rdi, RegId::Rsi, RegId::Rdx, RegId::Rcx, RegId::R8, RegId::R9],
            Self::Win64 => &[RegId::Rcx, RegId::Rdx, RegId::R8, RegId::R9],
        }
    }

    /// Get callee-saved registers.
    pub fn callee_saved(&self) -> &[RegId] {
        match self {
            Self::SystemV => &[RegId::Rbx, RegId::Rbp, RegId::R12, RegId::R13, RegId::R14, RegId::R15],
            Self::Win64 => &[RegId::Rbx, RegId::Rbp, RegId::Rdi, RegId::Rsi, RegId::R12, RegId::R13, RegId::R14, RegId::R15],
        }
    }
}

/// A basic block in the IR.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
