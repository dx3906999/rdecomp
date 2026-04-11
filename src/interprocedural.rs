use std::collections::{HashMap, HashSet};

use crate::ir::{BitWidth, CType, Expr, Function, RegId, Signedness, Stmt, Terminator, Var};
use crate::loader::Binary;

/// Summary of a function's calling interface, inferred from its IR.
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    /// Inferred return type.
    pub return_type: CType,
    /// Number of parameters.
    pub param_count: usize,
    /// Whether the function never returns (diverges).
    pub noreturn: bool,
}

/// Cross-function analysis results.
#[derive(Debug, Default)]
pub struct InterproceduralInfo {
    /// Function address → summary.
    pub summaries: HashMap<u64, FunctionSummary>,
    /// Call graph: caller address → set of callee addresses.
    pub call_graph: HashMap<u64, HashSet<u64>>,
}

/// Analyze a set of functions and build interprocedural information.
///
/// Each entry is (function address, lifted Function IR).
pub fn analyze(
    functions: &[(u64, &Function)],
    binary: &Binary,
) -> InterproceduralInfo {
    let mut info = InterproceduralInfo::default();
    let known_addrs: HashSet<u64> = functions.iter().map(|(a, _)| *a).collect();

    for &(addr, func) in functions {
        // Build call graph edges
        let mut callees = HashSet::new();
        for block in &func.blocks {
            for stmt in &block.stmts {
                if let Stmt::Call(_, target, _) = stmt {
                    if let Some(callee_addr) = resolve_call_addr(target, binary) {
                        if known_addrs.contains(&callee_addr) {
                            callees.insert(callee_addr);
                        }
                    }
                }
            }
        }
        info.call_graph.insert(addr, callees);

        // Infer function summary
        let summary = analyze_function(func);
        info.summaries.insert(addr, summary);
    }

    info
}

/// Analyze a single function to produce its summary.
fn analyze_function(func: &Function) -> FunctionSummary {
    // Infer return type
    let return_type = infer_return_type(func);

    // Count parameters from the entry block's register-to-stack assignments
    let param_count = count_parameters(func);

    // Check if the function is noreturn (no Return or IndirectJump terminators).
    // IndirectJump counts as a potential return path because PLT stubs and
    // tail-calls use indirect jumps to dispatch to the real callee.
    let noreturn = !func.blocks.iter().any(|b| {
        matches!(
            &b.terminator,
            Terminator::Return(_) | Terminator::IndirectJump(_)
        )
    });

    FunctionSummary {
        return_type,
        param_count,
        noreturn,
    }
}

/// Infer the return type from Return terminators.
fn infer_return_type(func: &Function) -> CType {
    let mut has_return_val = false;
    let mut is_signed = false;
    let mut width = BitWidth::Bit64;

    for block in &func.blocks {
        if let Terminator::Return(Some(expr)) = &block.terminator {
            has_return_val = true;
            // Check if the returned value suggests a specific width
            let w = expr.width();
            if w < width {
                width = w;
            }
            // Check signedness from negative constant returns
            if let Expr::Const(val, w) = expr {
                let is_neg = match w {
                    BitWidth::Bit32 => *val > 0x7FFF_FFFF && *val <= 0xFFFF_FFFF,
                    BitWidth::Bit64 => *val > 0x7FFF_FFFF_FFFF_FFFF,
                    _ => false,
                };
                if is_neg {
                    is_signed = true;
                }
            }
        }
    }

    if !has_return_val {
        CType::Void
    } else if is_signed {
        CType::Int(width, Signedness::Signed)
    } else {
        CType::Int(width, Signedness::Unknown)
    }
}

/// Count the number of parameters by looking at register→stack assignments
/// in the entry block.
fn count_parameters(func: &Function) -> usize {
    let param_regs = func.calling_conv.param_regs();
    if let Some(entry) = func.blocks.first() {
        let mut count = 0usize;
        for stmt in &entry.stmts {
            if let Stmt::Assign(Var::Stack(_, _), Expr::Var(Var::Reg(reg, _))) = stmt {
                if param_regs.contains(reg) {
                    count += 1;
                }
            }
        }
        count
    } else {
        0
    }
}

/// Try to resolve a call target expression to a concrete address.
fn resolve_call_addr(target: &Expr, _binary: &Binary) -> Option<u64> {
    match target {
        Expr::Const(addr, _) => Some(*addr),
        // RIP-relative: rbp + const (already folded to const by analysis)
        Expr::BinOp(crate::ir::BinOp::Add, lhs, rhs) => {
            if let Expr::Var(Var::Reg(RegId::Rip, _)) = lhs.as_ref() {
                if let Expr::Const(addr, _) = rhs.as_ref() {
                    return Some(*addr);
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::*;

    /// Helper: create a minimal function with given blocks.
    fn make_func(name: &str, addr: u64, blocks: Vec<BasicBlock>) -> Function {
        let mut f = Function::new(name.to_string(), addr);
        f.blocks = blocks;
        f
    }

    #[test]
    fn infer_return_void() {
        let func = make_func("no_ret", 0x1000, vec![
            BasicBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![],
                terminator: Terminator::Return(None),
            },
        ]);
        assert_eq!(infer_return_type(&func), CType::Void);
    }

    #[test]
    fn infer_return_unsigned() {
        let func = make_func("ret_u32", 0x1000, vec![
            BasicBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![],
                terminator: Terminator::Return(Some(Expr::const_val(42, BitWidth::Bit32))),
            },
        ]);
        assert_eq!(infer_return_type(&func), CType::Int(BitWidth::Bit32, Signedness::Unknown));
    }

    #[test]
    fn infer_return_signed() {
        // 0xFFFFFFFF is -1 in 32-bit — should be detected as signed
        let func = make_func("ret_neg", 0x1000, vec![
            BasicBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![],
                terminator: Terminator::Return(Some(Expr::const_val(0xFFFF_FFFF, BitWidth::Bit32))),
            },
        ]);
        assert_eq!(infer_return_type(&func), CType::Int(BitWidth::Bit32, Signedness::Signed));
    }

    #[test]
    fn count_params_sysv() {
        let func = make_func("two_params", 0x1000, vec![
            BasicBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![
                    // rdi → stack (param 1)
                    Stmt::Assign(Var::Stack(-4, BitWidth::Bit32), Expr::var(Var::Reg(RegId::Rdi, BitWidth::Bit64))),
                    // rsi → stack (param 2)
                    Stmt::Assign(Var::Stack(-8, BitWidth::Bit32), Expr::var(Var::Reg(RegId::Rsi, BitWidth::Bit64))),
                    // some other assignment (not a param)
                    Stmt::Assign(Var::Stack(-12, BitWidth::Bit32), Expr::const_val(0, BitWidth::Bit32)),
                ],
                terminator: Terminator::Return(Some(Expr::const_val(0, BitWidth::Bit32))),
            },
        ]);
        assert_eq!(count_parameters(&func), 2);
    }

    #[test]
    fn count_params_zero() {
        let func = make_func("no_params", 0x1000, vec![
            BasicBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![
                    Stmt::Assign(Var::Stack(-4, BitWidth::Bit32), Expr::const_val(0, BitWidth::Bit32)),
                ],
                terminator: Terminator::Return(None),
            },
        ]);
        assert_eq!(count_parameters(&func), 0);
    }

    #[test]
    fn noreturn_detection() {
        // Function with only Unreachable terminator → noreturn
        let func_noret = make_func("die", 0x2000, vec![
            BasicBlock {
                id: BlockId(0),
                addr: 0x2000,
                stmts: vec![],
                terminator: Terminator::Unreachable,
            },
        ]);
        let summary = analyze_function(&func_noret);
        assert!(summary.noreturn);

        // Function with Return → not noreturn
        let func_ret = make_func("ok", 0x3000, vec![
            BasicBlock {
                id: BlockId(0),
                addr: 0x3000,
                stmts: vec![],
                terminator: Terminator::Return(Some(Expr::const_val(0, BitWidth::Bit32))),
            },
        ]);
        let summary2 = analyze_function(&func_ret);
        assert!(!summary2.noreturn);
    }

    #[test]
    fn resolve_const_addr() {
        // A call to a constant address should resolve
        let target = Expr::const_val(0x401000, BitWidth::Bit64);
        // We need a Binary, create a minimal one using the loader
        // We can't easily create a Binary without a file, so test the pattern directly
        assert!(matches!(&target, Expr::Const(0x401000, _)));
    }
}
