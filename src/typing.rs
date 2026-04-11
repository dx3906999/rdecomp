use crate::ir::*;
use std::collections::HashMap;

/// Run type inference on a function.
///
/// Populates `func.var_types` with inferred `CType` for each variable key,
/// and `func.return_type` with the inferred return type.
pub fn infer_types(func: &mut Function) {
    let mut types: HashMap<String, CType> = HashMap::new();

    // Pass 1: Collect constraints from operations
    for block in &func.blocks {
        for stmt in &block.stmts {
            collect_stmt_constraints(stmt, &mut types);
        }
        collect_terminator_constraints(&block.terminator, &mut types);
    }

    // Pass 2: Propagate through assignments (var = expr → var gets expr's type)
    for block in &func.blocks {
        for stmt in &block.stmts {
            if let Stmt::Assign(var, expr) = stmt {
                let key = var_key(var);
                if !types.contains_key(&key) {
                    if let Some(ty) = expr_type(expr, &types) {
                        types.insert(key, ty);
                    }
                }
            }
        }
    }

    // Pass 3: Fill remaining variables from their BitWidth
    for block in &func.blocks {
        for stmt in &block.stmts {
            let var = match stmt {
                Stmt::Assign(v, _) => Some(v),
                Stmt::Call(Some(v), _, _) => Some(v),
                _ => None,
            };
            if let Some(v) = var {
                let key = var_key(v);
                types.entry(key).or_insert_with(|| {
                    CType::Int(v.width(), Signedness::Unknown)
                });
            }
        }
    }

    // Infer return type
    func.return_type = infer_return_type(func, &types);
    func.var_types = types;
}

/// Collect type constraints from a single statement.
fn collect_stmt_constraints(stmt: &Stmt, types: &mut HashMap<String, CType>) {
    match stmt {
        Stmt::Assign(var, expr) => {
            let key = var_key(var);
            // Signed division/modulo → operands are signed
            if let Some(sign) = expr_signedness(expr) {
                let width = var.width();
                types.entry(key).or_insert(CType::Int(width, sign));
            }
            // Comparison results are boolean
            if matches!(expr, Expr::Cmp(..) | Expr::Cond(_)) {
                types.insert(var_key(var), CType::Bool);
            }
            // Collect constraints from sub-expressions
            collect_expr_constraints(expr, types);
        }
        Stmt::Store(addr, val, _) => {
            collect_expr_constraints(addr, types);
            collect_expr_constraints(val, types);
            // Address expression used in Store → pointer-like
            mark_pointer_operands(addr, types);
        }
        Stmt::Call(_, _, args) => {
            for arg in args {
                collect_expr_constraints(arg, types);
            }
        }
        Stmt::Nop => {}
    }
}

/// Collect type constraints from a terminator.
fn collect_terminator_constraints(term: &Terminator, types: &mut HashMap<String, CType>) {
    match term {
        Terminator::Branch(cond, _, _) => {
            collect_expr_constraints(cond, types);
        }
        Terminator::Return(Some(val)) => {
            collect_expr_constraints(val, types);
        }
        Terminator::Switch(val, _, _) => {
            collect_expr_constraints(val, types);
        }
        _ => {}
    }
}

/// Recursively collect constraints from an expression.
fn collect_expr_constraints(expr: &Expr, types: &mut HashMap<String, CType>) {
    match expr {
        Expr::BinOp(op, lhs, rhs) => {
            // Signed operations → operands are signed
            if matches!(op, BinOp::SDiv | BinOp::SMod | BinOp::Slt | BinOp::Sle | BinOp::Sar) {
                mark_expr_signed(lhs, types);
                mark_expr_signed(rhs, types);
            }
            // Unsigned operations → operands are unsigned
            if matches!(op, BinOp::UDiv | BinOp::UMod | BinOp::Ult | BinOp::Ule | BinOp::Shr) {
                mark_expr_unsigned(lhs, types);
                mark_expr_unsigned(rhs, types);
            }
            collect_expr_constraints(lhs, types);
            collect_expr_constraints(rhs, types);
        }
        Expr::UnaryOp(op, inner) => {
            if matches!(op, UnaryOp::SignExt(_)) {
                mark_expr_signed(inner, types);
            }
            if matches!(op, UnaryOp::ZeroExt(_)) {
                mark_expr_unsigned(inner, types);
            }
            collect_expr_constraints(inner, types);
        }
        Expr::Load(addr, _) => {
            collect_expr_constraints(addr, types);
            mark_pointer_operands(addr, types);
        }
        Expr::Cmp(cc, lhs, rhs) => {
            // Signed comparison → signed operands
            if matches!(cc, CondCode::Lt | CondCode::Le | CondCode::Gt | CondCode::Ge | CondCode::Sign | CondCode::NotSign) {
                mark_expr_signed(lhs, types);
                mark_expr_signed(rhs, types);
            }
            // Unsigned comparison → unsigned operands
            if matches!(cc, CondCode::Below | CondCode::BelowEq | CondCode::Above | CondCode::AboveEq) {
                mark_expr_unsigned(lhs, types);
                mark_expr_unsigned(rhs, types);
            }
            collect_expr_constraints(lhs, types);
            collect_expr_constraints(rhs, types);
        }
        _ => {}
    }
}

/// Mark a variable expression as signed.
fn mark_expr_signed(expr: &Expr, types: &mut HashMap<String, CType>) {
    if let Expr::Var(v) = expr {
        let key = var_key(v);
        let width = v.width();
        types.entry(key)
            .and_modify(|t| {
                if let CType::Int(w, Signedness::Unknown) = t {
                    *t = CType::Int(*w, Signedness::Signed);
                }
            })
            .or_insert(CType::Int(width, Signedness::Signed));
    }
}

/// Mark a variable expression as unsigned.
fn mark_expr_unsigned(expr: &Expr, types: &mut HashMap<String, CType>) {
    if let Expr::Var(v) = expr {
        let key = var_key(v);
        let width = v.width();
        types.entry(key)
            .and_modify(|t| {
                if let CType::Int(w, Signedness::Unknown) = t {
                    *t = CType::Int(*w, Signedness::Unsigned);
                }
            })
            .or_insert(CType::Int(width, Signedness::Unsigned));
    }
}

/// If an address expression is a simple variable, mark it as pointer-like.
fn mark_pointer_operands(addr: &Expr, types: &mut HashMap<String, CType>) {
    if let Expr::Var(v) = addr {
        // Only mark non-stack, non-rbp registers as pointers
        match v {
            Var::Reg(RegId::Rbp, _) | Var::Reg(RegId::Rsp, _) => {}
            Var::Stack(_, _) => {}
            _ => {
                let key = var_key(v);
                types.entry(key).or_insert(CType::Ptr(Box::new(CType::Unknown)));
            }
        }
    }
}

/// Determine signedness from an expression's operation.
fn expr_signedness(expr: &Expr) -> Option<Signedness> {
    match expr {
        Expr::BinOp(op, _, _) => match op {
            BinOp::SDiv | BinOp::SMod | BinOp::Slt | BinOp::Sle | BinOp::Sar => {
                Some(Signedness::Signed)
            }
            BinOp::UDiv | BinOp::UMod | BinOp::Ult | BinOp::Ule | BinOp::Shr => {
                Some(Signedness::Unsigned)
            }
            _ => None,
        },
        Expr::UnaryOp(UnaryOp::SignExt(_), _) => Some(Signedness::Signed),
        Expr::UnaryOp(UnaryOp::ZeroExt(_), _) => Some(Signedness::Unsigned),
        Expr::Cmp(cc, _, _) => match cc {
            CondCode::Lt | CondCode::Le | CondCode::Gt | CondCode::Ge
            | CondCode::Sign | CondCode::NotSign => Some(Signedness::Signed),
            CondCode::Below | CondCode::BelowEq | CondCode::Above
            | CondCode::AboveEq => Some(Signedness::Unsigned),
            _ => None,
        },
        _ => None,
    }
}

/// Try to infer a CType from an expression and existing type map.
fn expr_type(expr: &Expr, types: &HashMap<String, CType>) -> Option<CType> {
    match expr {
        Expr::Var(v) => types.get(&var_key(v)).cloned(),
        Expr::Const(_, w) => Some(CType::Int(*w, Signedness::Unknown)),
        Expr::BinOp(op, _, _) => {
            let sign = match op {
                BinOp::SDiv | BinOp::SMod | BinOp::Slt | BinOp::Sle => Signedness::Signed,
                BinOp::UDiv | BinOp::UMod | BinOp::Ult | BinOp::Ule => Signedness::Unsigned,
                _ => Signedness::Unknown,
            };
            Some(CType::Int(expr.width(), sign))
        }
        Expr::Cmp(..) | Expr::Cond(_) => Some(CType::Bool),
        Expr::Load(_, w) => Some(CType::Int(*w, Signedness::Unknown)),
        Expr::UnaryOp(UnaryOp::SignExt(w), _) => Some(CType::Int(*w, Signedness::Signed)),
        Expr::UnaryOp(UnaryOp::ZeroExt(w), _) => Some(CType::Int(*w, Signedness::Unsigned)),
        Expr::UnaryOp(UnaryOp::Trunc(w), _) => Some(CType::Int(*w, Signedness::Unknown)),
        Expr::UnaryOp(UnaryOp::Neg, inner) => {
            Some(CType::Int(inner.width(), Signedness::Signed))
        }
        Expr::UnaryOp(UnaryOp::Not, inner) => {
            Some(CType::Int(inner.width(), Signedness::Unknown))
        }
        Expr::UnaryOp(UnaryOp::AddrOf, _) => {
            Some(CType::Ptr(Box::new(CType::Unknown)))
        }
        Expr::LogicalAnd(..) | Expr::LogicalOr(..) => Some(CType::Bool),
    }
}

/// Infer the function return type from Return terminators.
fn infer_return_type(func: &Function, types: &HashMap<String, CType>) -> CType {
    let mut has_return_val = false;
    let mut inferred: Option<CType> = None;

    for block in &func.blocks {
        if let Terminator::Return(Some(val)) = &block.terminator {
            has_return_val = true;
            let ty = match val {
                // return rax → check what was assigned to rax
                Expr::Var(Var::Reg(RegId::Rax, _)) => {
                    // Look backwards for last assignment to rax in the block
                    find_rax_source_type(block, types)
                }
                Expr::Var(v) => types.get(&var_key(v)).cloned(),
                _ => expr_type(val, types),
            };
            if let Some(ty) = ty {
                inferred = Some(merge_return_types(inferred, ty));
            }
        }
    }

    if !has_return_val {
        return CType::Void;
    }

    inferred.unwrap_or(if func.calling_conv.is_32bit() {
        CType::Int(BitWidth::Bit32, Signedness::Unknown)
    } else {
        CType::Int(BitWidth::Bit64, Signedness::Unknown)
    })
}

/// Look backwards in a block for the source of RAX to determine return type.
fn find_rax_source_type(block: &BasicBlock, types: &HashMap<String, CType>) -> Option<CType> {
    for stmt in block.stmts.iter().rev() {
        match stmt {
            Stmt::Assign(Var::Reg(RegId::Rax, _), expr) => {
                return expr_type(expr, types);
            }
            Stmt::Call(Some(Var::Reg(RegId::Rax, _)), _, _) => {
                // Call result → default int
                return Some(CType::Int(BitWidth::Bit32, Signedness::Signed));
            }
            _ => {}
        }
    }
    None
}

/// Merge two return types, preferring the more specific one.
fn merge_return_types(existing: Option<CType>, new: CType) -> CType {
    let Some(old) = existing else { return new; };

    // If widths differ, use the wider one
    match (&old, &new) {
        (CType::Int(w1, s1), CType::Int(w2, s2)) => {
            let width = if *w1 >= *w2 { *w1 } else { *w2 };
            let sign = match (s1, s2) {
                (Signedness::Signed, _) | (_, Signedness::Signed) => Signedness::Signed,
                (Signedness::Unsigned, _) | (_, Signedness::Unsigned) => Signedness::Unsigned,
                _ => Signedness::Unknown,
            };
            CType::Int(width, sign)
        }
        (CType::Void, _) => new,
        _ => old,
    }
}

/// Get the string key for a variable (matching codegen's naming).
fn var_key(v: &Var) -> String {
    match v {
        Var::Reg(r, _) => format!("{r}"),
        Var::Stack(off, _) => {
            if *off >= 0 {
                format!("arg_{off:x}")
            } else {
                format!("var_{:x}", off.unsigned_abs())
            }
        }
        Var::Temp(id, _) => format!("t{id}"),
        Var::Flag(f) => format!("{f}"),
    }
}
