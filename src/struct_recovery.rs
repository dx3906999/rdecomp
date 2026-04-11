//! Struct field access recovery.
//!
//! Analyses IR Load/Store patterns to detect struct pointer dereferences.
//!
//! The key pattern is: a stack variable holds a pointer (loaded from rbp±offset),
//! and that pointer is then used as the base address for field accesses at
//! multiple distinct offsets.
//!
//! IR pattern for `p->field`:
//!   Load(Load(rbp - 8, 64), 32)         — field at offset 0
//!   Load(BinOp(Add, Load(rbp-8, 64), Const(4)), 32) — field at offset 4
//!
//! If a stack offset has ≥ 2 field accesses at different offsets, we infer
//! a struct layout and map it to the stack variable name.

use crate::ir::*;
use std::collections::{BTreeMap, HashMap};

/// A single struct field at a known offset.
#[derive(Debug, Clone)]
pub struct FieldInfo {
    /// Byte offset from struct base.
    pub offset: i64,
    /// Width of the access.
    pub width: BitWidth,
    /// Generated name, e.g. `field_0`, `field_4`.
    pub name: String,
}

/// Inferred struct layout for a pointer base.
#[derive(Debug, Clone)]
pub struct StructLayout {
    /// Ordered fields by offset.
    pub fields: Vec<FieldInfo>,
}

/// Maps a stack offset (the slot holding the pointer) to its inferred struct layout.
pub type StructMap = HashMap<i64, StructLayout>;

/// Analyse a function and infer struct layouts from pointer dereference patterns.
///
/// Scans all Load/Store addresses looking for:
///   - `Load(rbp + off, 64)` → base pointer at stack offset `off`, field offset 0
///   - `BinOp(Add, Load(rbp + off, 64), Const(field_off))` → field at `field_off`
///
/// Returns a map from stack offset → StructLayout for variables with ≥ 2 field offsets.
pub fn recover_structs(func: &Function) -> StructMap {
    // access_map: stack_offset → BTreeMap<field_offset, width>
    let mut access_map: HashMap<i64, BTreeMap<i64, BitWidth>> = HashMap::new();

    for block in &func.blocks {
        for stmt in &block.stmts {
            collect_from_stmt(stmt, &mut access_map);
        }
        collect_from_term(&block.terminator, &mut access_map);
    }

    // Build struct layouts for stack offsets with ≥ 2 distinct field offsets.
    let mut result = HashMap::new();
    for (stack_off, field_offsets) in &access_map {
        if field_offsets.len() < 2 {
            continue;
        }
        let fields: Vec<FieldInfo> = field_offsets
            .iter()
            .map(|(&offset, &width)| FieldInfo {
                offset,
                width,
                name: format!("field_{:x}", offset as u64),
            })
            .collect();
        result.insert(*stack_off, StructLayout { fields });
    }

    result
}

/// Extract the rbp-relative stack offset from an expression.
/// Recognises `BinOp(Add/Sub, Rbp, Const)` patterns.
fn extract_rbp_offset(expr: &Expr) -> Option<i64> {
    match expr {
        // rbp + const
        Expr::BinOp(BinOp::Add, lhs, rhs) => {
            if matches!(lhs.as_ref(), Expr::Var(Var::Reg(RegId::Rbp, _))) {
                if let Expr::Const(c, _) = rhs.as_ref() {
                    return Some(*c as i64);
                }
            }
            if matches!(rhs.as_ref(), Expr::Var(Var::Reg(RegId::Rbp, _))) {
                if let Expr::Const(c, _) = lhs.as_ref() {
                    return Some(*c as i64);
                }
            }
            None
        }
        // rbp - const → negative offset
        Expr::BinOp(BinOp::Sub, lhs, rhs) => {
            if matches!(lhs.as_ref(), Expr::Var(Var::Reg(RegId::Rbp, _))) {
                if let Expr::Const(c, _) = rhs.as_ref() {
                    return Some(-(*c as i64));
                }
            }
            None
        }
        _ => None,
    }
}

/// Check if expr is `Load(rbp ± const, 64)` — loading a pointer from the stack.
/// Also accepts `Var::Stack(off, Bit64)` after stack variable recovery.
/// Returns the stack offset if matched.
fn is_stack_ptr_load(expr: &Expr) -> Option<i64> {
    // Post-optimization: Var::Stack(off, 64)
    if let Expr::Var(Var::Stack(off, BitWidth::Bit64)) = expr {
        return Some(*off);
    }
    // Pre-optimization: Load(rbp ± const, 64)
    if let Expr::Load(addr, BitWidth::Bit64) = expr {
        return extract_rbp_offset(addr);
    }
    None
}

/// Extract (stack_offset_of_ptr, field_offset) from an address expression.
///
/// Patterns:
///   - `Load(rbp+X, 64)` or `Var::Stack(X, 64)` → (X, 0)
///   - `BinOp(Add, Load(rbp+X, 64), Const(F))` → (X, F)
///   - `BinOp(Add, Const(F), Load(rbp+X, 64))` → (X, F)
fn extract_struct_access(addr: &Expr) -> Option<(i64, i64)> {
    // Direct: ptr → field at offset 0
    if let Some(stack_off) = is_stack_ptr_load(addr) {
        return Some((stack_off, 0));
    }

    // ptr + const_field_offset
    if let Expr::BinOp(BinOp::Add, lhs, rhs) = addr {
        if let Some(stack_off) = is_stack_ptr_load(lhs) {
            if let Expr::Const(field_off, _) = rhs.as_ref() {
                return Some((stack_off, *field_off as i64));
            }
        }
        if let Some(stack_off) = is_stack_ptr_load(rhs) {
            if let Expr::Const(field_off, _) = lhs.as_ref() {
                return Some((stack_off, *field_off as i64));
            }
        }
    }

    None
}

/// Record struct field accesses from expressions (recursively).
fn collect_from_expr(
    expr: &Expr,
    access_map: &mut HashMap<i64, BTreeMap<i64, BitWidth>>,
) {
    match expr {
        Expr::Load(addr, width) => {
            if let Some((stack_off, field_off)) = extract_struct_access(addr) {
                access_map
                    .entry(stack_off)
                    .or_default()
                    .entry(field_off)
                    .or_insert(*width);
            }
            collect_from_expr(addr, access_map);
        }
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs) => {
            collect_from_expr(lhs, access_map);
            collect_from_expr(rhs, access_map);
        }
        Expr::UnaryOp(_, inner) => {
            collect_from_expr(inner, access_map);
        }
        _ => {}
    }
}

/// Record struct accesses from a statement.
fn collect_from_stmt(
    stmt: &Stmt,
    access_map: &mut HashMap<i64, BTreeMap<i64, BitWidth>>,
) {
    match stmt {
        Stmt::Assign(_, expr) => {
            collect_from_expr(expr, access_map);
        }
        Stmt::Store(addr, val, width) => {
            if let Some((stack_off, field_off)) = extract_struct_access(addr) {
                access_map
                    .entry(stack_off)
                    .or_default()
                    .entry(field_off)
                    .or_insert(*width);
            }
            collect_from_expr(addr, access_map);
            collect_from_expr(val, access_map);
        }
        Stmt::Call(_, target, args) => {
            collect_from_expr(target, access_map);
            for arg in args {
                collect_from_expr(arg, access_map);
            }
        }
        Stmt::Nop => {}
    }
}

/// Record accesses from a terminator.
fn collect_from_term(
    term: &Terminator,
    access_map: &mut HashMap<i64, BTreeMap<i64, BitWidth>>,
) {
    match term {
        Terminator::Branch(cond, _, _) => {
            collect_from_expr(cond, access_map);
        }
        Terminator::Return(Some(val)) => {
            collect_from_expr(val, access_map);
        }
        Terminator::Switch(val, _, _) => {
            collect_from_expr(val, access_map);
        }
        _ => {}
    }
}
