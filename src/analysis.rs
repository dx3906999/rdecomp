use crate::ir::*;
use std::collections::{HashMap, HashSet};

/// Sentinel address for fs:0x28 (stack canary).
/// lift_memory_operand maps `fs:disp` to `0xFFFF_FFFF_FFFF_E000 + disp`.
const FS_CANARY_ADDR: u64 = 0xFFFF_FFFF_FFFF_E000u64.wrapping_add(0x28);

// ── Entry point ──────────────────────────────────────────────────

/// Run all optimization passes on a function.
pub fn optimize(func: &mut Function, noreturn_addrs: &HashSet<u64>) {
    // First, eliminate dead code after noreturn calls (changes CFG edges)
    noreturn_elimination(func, noreturn_addrs);

    // Early: eliminate stack canary boilerplate before other passes
    eliminate_stack_canary(func);

    // Run passes iteratively until no more changes
    for _ in 0..10 {
        let mut changed = false;
        changed |= constant_fold(func);
        changed |= dead_nop_elimination(func);
        changed |= copy_propagation(func);
        changed |= expression_inlining(func);
        changed |= dead_store_elimination(func);
        changed |= local_dead_store_elimination(func);
        changed |= stack_variable_recovery(func);
        changed |= absorb_call_args(func);
        changed |= absorb_call_result(func);
        changed |= propagate_call_results(func);
        changed |= trim_call_args(func);
        changed |= eliminate_unused_call_results(func);
        if !changed {
            break;
        }
    }
    // Cross-block register propagation (run multiple times for chains)
    for _ in 0..5 {
        cross_block_propagation(func);
    }

    // Late passes
    substitute_param_regs(func);
    eliminate_self_assignments(func);
    promote_callee_saved_to_locals(func);
    fold_zero_init_buffers(func);
    simplify_void_returns(func);
}

// ── Noreturn elimination ──────────────────────────────────────────

/// Remove dead code after calls to noreturn functions (exit, abort, etc.).
/// Truncates statements after the noreturn call and changes the block terminator to Unreachable.
fn noreturn_elimination(func: &mut Function, noreturn_addrs: &HashSet<u64>) {
    for block in &mut func.blocks {
        let mut noreturn_idx = None;
        for (i, stmt) in block.stmts.iter().enumerate() {
            if let Stmt::Call(_, target, _) = stmt {
                let is_noreturn = match target {
                    Expr::Const(addr, _) => noreturn_addrs.contains(addr),
                    _ => false,
                };
                if is_noreturn {
                    noreturn_idx = Some(i);
                    break;
                }
            }
        }
        if let Some(idx) = noreturn_idx {
            block.stmts.truncate(idx + 1);
            block.terminator = Terminator::Unreachable;
        }
    }

    // Remove blocks that are now unreachable (no predecessors, except entry)
    if func.blocks.len() > 1 {
        let entry = func.blocks[0].id;
        let mut reachable: HashSet<BlockId> = HashSet::new();
        let mut worklist = vec![entry];
        while let Some(bid) = worklist.pop() {
            if !reachable.insert(bid) {
                continue;
            }
            if let Some(block) = func.blocks.iter().find(|b| b.id == bid) {
                match &block.terminator {
                    Terminator::Jump(t) => worklist.push(*t),
                    Terminator::Branch(_, t, f) => {
                        worklist.push(*t);
                        worklist.push(*f);
                    }
                    _ => {}
                }
            }
        }
        func.blocks.retain(|b| reachable.contains(&b.id));
    }
}

// ── Stack canary elimination ─────────────────────────────────────

/// Remove stack canary boilerplate: `var_8 = *(u64*)(fs:0x28)`, the XOR check,
/// `__stack_chk_fail` call, and the guarding branch.
fn eliminate_stack_canary(func: &mut Function) {
    // Step 1: Find the canary stack variable.
    // Pattern: `reg = Load(FS_CANARY_ADDR)` then `var_N = reg`.
    // Find the register that carries the canary, then the stack var it's stored into.
    let mut canary_reg: Option<String> = None;
    let mut canary_stack_key: Option<String> = None;
    let mut canary_stack_off: Option<i64> = None;

    'outer: for block in &func.blocks {
        for stmt in &block.stmts {
            if let Stmt::Assign(var, expr) = stmt {
                if expr_references_canary(expr) {
                    canary_reg = Some(format!("{var}"));
                }
                // If we found the register carrying the canary, look for var_N = reg
                if let Some(ref reg_key) = canary_reg {
                    if let Var::Stack(off, _) = var {
                        if let Expr::Var(src_var) = expr {
                            if format!("{src_var}") == *reg_key {
                                canary_stack_key = Some(format!("{var}"));
                                canary_stack_off = Some(*off);
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }
    }

    let Some(canary_key) = canary_stack_key else { return };
    let canary_reg_key = canary_reg.unwrap();
    let canary_off = canary_stack_off.unwrap();

    // Pre-collect: which blocks have Unreachable terminator (from noreturn_elimination)
    let unreachable_blocks: HashSet<BlockId> = func.blocks.iter()
        .filter(|b| matches!(b.terminator, Terminator::Unreachable))
        .map(|b| b.id)
        .collect();

    // Step 2 + 3: Remove canary statements and simplify guarding branches
    for block in &mut func.blocks {
        block.stmts.retain(|s| {
            match s {
                Stmt::Assign(var, expr) => {
                    let key = format!("{var}");
                    // Remove `var_8 = rax` (canary stored to stack)
                    if key == canary_key { return false; }
                    // Remove `rax = Load(fs:0x28)` (canary load into register)
                    if key == canary_reg_key && expr_references_canary(expr) {
                        return false;
                    }
                    // Remove canary readback: `rax = Load(rbp + canary_off)`
                    if let Expr::Load(addr, _) = expr {
                        if let Some(off) = extract_stack_offset(addr) {
                            if off == canary_off {
                                return false;
                            }
                        }
                    }
                    // Remove XOR results involving canary stack var or sentinel
                    if expr_references_canary(expr) || expr_uses_var_key(expr, &canary_key) {
                        return false;
                    }
                    true
                }
                _ => true,
            }
        });

        // Simplify canary-guarding branches: the fail side leads to an Unreachable block
        if let Terminator::Branch(cond, t, f) = &block.terminator {
            if expr_references_canary(cond) || expr_uses_var_key(cond, &canary_key) {
                let target = if unreachable_blocks.contains(f) { *t } else { *f };
                block.terminator = Terminator::Jump(target);
            }
        }
    }

    // Step 4: Remove blocks that became unreachable
    if func.blocks.len() > 1 {
        let entry = func.blocks[0].id;
        let mut reachable: HashSet<BlockId> = HashSet::new();
        let mut worklist = vec![entry];
        while let Some(bid) = worklist.pop() {
            if !reachable.insert(bid) { continue; }
            if let Some(block) = func.blocks.iter().find(|b| b.id == bid) {
                match &block.terminator {
                    Terminator::Jump(t) => worklist.push(*t),
                    Terminator::Branch(_, t, f) => { worklist.push(*t); worklist.push(*f); }
                    _ => {}
                }
            }
        }
        func.blocks.retain(|b| reachable.contains(&b.id));
    }
}

/// Check if an expression references the stack canary sentinel address.
fn expr_references_canary(expr: &Expr) -> bool {
    match expr {
        Expr::Const(v, _) => *v == FS_CANARY_ADDR,
        Expr::Load(addr, _) => expr_references_canary(addr),
        Expr::BinOp(_, l, r) | Expr::Cmp(_, l, r) => {
            expr_references_canary(l) || expr_references_canary(r)
        }
        Expr::UnaryOp(_, inner) => expr_references_canary(inner),
        _ => false,
    }
}

// ── Zero-init buffer folding ─────────────────────────────────────

/// Fold consecutive `var_xx = 0` assignments into a single buffer declaration.
/// Detects when the compiler inlined `memset(buf, 0, N)` as a series of 8-byte stores.
fn fold_zero_init_buffers(func: &mut Function) {
    for block in &mut func.blocks {
        let mut i = 0;
        while i < block.stmts.len() {
            // Look for a run of consecutive zero-assigned stack variables
            let run_start = i;
            let mut offsets: Vec<(i64, BitWidth)> = Vec::new();

            while i < block.stmts.len() {
                if let Stmt::Assign(Var::Stack(off, w), Expr::Const(0, _)) = &block.stmts[i] {
                    offsets.push((*off, *w));
                    i += 1;
                } else {
                    break;
                }
            }

            if offsets.len() >= 2 {
                // Check if they form a contiguous buffer
                offsets.sort_by_key(|(off, _)| *off);
                let mut contiguous = true;
                for pair in offsets.windows(2) {
                    let expected_next = pair[0].0 + pair[0].1.bytes() as i64;
                    if pair[1].0 != expected_next {
                        contiguous = false;
                        break;
                    }
                }

                if contiguous {
                    let total_bytes: u64 = offsets.iter().map(|(_, w)| w.bytes() as u64).sum();
                    let base_off = offsets[0].0;
                    // Keep first assignment as a representative, NOP the rest
                    // Assign to a buffer variable with total size annotation
                    block.stmts[run_start] = Stmt::Assign(
                        Var::Stack(base_off, BitWidth::Bit8), // Use Bit8 to signal "buffer"
                        Expr::Const(total_bytes, BitWidth::Bit64), // Store total size as marker
                    );
                    for j in (run_start + 1)..i {
                        block.stmts[j] = Stmt::Nop;
                    }
                }
            } else {
                i += 1;
            }
        }
    }
}

// ── Cross-block dataflow ─────────────────────────────────────────

/// Propagate register values across block boundaries using dataflow analysis.
/// Computes a fixpoint: each block's outgoing register state = incoming (from predecessors) + local assignments.
/// Incoming = intersection of all predecessors' outgoing values (only registers where ALL agree).
fn cross_block_propagation(func: &mut Function) {
    // For each block, compute local "gen" (registers assigned) and "kill" (registers killed by calls)
    // We store: does the block contain a call? And what are the assignments after the last call?
    struct BlockTransfer {
        /// True if block contains a Call (which clobbers all regs)
        has_call: bool,
        /// Register assignments accumulated (after the last call, if any)
        local_defs: HashMap<String, Expr>,
        // Registers defined before any call (only used if has_call is false; otherwise local_defs captures post-call)
    }

    let mut transfers: HashMap<BlockId, BlockTransfer> = HashMap::new();
    for block in &func.blocks {
        let mut has_call = false;
        let mut defs: HashMap<String, Expr> = HashMap::new();
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign(var @ Var::Reg(_, _), expr) => {
                    let k = format!("{var}");
                    if expr_uses_var_key(expr, &k) {
                        defs.remove(&k);
                    } else {
                        defs.insert(k, expr.clone());
                    }
                }
                Stmt::Call(..) => {
                    has_call = true;
                    defs.clear(); // call clobbers everything, restart
                }
                _ => {}
            }
        }
        transfers.insert(block.id, BlockTransfer { has_call, local_defs: defs });
    }

    // Iterative fixpoint: out[b] = transfer(in[b])
    // in[b] = intersection of out[p] for all predecessors p
    // out[b] = if has_call { local_defs } else { in[b] + local_defs (overwrite) }
    let mut out_regs: HashMap<BlockId, HashMap<String, Expr>> = HashMap::new();
    for block in &func.blocks {
        out_regs.insert(block.id, HashMap::new());
    }

    for _iter in 0..20 {
        let mut changed = false;
        for block in &func.blocks {
            let bid = block.id;
            let preds = func.predecessors(bid);
            let transfer = &transfers[&bid];

            // Compute incoming: intersection of predecessors' out values
            let incoming: HashMap<String, Expr> = if preds.is_empty() {
                HashMap::new()
            } else {
                let pred_outs: Vec<&HashMap<String, Expr>> = preds.iter()
                    .filter_map(|p| out_regs.get(p))
                    .collect();
                if pred_outs.is_empty() {
                    HashMap::new()
                } else if pred_outs.len() == 1 {
                    pred_outs[0].clone()
                } else {
                    let mut common: HashMap<String, Expr> = pred_outs[0].clone();
                    for other in &pred_outs[1..] {
                        common.retain(|k, v| other.get(k).is_some_and(|ov| ov == v));
                    }
                    common
                }
            };

            // Apply transfer function
            let new_out = if transfer.has_call {
                // Call clobbers everything; only post-call defs survive
                transfer.local_defs.clone()
            } else {
                // Merge incoming with local defs (local defs override)
                let mut out = incoming;
                for (k, v) in &transfer.local_defs {
                    out.insert(k.clone(), v.clone());
                }
                out
            };

            if out_regs.get(&bid) != Some(&new_out) {
                out_regs.insert(bid, new_out);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Now apply: for each block, compute its incoming state and propagate into stmts/terminators
    for i in 0..func.blocks.len() {
        let bid = func.blocks[i].id;
        let preds = func.predecessors(bid);
        if preds.is_empty() {
            continue;
        }

        let pred_outs: Vec<&HashMap<String, Expr>> = preds.iter()
            .filter_map(|p| out_regs.get(p))
            .collect();
        if pred_outs.is_empty() {
            continue;
        }

        let incoming: HashMap<String, Expr> = if pred_outs.len() == 1 {
            pred_outs[0].clone()
        } else {
            let mut common = pred_outs[0].clone();
            for other in &pred_outs[1..] {
                common.retain(|k, v| other.get(k).is_some_and(|ov| ov == v));
            }
            common
        };

        if incoming.is_empty() {
            continue;
        }

        for stmt in &mut func.blocks[i].stmts {
            match stmt {
                Stmt::Assign(_, expr) => {
                    propagate_copies(expr, &incoming);
                }
                Stmt::Store(addr, val, _) => {
                    propagate_copies(addr, &incoming);
                    propagate_copies(val, &incoming);
                }
                Stmt::Call(_, target, args) => {
                    propagate_copies(target, &incoming);
                    for a in args.iter_mut() {
                        propagate_copies(a, &incoming);
                    }
                }
                _ => {}
            }
        }
        match &mut func.blocks[i].terminator {
            Terminator::Branch(cond, _, _) => {
                propagate_copies(cond, &incoming);
            }
            Terminator::Return(Some(val)) => {
                propagate_copies(val, &incoming);
            }
            Terminator::IndirectJump(target) => {
                propagate_copies(target, &incoming);
            }
            _ => {}
        }
    }
}

// ── Constant folding ─────────────────────────────────────────────

/// Constant folding: evaluate constant expressions at compile time.
fn constant_fold(func: &mut Function) -> bool {
    let mut changed = false;

    for block in &mut func.blocks {
        for stmt in &mut block.stmts {
            match stmt {
                Stmt::Assign(_, expr) => {
                    if let Some(folded) = fold_expr(expr) {
                        *expr = folded;
                        changed = true;
                    }
                }
                Stmt::Call(_, target, args) => {
                    if let Some(folded) = fold_expr(target) {
                        *target = folded;
                        changed = true;
                    }
                    for arg in args.iter_mut() {
                        if let Some(folded) = fold_expr(arg) {
                            *arg = folded;
                            changed = true;
                        }
                    }
                }
                Stmt::Store(addr, val, _) => {
                    if let Some(folded) = fold_expr(addr) {
                        *addr = folded;
                        changed = true;
                    }
                    if let Some(folded) = fold_expr(val) {
                        *val = folded;
                        changed = true;
                    }
                }
                _ => {}
            }
        }
        // Also fold in terminators
        match &mut block.terminator {
            Terminator::Branch(cond, _, _) => {
                if let Some(folded) = fold_expr(cond) {
                    *cond = folded;
                    changed = true;
                }
            }
            Terminator::Return(Some(val)) => {
                if let Some(folded) = fold_expr(val) {
                    *val = folded;
                    changed = true;
                }
            }
            Terminator::IndirectJump(target) => {
                if let Some(folded) = fold_expr(target) {
                    *target = folded;
                    changed = true;
                }
            }
            _ => {}
        }
    }

    changed
}

fn fold_expr(expr: &Expr) -> Option<Expr> {
    // First, try to fold subexpressions recursively
    let expr = match expr {
        Expr::BinOp(op, lhs, rhs) => {
            let new_lhs = fold_expr(lhs);
            let new_rhs = fold_expr(rhs);
            if new_lhs.is_some() || new_rhs.is_some() {
                let l = new_lhs.map_or_else(|| *lhs.clone(), |e| e);
                let r = new_rhs.map_or_else(|| *rhs.clone(), |e| e);
                std::borrow::Cow::Owned(Expr::BinOp(*op, Box::new(l), Box::new(r)))
            } else {
                std::borrow::Cow::Borrowed(expr)
            }
        }
        Expr::UnaryOp(op, inner) => {
            if let Some(folded) = fold_expr(inner) {
                std::borrow::Cow::Owned(Expr::UnaryOp(*op, Box::new(folded)))
            } else {
                std::borrow::Cow::Borrowed(expr)
            }
        }
        Expr::Cmp(cc, lhs, rhs) => {
            let new_lhs = fold_expr(lhs);
            let new_rhs = fold_expr(rhs);
            if new_lhs.is_some() || new_rhs.is_some() {
                let l = new_lhs.map_or_else(|| *lhs.clone(), |e| e);
                let r = new_rhs.map_or_else(|| *rhs.clone(), |e| e);
                std::borrow::Cow::Owned(Expr::Cmp(*cc, Box::new(l), Box::new(r)))
            } else {
                std::borrow::Cow::Borrowed(expr)
            }
        }
        Expr::Load(addr, w) => {
            if let Some(folded) = fold_expr(addr) {
                std::borrow::Cow::Owned(Expr::Load(Box::new(folded), *w))
            } else {
                std::borrow::Cow::Borrowed(expr)
            }
        }
        _ => std::borrow::Cow::Borrowed(expr),
    };

    // Now try to fold the (potentially updated) expression
    let folded_top = match expr.as_ref() {
        Expr::BinOp(op, lhs, rhs) => {
            if let (Expr::Const(l, w), Expr::Const(r, _)) = (lhs.as_ref(), rhs.as_ref()) {
                let result = match op {
                    BinOp::Add => Some(l.wrapping_add(*r)),
                    BinOp::Sub => Some(l.wrapping_sub(*r)),
                    BinOp::Mul => Some(l.wrapping_mul(*r)),
                    BinOp::And => Some(l & r),
                    BinOp::Or => Some(l | r),
                    BinOp::Xor => Some(l ^ r),
                    BinOp::Shl => Some(l.wrapping_shl(*r as u32)),
                    BinOp::Shr => Some(l.wrapping_shr(*r as u32)),
                    _ => None,
                };
                if let Some(val) = result {
                    return Some(Expr::Const(val, *w));
                }
            }

            // Algebraic simplifications
            match op {
                BinOp::Add => {
                    if matches!(rhs.as_ref(), Expr::Const(0, _)) {
                        return Some(*lhs.clone());
                    }
                    if matches!(lhs.as_ref(), Expr::Const(0, _)) {
                        return Some(*rhs.clone());
                    }
                }
                BinOp::Sub => {
                    if matches!(rhs.as_ref(), Expr::Const(0, _)) {
                        return Some(*lhs.clone());
                    }
                    // Magic-number signed division pattern:
                    // Sub(Sar(Shr(Mul(SignExt(x), magic), 32), shift), Sar(x, 31))
                    // → SDiv(x, divisor)
                    if let Some(div_expr) = try_fold_magic_sdiv(lhs, rhs) {
                        return Some(div_expr);
                    }
                }
                BinOp::Mul => {
                    if matches!(rhs.as_ref(), Expr::Const(1, _)) {
                        return Some(*lhs.clone());
                    }
                    if let Expr::Const(0, w) = rhs.as_ref() {
                        return Some(Expr::Const(0, *w));
                    }
                }
                BinOp::And => {
                    if let Expr::Const(0, w) = rhs.as_ref() {
                        return Some(Expr::Const(0, *w));
                    }
                }
                BinOp::Or => {
                    if matches!(rhs.as_ref(), Expr::Const(0, _)) {
                        return Some(*lhs.clone());
                    }
                }
                _ => {}
            }

            None
        }
        Expr::UnaryOp(op, inner) => {
            if let Expr::Const(val, w) = inner.as_ref() {
                match op {
                    UnaryOp::Neg => return Some(Expr::Const((!val).wrapping_add(1), *w)),
                    UnaryOp::Not => return Some(Expr::Const(!val, *w)),
                    UnaryOp::Trunc(tw) => {
                        let mask = match tw {
                            BitWidth::Bit8 => 0xFF,
                            BitWidth::Bit16 => 0xFFFF,
                            BitWidth::Bit32 => 0xFFFF_FFFF,
                            BitWidth::Bit64 => u64::MAX,
                        };
                        return Some(Expr::Const(val & mask, *tw));
                    }
                    UnaryOp::ZeroExt(tw) => return Some(Expr::Const(*val, *tw)),
                    UnaryOp::SignExt(tw) => {
                        let sign_extended = match w {
                            BitWidth::Bit8 => *val as i8 as i64 as u64,
                            BitWidth::Bit16 => *val as i16 as i64 as u64,
                            BitWidth::Bit32 => *val as i32 as i64 as u64,
                            BitWidth::Bit64 => *val,
                        };
                        return Some(Expr::Const(sign_extended, *tw));
                    }
                    UnaryOp::AddrOf => {}
                }
            }
            // Simplify nested casts
            if let Expr::UnaryOp(inner_op, inner_inner) = inner.as_ref() {
                match (op, inner_op) {
                    (UnaryOp::SignExt(sw), UnaryOp::Trunc(tw)) if sw == tw => {
                        return Some(Expr::UnaryOp(UnaryOp::SignExt(*sw), inner_inner.clone()));
                    }
                    (UnaryOp::ZeroExt(zw), UnaryOp::Trunc(tw)) if zw == tw => {
                        return Some(Expr::UnaryOp(UnaryOp::ZeroExt(*zw), inner_inner.clone()));
                    }
                    (UnaryOp::Trunc(tw), UnaryOp::ZeroExt(_) | UnaryOp::SignExt(_)) => {
                        if inner_inner.width().bytes() <= tw.bytes() {
                            if inner_inner.width() == *tw {
                                return Some(*inner_inner.clone());
                            }
                            return Some(Expr::UnaryOp(UnaryOp::Trunc(*tw), inner_inner.clone()));
                        }
                    }
                    _ => {}
                }
            }
            // Cast to same width is identity
            match op {
                UnaryOp::ZeroExt(w) | UnaryOp::SignExt(w) | UnaryOp::Trunc(w) => {
                    if inner.width() == *w {
                        return Some(*inner.clone());
                    }
                }
                _ => {}
            }
            None
        }
        _ => None,
    };

    // If top-level fold succeeded, return it
    if folded_top.is_some() {
        return folded_top;
    }

    // If subexpressions were folded (Cow::Owned), return the updated expression
    match expr {
        std::borrow::Cow::Owned(e) => Some(e),
        std::borrow::Cow::Borrowed(_) => None,
    }
}

/// Recognize GCC/Clang magic-number signed division pattern.
///
/// Pattern: `Sub(Sar(Shr(Mul(SignExt(x), magic), 32), shift), Sar(x, 31))`
/// Folds to: `SDiv(x, divisor)` where divisor is derived from magic and shift.
fn try_fold_magic_sdiv(lhs: &Expr, rhs: &Expr) -> Option<Expr> {
    // rhs must be Sar(x, 31) — sign correction
    let (sign_x, sign_shift) = match rhs {
        Expr::BinOp(BinOp::Sar, x, s) => (x.as_ref(), s.as_ref()),
        _ => return None,
    };
    match sign_shift {
        Expr::Const(31, _) => {}
        _ => return None,
    }

    // lhs: Sar(Shr(Mul(SignExt(x), magic), 32), shift) when shift > 0
    //    or Shr(Mul(SignExt(x), magic), 32)             when shift == 0
    let (shr_expr, extra_shift) = match lhs {
        Expr::BinOp(BinOp::Sar, inner, s) => {
            let Expr::Const(shift, _) = s.as_ref() else { return None };
            (inner.as_ref(), *shift)
        }
        _ => (lhs, 0),
    };

    // shr_expr must be Shr(Mul(SignExt(x), magic), 32)
    let mul_expr = match shr_expr {
        Expr::BinOp(BinOp::Shr, inner, s) => {
            let Expr::Const(0x20, _) = s.as_ref() else { return None };
            inner.as_ref()
        }
        _ => return None,
    };

    // mul_expr must be Mul(SignExt(x), Const(magic)) or vice-versa
    let (x, magic) = match mul_expr {
        Expr::BinOp(BinOp::Mul, a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::UnaryOp(UnaryOp::SignExt(_), x), Expr::Const(m, _)) => (x.as_ref(), *m),
            (Expr::Const(m, _), Expr::UnaryOp(UnaryOp::SignExt(_), x)) => (x.as_ref(), *m),
            _ => return None,
        },
        _ => return None,
    };

    // x (from multiply) and sign_x (from sign correction) must match
    if x != sign_x {
        return None;
    }

    // Compute divisor from magic constant and shift amount
    let divisor = magic_to_divisor(magic, extra_shift)?;
    let w = x.width();
    Some(Expr::binop(BinOp::SDiv, x.clone(), Expr::const_val(divisor, w)))
}

/// Given a magic multiplier and shift amount, recover the original divisor.
///
/// The compiler uses: `magic = ceil(2^(32+shift) / divisor)`.
/// We reverse this by trying `d = floor(2^(32+shift) / magic)` and `d+1`.
fn magic_to_divisor(magic: u64, shift: u64) -> Option<u64> {
    let m = magic as u128;
    if m == 0 || shift > 31 {
        return None;
    }
    let pow = 1u128 << (32 + shift);
    let d_floor = pow / m;
    for d in [d_floor, d_floor + 1] {
        if d < 2 {
            continue;
        }
        // Verify: ceil(2^(32+shift) / d) should equal magic
        let expected_magic = (pow + d - 1) / d;
        if expected_magic == m {
            return Some(d as u64);
        }
    }
    None
}

// ── Copy propagation ─────────────────────────────────────────────

/// Remove Nop statements.
fn dead_nop_elimination(func: &mut Function) -> bool {
    let mut changed = false;
    for block in &mut func.blocks {
        let before = block.stmts.len();
        block.stmts.retain(|s| !matches!(s, Stmt::Nop));
        if block.stmts.len() != before {
            changed = true;
        }
    }
    changed
}

/// Simple copy propagation: replace uses of `x = y` with `y`.
fn copy_propagation(func: &mut Function) -> bool {
    let mut changed = false;

    for block in &mut func.blocks {
        // Build a map of register copies: reg_name -> expr
        // Phase 1: collect definitions (forward pass)
        let mut copies: HashMap<String, Expr> = HashMap::new();

        for stmt in block.stmts.iter() {
            if let Stmt::Assign(var, expr) = stmt {
                let key = format!("{var}");
                match var {
                    Var::Reg(_, _) => {
                        if expr_uses_var_key(expr, &key) {
                            copies.remove(&key);
                        } else {
                            copies.insert(key.clone(), expr.clone());
                        }
                        let invalidated: Vec<String> = copies
                            .iter()
                            .filter(|(k, v)| *k != &key && expr_uses_var_key(v, &key))
                            .map(|(k, _)| k.clone())
                            .collect();
                        for k in invalidated {
                            copies.remove(&k);
                        }
                    }
                    _ => {
                        // For non-register vars, only propagate simple copies.
                        // BUT don't propagate stack = register (parameter stores)
                        // as that would replace var_N with rdi/rsi, undoing arg absorption.
                        match expr {
                            Expr::Var(Var::Reg(_, _)) => {
                                // Don't add to copy map: var_18 = rdi should not
                                // cause var_18 to be replaced with rdi elsewhere
                            }
                            Expr::Var(_) | Expr::Const(_, _) => {
                                copies.insert(key, expr.clone());
                            }
                            _ => {
                                copies.remove(&key);
                            }
                        }
                    }
                }
            }
            // Calls may clobber registers
            if matches!(stmt, Stmt::Call(..)) {
                copies.clear();
            }
        }

        // Phase 2: apply copies (forward pass)
        let mut copies2: HashMap<String, Expr> = HashMap::new();
        for stmt in &mut block.stmts {
            // Apply current copies to this statement
            match stmt {
                Stmt::Assign(var, expr) => {
                    if propagate_copies(expr, &copies2) {
                        changed = true;
                    }
                    let key = format!("{var}");
                    match var {
                        Var::Reg(_, _) => {
                            // Don't propagate self-referential definitions (e.g. rsp = rsp + 8)
                            // as they cause expression trees to grow unboundedly across iterations.
                            if expr_uses_var_key(expr, &key) {
                                copies2.remove(&key);
                            } else {
                                copies2.insert(key.clone(), expr.clone());
                            }
                            let invalidated: Vec<String> = copies2
                                .iter()
                                .filter(|(k, v)| *k != &key && expr_uses_var_key(v, &key))
                                .map(|(k, _)| k.clone())
                                .collect();
                            for k in invalidated {
                                copies2.remove(&k);
                            }
                        }
                        _ => {
                            match expr {
                                Expr::Var(Var::Reg(_, _)) => {
                                    // Don't propagate stack = register
                                }
                                Expr::Var(_) | Expr::Const(_, _) => {
                                    copies2.insert(key, expr.clone());
                                }
                                _ => {
                                    copies2.remove(&key);
                                }
                            }
                        }
                    }
                }
                Stmt::Store(addr, val, _) => {
                    changed |= propagate_copies(addr, &copies2);
                    changed |= propagate_copies(val, &copies2);
                }
                Stmt::Call(_, target, args) => {
                    changed |= propagate_copies(target, &copies2);
                    for arg in args.iter_mut() {
                        changed |= propagate_copies(arg, &copies2);
                    }
                    copies2.clear(); // calls clobber registers
                }
                Stmt::Nop => {}
            }
        }

        // Propagate into terminator
        match &mut block.terminator {
            Terminator::Branch(cond, _, _) => {
                changed |= propagate_copies(cond, &copies2);
            }
            Terminator::Return(Some(val)) => {
                changed |= propagate_copies(val, &copies2);
            }
            Terminator::IndirectJump(target) => {
                changed |= propagate_copies(target, &copies2);
            }
            _ => {}
        }
    }

    changed
}

/// Check if an expression references a variable by its string key.
fn expr_uses_var_key(expr: &Expr, key: &str) -> bool {
    match expr {
        Expr::Var(v) => format!("{v}") == key,
        Expr::BinOp(_, l, r) | Expr::Cmp(_, l, r) => {
            expr_uses_var_key(l, key) || expr_uses_var_key(r, key)
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => expr_uses_var_key(inner, key),
        _ => false,
    }
}

fn propagate_copies(expr: &mut Expr, copies: &HashMap<String, Expr>) -> bool {
    match expr {
        Expr::Var(v) => {
            let key = format!("{v}");
            if let Some(replacement) = copies.get(&key) {
                // Don't create self-references
                if *expr != *replacement {
                    *expr = replacement.clone();
                    return true;
                }
            }
            false
        }
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs) => {
            let a = propagate_copies(lhs, copies);
            let b = propagate_copies(rhs, copies);
            a || b
        }
        Expr::UnaryOp(UnaryOp::AddrOf, _) => {
            // Don't propagate into address-of: &var_50 is an address, not a value use
            false
        }
        Expr::UnaryOp(_, inner) => propagate_copies(inner, copies),
        Expr::Load(addr, _) => propagate_copies(addr, copies),
        _ => false,
    }
}

// ── Stack variable recovery ──────────────────────────────────────

/// Recover stack variables: replace RSP/RBP-relative memory accesses with named variables.
fn stack_variable_recovery(func: &mut Function) -> bool {
    let mut stack_vars: HashSet<i64> = HashSet::new();
    let mut changed = false;

    // Collect all stack offsets
    for block in &func.blocks {
        for stmt in &block.stmts {
            collect_stack_refs(stmt, &mut stack_vars);
        }
    }

    // Replace stack memory accesses with stack variables
    if !stack_vars.is_empty() {
        for block in &mut func.blocks {
            for stmt in &mut block.stmts {
                if replace_stack_refs(stmt) {
                    changed = true;
                }
            }
            // Also replace in terminators
            match &mut block.terminator {
                Terminator::Branch(cond, _, _) => {
                    if replace_stack_loads(cond) {
                        changed = true;
                    }
                }
                Terminator::Return(Some(val)) => {
                    if replace_stack_loads(val) {
                        changed = true;
                    }
                }
                Terminator::IndirectJump(target) => {
                    if replace_stack_loads(target) {
                        changed = true;
                    }
                }
                _ => {}
            }
        }
    }

    changed
}

fn collect_stack_refs(stmt: &Stmt, vars: &mut HashSet<i64>) {
    match stmt {
        Stmt::Assign(Var::Stack(off, _), _) => {
            vars.insert(*off);
        }
        Stmt::Store(addr, _, _) => {
            if let Some(off) = extract_stack_offset(addr) {
                vars.insert(off);
            }
        }
        _ => {}
    }
}

fn extract_stack_offset(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::BinOp(BinOp::Add, lhs, rhs) => {
            if matches!(
                lhs.as_ref(),
                Expr::Var(Var::Reg(RegId::Rbp, _)) | Expr::Var(Var::Reg(RegId::Rsp, _))
            ) {
                if let Expr::Const(val, _) = rhs.as_ref() {
                    return Some(*val as i64);
                }
            }
            None
        }
        Expr::BinOp(BinOp::Sub, lhs, rhs) => {
            if matches!(
                lhs.as_ref(),
                Expr::Var(Var::Reg(RegId::Rbp, _)) | Expr::Var(Var::Reg(RegId::Rsp, _))
            ) {
                if let Expr::Const(val, _) = rhs.as_ref() {
                    return Some(-(*val as i64));
                }
            }
            None
        }
        _ => None,
    }
}

fn replace_stack_refs(stmt: &mut Stmt) -> bool {
    match stmt {
        Stmt::Store(addr, val, width) => {
            if let Some(off) = extract_stack_offset(addr) {
                let var = Var::Stack(off, *width);
                *stmt = Stmt::Assign(var, val.clone());
                return true;
            }
            false
        }
        Stmt::Assign(_, expr) => replace_stack_loads(expr),
        Stmt::Call(_, target, args) => {
            let mut changed = replace_stack_loads(target);
            for arg in args.iter_mut() {
                // Convert bare stack-relative address to &var_XX
                if let Some(off) = extract_stack_offset(arg) {
                    *arg = Expr::UnaryOp(
                        UnaryOp::AddrOf,
                        Box::new(Expr::Var(Var::Stack(off, BitWidth::Bit8))),
                    );
                    changed = true;
                } else {
                    changed |= replace_stack_loads(arg);
                }
            }
            changed
        }
        _ => false,
    }
}

fn replace_stack_loads(expr: &mut Expr) -> bool {
    match expr {
        Expr::Load(addr, width) => {
            if let Some(off) = extract_stack_offset(addr) {
                *expr = Expr::Var(Var::Stack(off, *width));
                return true;
            }
            // Even if this Load isn't a direct stack access, recurse into its
            // address sub-expression (e.g. *(u32*)*(u64*)(rbp + off) — the
            // inner Load(rbp+off) should still become var_N).
            replace_stack_loads(addr)
        }
        Expr::BinOp(_, lhs, rhs) => {
            let a = replace_stack_loads(lhs);
            let b = replace_stack_loads(rhs);
            a || b
        }
        Expr::UnaryOp(_, inner) => replace_stack_loads(inner),
        Expr::Cmp(_, lhs, rhs) => {
            let a = replace_stack_loads(lhs);
            let b = replace_stack_loads(rhs);
            a || b
        }
        _ => false,
    }
}

// ── Expression inlining ──────────────────────────────────────────

/// Expression inlining: if a temp `t = expr` has exactly one use, inline it.
fn expression_inlining(func: &mut Function) -> bool {
    let mut changed = false;

    for block_idx in 0..func.blocks.len() {
        // Collect single-def temps: temp name -> (index, expr)
        let mut defs: HashMap<String, (usize, Expr)> = HashMap::new();
        let mut use_count: HashMap<String, usize> = HashMap::new();

        for (i, stmt) in func.blocks[block_idx].stmts.iter().enumerate() {
            if let Stmt::Assign(var @ Var::Temp(_, _), expr) = stmt {
                let key = format!("{var}");
                defs.insert(key, (i, expr.clone()));
            }
        }

        // Count uses
        for stmt in &func.blocks[block_idx].stmts {
            count_var_uses(stmt, &mut use_count);
        }
        count_var_uses_terminator(&func.blocks[block_idx].terminator, &mut use_count);

        // Inline temps used exactly once
        let mut to_remove = Vec::new();
        for (key, (def_idx, expr)) in &defs {
            if use_count.get(key).copied().unwrap_or(0) == 1 {
                // Find and inline
                let mut inlined = false;
                for i in (*def_idx + 1)..func.blocks[block_idx].stmts.len() {
                    if inline_var_in_stmt(&mut func.blocks[block_idx].stmts[i], key, expr) {
                        inlined = true;
                        break;
                    }
                }
                if !inlined {
                    inline_var_in_terminator(&mut func.blocks[block_idx].terminator, key, expr);
                }
                to_remove.push(*def_idx);
                changed = true;
            }
        }

        // Remove inlined defs (reverse order to keep indices valid)
        to_remove.sort_unstable();
        for idx in to_remove.into_iter().rev() {
            func.blocks[block_idx].stmts[idx] = Stmt::Nop;
        }
    }

    changed
}

fn count_var_uses(stmt: &Stmt, counts: &mut HashMap<String, usize>) {
    match stmt {
        Stmt::Assign(_, expr) => count_expr_uses(expr, counts),
        Stmt::Store(addr, val, _) => {
            count_expr_uses(addr, counts);
            count_expr_uses(val, counts);
        }
        Stmt::Call(_, target, args) => {
            count_expr_uses(target, counts);
            for a in args {
                count_expr_uses(a, counts);
            }
        }
        Stmt::Nop => {}
    }
}

fn count_var_uses_terminator(term: &Terminator, counts: &mut HashMap<String, usize>) {
    match term {
        Terminator::Branch(cond, _, _) => count_expr_uses(cond, counts),
        Terminator::Return(Some(v)) => count_expr_uses(v, counts),
        Terminator::IndirectJump(t) => count_expr_uses(t, counts),
        _ => {}
    }
}

fn count_expr_uses(expr: &Expr, counts: &mut HashMap<String, usize>) {
    match expr {
        Expr::Var(v) => {
            *counts.entry(format!("{v}")).or_insert(0) += 1;
        }
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs) => {
            count_expr_uses(lhs, counts);
            count_expr_uses(rhs, counts);
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
            count_expr_uses(inner, counts);
        }
        _ => {}
    }
}

fn inline_var_in_stmt(stmt: &mut Stmt, key: &str, replacement: &Expr) -> bool {
    match stmt {
        Stmt::Assign(_, expr) => inline_var_in_expr(expr, key, replacement),
        Stmt::Store(addr, val, _) => {
            inline_var_in_expr(addr, key, replacement) || inline_var_in_expr(val, key, replacement)
        }
        Stmt::Call(_, target, args) => {
            let mut found = inline_var_in_expr(target, key, replacement);
            for a in args {
                found |= inline_var_in_expr(a, key, replacement);
            }
            found
        }
        Stmt::Nop => false,
    }
}

fn inline_var_in_terminator(term: &mut Terminator, key: &str, replacement: &Expr) -> bool {
    match term {
        Terminator::Branch(cond, _, _) => inline_var_in_expr(cond, key, replacement),
        Terminator::Return(Some(v)) => inline_var_in_expr(v, key, replacement),
        Terminator::IndirectJump(t) => inline_var_in_expr(t, key, replacement),
        _ => false,
    }
}

fn inline_var_in_expr(expr: &mut Expr, key: &str, replacement: &Expr) -> bool {
    match expr {
        Expr::Var(v) if format!("{v}") == key => {
            *expr = replacement.clone();
            true
        }
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs) => {
            inline_var_in_expr(lhs, key, replacement)
                || inline_var_in_expr(rhs, key, replacement)
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
            inline_var_in_expr(inner, key, replacement)
        }
        _ => false,
    }
}

// ── Call result propagation ──────────────────────────────────────

/// Propagate call return values across block boundaries.
///
/// When block A ends with `rax = call foo(...)` + `Jump(B)` and block B
/// (with only A as predecessor) uses `rax`, introduce a temp variable to
/// carry the return value, eliminating the raw register reference.
fn propagate_call_results(func: &mut Function) -> bool {
    let id_to_idx: HashMap<BlockId, usize> = func.blocks.iter().enumerate()
        .map(|(i, b)| (b.id, i))
        .collect();

    // Collect candidates: (pred_idx, succ_idx, call_stmt_idx)
    let mut candidates: Vec<(usize, usize, usize)> = Vec::new();

    for (i, block) in func.blocks.iter().enumerate() {
        let succ_bid = match &block.terminator {
            Terminator::Jump(target) => *target,
            _ => continue,
        };
        let Some(&succ_idx) = id_to_idx.get(&succ_bid) else { continue };

        // Last non-Nop stmt must be a Call returning to rax
        let Some(call_idx) = block.stmts.iter().rposition(|s| !matches!(s, Stmt::Nop)) else {
            continue;
        };
        if !matches!(
            &block.stmts[call_idx],
            Stmt::Call(Some(Var::Reg(RegId::Rax, _)), _, _)
        ) {
            continue;
        }

        // Successor has only this one predecessor
        if func.predecessors(succ_bid).len() != 1 {
            continue;
        }

        // Skip if already handled by absorb_call_result (first stmt is var_X = rax)
        let succ = &func.blocks[succ_idx];
        if let Some(fi) = succ.stmts.iter().position(|s| !matches!(s, Stmt::Nop)) {
            if matches!(
                &succ.stmts[fi],
                Stmt::Assign(Var::Stack(_, _), Expr::Var(Var::Reg(RegId::Rax, _)))
            ) {
                continue;
            }
        }

        // Check if successor actually uses rax in stmts or terminator
        let rax_key = "rax";
        let mut uses = HashSet::new();
        for stmt in &succ.stmts {
            collect_rhs_uses(stmt, &mut uses);
        }
        collect_uses_terminator(&succ.terminator, &mut uses);
        if !uses.contains(rax_key) {
            continue;
        }

        candidates.push((i, succ_idx, call_idx));
    }

    let mut changed = false;
    for (pred_idx, succ_idx, call_idx) in candidates {
        let temp = func.new_temp(BitWidth::Bit64);
        let temp_expr = Expr::Var(temp.clone());

        // Change call's return from rax to temp
        if let Stmt::Call(ret, _, _) = &mut func.blocks[pred_idx].stmts[call_idx] {
            *ret = Some(temp);
        }

        // Replace Var::Reg(Rax, _) with temp in successor's stmts and terminator
        let succ = &mut func.blocks[succ_idx];
        for stmt in &mut succ.stmts {
            replace_reg_in_stmt(stmt, RegId::Rax, &temp_expr);
        }
        replace_reg_in_terminator(&mut succ.terminator, RegId::Rax, &temp_expr);
        changed = true;
    }
    changed
}

fn replace_reg_in_stmt(stmt: &mut Stmt, reg: RegId, replacement: &Expr) {
    match stmt {
        Stmt::Assign(_var, expr) => {
            replace_reg_in_expr(expr, reg, replacement);
            // If LHS is the same reg, this is a new definition — handled elsewhere
        }
        Stmt::Store(addr, val, _) => {
            replace_reg_in_expr(addr, reg, replacement);
            replace_reg_in_expr(val, reg, replacement);
        }
        Stmt::Call(_, target, args) => {
            replace_reg_in_expr(target, reg, replacement);
            for arg in args.iter_mut() {
                replace_reg_in_expr(arg, reg, replacement);
            }
        }
        Stmt::Nop => {}
    }
}

fn replace_reg_in_terminator(term: &mut Terminator, reg: RegId, replacement: &Expr) {
    match term {
        Terminator::Branch(cond, _, _) => { replace_reg_in_expr(cond, reg, replacement); }
        Terminator::Return(Some(val)) => { replace_reg_in_expr(val, reg, replacement); }
        Terminator::IndirectJump(target) => { replace_reg_in_expr(target, reg, replacement); }
        _ => {}
    }
}

fn replace_reg_in_expr(expr: &mut Expr, reg: RegId, replacement: &Expr) {
    match expr {
        Expr::Var(Var::Reg(r, _)) if *r == reg => {
            *expr = replacement.clone();
        }
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs) => {
            replace_reg_in_expr(lhs, reg, replacement);
            replace_reg_in_expr(rhs, reg, replacement);
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
            replace_reg_in_expr(inner, reg, replacement);
        }
        _ => {}
    }
}

// ── Dead store elimination ───────────────────────────────────────

/// Within-block dead store elimination for registers.
///
/// Removes register assignments that are overwritten before being read
/// within the same block, including clobbers by a subsequent Call.
fn local_dead_store_elimination(func: &mut Function) -> bool {
    let mut changed = false;

    for block in &mut func.blocks {
        // Forward scan: track pending assignments that haven't been read yet.
        // If a register is assigned again (or clobbered by Call) before being read,
        // the previous assignment is dead.
        let mut pending: HashMap<String, usize> = HashMap::new(); // reg_key → stmt index
        let mut to_nop: Vec<usize> = Vec::new();

        for i in 0..block.stmts.len() {
            match &block.stmts[i] {
                Stmt::Assign(var @ Var::Reg(reg_id, _), expr) => {
                    if matches!(reg_id, RegId::Rsp | RegId::Rbp) {
                        // Don't touch frame pointers
                        let mut uses = HashSet::new();
                        collect_expr_uses(expr, &mut uses);
                        for u in uses {
                            pending.remove(&u);
                        }
                        continue;
                    }
                    let key = format!("{var}");
                    // First: check if RHS reads any pending registers (marks them live)
                    let mut uses = HashSet::new();
                    collect_expr_uses(expr, &mut uses);
                    for u in &uses {
                        pending.remove(u);
                    }
                    // If there's a pending assignment to this same register, it's dead
                    if let Some(prev_idx) = pending.get(&key) {
                        to_nop.push(*prev_idx);
                    }
                    pending.insert(key, i);
                }
                Stmt::Call(ret, target, args) => {
                    // First: mark registers used in target/args as live
                    let mut uses = HashSet::new();
                    collect_expr_uses(target, &mut uses);
                    for arg in args {
                        collect_expr_uses(arg, &mut uses);
                    }
                    for u in &uses {
                        pending.remove(u);
                    }
                    // Call clobbers caller-saved registers: pending assignments are dead
                    for clobbered in &["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"] {
                        if let Some(prev_idx) = pending.remove(*clobbered) {
                            to_nop.push(prev_idx);
                        }
                    }
                    // If call returns to a reg, track it as pending
                    if let Some(v) = ret {
                        let key = format!("{v}");
                        pending.insert(key, i); // i is a Call, but we track it for clobber detection
                    }
                }
                Stmt::Store(addr, val, _) => {
                    let mut uses = HashSet::new();
                    collect_expr_uses(addr, &mut uses);
                    collect_expr_uses(val, &mut uses);
                    for u in uses {
                        pending.remove(&u);
                    }
                }
                Stmt::Assign(_, expr) => {
                    // Non-register assignments: mark any used registers as live
                    let mut uses = HashSet::new();
                    collect_expr_uses(expr, &mut uses);
                    for u in uses {
                        pending.remove(&u);
                    }
                }
                Stmt::Nop => {}
            }
        }
        // Don't nop anything still pending at block exit — it might be live across blocks

        for idx in to_nop {
            // Don't nop Call stmts (they have side effects)
            if !matches!(block.stmts[idx], Stmt::Call(..)) {
                block.stmts[idx] = Stmt::Nop;
                changed = true;
            }
        }
    }

    changed
}

/// Dead store elimination: remove assignments to registers never read afterwards.
fn dead_store_elimination(func: &mut Function) -> bool {
    let mut changed = false;
    let mut live_regs: HashSet<String> = HashSet::new();

    // Collect all variables used in terminators + across blocks
    for block in &func.blocks {
        collect_uses_terminator(&block.terminator, &mut live_regs);
    }

    // Within each block, backward pass
    for block in &mut func.blocks {
        let mut block_live: HashSet<String> = live_regs.clone();

        // Mark successor-used regs as live
        for stmt in block.stmts.iter().rev() {
            match stmt {
                Stmt::Assign(var, _) => {
                    let key = format!("{var}");
                    match var {
                        Var::Reg(RegId::Rsp, _) | Var::Reg(RegId::Rbp, _) => {}
                        Var::Reg(_, _) => {
                            if !block_live.contains(&key) {
                                // dead — will eliminate on second pass
                            }
                        }
                        _ => {}
                    }
                    block_live.insert(key);
                }
                _ => {
                    collect_rhs_uses(stmt, &mut block_live);
                }
            }
        }
    }

    // Simple: remove assignments to registers not read anywhere in function
    let mut all_uses: HashSet<String> = HashSet::new();
    for block in &func.blocks {
        for stmt in &block.stmts {
            collect_rhs_uses(stmt, &mut all_uses);
        }
        collect_uses_terminator(&block.terminator, &mut all_uses);
    }

    for block in &mut func.blocks {
        for stmt in &mut block.stmts {
            if let Stmt::Assign(var @ Var::Reg(_, _), _) = stmt {
                let key = format!("{var}");
                if !all_uses.contains(&key) {
                    *stmt = Stmt::Nop;
                    changed = true;
                }
            }
        }
    }

    changed
}

fn collect_uses_terminator(term: &Terminator, uses: &mut HashSet<String>) {
    match term {
        Terminator::Branch(cond, _, _) => collect_expr_uses(cond, uses),
        Terminator::Return(Some(v)) => collect_expr_uses(v, uses),
        Terminator::IndirectJump(t) => collect_expr_uses(t, uses),
        _ => {}
    }
}

fn collect_rhs_uses(stmt: &Stmt, uses: &mut HashSet<String>) {
    match stmt {
        Stmt::Assign(_, expr) => collect_expr_uses(expr, uses),
        Stmt::Store(addr, val, _) => {
            collect_expr_uses(addr, uses);
            collect_expr_uses(val, uses);
        }
        Stmt::Call(_, target, args) => {
            collect_expr_uses(target, uses);
            for a in args {
                collect_expr_uses(a, uses);
            }
        }
        Stmt::Nop => {}
    }
}

fn collect_expr_uses(expr: &Expr, uses: &mut HashSet<String>) {
    match expr {
        Expr::Var(v) => {
            uses.insert(format!("{v}"));
        }
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs) => {
            collect_expr_uses(lhs, uses);
            collect_expr_uses(rhs, uses);
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
            collect_expr_uses(inner, uses);
        }
        _ => {}
    }
}

// ── Call optimization ────────────────────────────────────────────

/// Absorb call return values across block boundaries.
///
/// If block A ends with `call foo()` (with ret = rax) and jumps to block B,
/// and B's first real stmt is `var_X = rax`, then change the call's return
/// to `var_X` and delete the `var_X = rax` in B.
fn absorb_call_result(func: &mut Function) -> bool {
    let id_to_idx: HashMap<BlockId, usize> = func.blocks.iter().enumerate()
        .map(|(i, b)| (b.id, i))
        .collect();

    // Collect (pred_idx, succ_idx, call_stmt_idx, first_real_idx) tuples
    let mut merges: Vec<(usize, usize, usize, usize)> = Vec::new();

    for (i, block) in func.blocks.iter().enumerate() {
        // Block must jump unconditionally to a successor
        let succ_bid = match &block.terminator {
            Terminator::Jump(target) => *target,
            _ => continue,
        };
        let Some(&succ_idx) = id_to_idx.get(&succ_bid) else { continue };

        // Block's last non-Nop stmt must be a Call with rax return
        let Some(call_idx) = block.stmts.iter().rposition(|s| !matches!(s, Stmt::Nop)) else {
            continue;
        };
        let is_call_rax = matches!(
            &block.stmts[call_idx],
            Stmt::Call(Some(Var::Reg(RegId::Rax, _)), _, _)
        );
        if !is_call_rax {
            continue;
        }

        // Successor must have only this one predecessor
        let preds = func.predecessors(succ_bid);
        if preds.len() != 1 {
            continue;
        }

        // Successor's first non-Nop stmt must be `var_X = rax`
        let succ_block = &func.blocks[succ_idx];
        let first_real = succ_block.stmts.iter().position(|s| !matches!(s, Stmt::Nop));
        if let Some(first_idx) = first_real {
            if matches!(
                &succ_block.stmts[first_idx],
                Stmt::Assign(Var::Stack(_, _), Expr::Var(Var::Reg(RegId::Rax, _)))
            ) {
                merges.push((i, succ_idx, call_idx, first_idx));
            }
        }
    }

    let mut changed = false;
    for (pred_idx, succ_idx, call_idx, first_idx) in merges {
        // Get the stack var from successor
        let stack_var = if let Stmt::Assign(v @ Var::Stack(_, _), _) = &func.blocks[succ_idx].stmts[first_idx] {
            v.clone()
        } else {
            continue;
        };

        // Change call's return to the stack var
        if let Stmt::Call(ret, _, _) = &mut func.blocks[pred_idx].stmts[call_idx] {
            *ret = Some(stack_var);
        }

        // Nop out the assignment in successor
        func.blocks[succ_idx].stmts[first_idx] = Stmt::Nop;
        changed = true;
    }
    changed
}

/// Absorb argument-register assignments into Call statements.
///
/// Before: `rdi = "hello"  ; rsi = 0  ; rax = call puts(rdi, rsi, ...)`
/// After:  `rax = call puts("hello", 0, ...)`  (with the assignments turned to Nop)
fn absorb_call_args(func: &mut Function) -> bool {
    let mut changed = false;
    let param_regs = func.calling_conv.param_regs().to_vec();

    for block in &mut func.blocks {
        // Find call statement indices
        let call_indices: Vec<usize> = block
            .stmts
            .iter()
            .enumerate()
            .filter_map(|(i, s)| matches!(s, Stmt::Call(..)).then_some(i))
            .collect();

        for &call_idx in &call_indices {
            // Extract call info
            let Stmt::Call(_, _, ref args) = block.stmts[call_idx] else {
                continue;
            };
            let mut new_args = args.clone();
            let mut absorbed = Vec::new();

            // For each parameter register, look backwards to find its last assignment
            for (param_idx, preg) in param_regs.iter().enumerate() {
                if param_idx >= new_args.len() {
                    break;
                }
                // Only absorb if the arg is currently Var(Reg(preg, _))
                let is_param_ref = matches!(&new_args[param_idx], Expr::Var(Var::Reg(r, _)) if r == preg);
                if !is_param_ref {
                    continue;
                }

                // Scan backwards for `preg = expr`, then resolve register chains
                let mut target_reg = *preg;
                let mut search_end = call_idx;
                loop {
                    let mut found = false;
                    for j in (0..search_end).rev() {
                        match &block.stmts[j] {
                            Stmt::Assign(Var::Reg(r, _), val) if *r == target_reg => {
                                new_args[param_idx] = val.clone();
                                absorbed.push(j);
                                // If the value is itself a register, continue resolving
                                if let Expr::Var(Var::Reg(next_reg, _)) = val {
                                    target_reg = *next_reg;
                                    search_end = j;
                                    found = true;
                                }
                                break;
                            }
                            Stmt::Call(..) => break,
                            _ => {}
                        }
                    }
                    if !found { break; }
                }
            }

            if !absorbed.is_empty() {
                // Update the call args
                if let Stmt::Call(_, _, ref mut args) = block.stmts[call_idx] {
                    *args = new_args;
                }
                // Mark absorbed assignments as Nop
                for idx in &absorbed {
                    block.stmts[*idx] = Stmt::Nop;
                }
                changed = true;
            }
        }
    }

    changed
}

/// Trim trailing raw-register arguments from Call statements.
///
/// After `absorb_call_args`, some calls may still have leftover register args
/// that were not absorbed (e.g. `puts("hello", rsi, rdx, rcx, r8, r9)`).
/// These trailing `Var(Reg(...))` args are ABI noise — trim them.
fn trim_call_args(func: &mut Function) -> bool {
    let mut changed = false;
    let param_regs: HashSet<RegId> = func.calling_conv.param_regs().iter().copied().collect();

    for block in &mut func.blocks {
        for stmt in &mut block.stmts {
            let Stmt::Call(_, _, args) = stmt else {
                continue;
            };
            // Trim from the end while we see raw param-register references.
            while args.len() > 0 {
                let Some(last) = args.last() else {
                    break;
                };
                if matches!(last, Expr::Var(Var::Reg(r, _)) if param_regs.contains(r)) {
                    args.pop();
                    changed = true;
                } else {
                    break;
                }
            }

            // Remove duplicated tail args (common after absorb_call_args when
            // intermediate register shuffles leave equivalent expressions).
            while args.len() > 1 {
                let n = args.len();
                if args[n - 1] == args[n - 2] {
                    args.pop();
                    changed = true;
                } else {
                    break;
                }
            }
        }
    }

    changed
}

/// Eliminate unused call return values.
///
/// If `rax = call foo(...)` and rax is never read before being overwritten
/// or the block terminates, turn it into `call foo(...)` (return = None).
fn eliminate_unused_call_results(func: &mut Function) -> bool {
    // Collect all (block_idx, stmt_idx) pairs where call return should be removed
    let mut to_remove: Vec<(usize, usize)> = Vec::new();

    for block_idx in 0..func.blocks.len() {
        let len = func.blocks[block_idx].stmts.len();
        for i in 0..len {
            let Stmt::Call(Some(ref ret_var), _, _) = func.blocks[block_idx].stmts[i] else {
                continue;
            };
            let ret_var = ret_var.clone();

            // For stack/temp variables, conservatively check ALL blocks for usage
            if matches!(ret_var, Var::Stack(_, _) | Var::Temp(_, _)) {
                let mut used = false;
                for (bi, block) in func.blocks.iter().enumerate() {
                    for (si, stmt) in block.stmts.iter().enumerate() {
                        if bi == block_idx && si == i {
                            continue;
                        }
                        if stmt_reads(stmt, &ret_var) {
                            used = true;
                            break;
                        }
                    }
                    if used { break; }
                    if terminator_reads(&block.terminator, &ret_var) {
                        used = true;
                        break;
                    }
                }
                if !used {
                    to_remove.push((block_idx, i));
                }
                continue;
            }

            // For register variables, check within the same block only
            let mut used = false;
            let stmts = &func.blocks[block_idx].stmts;
            for j in (i + 1)..len {
                if stmt_reads(&stmts[j], &ret_var) {
                    used = true;
                    break;
                }
                if stmt_writes(&stmts[j], &ret_var) {
                    break;
                }
            }

            if !used {
                if terminator_reads(&func.blocks[block_idx].terminator, &ret_var) {
                    used = true;
                }
            }

            if !used {
                to_remove.push((block_idx, i));
            }
        }
    }

    let changed = !to_remove.is_empty();
    for (block_idx, stmt_idx) in to_remove {
        if let Stmt::Call(ref mut ret, _, _) = func.blocks[block_idx].stmts[stmt_idx] {
            *ret = None;
        }
    }
    changed
}

/// Check if a statement reads a given variable.
fn stmt_reads(stmt: &Stmt, var: &Var) -> bool {
    match stmt {
        Stmt::Assign(_, expr) => expr_contains_var(expr, var),
        Stmt::Store(addr, val, _) => expr_contains_var(addr, var) || expr_contains_var(val, var),
        Stmt::Call(_, target, args) => {
            expr_contains_var(target, var)
                || args.iter().any(|a| expr_contains_var(a, var))
        }
        Stmt::Nop => false,
    }
}

/// Check if a statement writes to a given variable.
fn stmt_writes(stmt: &Stmt, var: &Var) -> bool {
    match stmt {
        Stmt::Assign(v, _) => v == var,
        Stmt::Call(Some(v), _, _) => v == var,
        _ => false,
    }
}

/// Check if a terminator reads a given variable.
fn terminator_reads(term: &Terminator, var: &Var) -> bool {
    match term {
        Terminator::Branch(cond, _, _) => expr_contains_var(cond, var),
        Terminator::Return(Some(expr)) => expr_contains_var(expr, var),
        Terminator::IndirectJump(expr) => expr_contains_var(expr, var),
        _ => false,
    }
}

/// Recursively check if an expression references a variable.
fn expr_contains_var(expr: &Expr, var: &Var) -> bool {
    match expr {
        Expr::Var(v) => v == var,
        Expr::Const(..) | Expr::Cond(_) => false,
        Expr::BinOp(_, l, r) | Expr::Cmp(_, l, r) => {
            expr_contains_var(l, var) || expr_contains_var(r, var)
        }
        Expr::UnaryOp(_, inner) => expr_contains_var(inner, var),
        Expr::Load(addr, _) => expr_contains_var(addr, var),
    }
}

// ── Self-assignment elimination ──────────────────────────────────

/// Remove self-assignments like `rdi = rdi` that arise from copy-propagation
/// collapsing register shuffles.
fn eliminate_self_assignments(func: &mut Function) {
    for block in &mut func.blocks {
        for stmt in &mut block.stmts {
            if let Stmt::Assign(var, Expr::Var(rhs)) = stmt {
                if var == rhs {
                    *stmt = Stmt::Nop;
                }
            }
        }
    }
}

// ── Parameter register substitution ─────────────────────────────

/// Replace raw parameter-register references with their named stack variables.
///
/// After parameter save (`var_14 = rdi`) in the entry block, subsequent uses
/// of `rdi` in call args and branch conditions should display as `var_14`.
fn substitute_param_regs(func: &mut Function) {
    let param_regs: Vec<RegId> = func.calling_conv.param_regs().to_vec();
    let mut param_map: HashMap<RegId, Var> = HashMap::new();

    // Collect parameter mappings from the entry block.
    if let Some(entry) = func.blocks.first() {
        for stmt in &entry.stmts {
            if let Stmt::Assign(var @ Var::Stack(_, _), Expr::Var(Var::Reg(reg, _))) = stmt {
                if param_regs.contains(reg) && !param_map.contains_key(reg) {
                    param_map.insert(*reg, var.clone());
                }
            }
        }
    }

    if param_map.is_empty() {
        return;
    }

    // Replace bare parameter-register references in call args and expressions.
    // Skip the entry block's parameter-save stmts themselves so that codegen
    // can still detect them for function signature generation.
    for (block_idx, block) in func.blocks.iter_mut().enumerate() {
        for stmt in &mut block.stmts {
            // Preserve the original `var_X = param_reg` in the entry block
            if block_idx == 0 {
                if let Stmt::Assign(Var::Stack(_, _), Expr::Var(Var::Reg(reg, _))) = stmt {
                    if param_map.contains_key(reg) {
                        continue;
                    }
                }
            }
            match stmt {
                Stmt::Call(_, _, _args) => {
                    // Don't substitute param regs in call args — stale registers
                    // that weren't absorbed are ABI noise, not param references.
                }
                Stmt::Assign(_, expr) => {
                    substitute_param_reg_in_expr(expr, &param_map);
                }
                Stmt::Store(addr, val, _) => {
                    substitute_param_reg_in_expr(addr, &param_map);
                    substitute_param_reg_in_expr(val, &param_map);
                }
                _ => {}
            }
        }
        match &mut block.terminator {
            Terminator::Branch(cond, _, _) => {
                substitute_param_reg_in_expr(cond, &param_map);
            }
            Terminator::Return(Some(val)) => {
                substitute_param_reg_in_expr(val, &param_map);
            }
            _ => {}
        }
    }
}

fn substitute_param_reg_in_expr(expr: &mut Expr, map: &HashMap<RegId, Var>) {
    match expr {
        Expr::Var(Var::Reg(reg, _)) => {
            if let Some(stack_var) = map.get(reg) {
                *expr = Expr::Var(stack_var.clone());
            }
        }
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs) => {
            substitute_param_reg_in_expr(lhs, map);
            substitute_param_reg_in_expr(rhs, map);
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
            substitute_param_reg_in_expr(inner, map);
        }
        _ => {}
    }
}

// ── Register promotion & void returns ────────────────────────────

/// Promote callee-saved registers to temp variables.
///
/// After all other passes, callee-saved registers (rbx, r12–r15) that are still
/// referenced in the function body are effectively local variables (their
/// push/pop was already suppressed by the lifter). Replace every remaining
/// Var::Reg reference with a Var::Temp so the output shows clean local names.
fn promote_callee_saved_to_locals(func: &mut Function) {
    let callee_saved = func.calling_conv.callee_saved().to_vec();

    for &reg in &callee_saved {
        // rbp is the frame pointer — skip it if the function uses a frame pointer
        if reg == RegId::Rbp && func.has_frame_pointer {
            continue;
        }
        // rsp is never promoted
        if reg == RegId::Rsp {
            continue;
        }

        // Check if this register is actually referenced anywhere in the function
        let mut found = false;
        'outer: for block in &func.blocks {
            for stmt in &block.stmts {
                if stmt_uses_reg(stmt, reg) {
                    found = true;
                    break 'outer;
                }
            }
            if terminator_uses_reg(&block.terminator, reg) {
                found = true;
                break;
            }
        }

        if !found {
            continue;
        }

        // Create a temp var and replace all occurrences
        let temp = func.new_temp(BitWidth::Bit64);
        let temp_expr = Expr::Var(temp.clone());

        for block in &mut func.blocks {
            for stmt in &mut block.stmts {
                // Replace LHS assignments
                match stmt {
                    Stmt::Assign(Var::Reg(r, _), _) if *r == reg => {
                        let Stmt::Assign(v, _) = stmt else { unreachable!() };
                        *v = temp.clone();
                    }
                    Stmt::Call(Some(Var::Reg(r, _)), _, _) if *r == reg => {
                        let Stmt::Call(Some(v), _, _) = stmt else { unreachable!() };
                        *v = temp.clone();
                    }
                    _ => {}
                }
                // Replace RHS references
                replace_reg_in_stmt(stmt, reg, &temp_expr);
            }
            replace_reg_in_terminator(&mut block.terminator, reg, &temp_expr);
        }
    }
}

/// Check if a statement references a register (either reading or writing).
fn stmt_uses_reg(stmt: &Stmt, reg: RegId) -> bool {
    match stmt {
        Stmt::Assign(Var::Reg(r, _), expr) => {
            *r == reg || expr_uses_reg(expr, reg)
        }
        Stmt::Assign(_, expr) => expr_uses_reg(expr, reg),
        Stmt::Store(addr, val, _) => expr_uses_reg(addr, reg) || expr_uses_reg(val, reg),
        Stmt::Call(ret, target, args) => {
            matches!(ret, Some(Var::Reg(r, _)) if *r == reg)
                || expr_uses_reg(target, reg)
                || args.iter().any(|a| expr_uses_reg(a, reg))
        }
        Stmt::Nop => false,
    }
}

fn terminator_uses_reg(term: &Terminator, reg: RegId) -> bool {
    match term {
        Terminator::Branch(cond, _, _) => expr_uses_reg(cond, reg),
        Terminator::Return(Some(val)) => expr_uses_reg(val, reg),
        Terminator::IndirectJump(target) => expr_uses_reg(target, reg),
        _ => false,
    }
}

fn expr_uses_reg(expr: &Expr, reg: RegId) -> bool {
    match expr {
        Expr::Var(Var::Reg(r, _)) => *r == reg,
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs) => {
            expr_uses_reg(lhs, reg) || expr_uses_reg(rhs, reg)
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => expr_uses_reg(inner, reg),
        _ => false,
    }
}

/// Simplify `return rax` to `return` (void) when rax has no meaningful value.
///
/// If a Return terminator returns a bare `Var::Reg(Rax, _)` and no preceding
/// statement in the same block visibly sets rax, it's likely a void function.
fn simplify_void_returns(func: &mut Function) {
    // Check if the function intentionally computes a return value in rax.
    // Exclude:
    //   - `rax = 0` — this is `xor eax, eax` ABI noise before variadic calls
    //   - `Call(Some(rax), _, _)` — call results land in rax by ABI convention,
    //     not because the caller wants to return them
    // Only real rax defs (non-zero constants, computed expressions) block void
    // simplification.  If those got constant-folded into the Return terminator
    // (e.g. `return 0`), the loop below already preserves them because they
    // are not bare `Expr::Var(Rax)`.
    let has_intentional_rax_def = func.blocks.iter().any(|b| {
        b.stmts.iter().any(|s| match s {
            Stmt::Assign(Var::Reg(RegId::Rax, _), Expr::Const(0, _)) => false,
            Stmt::Assign(Var::Reg(RegId::Rax, _), _) => true,
            _ => false,
        })
    });
    if has_intentional_rax_def {
        return;
    }

    for block in &mut func.blocks {
        let Terminator::Return(Some(expr)) = &block.terminator else {
            continue;
        };

        // Only simplify bare `rax` returns (not propagated expressions)
        if !matches!(expr, Expr::Var(Var::Reg(RegId::Rax, _))) {
            continue;
        }

        block.terminator = Terminator::Return(None);
    }
}
