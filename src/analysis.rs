use crate::dataflow;
use crate::ir::*;
use crate::pass::{Pass, PassContext, PassManager, PassPhase};
use crate::typing;
use std::collections::{HashMap, HashSet};

/// Sentinel address for fs:0x28 (stack canary).
/// lift_memory_operand maps `fs:disp` to `0xFFFF_FFFF_FFFF_E000 + disp`.
const FS_CANARY_ADDR: u64 = 0xFFFF_FFFF_FFFF_E000u64.wrapping_add(0x28);

// ── Pass structs ─────────────────────────────────────────────────
// Each struct wraps an existing pass function behind the Pass trait.

macro_rules! define_pass {
    ($name:ident, $phase:expr, $display:expr, |$func:ident, $ctx:ident| $body:expr) => {
        pub struct $name;
        impl Pass for $name {
            fn name(&self) -> &'static str { $display }
            fn phase(&self) -> PassPhase { $phase }
            fn run(&self, $func: &mut Function, $ctx: &PassContext) -> bool { $body }
        }
    };
}

// Early passes
define_pass!(NoreturnElimination, PassPhase::Early, "noreturn_elimination",
    |func, ctx| { noreturn_elimination(func, &ctx.noreturn_addrs); true });
define_pass!(StackCanaryElimination, PassPhase::Early, "stack_canary_elimination",
    |func, _ctx| { eliminate_stack_canary(func); true });

// Iterative passes
define_pass!(ConstantFold, PassPhase::Iterative, "constant_fold",
    |func, _ctx| constant_fold(func));
define_pass!(DeadNopElimination, PassPhase::Iterative, "dead_nop_elimination",
    |func, _ctx| dead_nop_elimination(func));
define_pass!(CopyPropagation, PassPhase::Iterative, "copy_propagation",
    |func, _ctx| copy_propagation(func));
define_pass!(ExpressionInlining, PassPhase::Iterative, "expression_inlining",
    |func, _ctx| expression_inlining(func));
define_pass!(CrossBlockTempInlining, PassPhase::Late, "cross_block_temp_inlining",
    |func, _ctx| cross_block_temp_inlining(func));
define_pass!(DeadStoreElimination, PassPhase::Iterative, "dead_store_elimination",
    |func, _ctx| dead_store_elimination(func));
define_pass!(LocalDeadStoreElimination, PassPhase::Iterative, "local_dead_store_elimination",
    |func, _ctx| local_dead_store_elimination(func));
define_pass!(StackVariableRecovery, PassPhase::Iterative, "stack_variable_recovery",
    |func, _ctx| stack_variable_recovery(func));
define_pass!(AbsorbCallArgs, PassPhase::Iterative, "absorb_call_args",
    |func, _ctx| absorb_call_args(func));
define_pass!(AbsorbCallResult, PassPhase::Iterative, "absorb_call_result",
    |func, _ctx| absorb_call_result(func));
define_pass!(PropagateCallResults, PassPhase::Iterative, "propagate_call_results",
    |func, _ctx| propagate_call_results(func));
define_pass!(TrimCallArgs, PassPhase::Iterative, "trim_call_args",
    |func, ctx| trim_call_args(func, &ctx.callee_param_counts));
define_pass!(EliminateUnusedCallResults, PassPhase::Iterative, "eliminate_unused_call_results",
    |func, _ctx| eliminate_unused_call_results(func));

// Repeated pass
define_pass!(CrossBlockPropagation, PassPhase::Repeated, "cross_block_propagation",
    |func, _ctx| { cross_block_propagation(func); true });

// Late passes
define_pass!(SubstituteParamRegs, PassPhase::Late, "substitute_param_regs",
    |func, _ctx| { substitute_param_regs(func); true });
define_pass!(EliminateSelfAssignments, PassPhase::Late, "eliminate_self_assignments",
    |func, _ctx| { eliminate_self_assignments(func); true });
define_pass!(PromoteCalleeSaved, PassPhase::Late, "promote_callee_saved",
    |func, _ctx| { promote_callee_saved_to_locals(func); true });
define_pass!(PromoteAllRegs, PassPhase::Late, "promote_all_regs",
    |func, _ctx| { promote_all_regs_to_locals(func); true });
define_pass!(FoldTempReturns, PassPhase::Late, "fold_temp_returns",
    |func, _ctx| { fold_temp_returns(func); true });
define_pass!(FoldZeroInitBuffers, PassPhase::Late, "fold_zero_init_buffers",
    |func, _ctx| { fold_zero_init_buffers(func); true });
define_pass!(InferBufferSizesPass, PassPhase::Late, "infer_buffer_sizes",
    |func, _ctx| { infer_buffer_sizes(func); true });
define_pass!(FoldReturnValues, PassPhase::Late, "fold_return_values",
    |func, _ctx| { fold_return_values(func); true });
define_pass!(SimplifyVoidReturnsPass, PassPhase::Late, "simplify_void_returns",
    |func, _ctx| { simplify_void_returns(func); true });
define_pass!(TypeInference, PassPhase::Late, "type_inference",
    |func, _ctx| { typing::infer_types(func); true });

/// Build a PassManager with the default set of passes.
pub fn default_pass_manager() -> PassManager {
    let mut pm = PassManager::new();
    // Early
    pm.add(Box::new(NoreturnElimination));
    pm.add(Box::new(StackCanaryElimination));
    // Iterative
    pm.add(Box::new(ConstantFold));
    pm.add(Box::new(DeadNopElimination));
    pm.add(Box::new(CopyPropagation));
    pm.add(Box::new(ExpressionInlining));
    pm.add(Box::new(DeadStoreElimination));
    pm.add(Box::new(LocalDeadStoreElimination));
    pm.add(Box::new(StackVariableRecovery));
    pm.add(Box::new(AbsorbCallArgs));
    pm.add(Box::new(AbsorbCallResult));
    pm.add(Box::new(PropagateCallResults));
    pm.add(Box::new(TrimCallArgs));
    pm.add(Box::new(EliminateUnusedCallResults));
    // Repeated
    pm.add(Box::new(CrossBlockPropagation));
    // Late
    pm.add(Box::new(SubstituteParamRegs));
    pm.add(Box::new(EliminateSelfAssignments));
    pm.add(Box::new(PromoteCalleeSaved));
    pm.add(Box::new(FoldReturnValues));
    pm.add(Box::new(PromoteAllRegs));
    pm.add(Box::new(CrossBlockTempInlining));
    pm.add(Box::new(FoldTempReturns));
    pm.add(Box::new(FoldZeroInitBuffers));
    pm.add(Box::new(InferBufferSizesPass));
    pm.add(Box::new(SimplifyVoidReturnsPass));
    pm.add(Box::new(TypeInference));
    pm
}

// ── Entry points ─────────────────────────────────────────────────

/// Run all optimization passes on a function (legacy entry point).
pub fn optimize(
    func: &mut Function,
    noreturn_addrs: &HashSet<u64>,
    callee_param_counts: &HashMap<u64, usize>,
) {
    let pm = default_pass_manager();
    let ctx = PassContext {
        noreturn_addrs: noreturn_addrs.clone(),
        callee_param_counts: callee_param_counts.clone(),
    };
    pm.run_all(func, &ctx);
}

/// Run all optimization passes with a custom PassManager (for CLI options).
pub fn optimize_with(
    func: &mut Function,
    pm: &PassManager,
    noreturn_addrs: &HashSet<u64>,
    callee_param_counts: &HashMap<u64, usize>,
) {
    let ctx = PassContext {
        noreturn_addrs: noreturn_addrs.clone(),
        callee_param_counts: callee_param_counts.clone(),
    };
    pm.run_all(func, &ctx);
}

fn block_indices_by_addr(func: &Function) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..func.blocks.len()).collect();
    indices.sort_by_key(|&idx| (func.blocks[idx].addr, idx));
    indices
}

/// Detect how many parameters a function takes by finding param registers
/// that are read before being written.
pub fn detect_param_count(func: &Function) -> usize {
    let param_regs = func.calling_conv.param_regs();
    let mut read_before_write: HashSet<RegId> = HashSet::new();
    let mut written: HashSet<RegId> = HashSet::new();

    for block_idx in block_indices_by_addr(func) {
        let block = &func.blocks[block_idx];
        for stmt in &block.stmts {
            // Collect reads from RHS first
            match stmt {
                Stmt::Assign(_, expr) => {
                    collect_param_reads(expr, param_regs, &written, &mut read_before_write);
                }
                Stmt::Store(addr, val, _) => {
                    collect_param_reads(addr, param_regs, &written, &mut read_before_write);
                    collect_param_reads(val, param_regs, &written, &mut read_before_write);
                }
                Stmt::Call(_, target, _args) => {
                    // Only check the call target, NOT the args — raw call args
                    // contain all 6 ABI registers as noise before trim_call_args runs.
                    collect_param_reads(target, param_regs, &written, &mut read_before_write);
                }
                Stmt::Nop => {}
            }
            // Then record writes
            match stmt {
                Stmt::Assign(Var::Reg(r, _), _) => { written.insert(*r); }
                Stmt::Call(Some(Var::Reg(r, _)), _, _) => { written.insert(*r); }
                _ => {}
            }
        }
        // Check terminator reads
        match &block.terminator {
            Terminator::Return(Some(e)) | Terminator::Branch(e, _, _) => {
                collect_param_reads(e, param_regs, &written, &mut read_before_write);
            }
            _ => {}
        }
    }

    // Find highest param reg index that's read-before-write
    let mut count = 0;
    for (i, reg) in param_regs.iter().enumerate() {
        if read_before_write.contains(reg) {
            count = i + 1;
        }
    }
    count
}

fn collect_param_reads(
    expr: &Expr,
    param_regs: &[RegId],
    written: &HashSet<RegId>,
    out: &mut HashSet<RegId>,
) {
    match expr {
        Expr::Var(Var::Reg(r, _)) => {
            if param_regs.contains(r) && !written.contains(r) {
                out.insert(*r);
            }
        }
        Expr::BinOp(_, l, r) | Expr::Cmp(_, l, r)
        | Expr::LogicalAnd(l, r) | Expr::LogicalOr(l, r) => {
            collect_param_reads(l, param_regs, written, out);
            collect_param_reads(r, param_regs, written, out);
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
            collect_param_reads(inner, param_regs, written, out);
        }
        Expr::Select(c, t, f) => {
            collect_param_reads(c, param_regs, written, out);
            collect_param_reads(t, param_regs, written, out);
            collect_param_reads(f, param_regs, written, out);
        }
        _ => {}
    }
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
                    Terminator::Switch(_, cases, default) => {
                        for (_, bid) in cases { worklist.push(*bid); }
                        if let Some(d) = default { worklist.push(*d); }
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
                if let Some(ref reg_key) = canary_reg
                    && let Var::Stack(off, _) = var
                        && let Expr::Var(src_var) = expr
                            && format!("{src_var}") == *reg_key {
                                canary_stack_key = Some(format!("{var}"));
                                canary_stack_off = Some(*off);
                                break 'outer;
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
                    if let Expr::Load(addr, _) = expr
                        && let Some(off) = extract_stack_offset(addr, func.has_frame_pointer)
                            && off == canary_off {
                                return false;
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

        // Simplify canary-guarding branches: only fold when exactly one side is unreachable.
        // If both sides are reachable, keep the conditional branch to avoid semantic changes.
        if let Terminator::Branch(cond, t, f) = &block.terminator
            && (expr_references_canary(cond) || expr_uses_var_key(cond, &canary_key)) {
                let t_unreachable = unreachable_blocks.contains(t);
                let f_unreachable = unreachable_blocks.contains(f);
                if t_unreachable && !f_unreachable {
                    block.terminator = Terminator::Jump(*f);
                } else if f_unreachable && !t_unreachable {
                    block.terminator = Terminator::Jump(*t);
                }
                // If both reachable or both unreachable, leave the branch as-is.
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
                    Terminator::Switch(_, cases, default) => {
                        for (_, bid) in cases { worklist.push(*bid); }
                        if let Some(d) = default { worklist.push(*d); }
                    }
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
        Expr::BinOp(_, l, r) | Expr::Cmp(_, l, r)
        | Expr::LogicalAnd(l, r) | Expr::LogicalOr(l, r) => {
            expr_references_canary(l) || expr_references_canary(r)
        }
        Expr::Select(c, t, f) => {
            expr_references_canary(c) || expr_references_canary(t) || expr_references_canary(f)
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
                    // Only fold when total size is large enough to be a real buffer,
                    // not just a pair of zero-initialized scalar variables (e.g. sum=0, i=0).
                    if total_bytes >= 16 {
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
                }
            } else {
                i += 1;
            }
        }
    }
}

// ── Buffer size inference ────────────────────────────────────────

/// Infer stack buffer sizes from usage evidence.
///
/// Sources of evidence:
/// 1. Folded zero-init markers: `Assign(Stack(off, Bit8), Const(total, Bit64))` with total >= 16
/// 2. Call arguments: when `&var_XX` appears alongside a constant size argument,
///    e.g. `memset(&buf, 0, 64)`, `read(fd, &buf, 80)`, `fgets(&buf, 64, stream)`.
///
/// For each stack offset, records the **maximum** size seen across all evidence.
fn infer_buffer_sizes(func: &mut Function) {
    let mut sizes: HashMap<i64, u64> = HashMap::new();

    for block in &func.blocks {
        for stmt in &block.stmts {
            match stmt {
                // Source 1: folded zero-init marker (local variables only)
                Stmt::Assign(Var::Stack(off, BitWidth::Bit8), Expr::Const(total, BitWidth::Bit64))
                    if *total >= 16 && *off < 0 =>
                {
                    let entry = sizes.entry(*off).or_insert(0);
                    *entry = (*entry).max(*total);
                }
                // Source 2: call with &var_XX and a constant size arg
                Stmt::Call(_, _, args) => {
                    // Collect all local stack buffer references from AddrOf args
                    let buf_offsets: Vec<i64> = args
                        .iter()
                        .filter_map(|a| {
                            if let Expr::UnaryOp(UnaryOp::AddrOf, inner) = a
                                && let Expr::Var(Var::Stack(off, BitWidth::Bit8)) = inner.as_ref()
                                    && *off < 0 {
                                        return Some(*off);
                                    }
                            None
                        })
                        .collect();

                    if buf_offsets.is_empty() {
                        continue;
                    }

                    // Collect all constant values from other args as candidate sizes
                    let const_vals: Vec<u64> = args
                        .iter()
                        .filter_map(|a| {
                            if let Expr::Const(v, _) = a {
                                // Filter out unlikely sizes: 0, very small, or huge values
                                if *v >= 2 && *v <= 0x10000 {
                                    return Some(*v);
                                }
                            }
                            None
                        })
                        .collect();

                    // Associate each buffer with the max constant size in this call
                    if let Some(&max_size) = const_vals.iter().max() {
                        for off in &buf_offsets {
                            let entry = sizes.entry(*off).or_insert(0);
                            *entry = (*entry).max(max_size);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    func.buffer_sizes = sizes;
}

// ── Cross-block dataflow ─────────────────────────────────────────

/// Propagate register values across block boundaries using dataflow analysis.
/// Uses the generic reaching-definitions framework from `dataflow.rs` for
/// worklist-based fixpoint iteration (replacing hardcoded 20-iteration cap).
fn cross_block_propagation(func: &mut Function) {
    let reaching = dataflow::reaching_definitions(func);

    // Apply: for each block, use its incoming reaching defs to propagate into stmts/terminators
    for i in 0..func.blocks.len() {
        let bid = func.blocks[i].id;
        let Some(defs) = reaching.get(&bid) else { continue };
        let Some(incoming) = defs.as_map() else { continue };
        if incoming.is_empty() {
            continue;
        }

        // Clone the incoming map so we can invalidate entries as we
        // encounter Stores within the block.
        let mut live_copies: HashMap<String, Expr> = incoming.clone();

        for stmt in &mut func.blocks[i].stmts {
            match stmt {
                Stmt::Assign(var, expr) => {
                    propagate_copies(expr, &live_copies);
                    // This definition kills any incoming copy for the same var
                    let key = format!("{var}");
                    live_copies.remove(&key);
                }
                Stmt::Store(addr, val, _) => {
                    propagate_copies(addr, &live_copies);
                    propagate_copies(val, &live_copies);
                    // A store may invalidate any copy whose value reads memory
                    live_copies.retain(|_, v| !expr_contains_load(v));
                }
                Stmt::Call(_, target, args) => {
                    propagate_copies(target, &live_copies);
                    for a in args.iter_mut() {
                        propagate_copies(a, &live_copies);
                    }
                    // Calls may clobber everything
                    live_copies.clear();
                }
                _ => {}
            }
        }
        match &mut func.blocks[i].terminator {
            Terminator::Branch(cond, _, _) => {
                propagate_copies(cond, &live_copies);
            }
            Terminator::Return(Some(val)) => {
                propagate_copies(val, &live_copies);
            }
            Terminator::IndirectJump(target) => {
                propagate_copies(target, &live_copies);
            }
            Terminator::Switch(val, _, _) => {
                propagate_copies(val, &live_copies);
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
            Terminator::Switch(val, _, _) => {
                if let Some(folded) = fold_expr(val) {
                    *val = folded;
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
                let l = new_lhs.unwrap_or_else(|| *lhs.clone());
                let r = new_rhs.unwrap_or_else(|| *rhs.clone());
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
                let l = new_lhs.unwrap_or_else(|| *lhs.clone());
                let r = new_rhs.unwrap_or_else(|| *rhs.clone());
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
                    BinOp::Rol => Some(l.rotate_left(*r as u32)),
                    BinOp::Ror => Some(l.rotate_right(*r as u32)),
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
                    // x + x → x << 1  (compiler strength-reduction for *2)
                    if lhs == rhs {
                        return Some(Expr::BinOp(
                            BinOp::Shl,
                            lhs.clone(),
                            Box::new(Expr::Const(1, BitWidth::Bit8)),
                        ));
                    }
                }
                BinOp::Sub => {
                    if matches!(rhs.as_ref(), Expr::Const(0, _)) {
                        return Some(*lhs.clone());
                    }
                    // Sub(0, x) → Neg(x)
                    if matches!(lhs.as_ref(), Expr::Const(0, _)) {
                        return Some(Expr::UnaryOp(UnaryOp::Neg, rhs.clone()));
                    }
                    // Sub(x, negative_const) → Add(x, -negative_const)
                    // e.g. Sub(x, 0xFFFFFFFF) → Add(x, 1) for 32-bit
                    if let Expr::Const(c, w) = rhs.as_ref() {
                        let is_neg = match w {
                            BitWidth::Bit8 => *c > 0x7F && *c <= 0xFF,
                            BitWidth::Bit16 => *c > 0x7FFF && *c <= 0xFFFF,
                            BitWidth::Bit32 => *c > 0x7FFF_FFFF && *c <= 0xFFFF_FFFF,
                            BitWidth::Bit64 => *c > 0x7FFF_FFFF_FFFF_FFFF,
                        };
                        if is_neg {
                            let neg_c = match w {
                                BitWidth::Bit8 => (!*c).wrapping_add(1) & 0xFF,
                                BitWidth::Bit16 => (!*c).wrapping_add(1) & 0xFFFF,
                                BitWidth::Bit32 => (!*c).wrapping_add(1) & 0xFFFF_FFFF,
                                BitWidth::Bit64 => (!*c).wrapping_add(1),
                            };
                            return Some(Expr::BinOp(
                                BinOp::Add,
                                lhs.clone(),
                                Box::new(Expr::Const(neg_c, *w)),
                            ));
                        }
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
                    // And(x, 0xFF) → Trunc8(x), And(x, 0xFFFF) → Trunc16(x), etc.
                    if let Expr::Const(mask, _) = rhs.as_ref() {
                        let trunc_w = match *mask {
                            0xFF => Some(BitWidth::Bit8),
                            0xFFFF => Some(BitWidth::Bit16),
                            0xFFFF_FFFF => Some(BitWidth::Bit32),
                            _ => None,
                        };
                        if let Some(tw) = trunc_w {
                            if lhs.width().bytes() > tw.bytes() {
                                return Some(Expr::UnaryOp(UnaryOp::Trunc(tw), lhs.clone()));
                            }
                        }
                    }
                }
                BinOp::Shr | BinOp::Sar => {
                    // MSVC unsigned division pattern:
                    // Shr(Mul(ZeroExt(x), magic), 32+shift) → UDiv(x, divisor)
                    if matches!(op, BinOp::Shr) {
                        if let Some(div_expr) = try_fold_magic_udiv(lhs, rhs) {
                            return Some(div_expr);
                        }
                    }
                    // Signed division by 2 pattern:
                    // ((x >> 31) + x) >> 1  →  x / 2   (signed, rounds toward zero)
                    // Also handles 64-bit: ((x >> 63) + x) >> 1
                    // The inner >> can be Shr or Sar, the outer >> can be Shr or Sar.
                    if matches!(rhs.as_ref(), Expr::Const(1, _)) {
                        if let Expr::BinOp(BinOp::Add, a, b) = lhs.as_ref() {
                            // Check both orderings: (shr(x,31) + x) and (x + shr(x,31))
                            let matched = match (a.as_ref(), b.as_ref()) {
                                (Expr::BinOp(shift_op, x1, shift), x2)
                                    if matches!(shift_op, BinOp::Shr | BinOp::Sar)
                                    && matches!(shift.as_ref(), Expr::Const(31, _) | Expr::Const(63, _))
                                    && x1.as_ref() == x2 =>
                                {
                                    Some(x2)
                                }
                                (x2, Expr::BinOp(shift_op, x1, shift))
                                    if matches!(shift_op, BinOp::Shr | BinOp::Sar)
                                    && matches!(shift.as_ref(), Expr::Const(31, _) | Expr::Const(63, _))
                                    && x1.as_ref() == x2 =>
                                {
                                    Some(x2)
                                }
                                _ => None,
                            };
                            if let Some(x) = matched {
                                return Some(Expr::BinOp(
                                    BinOp::SDiv,
                                    Box::new(x.clone()),
                                    Box::new(Expr::Const(2, x.width())),
                                ));
                            }
                        }
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
        let expected_magic = pow.div_ceil(d);
        if expected_magic == m {
            return Some(d as u64);
        }
    }
    None
}

/// Recognize MSVC unsigned division pattern.
///
/// Pattern: `Shr(Mul(ZeroExt(x), magic), total_shift)` → `UDiv(x, divisor)`
/// Also: `Shr(Shr(Mul(ZeroExt(x), magic), 32), extra_shift)` (two-stage shift)
fn try_fold_magic_udiv(lhs: &Expr, rhs: &Expr) -> Option<Expr> {
    let Expr::Const(total_shift, _) = rhs else { return None };
    if *total_shift < 32 || *total_shift > 63 {
        return None;
    }

    // lhs could be Mul(ZeroExt(x), magic) directly
    let (mul_expr, extra_shift) = match lhs {
        Expr::BinOp(BinOp::Shr, inner, s) => {
            let Expr::Const(s_val, _) = s.as_ref() else { return None };
            (inner.as_ref(), *s_val)
        }
        _ => (lhs, 0),
    };

    let actual_shift = if extra_shift > 0 {
        // Two-stage: Shr(Shr(Mul(...), 32), extra_shift)
        // The outer Shr rhs is extra_shift, but we came here with total_shift = rhs
        // Actually this arm triggers for Shr(inner, total_shift) where inner is Shr(Mul(...),s_val)
        // so the total shift = s_val + total_shift
        extra_shift + total_shift
    } else {
        *total_shift
    };

    // mul_expr must be Mul(ZeroExt(x), Const(magic)) or vice-versa
    let (x, magic) = match mul_expr {
        Expr::BinOp(BinOp::Mul, a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::UnaryOp(UnaryOp::ZeroExt(_), x), Expr::Const(m, _)) => (x.as_ref(), *m),
            (Expr::Const(m, _), Expr::UnaryOp(UnaryOp::ZeroExt(_), x)) => (x.as_ref(), *m),
            _ => return None,
        },
        _ => return None,
    };

    let shift = actual_shift.saturating_sub(32);
    let divisor = magic_to_divisor(magic, shift)?;
    let w = x.width();
    Some(Expr::binop(BinOp::UDiv, x.clone(), Expr::const_val(divisor, w)))
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
                                copies.insert(key.clone(), expr.clone());
                            }
                            _ => {
                                copies.remove(&key);
                            }
                        }
                        // Invalidate any copies whose RHS references
                        // this variable (it was just reassigned).
                        let invalidated: Vec<String> = copies
                            .iter()
                            .filter(|(k, v)| *k != &key && expr_uses_var_key(v, &key))
                            .map(|(k, _)| k.clone())
                            .collect();
                        for k in invalidated {
                            copies.remove(&k);
                        }
                        // Also invalidate copies whose RHS contains a Load
                        // from the same stack offset (aliasing: Load(rbp-off) == var_off).
                        if let Var::Stack(off, _) = var {
                            let has_fp = func.has_frame_pointer;
                            let invalidated2: Vec<String> = copies
                                .iter()
                                .filter(|(k, v)| *k != &key && expr_contains_stack_load(v, *off, has_fp))
                                .map(|(k, _)| k.clone())
                                .collect();
                            for k in invalidated2 {
                                copies.remove(&k);
                            }
                        }
                    }
                }
            }
            // Calls may clobber registers
            if matches!(stmt, Stmt::Call(..)) {
                copies.clear();
            }
            // Stores may invalidate copies whose values are memory loads
            if matches!(stmt, Stmt::Store(..)) {
                copies.retain(|_, v| !expr_contains_load(v));
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
                                    copies2.insert(key.clone(), expr.clone());
                                }
                                _ => {
                                    copies2.remove(&key);
                                }
                            }
                            // Invalidate any copies whose RHS references
                            // this variable (it was just reassigned).
                            let invalidated: Vec<String> = copies2
                                .iter()
                                .filter(|(k, v)| *k != &key && expr_uses_var_key(v, &key))
                                .map(|(k, _)| k.clone())
                                .collect();
                            for k in invalidated {
                                copies2.remove(&k);
                            }
                            // Also invalidate copies whose RHS contains a Load
                            // from the same stack offset (aliasing: Load(rbp-off) == var_off).
                            if let Var::Stack(off, _) = var {
                                let has_fp = func.has_frame_pointer;
                                let invalidated2: Vec<String> = copies2
                                    .iter()
                                    .filter(|(k, v)| *k != &key && expr_contains_stack_load(v, *off, has_fp))
                                    .map(|(k, _)| k.clone())
                                    .collect();
                                for k in invalidated2 {
                                    copies2.remove(&k);
                                }
                            }
                        }
                    }
                }
                Stmt::Store(addr, val, _) => {
                    changed |= propagate_copies(addr, &copies2);
                    changed |= propagate_copies(val, &copies2);
                    // Stores may invalidate copies whose values are memory loads
                    copies2.retain(|_, v| !expr_contains_load(v));
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
            Terminator::Switch(val, _, _) => {
                changed |= propagate_copies(val, &copies2);
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
        Expr::Select(c, t, f) => {
            expr_uses_var_key(c, key) || expr_uses_var_key(t, key) || expr_uses_var_key(f, key)
        }
        _ => false,
    }
}

/// Check if an expression contains a Load from a specific stack offset.
/// This detects aliasing between `Load(rbp - off)` and `Var::Stack(-off)`.
fn expr_contains_stack_load(expr: &Expr, offset: i64, has_fp: bool) -> bool {
    match expr {
        Expr::Load(addr, _) => {
            if let Some(off) = extract_stack_offset(addr, has_fp) {
                if off == offset {
                    return true;
                }
            }
            expr_contains_stack_load(addr, offset, has_fp)
        }
        Expr::BinOp(_, l, r) | Expr::Cmp(_, l, r) => {
            expr_contains_stack_load(l, offset, has_fp) || expr_contains_stack_load(r, offset, has_fp)
        }
        Expr::UnaryOp(_, inner) => expr_contains_stack_load(inner, offset, has_fp),
        Expr::Select(c, t, f) => {
            expr_contains_stack_load(c, offset, has_fp) || expr_contains_stack_load(t, offset, has_fp) || expr_contains_stack_load(f, offset, has_fp)
        }
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
        Expr::Select(c, t, f) => {
            let a = propagate_copies(c, copies);
            let b = propagate_copies(t, copies);
            let d = propagate_copies(f, copies);
            a || b || d
        }
        _ => false,
    }
}

// ── Stack variable recovery ──────────────────────────────────────

/// Recover stack variables: replace RSP/RBP-relative memory accesses with named variables.
fn stack_variable_recovery(func: &mut Function) -> bool {
    let has_fp = func.has_frame_pointer;
    let frame_size = func.frame_size;
    let mut stack_vars: HashSet<i64> = HashSet::new();
    let mut changed = false;

    // Collect all stack offsets
    for block in &func.blocks {
        for stmt in &block.stmts {
            collect_stack_refs(stmt, &mut stack_vars, has_fp);
        }
    }

    // Replace stack memory accesses with stack variables
    {
        for block in &mut func.blocks {
            for stmt in &mut block.stmts {
                if replace_stack_refs(stmt, has_fp, frame_size) {
                    changed = true;
                }
            }
            // Also replace in terminators
            match &mut block.terminator {
                Terminator::Branch(cond, _, _) => {
                    if replace_stack_loads(cond, has_fp, frame_size) {
                        changed = true;
                    }
                }
                Terminator::Return(Some(val)) => {
                    if replace_stack_loads(val, has_fp, frame_size) {
                        changed = true;
                    }
                }
                Terminator::IndirectJump(target) => {
                    if replace_stack_loads(target, has_fp, frame_size) {
                        changed = true;
                    }
                }
                Terminator::Switch(val, _, _) => {
                    if replace_stack_loads(val, has_fp, frame_size) {
                        changed = true;
                    }
                }
                _ => {}
            }
        }
    }

    changed
}

fn collect_stack_refs(stmt: &Stmt, vars: &mut HashSet<i64>, has_fp: bool) {
    match stmt {
        Stmt::Assign(Var::Stack(off, _), _) => {
            vars.insert(*off);
        }
        Stmt::Store(addr, _, _) => {
            if let Some(off) = extract_stack_offset(addr, has_fp) {
                vars.insert(off);
            }
        }
        _ => {}
    }
}

fn extract_stack_offset(expr: &Expr, has_frame_pointer: bool) -> Option<i64> {
    let is_stack_base = |reg: &RegId| -> bool {
        matches!(reg, RegId::Rsp) || (has_frame_pointer && matches!(reg, RegId::Rbp))
    };
    match expr {
        Expr::Var(Var::Reg(reg, _)) if is_stack_base(reg) => Some(0),
        Expr::BinOp(BinOp::Add, lhs, rhs) => {
            if let Expr::Var(Var::Reg(reg, _)) = lhs.as_ref()
                && is_stack_base(reg)
                && let Expr::Const(val, w) = rhs.as_ref() {
                    return Some(sign_extend_offset(*val, *w));
                }
            None
        }
        Expr::BinOp(BinOp::Sub, lhs, rhs) => {
            if let Expr::Var(Var::Reg(reg, _)) = lhs.as_ref()
                && is_stack_base(reg)
                && let Expr::Const(val, w) = rhs.as_ref() {
                    return Some(-sign_extend_offset(*val, *w));
                }
            None
        }
        _ => None,
    }
}

/// Sign-extend a constant from its declared width to i64.
/// On x86, `ebp + 0xfffffff0` stores `0xfffffff0` as a Bit32 constant
/// which should be interpreted as `-16` (i32), not `4294967280` (u64).
fn sign_extend_offset(val: u64, width: BitWidth) -> i64 {
    match width {
        BitWidth::Bit8 => val as i8 as i64,
        BitWidth::Bit16 => val as i16 as i64,
        BitWidth::Bit32 => val as i32 as i64,
        BitWidth::Bit64 => val as i64,
    }
}

fn stack_base_reg_offset(reg: &RegId, has_frame_pointer: bool, frame_size: u64) -> Option<i64> {
    match reg {
        RegId::Rsp => Some(-(frame_size as i64)),
        RegId::Rbp if has_frame_pointer => Some(0),
        _ => None,
    }
}

fn extract_stack_address(
    expr: &Expr,
    has_frame_pointer: bool,
    frame_size: u64,
) -> Option<(i64, Option<Expr>)> {
    let mut base_offset: Option<i64> = None;
    let mut const_sum = 0i64;
    let mut dynamic_parts: Vec<Expr> = Vec::new();
    let mut valid = true;

    flatten_stack_address(
        expr,
        true,
        has_frame_pointer,
        frame_size,
        &mut base_offset,
        &mut const_sum,
        &mut dynamic_parts,
        &mut valid,
    );

    if !valid {
        return None;
    }

    let base = base_offset?;
    let dynamic = if dynamic_parts.is_empty() {
        None
    } else {
        let mut iter = dynamic_parts.into_iter();
        let mut acc = iter.next().unwrap();
        for part in iter {
            acc = Expr::binop(BinOp::Add, acc, part);
        }
        Some(acc)
    };

    Some((base.wrapping_add(const_sum), dynamic))
}

fn flatten_stack_address(
    expr: &Expr,
    positive: bool,
    has_frame_pointer: bool,
    frame_size: u64,
    base_offset: &mut Option<i64>,
    const_sum: &mut i64,
    dynamic_parts: &mut Vec<Expr>,
    valid: &mut bool,
) {
    if !*valid {
        return;
    }

    match expr {
        Expr::BinOp(BinOp::Add, lhs, rhs) => {
            flatten_stack_address(
                lhs,
                positive,
                has_frame_pointer,
                frame_size,
                base_offset,
                const_sum,
                dynamic_parts,
                valid,
            );
            flatten_stack_address(
                rhs,
                positive,
                has_frame_pointer,
                frame_size,
                base_offset,
                const_sum,
                dynamic_parts,
                valid,
            );
        }
        Expr::BinOp(BinOp::Sub, lhs, rhs) => {
            flatten_stack_address(
                lhs,
                positive,
                has_frame_pointer,
                frame_size,
                base_offset,
                const_sum,
                dynamic_parts,
                valid,
            );
            flatten_stack_address(
                rhs,
                !positive,
                has_frame_pointer,
                frame_size,
                base_offset,
                const_sum,
                dynamic_parts,
                valid,
            );
        }
        Expr::Var(Var::Reg(reg, _)) => {
            let Some(base) = stack_base_reg_offset(reg, has_frame_pointer, frame_size) else {
                if positive {
                    dynamic_parts.push(expr.clone());
                } else {
                    *valid = false;
                }
                return;
            };

            if !positive {
                *valid = false;
                return;
            }

            match base_offset {
                Some(existing) if *existing != base => *valid = false,
                Some(_) => {}
                None => *base_offset = Some(base),
            }
        }
        Expr::Const(val, width) => {
            let signed = sign_extend_offset(*val, *width);
            if positive {
                *const_sum = const_sum.wrapping_add(signed);
            } else {
                *const_sum = const_sum.wrapping_sub(signed);
            }
        }
        _ => {
            if positive {
                dynamic_parts.push(expr.clone());
            } else {
                *valid = false;
            }
        }
    }
}

fn make_stack_addr_expr(offset: i64, dynamic: Option<Expr>) -> Expr {
    let base = Expr::UnaryOp(
        UnaryOp::AddrOf,
        Box::new(Expr::Var(Var::Stack(offset, BitWidth::Bit8))),
    );

    match dynamic {
        Some(dynamic) => Expr::binop(BinOp::Add, base, dynamic),
        None => base,
    }
}

fn replace_stack_refs(stmt: &mut Stmt, has_fp: bool, frame_size: u64) -> bool {
    match stmt {
        Stmt::Store(addr, val, width) => {
            if let Some((off, None)) = extract_stack_address(addr, has_fp, frame_size) {
                let var = Var::Stack(off, *width);
                *stmt = Stmt::Assign(var, val.clone());
                return true;
            }
            // Even if the full address doesn't match rsp+const,
            // recurse to replace bare rsp inside the address expression.
            let a = replace_stack_loads(addr, has_fp, frame_size);
            let b = replace_stack_loads(val, has_fp, frame_size);
            a || b
        }
        Stmt::Assign(_, expr) => {
            // Convert stack-relative pointer expressions in RHS.
            if let Some((off, dynamic)) = extract_stack_address(expr, has_fp, frame_size) {
                *expr = make_stack_addr_expr(off, dynamic);
                return true;
            }
            replace_stack_loads(expr, has_fp, frame_size)
        }
        Stmt::Call(_, target, args) => {
            let mut changed = replace_stack_loads(target, has_fp, frame_size);
            for arg in args.iter_mut() {
                // Convert bare stack-relative address to &var_XX
                if let Some((off, dynamic)) = extract_stack_address(arg, has_fp, frame_size) {
                    *arg = make_stack_addr_expr(off, dynamic);
                    changed = true;
                } else {
                    changed |= replace_stack_loads(arg, has_fp, frame_size);
                }
            }
            changed
        }
        _ => false,
    }
}

fn replace_stack_loads(expr: &mut Expr, has_fp: bool, frame_size: u64) -> bool {
    if !matches!(expr, Expr::Load(_, _)) {
        if let Some((off, dynamic)) = extract_stack_address(expr, has_fp, frame_size) {
            *expr = make_stack_addr_expr(off, dynamic);
            return true;
        }
    }

    match expr {
        Expr::Load(addr, width) => {
            if let Some((off, None)) = extract_stack_address(addr, has_fp, frame_size) {
                *expr = Expr::Var(Var::Stack(off, *width));
                return true;
            }
            // Even if this Load isn't a direct stack access, recurse into its
            // address sub-expression (e.g. *(u32*)*(u64*)(rbp + off) — the
            // inner Load(rbp+off) should still become var_N).
            replace_stack_loads(addr, has_fp, frame_size)
        }
        Expr::BinOp(_, lhs, rhs) => {
            let a = replace_stack_loads(lhs, has_fp, frame_size);
            let b = replace_stack_loads(rhs, has_fp, frame_size);
            a || b
        }
        Expr::UnaryOp(_, inner) => replace_stack_loads(inner, has_fp, frame_size),
        Expr::Cmp(_, lhs, rhs) => {
            let a = replace_stack_loads(lhs, has_fp, frame_size);
            let b = replace_stack_loads(rhs, has_fp, frame_size);
            a || b
        }
        Expr::LogicalAnd(lhs, rhs) | Expr::LogicalOr(lhs, rhs) => {
            let a = replace_stack_loads(lhs, has_fp, frame_size);
            let b = replace_stack_loads(rhs, has_fp, frame_size);
            a || b
        }
        Expr::Select(cond, true_val, false_val) => {
            let a = replace_stack_loads(cond, has_fp, frame_size);
            let b = replace_stack_loads(true_val, has_fp, frame_size);
            let c = replace_stack_loads(false_val, has_fp, frame_size);
            a || b || c
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
                // Safety check: if expr contains a Load (memory read), and
                // there is an intervening Store or Call between the def and
                // the use, inlining would change the execution order and
                // potentially read a different value.
                let has_load = expr_contains_load(expr);
                if has_load {
                    // Find use site and check for intervening side effects
                    let mut use_idx = None;
                    for i in (*def_idx + 1)..func.blocks[block_idx].stmts.len() {
                        if stmt_mentions_var(&func.blocks[block_idx].stmts[i], key) {
                            use_idx = Some(i);
                            break;
                        }
                    }
                    if let Some(ui) = use_idx {
                        let has_intervening = (*def_idx + 1..ui).any(|i| {
                            matches!(
                                &func.blocks[block_idx].stmts[i],
                                Stmt::Store(..) | Stmt::Call(..)
                            )
                        });
                        if has_intervening {
                            continue; // skip this inlining — unsafe
                        }
                    }
                }

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

// ── Cross-block temp inlining ────────────────────────────────────

/// Cross-block temp inlining: inline temp variables used exactly once across
/// the entire function (not just within a single block).
///
/// This runs as a Late pass after PromoteAllRegs, when the IR is stable and
/// most temps are already resolved. It handles patterns like:
///   block A: t1 = arg_1      (save caller's arg across call)
///   block A: call foo(...)
///   block A/B: ...use t1...
fn cross_block_temp_inlining(func: &mut Function) -> bool {
    let mut changed = false;

    // Step 1: Collect all temp definitions: temp_key -> (block_idx, stmt_idx, expr)
    // Only consider temps defined exactly once.
    let mut temp_defs: HashMap<String, (usize, usize, Expr)> = HashMap::new();
    let mut multi_def: HashSet<String> = HashSet::new();

    for (bi, block) in func.blocks.iter().enumerate() {
        for (si, stmt) in block.stmts.iter().enumerate() {
            if let Stmt::Assign(var @ Var::Temp(_, _), expr) = stmt {
                let key = format!("{var}");
                if multi_def.contains(&key) {
                    continue;
                }
                if temp_defs.contains_key(&key) {
                    multi_def.insert(key.clone());
                    temp_defs.remove(&key);
                } else {
                    temp_defs.insert(key, (bi, si, expr.clone()));
                }
            }
        }
    }

    // Step 2: Count global uses of each temp across all blocks.
    let mut global_uses: HashMap<String, usize> = HashMap::new();
    for block in &func.blocks {
        for stmt in &block.stmts {
            count_temp_uses_in_stmt(stmt, &mut global_uses);
        }
        count_temp_uses_in_terminator(&block.terminator, &mut global_uses);
    }

    // Step 3: Inline temps used exactly once, with safety checks.
    let mut to_nop: Vec<(usize, usize)> = Vec::new(); // (block_idx, stmt_idx)
    for (key, (def_bi, def_si, expr)) in &temp_defs {
        if global_uses.get(key).copied().unwrap_or(0) != 1 {
            continue;
        }

        // Skip if expr contains a Load and there might be intervening side effects
        // across block boundaries — too complex to verify safety.
        if expr_contains_load(expr) {
            continue;
        }

        // Skip if expr references variables that might be reassigned between
        // def and use. Only allow exprs that consist solely of constants,
        // other temps, args, and stack vars (which don't get reassigned
        // between blocks in practice at this late stage).
        if expr_contains_call_or_store(expr) {
            continue;
        }

        // Find the use site
        let mut found = false;
        for bi in 0..func.blocks.len() {
            // Within the def block, only scan stmts after the def
            let start_si = if bi == *def_bi { *def_si + 1 } else { 0 };
            for si in start_si..func.blocks[bi].stmts.len() {
                if stmt_mentions_var(&func.blocks[bi].stmts[si], key) {
                    // Check: between def and use, is there a Call or Store that
                    // could affect any sub-expression of expr?
                    if bi == *def_bi {
                        // Same block: check intervening stmts
                        let has_intervening = (*def_si + 1..si).any(|i| {
                            stmt_may_clobber_expr(&func.blocks[*def_bi].stmts[i], expr)
                        });
                        if has_intervening { break; }
                    } else {
                        // Different block: check if any var in expr might be
                        // reassigned. Only safe for simple exprs (Var, Const).
                        if !expr_is_stable_across_blocks(expr) { break; }
                    }

                    inline_var_in_stmt(&mut func.blocks[bi].stmts[si], key, expr);
                    to_nop.push((*def_bi, *def_si));
                    changed = true;
                    found = true;
                    break;
                }
            }
            if found { break; }

            // Check terminator
            if inline_var_in_terminator(&mut func.blocks[bi].terminator, key, expr) {
                if bi == *def_bi {
                    let has_intervening = (*def_si + 1..func.blocks[bi].stmts.len()).any(|i| {
                        stmt_may_clobber_expr(&func.blocks[*def_bi].stmts[i], expr)
                    });
                    if has_intervening {
                        // Undo — re-insert the var
                        // Actually we already mutated...skip this case
                        continue;
                    }
                } else if !expr_is_stable_across_blocks(expr) {
                    continue;
                }
                to_nop.push((*def_bi, *def_si));
                changed = true;
                found = true;
            }
            if found { break; }
        }
    }

    // Remove inlined definitions
    for (bi, si) in &to_nop {
        func.blocks[*bi].stmts[*si] = Stmt::Nop;
    }

    // Step 3b: Multi-use temp copy propagation.
    // If temp is defined once as a stable expression (no Load, no Call,
    // consists only of stable vars/consts/temps/stack) and temp is never
    // reassigned, replace ALL uses of temp with its definition.

    // For each eligible temp, replace all uses across all blocks.
    // Repeat in rounds because propagating t_a = val may expose new
    // opportunities when another temp t_b = expr(t_a) now becomes simple.
    // Process one temp per round to avoid cascading issues.
    loop {
        // Rebuild defs from current state (defs may have been noped)
        let mut round_defs: HashMap<String, (usize, usize, Expr)> = HashMap::new();
        let mut round_multi: HashSet<String> = HashSet::new();
        for (bi, block) in func.blocks.iter().enumerate() {
            for (si, stmt) in block.stmts.iter().enumerate() {
                if let Stmt::Assign(var @ Var::Temp(_, _), expr) = stmt {
                    let key = format!("{var}");
                    if round_multi.contains(&key) { continue; }
                    if round_defs.contains_key(&key) {
                        round_multi.insert(key.clone());
                        round_defs.remove(&key);
                    } else {
                        round_defs.insert(key, (bi, si, expr.clone()));
                    }
                }
            }
        }

        // Find the first eligible temp to propagate
        let mut propagated = false;
        for (key, (def_bi, def_si, expr)) in &round_defs {
            if !expr_is_stable_across_blocks(expr) { continue; }
            if expr_contains_load(expr) || expr_contains_call_or_store(expr) { continue; }

            let mut use_count = 0usize;
            for bi in 0..func.blocks.len() {
                // Scan ALL stmts in all blocks, but skip the def stmt itself
                for si in 0..func.blocks[bi].stmts.len() {
                    if bi == *def_bi && si == *def_si { continue; } // skip the def
                    if stmt_mentions_var(&func.blocks[bi].stmts[si], key) {
                        inline_var_in_stmt(&mut func.blocks[bi].stmts[si], key, expr);
                        use_count += 1;
                    }
                }
                if inline_var_in_terminator(&mut func.blocks[bi].terminator, key, expr) {
                    use_count += 1;
                }
            }
            if use_count > 0 {
                func.blocks[*def_bi].stmts[*def_si] = Stmt::Nop;
                changed = true;
                propagated = true;
                break; // restart round with fresh state
            }
        }
        if !propagated { break; }
    }

    changed
}

/// Count uses of temp variables in a statement.
fn count_temp_uses_in_stmt(stmt: &Stmt, counts: &mut HashMap<String, usize>) {
    match stmt {
        Stmt::Assign(_, expr) => count_temp_uses_in_expr(expr, counts),
        Stmt::Store(addr, val, _) => {
            count_temp_uses_in_expr(addr, counts);
            count_temp_uses_in_expr(val, counts);
        }
        Stmt::Call(_, target, args) => {
            count_temp_uses_in_expr(target, counts);
            for a in args {
                count_temp_uses_in_expr(a, counts);
            }
        }
        Stmt::Nop => {}
    }
}

fn count_temp_uses_in_terminator(term: &Terminator, counts: &mut HashMap<String, usize>) {
    match term {
        Terminator::Branch(cond, _, _) => count_temp_uses_in_expr(cond, counts),
        Terminator::Return(Some(v)) => count_temp_uses_in_expr(v, counts),
        Terminator::IndirectJump(t) => count_temp_uses_in_expr(t, counts),
        Terminator::Switch(v, _, _) => count_temp_uses_in_expr(v, counts),
        _ => {}
    }
}

fn count_temp_uses_in_expr(expr: &Expr, counts: &mut HashMap<String, usize>) {
    match expr {
        Expr::Var(v @ Var::Temp(_, _)) => {
            *counts.entry(format!("{v}")).or_insert(0) += 1;
        }
        Expr::BinOp(_, l, r) | Expr::Cmp(_, l, r)
        | Expr::LogicalAnd(l, r) | Expr::LogicalOr(l, r) => {
            count_temp_uses_in_expr(l, counts);
            count_temp_uses_in_expr(r, counts);
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
            count_temp_uses_in_expr(inner, counts);
        }
        Expr::Select(c, t, f) => {
            count_temp_uses_in_expr(c, counts);
            count_temp_uses_in_expr(t, counts);
            count_temp_uses_in_expr(f, counts);
        }
        _ => {}
    }
}

/// Check if an expression contains a Call or Store (shouldn't be in expr trees, but guard).
fn expr_contains_call_or_store(_expr: &Expr) -> bool {
    false // Exprs don't contain calls/stores; they're in Stmt
}

/// Check if an expression is "stable" across block boundaries — i.e., its
/// sub-expressions won't be modified by intervening statements in other blocks.
/// Conservative: only allow Var (args, stack vars, temps), Const, and simple ops on them.
fn expr_is_stable_across_blocks(expr: &Expr) -> bool {
    match expr {
        Expr::Var(Var::Temp(_, _)) => true, // temps aren't reassigned if single-def
        Expr::Var(Var::Stack(_, _)) => true, // stack vars stable at late stage
        Expr::Var(Var::Reg(_, _)) => true,   // after PromoteAllRegs, no more reg assigns
        Expr::Const(_, _) => true,
        Expr::BinOp(_, l, r) | Expr::Cmp(_, l, r) => {
            expr_is_stable_across_blocks(l) && expr_is_stable_across_blocks(r)
        }
        Expr::UnaryOp(_, inner) => expr_is_stable_across_blocks(inner),
        Expr::Load(_, _) => false, // memory reads not stable
        _ => false,
    }
}

/// Check if a statement might clobber any sub-expression in the given expr.
fn stmt_may_clobber_expr(stmt: &Stmt, expr: &Expr) -> bool {
    match stmt {
        Stmt::Call(..) => true, // calls can clobber anything
        Stmt::Store(..) => expr_contains_load(expr),
        Stmt::Assign(var, _) => {
            let key = format!("{var}");
            expr_mentions_var(expr, &key)
        }
        Stmt::Nop => false,
    }
}

/// Check if an expression contains a Load (memory read).
fn expr_contains_load(expr: &Expr) -> bool {
    match expr {
        Expr::Load(_, _) => true,
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs)
        | Expr::LogicalAnd(lhs, rhs) | Expr::LogicalOr(lhs, rhs) => {
            expr_contains_load(lhs) || expr_contains_load(rhs)
        }
        Expr::UnaryOp(_, inner) => expr_contains_load(inner),
        Expr::Select(c, t, f) => {
            expr_contains_load(c) || expr_contains_load(t) || expr_contains_load(f)
        }
        _ => false,
    }
}

/// Check if a statement references a variable by key string (in its RHS).
fn stmt_mentions_var(stmt: &Stmt, key: &str) -> bool {
    match stmt {
        Stmt::Assign(_, expr) => expr_mentions_var(expr, key),
        Stmt::Store(addr, val, _) => expr_mentions_var(addr, key) || expr_mentions_var(val, key),
        Stmt::Call(_, target, args) => {
            expr_mentions_var(target, key) || args.iter().any(|a| expr_mentions_var(a, key))
        }
        Stmt::Nop => false,
    }
}

fn expr_mentions_var(expr: &Expr, key: &str) -> bool {
    match expr {
        Expr::Var(v) => format!("{v}") == key,
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs)
        | Expr::LogicalAnd(lhs, rhs) | Expr::LogicalOr(lhs, rhs) => {
            expr_mentions_var(lhs, key) || expr_mentions_var(rhs, key)
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => expr_mentions_var(inner, key),
        Expr::Select(c, t, f) => {
            expr_mentions_var(c, key) || expr_mentions_var(t, key) || expr_mentions_var(f, key)
        }
        _ => false,
    }
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
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs)
        | Expr::LogicalAnd(lhs, rhs) | Expr::LogicalOr(lhs, rhs) => {
            count_expr_uses(lhs, counts);
            count_expr_uses(rhs, counts);
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
            count_expr_uses(inner, counts);
        }
        Expr::Select(c, t, f) => {
            count_expr_uses(c, counts);
            count_expr_uses(t, counts);
            count_expr_uses(f, counts);
        }
        _ => {}
    }
}

fn inline_var_in_stmt(stmt: &mut Stmt, key: &str, replacement: &Expr) -> bool {
    match stmt {
        Stmt::Assign(_, expr) => inline_var_in_expr(expr, key, replacement),
        Stmt::Store(addr, val, _) => {
            let a = inline_var_in_expr(addr, key, replacement);
            let b = inline_var_in_expr(val, key, replacement);
            a | b
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
            let a = inline_var_in_expr(lhs, key, replacement);
            let b = inline_var_in_expr(rhs, key, replacement);
            a | b
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
            inline_var_in_expr(inner, key, replacement)
        }
        Expr::Select(c, t, f) => {
            let a = inline_var_in_expr(c, key, replacement);
            let b = inline_var_in_expr(t, key, replacement);
            let d = inline_var_in_expr(f, key, replacement);
            a || b || d
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
        if let Some(fi) = succ.stmts.iter().position(|s| !matches!(s, Stmt::Nop))
            && matches!(
                &succ.stmts[fi],
                Stmt::Assign(Var::Stack(_, _), Expr::Var(Var::Reg(RegId::Rax, _)))
            ) {
                continue;
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

    // Precompute successors for each block index
    let succ_map: Vec<Vec<usize>> = func.blocks.iter().map(|b| {
        let ids = match &b.terminator {
            Terminator::Jump(t) => vec![*t],
            Terminator::Branch(_, t, f) => vec![*t, *f],
            Terminator::Switch(_, cases, def) => {
                let mut v: Vec<_> = cases.iter().map(|(_, bid)| *bid).collect();
                if let Some(d) = def { v.push(*d); }
                v
            }
            _ => vec![],
        };
        ids.into_iter().filter_map(|bid| id_to_idx.get(&bid).copied()).collect()
    }).collect();

    // Precompute predecessors for each block index
    let pred_map: Vec<Vec<usize>> = {
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); func.blocks.len()];
        for (i, succs) in succ_map.iter().enumerate() {
            for &s in succs {
                preds[s].push(i);
            }
        }
        preds
    };

    // Precompute which blocks redefine rax (or call)
    let rax_redefined_in: HashSet<usize> = func.blocks.iter().enumerate()
        .filter(|(_, block)| {
            block.stmts.iter().any(|s| matches!(s,
                Stmt::Assign(Var::Reg(RegId::Rax, _), _) | Stmt::Call(..)))
        })
        .map(|(i, _)| i)
        .collect();

    let mut changed = false;
    for (pred_idx, succ_idx, call_idx) in candidates {
        let temp = func.new_temp(BitWidth::Bit64);
        let temp_expr = Expr::Var(temp.clone());

        // Change call's return from rax to temp
        if let Stmt::Call(ret, _, _) = &mut func.blocks[pred_idx].stmts[call_idx] {
            *ret = Some(temp);
        }

        // Replace Var::Reg(Rax, _) with temp in successor's stmts and terminator,
        // and continue transitively through the CFG until rax is redefined.
        // SAFETY: don't propagate into a block if any of its CFG predecessors
        // (not just ones we've visited) redefine rax — that means the block
        // is a merge point where rax may carry a different value (e.g. loop
        // back-edge with rax incremented). Instead, insert `rax = temp` at
        // the end of the predecessor block(s) that reach the merge point.
        let mut worklist = vec![succ_idx];
        let mut visited: HashSet<usize> = HashSet::new();
        let mut rax_restore_blocks: Vec<usize> = Vec::new();
        while let Some(bi) = worklist.pop() {
            if !visited.insert(bi) {
                continue;
            }
            // Check if any predecessor redefines rax (excluding the call block itself,
            // since its rax-assignment is the call we're replacing).
            let has_rax_redef_pred = pred_map[bi].iter()
                .any(|&pi| pi != pred_idx && rax_redefined_in.contains(&pi));
            if has_rax_redef_pred {
                // This is a merge point — find which visited predecessors
                // should get `rax = temp` inserted before entering this block.
                for &pi in &pred_map[bi] {
                    if visited.contains(&pi) || pi == pred_idx {
                        rax_restore_blocks.push(pi);
                    }
                }
                continue;
            }
            let block = &mut func.blocks[bi];
            let mut rax_redefined = false;
            for stmt in &mut block.stmts {
                if !rax_redefined {
                    replace_reg_in_stmt(stmt, RegId::Rax, &temp_expr);
                }
                match stmt {
                    Stmt::Assign(Var::Reg(RegId::Rax, _), _) => { rax_redefined = true; }
                    Stmt::Call(_, _, _) => { rax_redefined = true; }
                    _ => {}
                }
            }
            if !rax_redefined {
                replace_reg_in_terminator(&mut block.terminator, RegId::Rax, &temp_expr);
                // Continue to successor blocks
                for &si in &succ_map[bi] {
                    worklist.push(si);
                }
            }
        }
        // Insert `rax = temp` at the end of blocks that feed into merge points
        for bi in rax_restore_blocks {
            let restore_stmt = Stmt::Assign(
                Var::Reg(RegId::Rax, BitWidth::Bit64),
                temp_expr.clone(),
            );
            func.blocks[bi].stmts.push(restore_stmt);
        }
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
        Terminator::Switch(val, _, _) => { replace_reg_in_expr(val, reg, replacement); }
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
        Expr::Select(cond, true_val, false_val) => {
            replace_reg_in_expr(cond, reg, replacement);
            replace_reg_in_expr(true_val, reg, replacement);
            replace_reg_in_expr(false_val, reg, replacement);
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

    // Collect stack locations for alias analysis
    let stack_locs = dataflow::collect_stack_locs(func);

    for block in &mut func.blocks {
        // Forward scan: track pending assignments that haven't been read yet.
        // If a register/stack-var is assigned again before being read,
        // the previous assignment is dead.
        let mut pending: HashMap<String, usize> = HashMap::new(); // key → stmt index
        let mut to_nop: Vec<usize> = Vec::new();

        for i in 0..block.stmts.len() {
            match &block.stmts[i] {
                Stmt::Assign(var @ Var::Reg(reg_id, _), expr) => {
                    if matches!(reg_id, RegId::Rsp | RegId::Rbp) {
                        let mut uses = HashSet::new();
                        collect_expr_uses(expr, &mut uses);
                        for u in uses {
                            pending.remove(&u);
                        }
                        continue;
                    }
                    let key = format!("{var}");
                    let mut uses = HashSet::new();
                    collect_expr_uses(expr, &mut uses);
                    for u in &uses {
                        pending.remove(u);
                    }
                    if let Some(prev_idx) = pending.get(&key) {
                        to_nop.push(*prev_idx);
                    }
                    pending.insert(key, i);
                }
                Stmt::Assign(var @ Var::Stack(_, _), expr) => {
                    let key = format!("{var}");
                    let mut uses = HashSet::new();
                    collect_expr_uses(expr, &mut uses);
                    for u in &uses {
                        pending.remove(u);
                    }
                    // Mark aliasing pending stack vars as live (conservative)
                    let invalidated: Vec<String> = pending.keys()
                        .filter(|k| k.starts_with("var_") || k.starts_with("arg_"))
                        .filter(|k| *k != &key && dataflow::stack_may_alias(k, &key, &stack_locs))
                        .cloned()
                        .collect();
                    for k in &invalidated {
                        pending.remove(k);
                    }
                    // Same key → previous is dead
                    if let Some(prev_idx) = pending.get(&key) {
                        to_nop.push(*prev_idx);
                    }
                    pending.insert(key, i);
                }
                Stmt::Call(ret, target, args) => {
                    let mut uses = HashSet::new();
                    collect_expr_uses(target, &mut uses);
                    for arg in args {
                        collect_expr_uses(arg, &mut uses);
                    }
                    for u in &uses {
                        pending.remove(u);
                    }
                    // Call clobbers caller-saved registers
                    for clobbered in &["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"] {
                        if let Some(prev_idx) = pending.remove(*clobbered) {
                            to_nop.push(prev_idx);
                        }
                    }
                    // Calls with address-of args may read stack vars — mark them live
                    for arg in args {
                        if let Expr::UnaryOp(UnaryOp::AddrOf, inner) = arg {
                            if let Expr::Var(Var::Stack(_, _)) = inner.as_ref() {
                                // Conservatively mark all pending stack vars as live
                                pending.retain(|k, _| !k.starts_with("var_") && !k.starts_with("arg_"));
                                break;
                            }
                        }
                    }
                    if let Some(v) = ret {
                        let key = format!("{v}");
                        pending.insert(key, i);
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
                    let mut uses = HashSet::new();
                    collect_expr_uses(expr, &mut uses);
                    for u in uses {
                        pending.remove(&u);
                    }
                }
                Stmt::Nop => {}
            }
        }

        for idx in to_nop {
            if !matches!(block.stmts[idx], Stmt::Call(..)) {
                block.stmts[idx] = Stmt::Nop;
                changed = true;
            }
        }
    }

    changed
}

/// Dead store elimination: remove assignments to registers never read afterwards.
/// Uses liveness analysis from the dataflow framework for precise inter-block analysis.
fn dead_store_elimination(func: &mut Function) -> bool {
    let mut changed = false;

    // Use dataflow liveness to get live-out per block
    let live_out = dataflow::liveness_at_exit(func);

    // Within each block: backward pass using liveness info
    for block in &mut func.blocks {
        let block_live_out = live_out.get(&block.id).cloned().unwrap_or_default();
        let mut live: HashSet<String> = block_live_out;

        // Add uses from terminator
        collect_uses_terminator(&block.terminator, &mut live);

        // Backward scan
        let mut to_nop: Vec<usize> = Vec::new();
        for i in (0..block.stmts.len()).rev() {
            match &block.stmts[i] {
                Stmt::Assign(var @ Var::Reg(reg_id, _), expr) => {
                    let key = format!("{var}");
                    // Never eliminate frame pointer assignments
                    if matches!(reg_id, RegId::Rsp | RegId::Rbp) {
                        collect_expr_uses(expr, &mut live);
                        continue;
                    }
                    if !live.contains(&key) {
                        to_nop.push(i);
                    } else {
                        live.remove(&key);
                        collect_expr_uses(expr, &mut live);
                    }
                }
                Stmt::Assign(var, expr) => {
                    // Stack/temp assignments: just track uses, don't eliminate
                    // (stack reads go through Load(rbp+offset), not the var key)
                    let key = format!("{var}");
                    live.remove(&key);
                    collect_expr_uses(expr, &mut live);
                }
                Stmt::Call(ret, target, args) => {
                    if let Some(v) = ret {
                        live.remove(&format!("{v}"));
                    }
                    collect_expr_uses(target, &mut live);
                    for a in args {
                        collect_expr_uses(a, &mut live);
                    }
                }
                Stmt::Store(addr, val, _) => {
                    collect_expr_uses(addr, &mut live);
                    collect_expr_uses(val, &mut live);
                }
                Stmt::Nop => {}
            }
        }

        for idx in to_nop {
            block.stmts[idx] = Stmt::Nop;
            changed = true;
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
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs)
        | Expr::LogicalAnd(lhs, rhs) | Expr::LogicalOr(lhs, rhs) => {
            collect_expr_uses(lhs, uses);
            collect_expr_uses(rhs, uses);
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
            collect_expr_uses(inner, uses);
        }
        Expr::Select(c, t, f) => {
            collect_expr_uses(c, uses);
            collect_expr_uses(t, uses);
            collect_expr_uses(f, uses);
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
        if let Some(first_idx) = first_real
            && matches!(
                &succ_block.stmts[first_idx],
                Stmt::Assign(Var::Stack(_, _), Expr::Var(Var::Reg(RegId::Rax, _)))
            ) {
                merges.push((i, succ_idx, call_idx, first_idx));
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
            // Vec of (stmt_index, param_index, expression) for potential absorptions
            let mut candidates: Vec<(usize, usize, Expr)> = Vec::new();

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
                let mut visited_regs: HashSet<RegId> = HashSet::new();
                visited_regs.insert(target_reg);
                let mut chain: Vec<(usize, Expr)> = Vec::new();
                loop {
                    let mut found = false;
                    for j in (0..search_end).rev() {
                        match &block.stmts[j] {
                            Stmt::Assign(Var::Reg(r, _), val) if *r == target_reg => {
                                chain.push((j, val.clone()));
                                // If the value is itself a register, continue resolving
                                // but only if we haven't seen it before (cycle detection)
                                if let Expr::Var(Var::Reg(next_reg, _)) = val {
                                    if visited_regs.insert(*next_reg) {
                                        target_reg = *next_reg;
                                        search_end = j;
                                        found = true;
                                    }
                                }
                                break;
                            }
                            Stmt::Call(..) => break,
                            _ => {}
                        }
                    }
                    if !found { break; }
                }

                // Build the final absorbed expression from the chain,
                // recording each link as a candidate for Nop'ing.
                if !chain.is_empty() {
                    let final_expr = chain.last().unwrap().1.clone();
                    for &(idx, _) in &chain {
                        candidates.push((idx, param_idx, final_expr.clone()));
                    }
                }
            }

            if !candidates.is_empty() {
                // Determine which assignments can be safely Nop'd
                // (assigned register not read between assignment and call)
                let mut to_nop = Vec::new();
                let mut noppable = HashSet::new();
                for &(idx, _, _) in &candidates {
                    if let Stmt::Assign(Var::Reg(r, _), _) = &block.stmts[idx] {
                        let r = *r;
                        let has_reader = (idx + 1..call_idx)
                            .any(|k| stmt_reads_reg(&block.stmts[k], r));
                        if !has_reader {
                            to_nop.push(idx);
                            noppable.insert(idx);
                        }
                    }
                }

                // Only inline the expression for params whose ENTIRE chain
                // can be Nop'd. If any link in the chain can't be Nop'd,
                // the register is live and the call arg should stay as-is.
                let mut param_inline: HashMap<usize, Expr> = HashMap::new();
                // Group candidates by param_idx
                let mut param_chains: HashMap<usize, Vec<usize>> = HashMap::new();
                for &(idx, param_idx, _) in &candidates {
                    param_chains.entry(param_idx).or_default().push(idx);
                }
                for &(_, param_idx, ref expr) in &candidates {
                    let chain_idxs = &param_chains[&param_idx];
                    // The first link (closest to the call) must be noppable
                    // for us to inline the expression.
                    let _first_link = *chain_idxs.iter().min().unwrap();
                    // Actually: check if the FIRST link (the param reg assignment
                    // just before the call) is noppable. If it's not, the register
                    // value will be updated before the call and shouldn't be absorbed.
                    let direct_link = *chain_idxs.iter().max().unwrap();
                    if noppable.contains(&direct_link) {
                        param_inline.entry(param_idx).or_insert_with(|| expr.clone());
                    }
                }

                // Apply inlined expressions to call args
                for (param_idx, expr) in &param_inline {
                    new_args[*param_idx] = expr.clone();
                }

                if new_args != *args {
                    if let Stmt::Call(_, _, ref mut args) = block.stmts[call_idx] {
                        *args = new_args;
                    }
                    changed = true;
                }

                // Nop safe assignments
                for idx in to_nop {
                    block.stmts[idx] = Stmt::Nop;
                    changed = true;
                }
            }
        }
    }

    changed
}

/// Trim trailing raw-register arguments from Call statements.
///
/// After `absorb_call_args`, some calls may still have leftover register args
/// that were not absorbed (e.g. `puts("hello", rsi, rdx, rcx, r8, r9)`).
///
/// Strategy:
/// 1. For calls to known internal functions with a detected param count,
///    trim down to that count.
/// 2. For unknown callees, trim trailing identity-passthrough args
///    (register at its natural ABI position), but stop when encountering
///    a "shuffled" register (a param reg at a different position than its
///    natural slot), which indicates intentional argument setup.

/// Collect all registers that are *read* in a statement (RHS of assignments,
/// conditions, call arguments, etc.) into the provided set.
fn collect_regs_read(stmt: &Stmt, out: &mut HashSet<RegId>) {
    fn walk_expr(e: &Expr, out: &mut HashSet<RegId>) {
        match e {
            Expr::Var(Var::Reg(r, _)) => { out.insert(*r); }
            Expr::BinOp(_, a, b)
            | Expr::Cmp(_, a, b)
            | Expr::LogicalAnd(a, b)
            | Expr::LogicalOr(a, b) => { walk_expr(a, out); walk_expr(b, out); }
            Expr::UnaryOp(_, a) => walk_expr(a, out),
            Expr::Load(addr, _) => walk_expr(addr, out),
            Expr::Select(c, t, f) => { walk_expr(c, out); walk_expr(t, out); walk_expr(f, out); }
            _ => {}
        }
    }
    match stmt {
        Stmt::Assign(_, rhs) => walk_expr(rhs, out),
        Stmt::Store(addr, val, _) => { walk_expr(addr, out); walk_expr(val, out); }
        Stmt::Call(_, target, args) => {
            walk_expr(target, out);
            for a in args { walk_expr(a, out); }
        }
        _ => {}
    }
}

/// Check if a statement reads a specific register.
fn stmt_reads_reg(stmt: &Stmt, reg: RegId) -> bool {
    let mut regs = HashSet::new();
    collect_regs_read(stmt, &mut regs);
    regs.contains(&reg)
}

fn trim_call_args(func: &mut Function, callee_param_counts: &HashMap<u64, usize>) -> bool {
    let mut changed = false;
    let param_regs_vec: Vec<RegId> = func.calling_conv.param_regs().to_vec();
    let param_regs_set: HashSet<RegId> = param_regs_vec.iter().copied().collect();

    for block in &mut func.blocks {
        // Pre-compute: for each call statement index, collect the set of
        // registers that are *read* (appear on RHS) in prior statements
        // within the same block.  If a param register is read before the
        // call, it carries a meaningful value and should not be trimmed even
        // if it sits at its natural ABI position.
        let call_indices: Vec<usize> = block
            .stmts
            .iter()
            .enumerate()
            .filter_map(|(i, s)| matches!(s, Stmt::Call(..)).then_some(i))
            .collect();

        for &ci in &call_indices {
            // Collect registers read in stmts before this call
            let mut regs_read_before = HashSet::new();
            for j in 0..ci {
                collect_regs_read(&block.stmts[j], &mut regs_read_before);
            }

            let Stmt::Call(_, ref target, ref mut args) = block.stmts[ci] else {
                continue;
            };

            // Check if we know the callee's param count
            let known_count = if let Expr::Const(addr, _) = target {
                callee_param_counts.get(addr).copied()
            } else {
                None
            };

            if let Some(pc) = known_count {
                // Known callee: trim to exactly param_count args
                if pc > 0 && args.len() > pc {
                    args.truncate(pc);
                    changed = true;
                }
                // If param_count is 0 (couldn't detect), fall through to heuristic
                if pc > 0 {
                    continue;
                }
            }

            // Heuristic: trim trailing identity-passthrough args.
            // An arg at position i that equals param_regs[i] is an identity
            // passthrough (register was never modified — likely ABI noise).
            // A param reg at a DIFFERENT position indicates explicit setup — stop.
            // NEW: if the register was read earlier in the block, it carries a
            // real value (e.g. forwarded function parameter) — keep it.
            while !args.is_empty() {
                let idx = args.len() - 1;
                let last = args.last().unwrap();
                if let Expr::Var(Var::Reg(r, _)) = last {
                    if param_regs_vec.get(idx).map_or(false, |pr| pr == r) {
                        // Identity passthrough at natural position
                        if regs_read_before.contains(r) {
                            // Register was read before the call — it's a real value
                            break;
                        }
                        args.pop();
                        changed = true;
                    } else if param_regs_set.contains(r) {
                        // Shuffled param reg at wrong position — keep
                        break;
                    } else {
                        // Non-param register — keep
                        break;
                    }
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
            for stmt in &stmts[(i + 1)..len] {
                if stmt_reads(stmt, &ret_var) {
                    used = true;
                    break;
                }
                if stmt_writes(stmt, &ret_var) {
                    break;
                }
            }

            if !used
                && terminator_reads(&func.blocks[block_idx].terminator, &ret_var) {
                    used = true;
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
        Expr::BinOp(_, l, r) | Expr::Cmp(_, l, r)
        | Expr::LogicalAnd(l, r) | Expr::LogicalOr(l, r) => {
            expr_contains_var(l, var) || expr_contains_var(r, var)
        }
        Expr::UnaryOp(_, inner) => expr_contains_var(inner, var),
        Expr::Load(addr, _) => expr_contains_var(addr, var),
        Expr::Select(c, t, f) => {
            expr_contains_var(c, var) || expr_contains_var(t, var) || expr_contains_var(f, var)
        }
    }
}

// ── Self-assignment elimination ──────────────────────────────────

/// Remove self-assignments like `rdi = rdi` that arise from copy-propagation
/// collapsing register shuffles.
fn eliminate_self_assignments(func: &mut Function) {
    for block in &mut func.blocks {
        for stmt in &mut block.stmts {
            if let Stmt::Assign(var, Expr::Var(rhs)) = stmt
                && var == rhs {
                    *stmt = Stmt::Nop;
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
            if let Stmt::Assign(var @ Var::Stack(_, _), Expr::Var(Var::Reg(reg, _))) = stmt
                && param_regs.contains(reg) && !param_map.contains_key(reg) {
                    param_map.insert(*reg, var.clone());
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
            if block_idx == 0
                && let Stmt::Assign(Var::Stack(_, _), Expr::Var(Var::Reg(reg, _))) = stmt
                    && param_map.contains_key(reg) {
                        continue;
                    }
            match stmt {
                Stmt::Call(_, target, args) => {
                    substitute_param_reg_in_expr(target, &param_map);
                    for arg in args {
                        substitute_param_reg_in_expr(arg, &param_map);
                    }
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
            Terminator::IndirectJump(target) => {
                substitute_param_reg_in_expr(target, &param_map);
            }
            Terminator::Switch(val, _, _) => {
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
        Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs)
        | Expr::LogicalAnd(lhs, rhs) | Expr::LogicalOr(lhs, rhs) => {
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

/// Promote remaining register variables to temp variables.
///
/// After callee-saved promotion, some functions (especially optimised leaf
/// functions that don't use a stack frame) still reference general-purpose
/// registers like rax, rdi directly. These are effectively local variables.
/// Promoting them to temps enables structured control-flow recovery (loops,
/// if-then) and produces better output.
///
/// Only promotes registers that are *written to* in the function body.
/// Registers that are only read (e.g. parameter registers in leaf functions)
/// are left as-is so that the codegen parameter detection still works.
///
/// Skips rsp and rbp (frame pointers) since they have special semantics.
fn promote_all_regs_to_locals(func: &mut Function) {
    // Collect registers that are defined (written to) anywhere in the function
    let mut defined_regs: HashSet<RegId> = HashSet::new();
    for block in &func.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign(Var::Reg(r, _), _) => { defined_regs.insert(*r); }
                Stmt::Call(Some(Var::Reg(r, _)), _, _) => { defined_regs.insert(*r); }
                _ => {}
            }
        }
    }

    // Remove rsp/rbp — never promote
    defined_regs.remove(&RegId::Rsp);
    defined_regs.remove(&RegId::Rbp);

    // Exclude parameter registers that are read before being written.
    // When a param register is modified inside the function body (e.g.
    // `imul edi, edi`), promote_all_regs turns it into a temp, which
    // hides it from codegen's parameter detection.  By not promoting
    // param regs that are read-before-write we preserve them as `Var::Reg`
    // so codegen can recognise them as function parameters.
    {
        let param_regs = func.calling_conv.param_regs();
        let mut read_before_write: HashSet<RegId> = HashSet::new();
        let mut written: HashSet<RegId> = HashSet::new();

        fn collect_expr_reg_reads(
            expr: &Expr,
            param_regs: &[RegId],
            written: &HashSet<RegId>,
            out: &mut HashSet<RegId>,
        ) {
            match expr {
                Expr::Var(Var::Reg(r, _)) => {
                    if param_regs.contains(r) && !written.contains(r) {
                        out.insert(*r);
                    }
                }
                Expr::BinOp(_, l, r) | Expr::Cmp(_, l, r)
                | Expr::LogicalAnd(l, r) | Expr::LogicalOr(l, r) => {
                    collect_expr_reg_reads(l, param_regs, written, out);
                    collect_expr_reg_reads(r, param_regs, written, out);
                }
                Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
                    collect_expr_reg_reads(inner, param_regs, written, out);
                }
                Expr::Select(c, t, f) => {
                    collect_expr_reg_reads(c, param_regs, written, out);
                    collect_expr_reg_reads(t, param_regs, written, out);
                    collect_expr_reg_reads(f, param_regs, written, out);
                }
                _ => {}
            }
        }

        // Walk ALL blocks in order to find parameter registers that are
        // read before being written.  Some leaf functions (e.g. reverse_bits)
        // don't touch param regs in the entry block at all — they first
        // appear in a loop body.  We track writes globally so that a write
        // in an earlier block prevents later reads from being counted.
        for block_idx in block_indices_by_addr(func) {
            let block = &func.blocks[block_idx];
            for stmt in &block.stmts {
                // Collect reads from RHS first
                match stmt {
                    Stmt::Assign(_, expr) => {
                        collect_expr_reg_reads(expr, param_regs, &written, &mut read_before_write);
                    }
                    Stmt::Store(addr, val, _) => {
                        collect_expr_reg_reads(addr, param_regs, &written, &mut read_before_write);
                        collect_expr_reg_reads(val, param_regs, &written, &mut read_before_write);
                    }
                    Stmt::Call(_, target, args) => {
                        collect_expr_reg_reads(target, param_regs, &written, &mut read_before_write);
                        for a in args {
                            collect_expr_reg_reads(a, param_regs, &written, &mut read_before_write);
                        }
                    }
                    Stmt::Nop => {}
                }
                // Then record writes
                match stmt {
                    Stmt::Assign(Var::Reg(r, _), _) => { written.insert(*r); }
                    Stmt::Call(Some(Var::Reg(r, _)), _, _) => { written.insert(*r); }
                    _ => {}
                }
            }
            // Check terminator reads too
            match &block.terminator {
                Terminator::Return(Some(e)) | Terminator::Branch(e, _, _) => {
                    collect_expr_reg_reads(e, param_regs, &written, &mut read_before_write);
                }
                _ => {}
            }
        }

        for reg in &read_before_write {
            defined_regs.remove(reg);
        }
    }

    // rax is now always promoted because FoldReturnValues runs before
    // this pass and has already resolved Return(rax) patterns.

    for reg in defined_regs {
        let temp = func.new_temp(BitWidth::Bit64);
        let temp_expr = Expr::Var(temp.clone());

        for block in &mut func.blocks {
            for stmt in &mut block.stmts {
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
        Terminator::Switch(val, _, _) => expr_uses_reg(val, reg),
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

/// Fold return values from predecessors into common return blocks.
///
/// When a block sets `rax = <expr>` and then jumps to a block that
/// is simply `return rax`, replace the jump with `return <expr>`.
/// This must run before `simplify_void_returns` so that the values
/// are visible in the returning block.
fn fold_return_values(func: &mut Function) {
    // Find blocks that return bare `rax` — these are return relays.
    let return_relay_ids: HashSet<BlockId> = func.blocks.iter()
        .filter(|b| {
            matches!(
                &b.terminator,
                Terminator::Return(Some(Expr::Var(Var::Reg(RegId::Rax, _))))
            )
        })
        .map(|b| b.id)
        .collect();

    if return_relay_ids.is_empty() {
        return;
    }

    // For each block, if it sets rax and then jumps to a return relay,
    // replace the jump with a direct return and remove the now-dead
    // rax assignment (otherwise promote_all_regs turns it into a visible
    // temp assignment that duplicates the return value).
    for block in &mut func.blocks {
        let rax_idx_expr = block.stmts.iter().enumerate().rev().find_map(|(i, s)| {
            match s {
                Stmt::Assign(Var::Reg(RegId::Rax, _), expr) => Some((i, expr.clone())),
                _ => None,
            }
        });
        let Some((idx, expr)) = rax_idx_expr else { continue };

        // Safety check: ensure no variable used in `expr` is modified between
        // the rax assignment and the end of the block.  If a variable gets
        // reassigned after `rax = expr`, substituting `expr` into the return
        // would use the stale value.
        if expr_vars_modified_after(&block.stmts, idx, &expr) {
            continue;
        }

        if let Terminator::Jump(target) = &block.terminator {
            if return_relay_ids.contains(target) {
                block.terminator = Terminator::Return(Some(expr));
                block.stmts[idx] = Stmt::Nop;
            }
        }
    }

    // Second pass: for return relay blocks that are still `return rax`,
    // check if they have a single predecessor that sets rax.  If so,
    // inline the value into the relay's return terminator itself.
    // This handles the Branch-to-relay case (after the Jump-based fold
    // above removed some predecessors).
    let remaining_relays: Vec<BlockId> = func.blocks.iter()
        .filter(|b| {
            matches!(
                &b.terminator,
                Terminator::Return(Some(Expr::Var(Var::Reg(RegId::Rax, _))))
            )
        })
        .map(|b| b.id)
        .collect();

    for relay_id in remaining_relays {
        let preds = func.predecessors(relay_id);
        if preds.len() != 1 {
            continue;
        }
        let pred_id = preds[0];
        let Some(pred_block) = func.blocks.iter().find(|b| b.id == pred_id) else {
            continue;
        };
        // Find the last rax assignment in the predecessor
        let Some((idx, expr)) = pred_block.stmts.iter().enumerate().rev().find_map(|(i, s)| {
            match s {
                Stmt::Assign(Var::Reg(RegId::Rax, _), expr) => Some((i, expr.clone())),
                _ => None,
            }
        }) else {
            continue;
        };
        if expr_vars_modified_after(&pred_block.stmts, idx, &expr) {
            continue;
        }
        // Inline: set the relay's return to the expression and nop the pred's rax assignment
        if let Some(relay_block) = func.blocks.iter_mut().find(|b| b.id == relay_id) {
            relay_block.terminator = Terminator::Return(Some(expr));
        }
        if let Some(pred_block) = func.blocks.iter_mut().find(|b| b.id == pred_id) {
            pred_block.stmts[idx] = Stmt::Nop;
        }
    }
}

/// Check if any variable appearing in `expr` is assigned in `stmts[idx+1..]`.
fn expr_vars_modified_after(stmts: &[Stmt], idx: usize, expr: &Expr) -> bool {
    let mut used_vars: HashSet<Var> = HashSet::new();
    collect_expr_vars(expr, &mut used_vars);
    for stmt in &stmts[idx + 1..] {
        match stmt {
            Stmt::Assign(v, _) => {
                if used_vars.contains(v) {
                    return true;
                }
            }
            // Any call clobbers caller-saved registers (rax, rcx, rdx, rsi, rdi, r8-r11).
            Stmt::Call(_, _, _) => {
                if used_vars.iter().any(|v| matches!(v, Var::Reg(_, _))) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Collect all `Var` nodes used in an expression.
fn collect_expr_vars(expr: &Expr, vars: &mut HashSet<Var>) {
    match expr {
        Expr::Var(v) => { vars.insert(v.clone()); }
        Expr::BinOp(_, l, r) | Expr::Cmp(_, l, r)
        | Expr::LogicalAnd(l, r) | Expr::LogicalOr(l, r) => {
            collect_expr_vars(l, vars);
            collect_expr_vars(r, vars);
        }
        Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
            collect_expr_vars(inner, vars);
        }
        Expr::Select(c, t, f) => {
            collect_expr_vars(c, vars);
            collect_expr_vars(t, vars);
            collect_expr_vars(f, vars);
        }
        Expr::Const(_, _) | Expr::Cond(_) => {}
    }
}

/// Fold `temp = expr; return temp` into `return expr`.
///
/// Runs after `promote_all_regs_to_locals`. When a block's terminator is
/// `Return(Var::Temp(id))` and the last non-Nop statement in that block is
/// `Assign(Var::Temp(id), expr)`, inline the expression into the return and
/// remove the now-dead assignment.
///
/// Also handles Jump → relay patterns (same as Branch but with Jump terminators).
fn fold_temp_returns(func: &mut Function) {
    // Pass 1: Same-block inline
    for block in &mut func.blocks {
        let ret_temp_id = match &block.terminator {
            Terminator::Return(Some(Expr::Var(Var::Temp(id, _)))) => *id,
            _ => continue,
        };

        let mut found_idx = None;
        for (i, stmt) in block.stmts.iter().enumerate().rev() {
            match stmt {
                Stmt::Nop => continue,
                Stmt::Assign(Var::Temp(id, _), _) if *id == ret_temp_id => {
                    found_idx = Some(i);
                    break;
                }
                _ => break,
            }
        }

        if let Some(idx) = found_idx {
            let expr = match &block.stmts[idx] {
                Stmt::Assign(_, expr) => expr.clone(),
                _ => unreachable!(),
            };
            block.terminator = Terminator::Return(Some(expr));
            block.stmts[idx] = Stmt::Nop;
        }
    }

    // Pass 2: Jump → relay pattern.  If a block assigns Temp(id) then
    // Jumps to a relay block `Return(Temp(id))` with no stmts, fold.
    let relay_info: Vec<(BlockId, u32)> = func.blocks.iter()
        .filter_map(|b| {
            if b.stmts.iter().any(|s| !matches!(s, Stmt::Nop)) {
                return None;
            }
            if let Terminator::Return(Some(Expr::Var(Var::Temp(id, _)))) = &b.terminator {
                Some((b.id, *id))
            } else {
                None
            }
        })
        .collect();

    struct JumpFold { block_idx: usize, stmt_idx: usize, expr: Expr }
    let mut jump_folds: Vec<JumpFold> = Vec::new();

    for &(relay_id, temp_id) in &relay_info {
        for (bi, block) in func.blocks.iter().enumerate() {
            if !matches!(&block.terminator, Terminator::Jump(t) if *t == relay_id) {
                continue;
            }
            let assign_info = block.stmts.iter().enumerate().rev().find_map(|(i, s)| {
                match s {
                    Stmt::Nop => None,
                    Stmt::Assign(Var::Temp(id, _), expr) if *id == temp_id => {
                        Some((i, expr.clone()))
                    }
                    _ => Some((usize::MAX, Expr::Const(0, BitWidth::Bit64))),
                }
            });
            let Some((idx, expr)) = assign_info else { continue };
            if idx == usize::MAX { continue; }
            jump_folds.push(JumpFold { block_idx: bi, stmt_idx: idx, expr });
        }
    }

    for fold in &jump_folds {
        func.blocks[fold.block_idx].terminator = Terminator::Return(Some(fold.expr.clone()));
        func.blocks[fold.block_idx].stmts[fold.stmt_idx] = Stmt::Nop;
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
