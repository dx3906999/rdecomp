//! Generic dataflow analysis framework.
//!
//! Provides lattice-based forward and backward analysis with worklist-driven
//! fixpoint iteration.  Concrete analyses (reaching definitions, liveness,
//! available expressions) are expressed as implementations of the [`Analysis`]
//! trait and run through [`solve`].

use crate::ir::*;
use std::collections::{HashMap, HashSet, VecDeque};

// ── Lattice value: sets of variable keys ─────────────────────────

/// A dataflow fact — a set of variable-key strings.
/// `Top` = unknown/uninitialized, `Set(s)` = concrete fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fact {
    /// Not yet computed (lattice top for forward, bottom for backward).
    Top,
    /// Concrete set of variable keys.
    Set(HashSet<String>),
}

impl Fact {
    pub fn empty() -> Self {
        Fact::Set(HashSet::new())
    }

    pub fn is_top(&self) -> bool {
        matches!(self, Fact::Top)
    }

    /// Intersection meet (AND): keeps only elements present in both.
    pub fn intersect(&self, other: &Fact) -> Fact {
        match (self, other) {
            (Fact::Top, x) | (x, Fact::Top) => x.clone(),
            (Fact::Set(a), Fact::Set(b)) => {
                Fact::Set(a.intersection(b).cloned().collect())
            }
        }
    }

    /// Union join (OR): keeps elements present in either.
    pub fn union(&self, other: &Fact) -> Fact {
        match (self, other) {
            (Fact::Top, _) | (_, Fact::Top) => Fact::Top,
            (Fact::Set(a), Fact::Set(b)) => {
                Fact::Set(a.union(b).cloned().collect())
            }
        }
    }

    pub fn as_set(&self) -> Option<&HashSet<String>> {
        match self {
            Fact::Set(s) => Some(s),
            Fact::Top => None,
        }
    }
}

// ── Reaching-definitions map ─────────────────────────────────────

/// A richer dataflow fact: maps variable keys to their defining expressions.
/// Used by reaching-definitions (forward copy propagation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachingDefs {
    Top,
    Map(HashMap<String, Expr>),
}

impl ReachingDefs {
    pub fn empty() -> Self {
        ReachingDefs::Map(HashMap::new())
    }

    /// Intersection meet: keep only keys present in both with equal values.
    pub fn intersect(&self, other: &ReachingDefs) -> ReachingDefs {
        match (self, other) {
            (ReachingDefs::Top, x) | (x, ReachingDefs::Top) => x.clone(),
            (ReachingDefs::Map(a), ReachingDefs::Map(b)) => {
                let mut result = HashMap::new();
                for (k, v) in a {
                    if b.get(k).is_some_and(|bv| bv == v) {
                        result.insert(k.clone(), v.clone());
                    }
                }
                ReachingDefs::Map(result)
            }
        }
    }

    pub fn as_map(&self) -> Option<&HashMap<String, Expr>> {
        match self {
            ReachingDefs::Map(m) => Some(m),
            ReachingDefs::Top => None,
        }
    }
}

// ── Liveness analysis ────────────────────────────────────────────

/// Compute live variables at the *entry* of each block (backward analysis).
///
/// A variable is live at a point if there exists a path from that point to
/// a use of the variable without an intervening definition.
///
/// Returns: `block_id → set of live variable keys at block entry`.
pub fn liveness_analysis(func: &Function) -> HashMap<BlockId, HashSet<String>> {
    let block_ids: Vec<BlockId> = func.blocks.iter().map(|b| b.id).collect();
    let block_idx: HashMap<BlockId, usize> = block_ids.iter().enumerate()
        .map(|(i, &id)| (id, i))
        .collect();

    // Precompute gen/kill for each block
    struct BlockInfo {
        /// Variables used before being defined in this block.
        gen_set: HashSet<String>,
        /// Variables defined in this block.
        kill: HashSet<String>,
    }

    let mut infos: Vec<BlockInfo> = Vec::with_capacity(func.blocks.len());

    for block in &func.blocks {
        let mut gen_set = HashSet::new();
        let mut kill = HashSet::new();

        // Forward scan: a use before def → gen; a def → kill
        for stmt in &block.stmts {
            // Collect uses from RHS
            let mut uses = HashSet::new();
            match stmt {
                Stmt::Assign(_, expr) => collect_expr_vars(expr, &mut uses),
                Stmt::Store(addr, val, _) => {
                    collect_expr_vars(addr, &mut uses);
                    collect_expr_vars(val, &mut uses);
                }
                Stmt::Call(_, target, args) => {
                    collect_expr_vars(target, &mut uses);
                    for a in args {
                        collect_expr_vars(a, &mut uses);
                    }
                }
                Stmt::Nop => {}
            }
            // Uses that haven't been killed yet are gen
            for u in &uses {
                if !kill.contains(u) {
                    gen_set.insert(u.clone());
                }
            }
            // Definitions
            match stmt {
                Stmt::Assign(var, _) => { kill.insert(format!("{var}")); }
                Stmt::Call(Some(var), _, _) => { kill.insert(format!("{var}")); }
                _ => {}
            }
        }

        // Terminator uses
        let mut term_uses = HashSet::new();
        collect_terminator_vars(&block.terminator, &mut term_uses);
        for u in &term_uses {
            if !kill.contains(u) {
                gen_set.insert(u.clone());
            }
        }

        infos.push(BlockInfo { gen_set, kill });
    }

    // live_out[b] = union of live_in[s] for all successors s
    // live_in[b] = gen[b] ∪ (live_out[b] - kill[b])
    let n = func.blocks.len();
    let mut live_in: Vec<HashSet<String>> = vec![HashSet::new(); n];
    let mut live_out: Vec<HashSet<String>> = vec![HashSet::new(); n];

    let mut worklist: VecDeque<usize> = (0..n).collect();
    let max_iters = n * 20;
    let mut iter_count = 0;

    while let Some(bi) = worklist.pop_front() {
        iter_count += 1;
        if iter_count > max_iters {
            break;
        }

        let bid = block_ids[bi];

        // Compute live_out = union of live_in of all successors
        let mut new_out = HashSet::new();
        for succ_bid in func.successors(bid) {
            if let Some(&si) = block_idx.get(&succ_bid) {
                for v in &live_in[si] {
                    new_out.insert(v.clone());
                }
            }
        }

        // live_in = gen ∪ (live_out - kill)
        let info = &infos[bi];
        let mut new_in = info.gen_set.clone();
        for v in &new_out {
            if !info.kill.contains(v) {
                new_in.insert(v.clone());
            }
        }

        if new_in != live_in[bi] || new_out != live_out[bi] {
            live_in[bi] = new_in;
            live_out[bi] = new_out;
            // Add predecessors to worklist
            for pred_bid in func.predecessors(bid) {
                if let Some(&pi) = block_idx.get(&pred_bid) {
                    if !worklist.contains(&pi) {
                        worklist.push_back(pi);
                    }
                }
            }
        }
    }

    // Return live_in per block
    let mut result = HashMap::new();
    for (i, &bid) in block_ids.iter().enumerate() {
        result.insert(bid, live_in[i].clone());
    }
    result
}

/// Compute live variables at the *exit* of each block.
pub fn liveness_at_exit(func: &Function) -> HashMap<BlockId, HashSet<String>> {
    let live_in = liveness_analysis(func);
    let mut live_out: HashMap<BlockId, HashSet<String>> = HashMap::new();

    for block in &func.blocks {
        let mut out = HashSet::new();
        for succ_bid in func.successors(block.id) {
            if let Some(succ_live) = live_in.get(&succ_bid) {
                for v in succ_live {
                    out.insert(v.clone());
                }
            }
        }
        live_out.insert(block.id, out);
    }
    live_out
}

// ── Reaching definitions (forward) ──────────────────────────────

/// Compute reaching register definitions at block entry (forward analysis).
///
/// For each block, the incoming state is the intersection of all predecessors'
/// outgoing states (only defs where ALL predecessors agree on the value).
///
/// Returns: `block_id → { var_key → defining expression }`.
pub fn reaching_definitions(func: &Function) -> HashMap<BlockId, ReachingDefs> {
    let block_ids: Vec<BlockId> = func.blocks.iter().map(|b| b.id).collect();
    let block_idx: HashMap<BlockId, usize> = block_ids.iter().enumerate()
        .map(|(i, &id)| (id, i))
        .collect();

    // Precompute transfer function per block:
    // out[b] = transfer(in[b])
    // If block has a call → only post-call defs survive.
    // Otherwise → in ∪ local_defs (with overwrites).
    struct TransferInfo {
        has_call: bool,
        /// Definitions accumulated (after last call if any).
        local_defs: HashMap<String, Expr>,
    }

    let mut transfers: Vec<TransferInfo> = Vec::with_capacity(func.blocks.len());
    for block in &func.blocks {
        let mut has_call = false;
        let mut defs: HashMap<String, Expr> = HashMap::new();
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign(var @ Var::Reg(_, _), expr) => {
                    let k = format!("{var}");
                    // When a variable is reassigned, invalidate any reaching
                    // definitions whose RHS references it — those defs are
                    // stale and would substitute the wrong value.
                    defs.retain(|_, def_expr| !expr_uses_key(def_expr, &k));
                    if expr_uses_key(expr, &k) {
                        defs.remove(&k);
                    } else {
                        defs.insert(k, expr.clone());
                    }
                }
                Stmt::Call(..) => {
                    has_call = true;
                    defs.clear();
                }
                _ => {}
            }
        }
        transfers.push(TransferInfo { has_call, local_defs: defs });
    }

    // Fixpoint iteration
    let n = func.blocks.len();
    let mut out_state: Vec<ReachingDefs> = vec![ReachingDefs::empty(); n];
    let mut worklist: VecDeque<usize> = (0..n).collect();
    let max_iters = n * 20;
    let mut iter_count = 0;

    while let Some(bi) = worklist.pop_front() {
        iter_count += 1;
        if iter_count > max_iters {
            break;
        }

        let bid = block_ids[bi];
        let preds = func.predecessors(bid);

        // Compute incoming state: intersection of predecessors' out
        let incoming = if preds.is_empty() {
            ReachingDefs::empty()
        } else {
            let mut result = ReachingDefs::Top;
            for pbid in &preds {
                if let Some(&pi) = block_idx.get(pbid) {
                    result = result.intersect(&out_state[pi]);
                }
            }
            result
        };

        // Apply transfer function
        let transfer = &transfers[bi];
        let new_out = if transfer.has_call {
            ReachingDefs::Map(transfer.local_defs.clone())
        } else {
            match incoming {
                ReachingDefs::Top => ReachingDefs::Map(transfer.local_defs.clone()),
                ReachingDefs::Map(mut m) => {
                    for (k, v) in &transfer.local_defs {
                        m.insert(k.clone(), v.clone());
                    }
                    ReachingDefs::Map(m)
                }
            }
        };

        if out_state[bi] != new_out {
            out_state[bi] = new_out;
            // Add successors to worklist
            for succ_bid in func.successors(bid) {
                if let Some(&si) = block_idx.get(&succ_bid) {
                    if !worklist.contains(&si) {
                        worklist.push_back(si);
                    }
                }
            }
        }
    }

    // Build block_id → incoming map
    let mut result = HashMap::new();
    for (_bi, &bid) in block_ids.iter().enumerate() {
        let preds = func.predecessors(bid);
        let incoming = if preds.is_empty() {
            ReachingDefs::empty()
        } else {
            let mut r = ReachingDefs::Top;
            for pbid in &preds {
                if let Some(&pi) = block_idx.get(pbid) {
                    r = r.intersect(&out_state[pi]);
                }
            }
            r
        };
        result.insert(bid, incoming);
    }
    result
}

// ── Stack alias analysis ─────────────────────────────────────────

/// Memory location on the stack, described by its offset from RBP and byte width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StackLoc {
    pub offset: i64,
    pub size: u32, // bytes
}

impl StackLoc {
    pub fn end(&self) -> i64 {
        self.offset + self.size as i64
    }

    /// Must-alias: exact same location (offset and size).
    pub fn must_alias(&self, other: &StackLoc) -> bool {
        self.offset == other.offset && self.size == other.size
    }

    /// May-alias: overlapping byte ranges.
    pub fn may_alias(&self, other: &StackLoc) -> bool {
        self.offset < other.end() && other.offset < self.end()
    }
}

/// Collect all stack locations accessed in a function.
pub fn collect_stack_locs(func: &Function) -> Vec<StackLoc> {
    let mut locs = HashSet::new();
    for block in &func.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign(Var::Stack(off, w), _) => {
                    locs.insert(StackLoc { offset: *off, size: w.bytes() });
                }
                _ => {}
            }
        }
    }
    let mut v: Vec<StackLoc> = locs.into_iter().collect();
    v.sort_by_key(|l| l.offset);
    v
}

/// Check if two stack variable keys (e.g. "var_8" and "var_4") may alias
/// based on their stack locations overlapping.
pub fn stack_may_alias(key_a: &str, key_b: &str, locs: &[StackLoc]) -> bool {
    let off_a = parse_stack_key(key_a);
    let off_b = parse_stack_key(key_b);
    let (Some(oa), Some(ob)) = (off_a, off_b) else { return false };

    // Find matching locations
    for la in locs.iter().filter(|l| l.offset == oa) {
        for lb in locs.iter().filter(|l| l.offset == ob) {
            if la.may_alias(lb) {
                return true;
            }
        }
    }
    false
}

/// Parse a stack variable key like "var_8" → offset -8, "arg_10" → offset 0x10.
fn parse_stack_key(key: &str) -> Option<i64> {
    if let Some(hex) = key.strip_prefix("var_") {
        i64::from_str_radix(hex, 16).ok().map(|v| -v)
    } else if let Some(hex) = key.strip_prefix("arg_") {
        i64::from_str_radix(hex, 16).ok()
    } else {
        None
    }
}

// ── Helpers ──────────────────────────────────────────────────────

/// Collect all variable keys referenced in an expression.
pub fn collect_expr_vars(expr: &Expr, vars: &mut HashSet<String>) {
    expr.walk(&mut |e| {
        if let Expr::Var(v) = e {
            vars.insert(format!("{v}"));
        }
    });
}

/// Collect all variable keys referenced in a terminator.
pub fn collect_terminator_vars(term: &Terminator, vars: &mut HashSet<String>) {
    match term {
        Terminator::Branch(cond, _, _) => collect_expr_vars(cond, vars),
        Terminator::Return(Some(v)) => collect_expr_vars(v, vars),
        Terminator::IndirectJump(t) => collect_expr_vars(t, vars),
        Terminator::Switch(v, _, _) => collect_expr_vars(v, vars),
        _ => {}
    }
}

/// Check if an expression uses a variable by its string key.
fn expr_uses_key(expr: &Expr, key: &str) -> bool {
    expr.any(&|e| matches!(e, Expr::Var(v) if format!("{v}") == key))
}
