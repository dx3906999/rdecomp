use crate::cfg::Cfg;
use crate::ir::*;
use crate::loader::{Binary, FunctionSymbol};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write;

/// Generate pseudo-C code from an IR function.
pub struct CodeGenerator<'a> {
    /// Known function symbols for resolving call targets.
    symbols: HashMap<u64, String>,
    /// Reference to the loaded binary for string constant extraction.
    binary: &'a Binary,
    indent: usize,
    /// Parameter stack variable names to suppress in output.
    param_vars: HashSet<String>,
    /// Temp vars that hold call results (temp_name → call expression string).
    /// Used to inline `t0 >= 0` as `seccomp_rule_add(...) >= 0`.
    call_results: HashMap<String, String>,
}

impl<'a> CodeGenerator<'a> {
    pub fn new(symbols: &[FunctionSymbol], binary: &'a Binary) -> Self {
        let sym_map: HashMap<u64, String> = symbols
            .iter()
            .map(|s| (s.addr, s.name.clone()))
            .collect();
        Self {
            symbols: sym_map,
            binary,
            indent: 0,
            param_vars: HashSet::new(),
            call_results: HashMap::new(),
        }
    }

    /// Generate pseudo-C code for a function.
    pub fn generate(&mut self, func: &Function, cfg: &Cfg) -> String {
        let mut out = String::new();

        // Detect function parameters from entry block: stack_var = param_reg assignments
        let param_regs = func.calling_conv.param_regs();
        let mut params: Vec<(String, BitWidth)> = Vec::new();
        let mut param_var_names: HashSet<String> = HashSet::new();

        if let Some(entry) = func.blocks.first() {
            for stmt in &entry.stmts {
                if let Stmt::Assign(Var::Stack(off, w), Expr::Var(Var::Reg(reg, _))) = stmt {
                    if param_regs.contains(reg) {
                        let name = if *off >= 0 {
                            format!("arg_{off:x}")
                        } else {
                            format!("var_{:x}", off.unsigned_abs())
                        };
                        params.push((name.clone(), *w));
                        param_var_names.insert(name);
                    }
                }
            }
        }

        // Function signature with parameters
        if params.is_empty() {
            let _ = writeln!(out, "uint64_t {}() {{", func.name);
        } else {
            let param_str: Vec<String> = params.iter()
                .map(|(name, w)| format!("{} {}", c_type(*w), name))
                .collect();
            let _ = writeln!(out, "uint64_t {}({}) {{", func.name, param_str.join(", "));
        }

        self.param_vars = param_var_names.clone();

        self.indent = 1;

        // Declare local variables (only stack/temp vars, not registers, excluding params)
        let locals = self.collect_locals(func);
        if !locals.is_empty() {
            let filtered: Vec<_> = locals.iter()
                .filter(|(name, _)| !param_var_names.contains(name))
                .collect();
            for (name, width) in &filtered {
                let _ = writeln!(out, "{}{}  {};", self.indent_str(), c_type(*width), name);
            }
            if !filtered.is_empty() {
                let _ = writeln!(out);
            }
        }

        // Build call-result map: temp vars that hold single-use call return values
        // These will be inlined as `func(args)` instead of displaying as `t0`.
        self.call_results.clear();
        for block in &func.blocks {
            for stmt in &block.stmts {
                if let Stmt::Call(Some(var @ Var::Temp(_, _)), target, args) = stmt {
                    let key = format!("{var}");
                    let target_str = self.resolve_call_target(target);
                    let args_str: Vec<String> = args.iter().map(|a| self.expr_to_c(a)).collect();
                    let call_str = format!("{}({})", target_str, args_str.join(", "));
                    self.call_results.insert(key, call_str);
                }
            }
        }

        // Structured control flow recovery
        let all_ids: Vec<BlockId> = func.blocks.iter().map(|b| b.id).collect();
        let loop_headers = self.find_loop_headers(func, cfg);
        let loop_bodies = self.compute_all_loop_bodies(func, &loop_headers);
        let nodes = self.structure_region(func, cfg, &all_ids, &loop_headers, &loop_bodies, None);
        let code = self.emit_structured(&nodes, func);
        out.push_str(&code);

        let _ = writeln!(out, "}}");
        out
    }

    fn indent_str(&self) -> String {
        "    ".repeat(self.indent)
    }

    /// Collect all local variables declared in the function.
    fn collect_locals(&self, func: &Function) -> Vec<(String, BitWidth)> {
        let mut locals: BTreeMap<String, BitWidth> = BTreeMap::new();

        for block in &func.blocks {
            for stmt in &block.stmts {
                if let Stmt::Assign(var, _) = stmt {
                    match var {
                        Var::Stack(off, w) => {
                            let name = if *off >= 0 {
                                format!("arg_{off:x}")
                            } else {
                                format!("var_{:x}", off.unsigned_abs())
                            };
                            locals.entry(name).or_insert(*w);
                        }
                        Var::Temp(id, w) => {
                            locals.entry(format!("t{id}")).or_insert(*w);
                        }
                        _ => {}
                    }
                }
            }
        }

        locals.into_iter().collect()
    }

    // ── Loop detection ───────────────────────────────────────────

    /// Find all loop header block IDs (targets of back-edges).
    fn find_loop_headers(&self, func: &Function, cfg: &Cfg) -> BTreeSet<BlockId> {
        let back_edges = cfg.back_edges();
        let addr_to_id: HashMap<u64, BlockId> = func
            .blocks
            .iter()
            .map(|b| (b.addr, b.id))
            .collect();
        back_edges
            .iter()
            .filter_map(|(_, header_addr)| addr_to_id.get(header_addr).copied())
            .collect()
    }

    /// Compute natural loop body for each loop header.
    fn compute_all_loop_bodies(
        &self,
        func: &Function,
        headers: &BTreeSet<BlockId>,
    ) -> HashMap<BlockId, BTreeSet<BlockId>> {
        let mut result = HashMap::new();
        for &header in headers {
            result.insert(header, self.natural_loop_body(func, header));
        }
        result
    }

    /// Compute the natural loop body: header + all blocks that can reach the
    /// header's back-edge source without going through outside the loop.
    fn natural_loop_body(&self, func: &Function, header: BlockId) -> BTreeSet<BlockId> {
        let mut body = BTreeSet::new();
        body.insert(header);

        let header_addr = func.block(header).map(|b| b.addr).unwrap_or(0);

        // Find true back-edge sources: blocks that jump to header AND appear after it
        // (i.e., their address > header's address, meaning they loop back)
        let mut worklist: Vec<BlockId> = Vec::new();
        for block in &func.blocks {
            let succs = match &block.terminator {
                Terminator::Jump(t) => vec![*t],
                Terminator::Branch(_, t, f) => vec![*t, *f],
                _ => vec![],
            };
            if succs.contains(&header) && block.id != header && block.addr > header_addr {
                if body.insert(block.id) {
                    worklist.push(block.id);
                }
            }
        }

        // Walk backwards from back-edge sources
        while let Some(bid) = worklist.pop() {
            for pred in func.predecessors(bid) {
                if body.insert(pred) {
                    worklist.push(pred);
                }
            }
        }

        body
    }

    /// Find the loop exit block (first block outside the loop that is a successor of a loop block).
    fn find_loop_exit(
        &self,
        func: &Function,
        body: &BTreeSet<BlockId>,
    ) -> Option<BlockId> {
        let mut exits = Vec::new();
        for &bid in body {
            for succ in func.successors(bid) {
                if !body.contains(&succ) {
                    exits.push(succ);
                }
            }
        }
        exits.sort();
        exits.dedup();
        exits.first().copied()
    }

    // ── Structure recovery ───────────────────────────────────────

    /// Structure a region of blocks into structured nodes.
    /// `block_ids` are in the desired emission order (same as the compiled layout).
    fn structure_region(
        &self,
        func: &Function,
        cfg: &Cfg,
        block_ids: &[BlockId],
        loop_headers: &BTreeSet<BlockId>,
        loop_bodies: &HashMap<BlockId, BTreeSet<BlockId>>,
        enclosing_loop: Option<BlockId>,
    ) -> Vec<StructuredNode> {
        let block_set: HashSet<BlockId> = block_ids.iter().copied().collect();
        let mut result = Vec::new();
        let mut i = 0;

        // Compute enclosing loop's exit for break detection
        let enclosing_exit: Option<BlockId> = enclosing_loop.and_then(|header| {
            loop_bodies.get(&header).and_then(|body| self.find_loop_exit(func, body))
        });

        while i < block_ids.len() {
            let bid = block_ids[i];
            let block = match func.block(bid) {
                Some(b) => b,
                None => {
                    i += 1;
                    continue;
                }
            };

            // Is this a loop header (and not the enclosing loop we're already in)?
            if loop_headers.contains(&bid) && Some(bid) != enclosing_loop {
                let body = &loop_bodies[&bid];

                // Collect body block IDs in layout order (skip the header itself for the body)
                let body_block_ids: Vec<BlockId> = block_ids[i..]
                    .iter()
                    .copied()
                    .filter(|b| body.contains(b) && *b != bid)
                    .collect();

                // Determine loop condition
                let (condition, loop_body_nodes) = match &block.terminator {
                    Terminator::Branch(cond, t, f) => {
                        let t_in_loop = body.contains(t);
                        let f_in_loop = body.contains(f);
                        if t_in_loop && !f_in_loop {
                            let body_nodes = self.structure_region(
                                func, cfg, &body_block_ids, loop_headers, loop_bodies, Some(bid),
                            );
                            (cond.clone(), body_nodes)
                        } else if !t_in_loop && f_in_loop {
                            let body_nodes = self.structure_region(
                                func, cfg, &body_block_ids, loop_headers, loop_bodies, Some(bid),
                            );
                            (negate_condition(cond), body_nodes)
                        } else {
                            let all_body_nodes = self.structure_region(
                                func, cfg, &body_block_ids, loop_headers, loop_bodies, Some(bid),
                            );
                            (Expr::const_val(1, BitWidth::Bit32), all_body_nodes)
                        }
                    }
                    _ => {
                        let body_nodes = self.structure_region(
                            func, cfg, &body_block_ids, loop_headers, loop_bodies, Some(bid),
                        );
                        (Expr::const_val(1, BitWidth::Bit32), body_nodes)
                    }
                };

                result.push(StructuredNode::While {
                    header: bid,
                    condition,
                    body: loop_body_nodes,
                });

                // Skip past all body blocks
                while i < block_ids.len() && body.contains(&block_ids[i]) {
                    i += 1;
                }
                continue;
            }

            let next_in_layout = block_ids.get(i + 1).copied();

            match &block.terminator {
                Terminator::Jump(target) => {
                    let target = *target;
                    // Jump to loop header → implicit continue
                    if Some(target) == enclosing_loop {
                        result.push(StructuredNode::Stmts(bid));
                    }
                    // Jump to loop exit → break
                    else if enclosing_exit == Some(target) {
                        result.push(StructuredNode::Stmts(bid));
                        result.push(StructuredNode::Break);
                    }
                    // Jump to next block in layout → fallthrough
                    else if next_in_layout == Some(target) {
                        result.push(StructuredNode::Stmts(bid));
                    }
                    // Jump to exit or outside region → try to inline the tail chain
                    else {
                        // If target is in the function but outside the region, inline the tail
                        let tail = self.collect_goto_tail(func, target);
                        if !tail.is_empty() {
                            result.push(StructuredNode::Stmts(bid));
                            for &tail_bid in &tail {
                                result.push(StructuredNode::Block(tail_bid));
                            }
                        } else {
                            result.push(StructuredNode::Block(bid));
                        }
                    }
                }

                Terminator::Branch(cond, t, f) => {
                    let t = *t;
                    let f = *f;
                    let cond = cond.clone();

                    // Check for loop back-edge branches
                    if Some(t) == enclosing_loop && Some(f) == enclosing_loop {
                        result.push(StructuredNode::Block(bid));
                    }
                    // Branch to loop exit → break
                    else if enclosing_exit == Some(t) && Some(f) == enclosing_loop {
                        // if(cond) break; else continue (implicit)
                        result.push(StructuredNode::Stmts(bid));
                        result.push(StructuredNode::IfThen {
                            condition: cond,
                            then_body: vec![StructuredNode::Break],
                        });
                    }
                    else if enclosing_exit == Some(f) && Some(t) == enclosing_loop {
                        // if(!cond) break; else continue (implicit)
                        result.push(StructuredNode::Stmts(bid));
                        result.push(StructuredNode::IfThen {
                            condition: negate_condition(&cond),
                            then_body: vec![StructuredNode::Break],
                        });
                    }
                    else if enclosing_exit == Some(t) {
                        // if(cond) break; then fallthrough
                        result.push(StructuredNode::Stmts(bid));
                        result.push(StructuredNode::IfThen {
                            condition: cond,
                            then_body: vec![StructuredNode::Break],
                        });
                        // f block is next (or goto)
                        if next_in_layout != Some(f) && block_set.contains(&f) {
                            // Need to handle the false branch
                        }
                    }
                    else if enclosing_exit == Some(f) {
                        // if(!cond) break; then fallthrough
                        result.push(StructuredNode::Stmts(bid));
                        result.push(StructuredNode::IfThen {
                            condition: negate_condition(&cond),
                            then_body: vec![StructuredNode::Break],
                        });
                    }
                    else if Some(f) == enclosing_loop {
                        // if(cond) { ... } then loop back
                        result.push(StructuredNode::Stmts(bid));
                        let then_body = self.structure_arm_inline(
                            func, cfg, t, &block_set, loop_headers, loop_bodies, enclosing_loop,
                        );
                        let new_i = self.advance_past_arm(block_ids, i + 1, &then_body);
                        result.push(StructuredNode::IfThen {
                            condition: cond,
                            then_body,
                        });
                        i = new_i;
                        continue;
                    } else if Some(t) == enclosing_loop {
                        result.push(StructuredNode::Stmts(bid));
                        let then_body = self.structure_arm_inline(
                            func, cfg, f, &block_set, loop_headers, loop_bodies, enclosing_loop,
                        );
                        let new_i = self.advance_past_arm(block_ids, i + 1, &then_body);
                        result.push(StructuredNode::IfThen {
                            condition: negate_condition(&cond),
                            then_body,
                        });
                        i = new_i;
                        continue;
                    }
                    // One branch is the next block → if-then pattern
                    else if next_in_layout == Some(f) {
                        result.push(StructuredNode::Stmts(bid));
                        let merge = self.find_merge_point(func, t, f, &block_set);
                        let then_blocks = self.collect_arm_blocks(func, t, merge, &block_set, enclosing_loop);

                        let then_body = if then_blocks.is_empty() {
                            vec![StructuredNode::Block(t)]
                        } else {
                            self.structure_region(func, cfg, &then_blocks, loop_headers, loop_bodies, enclosing_loop)
                        };

                        if merge == Some(f) || then_blocks.is_empty() {
                            result.push(StructuredNode::IfThen {
                                condition: cond,
                                then_body,
                            });
                        } else {
                            let else_blocks = self.collect_arm_blocks(func, f, merge, &block_set, enclosing_loop);
                            if else_blocks.is_empty() {
                                result.push(StructuredNode::IfThen {
                                    condition: cond,
                                    then_body,
                                });
                            } else {
                                let else_body = self.structure_region(func, cfg, &else_blocks, loop_headers, loop_bodies, enclosing_loop);
                                result.push(StructuredNode::IfThenElse {
                                    condition: cond,
                                    then_body,
                                    else_body,
                                });
                            }
                        }

                        let skip: HashSet<BlockId> = then_blocks.iter().copied().collect();
                        let else_skip: HashSet<BlockId> = if let Some(StructuredNode::IfThenElse { .. }) = result.last() {
                            self.collect_arm_blocks(func, f, merge, &block_set, enclosing_loop)
                                .into_iter().collect()
                        } else {
                            HashSet::new()
                        };
                        i += 1;
                        while i < block_ids.len() && (skip.contains(&block_ids[i]) || else_skip.contains(&block_ids[i])) {
                            i += 1;
                        }
                        // If no merge point, both arms terminate — remaining blocks are dead code
                        if merge.is_none() && !skip.is_empty() && !else_skip.is_empty() {
                            break;
                        }
                        continue;
                    } else if next_in_layout == Some(t) {
                        result.push(StructuredNode::Stmts(bid));
                        let merge = self.find_merge_point(func, f, t, &block_set);
                        let then_blocks = self.collect_arm_blocks(func, f, merge, &block_set, enclosing_loop);

                        let then_body = if then_blocks.is_empty() {
                            vec![StructuredNode::Block(f)]
                        } else {
                            self.structure_region(func, cfg, &then_blocks, loop_headers, loop_bodies, enclosing_loop)
                        };

                        if merge == Some(t) || then_blocks.is_empty() {
                            result.push(StructuredNode::IfThen {
                                condition: negate_condition(&cond),
                                then_body,
                            });
                        } else {
                            let else_blocks = self.collect_arm_blocks(func, t, merge, &block_set, enclosing_loop);
                            if else_blocks.is_empty() {
                                result.push(StructuredNode::IfThen {
                                    condition: negate_condition(&cond),
                                    then_body,
                                });
                            } else {
                                let else_body = self.structure_region(func, cfg, &else_blocks, loop_headers, loop_bodies, enclosing_loop);
                                result.push(StructuredNode::IfThenElse {
                                    condition: negate_condition(&cond),
                                    then_body,
                                    else_body,
                                });
                            }
                        }

                        let skip: HashSet<BlockId> = then_blocks.iter().copied().collect();
                        let else_skip: HashSet<BlockId> = if let Some(StructuredNode::IfThenElse { .. }) = result.last() {
                            self.collect_arm_blocks(func, t, merge, &block_set, enclosing_loop)
                                .into_iter().collect()
                        } else {
                            HashSet::new()
                        };
                        i += 1;
                        while i < block_ids.len() && (skip.contains(&block_ids[i]) || else_skip.contains(&block_ids[i])) {
                            i += 1;
                        }
                        // If no merge point, both arms terminate — remaining blocks are dead code
                        if merge.is_none() && !skip.is_empty() && !else_skip.is_empty() {
                            break;
                        }
                        continue;
                    } else {
                        // Neither branch is next → emit as raw block with gotos
                        result.push(StructuredNode::Block(bid));
                    }
                }

                Terminator::Return(_) => {
                    result.push(StructuredNode::Block(bid));
                }

                _ => {
                    result.push(StructuredNode::Block(bid));
                }
            }

            i += 1;
        }

        result
    }

    /// Collect blocks belonging to one arm of an if-then-else, stopping at the merge point.
    fn collect_arm_blocks(
        &self,
        func: &Function,
        start: BlockId,
        merge: Option<BlockId>,
        region: &HashSet<BlockId>,
        enclosing_loop: Option<BlockId>,
    ) -> Vec<BlockId> {
        let mut arm = Vec::new();
        let mut visited = HashSet::new();
        let mut worklist = vec![start];

        while let Some(bid) = worklist.pop() {
            if Some(bid) == merge {
                continue;
            }
            if Some(bid) == enclosing_loop {
                continue;
            }
            if !region.contains(&bid) {
                continue;
            }
            if !visited.insert(bid) {
                continue;
            }
            arm.push(bid);

            if let Some(block) = func.block(bid) {
                let succs = match &block.terminator {
                    Terminator::Jump(t) => vec![*t],
                    Terminator::Branch(_, t, f) => vec![*t, *f],
                    _ => vec![],
                };
                for s in succs {
                    if !visited.contains(&s) {
                        worklist.push(s);
                    }
                }
            }
        }

        // Sort by block index to maintain layout order
        arm.sort_by_key(|bid| func.block(*bid).map(|b| b.addr).unwrap_or(0));
        arm
    }

    /// Find the merge point where two branches converge.
    fn find_merge_point(
        &self,
        func: &Function,
        branch_a: BlockId,
        branch_b: BlockId,
        region: &HashSet<BlockId>,
    ) -> Option<BlockId> {
        let reach_a = self.reachable_from(func, branch_a, region);
        let reach_b = self.reachable_from(func, branch_b, region);

        let mut common: Vec<BlockId> = reach_a.intersection(&reach_b).copied().collect();
        common.sort_by_key(|bid| func.block(*bid).map(|b| b.addr).unwrap_or(u64::MAX));
        common.first().copied()
    }

    /// Compute set of blocks reachable from `start` within `region`.
    fn reachable_from(
        &self,
        func: &Function,
        start: BlockId,
        region: &HashSet<BlockId>,
    ) -> HashSet<BlockId> {
        let mut visited = HashSet::new();
        let mut worklist = vec![start];
        while let Some(bid) = worklist.pop() {
            if !region.contains(&bid) {
                continue;
            }
            if !visited.insert(bid) {
                continue;
            }
            for succ in func.successors(bid) {
                if !visited.contains(&succ) {
                    worklist.push(succ);
                }
            }
        }
        visited
    }

    /// Structure a single arm for inline emission (e.g., loop-back-edge branches).
    fn structure_arm_inline(
        &self,
        func: &Function,
        cfg: &Cfg,
        start: BlockId,
        region: &HashSet<BlockId>,
        loop_headers: &BTreeSet<BlockId>,
        loop_bodies: &HashMap<BlockId, BTreeSet<BlockId>>,
        enclosing_loop: Option<BlockId>,
    ) -> Vec<StructuredNode> {
        let arm_blocks = self.collect_linear_arm(func, start, region, enclosing_loop);
        if arm_blocks.is_empty() {
            vec![StructuredNode::Block(start)]
        } else {
            self.structure_region(func, cfg, &arm_blocks, loop_headers, loop_bodies, enclosing_loop)
        }
    }

    fn collect_linear_arm(
        &self,
        func: &Function,
        start: BlockId,
        region: &HashSet<BlockId>,
        enclosing_loop: Option<BlockId>,
    ) -> Vec<BlockId> {
        let mut arm = Vec::new();
        let mut current = start;
        let mut visited = HashSet::new();

        loop {
            if Some(current) == enclosing_loop && !arm.is_empty() {
                break;
            }
            if !region.contains(&current) {
                // Don't include blocks outside the current region
                break;
            }
            if !visited.insert(current) {
                break;
            }
            arm.push(current);

            match func.block(current).map(|b| &b.terminator) {
                Some(Terminator::Jump(t)) => {
                    current = *t;
                }
                _ => break,
            }
        }

        arm
    }

    /// Follow a chain of blocks starting from `start` for goto-tail inlining.
    /// Collects blocks that form a linear chain (Jump terminators) until
    /// reaching a Return, branch, or block with a noreturn call.
    fn collect_goto_tail(&self, func: &Function, start: BlockId) -> Vec<BlockId> {
        let mut chain = Vec::new();
        let mut current = start;
        let mut visited = HashSet::new();

        loop {
            let block = match func.block(current) {
                Some(b) => b,
                None => break,
            };
            if !visited.insert(current) {
                break;
            }
            chain.push(current);

            // Stop after noreturn calls
            if block.stmts.iter().any(|s| self.is_noreturn_call(s)) {
                break;
            }

            match &block.terminator {
                Terminator::Jump(t) => current = *t,
                Terminator::Return(_) => break,
                _ => break, // Branch or other complex terminator — stop
            }
        }

        chain
    }

    /// Advance index past blocks that were consumed by an arm.
    fn advance_past_arm(&self, block_ids: &[BlockId], start_idx: usize, arm_nodes: &[StructuredNode]) -> usize {
        let arm_ids: HashSet<BlockId> = arm_nodes
            .iter()
            .filter_map(|n| match n {
                StructuredNode::Block(id) | StructuredNode::Stmts(id) => Some(*id),
                _ => None,
            })
            .collect();
        let mut i = start_idx;
        while i < block_ids.len() && arm_ids.contains(&block_ids[i]) {
            i += 1;
        }
        i
    }

    // ── Code emission ────────────────────────────────────────────

    fn block_has_noreturn(&self, block: &BasicBlock) -> bool {
        block.stmts.iter().any(|s| self.is_noreturn_call(s))
    }

    fn emit_structured(&mut self, nodes: &[StructuredNode], func: &Function) -> String {
        let mut out = String::new();

        for node in nodes {
            match node {
                StructuredNode::Block(id) => {
                    if let Some(block) = func.block(*id) {
                        out.push_str(&self.emit_block_full(block, func));
                        if self.block_has_noreturn(block) {
                            break;
                        }
                    }
                }
                StructuredNode::Stmts(id) => {
                    if let Some(block) = func.block(*id) {
                        self.emit_stmts_only(&mut out, block);
                        if self.block_has_noreturn(block) {
                            break;
                        }
                    }
                }
                StructuredNode::IfThen { condition, then_body } => {
                    let _ = writeln!(out, "{}if ({}) {{", self.indent_str(), self.expr_to_c(condition));
                    self.indent += 1;
                    out.push_str(&self.emit_structured(then_body, func));
                    self.indent -= 1;
                    let _ = writeln!(out, "{}}}", self.indent_str());
                }
                StructuredNode::IfThenElse { condition, then_body, else_body } => {
                    let _ = writeln!(out, "{}if ({}) {{", self.indent_str(), self.expr_to_c(condition));
                    self.indent += 1;
                    out.push_str(&self.emit_structured(then_body, func));
                    self.indent -= 1;
                    // Check for else-if chain
                    if else_body.len() == 1 {
                        match &else_body[0] {
                            StructuredNode::IfThen { condition: ec, then_body: et } => {
                                let _ = writeln!(out, "{}}} else if ({}) {{", self.indent_str(), self.expr_to_c(ec));
                                self.indent += 1;
                                out.push_str(&self.emit_structured(et, func));
                                self.indent -= 1;
                                let _ = writeln!(out, "{}}}", self.indent_str());
                                continue;
                            }
                            StructuredNode::IfThenElse { condition: ec, then_body: et, else_body: ee } => {
                                let _ = writeln!(out, "{}}} else if ({}) {{", self.indent_str(), self.expr_to_c(ec));
                                self.indent += 1;
                                out.push_str(&self.emit_structured(et, func));
                                self.indent -= 1;
                                let _ = writeln!(out, "{}}} else {{", self.indent_str());
                                self.indent += 1;
                                out.push_str(&self.emit_structured(ee, func));
                                self.indent -= 1;
                                let _ = writeln!(out, "{}}}", self.indent_str());
                                continue;
                            }
                            _ => {}
                        }
                    }
                    let _ = writeln!(out, "{}}} else {{", self.indent_str());
                    self.indent += 1;
                    out.push_str(&self.emit_structured(else_body, func));
                    self.indent -= 1;
                    let _ = writeln!(out, "{}}}", self.indent_str());
                }
                StructuredNode::While { header, condition, body, .. } => {
                    // Emit header statements (before loop)
                    if let Some(block) = func.block(*header) {
                        self.emit_stmts_only(&mut out, block);
                    }
                    let cond_str = self.expr_to_c(condition);
                    let _ = writeln!(out, "{}while ({}) {{", self.indent_str(), cond_str);
                    self.indent += 1;
                    out.push_str(&self.emit_structured(body, func));
                    self.indent -= 1;
                    let _ = writeln!(out, "{}}}", self.indent_str());
                }
                StructuredNode::Break => {
                    let _ = writeln!(out, "{}break;", self.indent_str());
                }
            }
        }

        out
    }

    /// Emit a block with its statements AND terminator.
    fn emit_block_full(&mut self, block: &BasicBlock, func: &Function) -> String {
        let mut out = String::new();
        let mut hit_noreturn = false;

        for stmt in &block.stmts {
            let line = self.stmt_to_c(stmt);
            if !line.is_empty() {
                let _ = writeln!(out, "{}{};", self.indent_str(), line);
                if self.is_noreturn_call(stmt) {
                    hit_noreturn = true;
                    break;
                }
            }
        }

        if hit_noreturn {
            return out;
        }

        match &block.terminator {
            Terminator::Return(val) => {
                let _ = match val {
                    Some(v) => writeln!(out, "{}return {};", self.indent_str(), self.expr_to_c(v)),
                    None => writeln!(out, "{}return;", self.indent_str()),
                };
            }
            Terminator::Jump(target) => {
                // Try to inline the goto tail chain
                let tail = self.collect_goto_tail(func, *target);
                if !tail.is_empty() {
                    for (idx, &tail_bid) in tail.iter().enumerate() {
                        if let Some(tail_block) = func.block(tail_bid) {
                            // Emit stmts for all blocks
                            self.emit_stmts_only(&mut out, tail_block);
                            if self.block_has_noreturn(tail_block) {
                                return out;
                            }
                            // Emit terminator only for the last block
                            if idx == tail.len() - 1 {
                                match &tail_block.terminator {
                                    Terminator::Return(val) => {
                                        let _ = match val {
                                            Some(v) => writeln!(out, "{}return {};", self.indent_str(), self.expr_to_c(v)),
                                            None => writeln!(out, "{}return;", self.indent_str()),
                                        };
                                    }
                                    _ => {} // Jump/Branch in last block — skip (already inlined)
                                }
                            }
                        }
                    }
                } else {
                    let _ = writeln!(out, "{}goto {};", self.indent_str(), target);
                }
            }
            Terminator::Branch(cond, t, f) => {
                let _ = writeln!(
                    out,
                    "{}if ({}) goto {}; else goto {};",
                    self.indent_str(),
                    self.expr_to_c(cond),
                    t,
                    f
                );
            }
            Terminator::IndirectJump(target) => {
                let _ = writeln!(out, "{}goto *{};", self.indent_str(), self.expr_to_c(target));
            }
            Terminator::Unreachable => {
                let _ = writeln!(out, "{}__builtin_unreachable();", self.indent_str());
            }
        }

        out
    }

    fn emit_stmts_only(&mut self, out: &mut String, block: &BasicBlock) {
        for stmt in &block.stmts {
            let line = self.stmt_to_c(stmt);
            if !line.is_empty() {
                let _ = writeln!(out, "{}{};", self.indent_str(), line);
                // Stop after noreturn calls
                if self.is_noreturn_call(stmt) {
                    return;
                }
            }
        }
    }

    // ── Statement/expression rendering ───────────────────────────

    fn is_noreturn_call(&self, stmt: &Stmt) -> bool {
        if let Stmt::Call(_, target, _) = stmt {
            let name = self.resolve_call_target(target);
            is_noreturn_name(&name)
        } else {
            false
        }
    }

    fn stmt_to_c(&self, stmt: &Stmt) -> String {
        match stmt {
            Stmt::Assign(var, expr) => {
                // Suppress all register assignments — they're ABI noise
                if matches!(var, Var::Reg(_, _)) {
                    return String::new();
                }
                // Suppress parameter assignments (var_N = param_reg)
                if let Var::Stack(off, _) = var {
                    let name = if *off >= 0 {
                        format!("arg_{off:x}")
                    } else {
                        format!("var_{:x}", off.unsigned_abs())
                    };
                    if self.param_vars.contains(&name) {
                        if matches!(expr, Expr::Var(Var::Reg(_, _))) {
                            return String::new();
                        }
                    }
                }
                format!("{} = {}", self.var_to_c(var), self.expr_to_c(expr))
            }
            Stmt::Store(addr, val, width) => {
                format!(
                    "*({}*)({}) = {}",
                    c_type(*width),
                    self.expr_to_c(addr),
                    self.expr_to_c(val)
                )
            }
            Stmt::Call(ret, target, args) => {
                // Suppress call if its result temp is inlined into usage site
                if let Some(var @ Var::Temp(_, _)) = ret {
                    let key = format!("{var}");
                    if self.call_results.contains_key(&key) {
                        return String::new();
                    }
                }
                let target_str = self.resolve_call_target(target);
                let args_str: Vec<String> = args.iter().map(|a| self.expr_to_c(a)).collect();
                match ret {
                    Some(r) => format!("{} = {}({})", self.var_to_c(r), target_str, args_str.join(", ")),
                    None => format!("{}({})", target_str, args_str.join(", ")),
                }
            }
            Stmt::Nop => String::new(),
        }
    }

    fn resolve_call_target(&self, target: &Expr) -> String {
        match target {
            Expr::Const(addr, _) => {
                if let Some(name) = self.binary.resolve_func_name(*addr) {
                    return name;
                }
                if let Some(name) = self.symbols.get(addr) {
                    return name.clone();
                }
                format!("sub_{addr:x}")
            }
            _ => self.expr_to_c(target),
        }
    }

    fn expr_to_c(&self, expr: &Expr) -> String {
        match expr {
            Expr::Var(v) => self.var_to_c(v),
            Expr::Const(val, width) => {
                // Try to resolve as a string constant
                if *val > 0x1000 {
                    if let Some(s) = self.binary.read_cstring_at(*val) {
                        return format!("\"{}\"", escape_c_string(&s));
                    }
                }
                // Character literal for byte/dword-sized printable ASCII
                if matches!(width, BitWidth::Bit8 | BitWidth::Bit32) && *val >= 0x20 && *val <= 0x7e {
                    let ch = *val as u8 as char;
                    return format!("'{ch}'");
                }
                // Special characters
                if *val == 0x0a {
                    return "'\\n'".to_string();
                }
                // Common negative values: display as signed
                match (*val, *width) {
                    (0xff, BitWidth::Bit8) | (0xffff, BitWidth::Bit16)
                    | (0xffff_ffff, BitWidth::Bit32) | (0xffff_ffff_ffff_ffff, BitWidth::Bit64) => {
                        return "-1".to_string();
                    }
                    _ => {}
                }
                if *val > 9 {
                    format!("0x{val:x}")
                } else {
                    format!("{val}")
                }
            }
            Expr::BinOp(op, lhs, rhs) => {
                // rip + const → just the const (address)
                if matches!(op, BinOp::Add) {
                    if let Expr::Var(Var::Reg(RegId::Rip, _)) = lhs.as_ref() {
                        return self.expr_to_c(rhs);
                    }
                }
                // rbp + large_const → &var_N
                if matches!(op, BinOp::Add) {
                    if let Expr::Var(Var::Reg(RegId::Rbp, _)) = lhs.as_ref() {
                        if let Expr::Const(val, _) = rhs.as_ref() {
                            let offset = *val as i64;
                            if offset < 0 {
                                return format!("&var_{:x}", (-offset) as u64);
                            } else if offset > 0 {
                                return format!("&arg_{offset:x}");
                            }
                        }
                    }
                }
                // rbp - const → &var_N
                if matches!(op, BinOp::Sub) {
                    if let Expr::Var(Var::Reg(RegId::Rbp, _)) = lhs.as_ref() {
                        if let Expr::Const(val, _) = rhs.as_ref() {
                            return format!("&var_{val:x}");
                        }
                    }
                }
                let op_str = match op {
                    BinOp::Add => "+",
                    BinOp::Sub => "-",
                    BinOp::Mul => "*",
                    BinOp::UDiv | BinOp::SDiv => "/",
                    BinOp::UMod | BinOp::SMod => "%",
                    BinOp::And => "&",
                    BinOp::Or => "|",
                    BinOp::Xor => "^",
                    BinOp::Shl => "<<",
                    BinOp::Shr | BinOp::Sar => ">>",
                    BinOp::Eq => "==",
                    BinOp::Ne => "!=",
                    BinOp::Ult | BinOp::Slt => "<",
                    BinOp::Ule | BinOp::Sle => "<=",
                };
                format!("({} {} {})", self.expr_to_c(lhs), op_str, self.expr_to_c(rhs))
            }
            Expr::UnaryOp(op, inner) => match op {
                UnaryOp::Neg => format!("(-{})", self.expr_to_c(inner)),
                UnaryOp::Not => format!("(~{})", self.expr_to_c(inner)),
                UnaryOp::ZeroExt(w) | UnaryOp::Trunc(w) => {
                    format!("({}){}", c_type(*w), self.expr_to_c(inner))
                }
                UnaryOp::SignExt(w) => {
                    format!("({})(signed){}", c_type(*w), self.expr_to_c(inner))
                }
            },
            Expr::Load(addr, width) => {
                // Resolve rip-relative loads as globals/strings
                if let Expr::BinOp(BinOp::Add, lhs, rhs) = addr.as_ref() {
                    if let Expr::Var(Var::Reg(RegId::Rip, _)) = lhs.as_ref() {
                        if let Expr::Const(target_addr, _) = rhs.as_ref() {
                            if let Some(name) = self.binary.resolve_func_name(*target_addr) {
                                return name;
                            }
                            if let Some(name) = self.binary.resolve_global_name(*target_addr) {
                                return name;
                            }
                            if let Some(s) = self.binary.read_cstring_at(*target_addr) {
                                return format!("\"{}\"", escape_c_string(&s));
                            }
                        }
                    }
                }
                // Direct constant address → global
                if let Expr::Const(addr_val, _) = addr.as_ref() {
                    if let Some(name) = self.binary.resolve_global_name(*addr_val) {
                        return name;
                    }
                }
                // Stack loads: *(type*)(rbp + offset) → var_N
                if let Expr::BinOp(BinOp::Add, lhs, rhs) = addr.as_ref() {
                    if let Expr::Var(Var::Reg(RegId::Rbp, _)) = lhs.as_ref() {
                        if let Expr::Const(val, _) = rhs.as_ref() {
                            let offset = *val as i64;
                            if offset < 0 {
                                return format!("var_{:x}", (-offset) as u64);
                            }
                        }
                    }
                }
                format!("*({}*)({})", c_type(*width), self.expr_to_c(addr))
            }
            Expr::Cond(cc) => match cc {
                CondCode::Eq => "==".to_string(),
                CondCode::Ne => "!=".to_string(),
                CondCode::Lt => "<".to_string(),
                CondCode::Le => "<=".to_string(),
                CondCode::Gt => ">".to_string(),
                CondCode::Ge => ">=".to_string(),
                CondCode::Below => "<".to_string(),
                CondCode::BelowEq => "<=".to_string(),
                CondCode::Above => ">".to_string(),
                CondCode::AboveEq => ">=".to_string(),
                CondCode::Sign => "< 0".to_string(),
                CondCode::NotSign => ">= 0".to_string(),
            },
            Expr::Cmp(cc, lhs, rhs) => {
                let op = match cc {
                    CondCode::Eq => "==",
                    CondCode::Ne => "!=",
                    CondCode::Lt | CondCode::Below => "<",
                    CondCode::Le | CondCode::BelowEq => "<=",
                    CondCode::Gt | CondCode::Above => ">",
                    CondCode::Ge | CondCode::AboveEq => ">=",
                    CondCode::Sign => "<",
                    CondCode::NotSign => ">=",
                };
                format!("{} {} {}", self.expr_to_c(lhs), op, self.expr_to_c(rhs))
            }
        }
    }

    fn var_to_c(&self, var: &Var) -> String {
        match var {
            Var::Reg(reg, _) => format!("{reg}"),
            Var::Stack(off, _) => {
                if *off >= 0 {
                    format!("arg_{off:x}")
                } else {
                    format!("var_{:x}", off.unsigned_abs())
                }
            }
            Var::Temp(id, _) => {
                let key = format!("t{id}");
                // Inline call results: show `func(args)` instead of `t0`
                if let Some(call_str) = self.call_results.get(&key) {
                    return call_str.clone();
                }
                key
            }
            Var::Flag(f) => format!("{f}"),
        }
    }
}

/// Map bit width to C type name.
fn c_type(width: BitWidth) -> &'static str {
    match width {
        BitWidth::Bit8 => "uint8_t",
        BitWidth::Bit16 => "uint16_t",
        BitWidth::Bit32 => "uint32_t",
        BitWidth::Bit64 => "uint64_t",
    }
}

/// Negate a condition expression.
fn negate_condition(cond: &Expr) -> Expr {
    match cond {
        Expr::Cmp(cc, lhs, rhs) => Expr::Cmp(cc.negate(), lhs.clone(), rhs.clone()),
        Expr::Cond(cc) => Expr::Cond(cc.negate()),
        other => Expr::unaryop(UnaryOp::Not, other.clone()),
    }
}

/// Escape a string for C literal output.
fn escape_c_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

/// Structured control flow nodes.
#[derive(Debug, Clone)]
enum StructuredNode {
    /// A full block with statements + terminator rendered.
    Block(BlockId),
    /// Only statements of a block, no terminator (used for fallthroughs).
    Stmts(BlockId),
    IfThen {
        condition: Expr,
        then_body: Vec<StructuredNode>,
    },
    IfThenElse {
        condition: Expr,
        then_body: Vec<StructuredNode>,
        else_body: Vec<StructuredNode>,
    },
    While {
        header: BlockId,
        condition: Expr,
        body: Vec<StructuredNode>,
    },
    Break,
}
