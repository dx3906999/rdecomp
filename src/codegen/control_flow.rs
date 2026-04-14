use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write;
use crate::cfg::Cfg;
use crate::ir::*;
use super::{CodeGenerator, StructuredNode, negate_condition};

impl<'a> CodeGenerator<'a> {
    // Loop detection.

    /// Find all loop headers and their back-edge sources from the CFG.
    /// Returns the set of loop headers and a map from header to back-edge source blocks.
    pub(crate) fn find_loop_info(
        &self,
        func: &Function,
        cfg: &Cfg,
    ) -> (BTreeSet<BlockId>, HashMap<BlockId, Vec<BlockId>>) {
        let back_edges = cfg.back_edges();
        let addr_to_id: HashMap<u64, BlockId> = func
            .blocks
            .iter()
            .map(|b| (b.addr, b.id))
            .collect();
        let mut headers = BTreeSet::new();
        let mut sources: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for (src_addr, hdr_addr) in &back_edges {
            if let (Some(&src_id), Some(&hdr_id)) =
                (addr_to_id.get(src_addr), addr_to_id.get(hdr_addr))
            {
                headers.insert(hdr_id);
                sources.entry(hdr_id).or_default().push(src_id);
            }
        }
        (headers, sources)
    }

    /// Compute natural loop body for each loop header using the known back-edge sources.
    pub(crate) fn compute_all_loop_bodies(
        &self,
        func: &Function,
        headers: &BTreeSet<BlockId>,
        back_edge_sources: &HashMap<BlockId, Vec<BlockId>>,
    ) -> HashMap<BlockId, BTreeSet<BlockId>> {
        let mut result = HashMap::new();
        for &header in headers {
            let srcs = back_edge_sources
                .get(&header)
                .map_or(&[][..], |v| v.as_slice());
            result.insert(header, self.natural_loop_body(func, header, srcs));
        }
        result
    }

    /// Compute the natural loop body: header + all blocks that can reach the
    /// back-edge source(s) without going through outside the loop.
    /// Uses the standard algorithm: seed from known back-edge sources (determined
    /// by dominance in `cfg.back_edges()`), then walk predecessors backwards.
    pub(crate) fn natural_loop_body(
        &self,
        func: &Function,
        header: BlockId,
        back_edge_sources: &[BlockId],
    ) -> BTreeSet<BlockId> {
        let mut body = BTreeSet::new();
        body.insert(header);

        let mut worklist: Vec<BlockId> = Vec::new();
        for &src in back_edge_sources {
            if body.insert(src) {
                worklist.push(src);
            }
        }

        // Walk backwards: add predecessors until we reach blocks already in the body
        // (the header acts as the implicit stop because it's already inserted).
        while let Some(bid) = worklist.pop() {
            for pred in func.predecessors(bid) {
                if body.insert(pred) {
                    worklist.push(pred);
                }
            }
        }

        body
    }

    /// Check if a merge block is a "return relay": no meaningful stmts, just returns.
    /// When all if/else arms already emit their own return via goto-tail inlining,
    /// such a merge block is dead code and should be skipped.
    pub(crate) fn is_return_relay(&self, func: &Function, merge: Option<BlockId>) -> bool {
        let Some(bid) = merge else { return false };
        let Some(block) = func.block(bid) else { return false };
        if !matches!(block.terminator, Terminator::Return(_)) {
            return false;
        }
        // All stmts must be register assignments or nops (no meaningful computation)
        block.stmts.iter().all(|s| matches!(s, Stmt::Nop | Stmt::Assign(Var::Reg(_, _), _)))
    }

    /// Find the loop exit block (first block outside the loop that is a successor of a loop block).
    pub(crate) fn find_loop_exit(
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

    /// Decide what node to emit for a loop exit: if the exit target (or its
    /// goto-tail chain) ends with a return, inline the block as a return
    /// statement; otherwise emit a break.
    pub(crate) fn loop_exit_node(&self, func: &Function, target: BlockId) -> StructuredNode {
        let ends_with_return = func.block(target).is_some_and(|b| {
            match &b.terminator {
                Terminator::Return(_) => true,
                Terminator::Jump(j) => {
                    let tail = self.collect_goto_tail(func, *j);
                    tail.last().and_then(|&tb| func.block(tb))
                        .is_some_and(|tb| matches!(tb.terminator, Terminator::Return(_)))
                }
                _ => false,
            }
        });
        if ends_with_return {
            StructuredNode::Block(target)
        } else {
            StructuredNode::Break
        }
    }

    // Structure recovery.

    /// Structure a region of blocks into structured nodes.
    /// `block_ids` are in the desired emission order (same as the compiled layout).
    pub(crate) fn structure_region(
        &self,
        func: &Function,
        cfg: &Cfg,
        block_ids: &[BlockId],
        loop_headers: &BTreeSet<BlockId>,
        loop_bodies: &HashMap<BlockId, BTreeSet<BlockId>>,
        back_edge_sources: &HashMap<BlockId, Vec<BlockId>>,
        enclosing_loop: Option<BlockId>,
    ) -> Vec<StructuredNode> {
        let block_set: HashSet<BlockId> = block_ids.iter().copied().collect();
        let mut result = Vec::new();
        let mut i = 0;

        // Compute enclosing loop's exit for break detection
        let enclosing_exit: Option<BlockId> = enclosing_loop.and_then(|header| {
            loop_bodies.get(&header).and_then(|body| self.find_loop_exit(func, body))
        });

        // Defer loop-interior blocks: blocks that belong to a loop whose header
        // is in this region. They will be processed as part of the While body
        // when the header is reached, avoiding premature consumption by if-else.
        let mut deferred: HashSet<BlockId> = {
            let mut set = HashSet::new();
            for &hdr in loop_headers {
                if block_set.contains(&hdr) && Some(hdr) != enclosing_loop
                    && let Some(body) = loop_bodies.get(&hdr) {
                        for &b in body {
                            if b != hdr && block_set.contains(&b) {
                                set.insert(b);
                            }
                        }
                    }
            }
            set
        };

        while i < block_ids.len() {
            let bid = block_ids[i];

            // Skip blocks deferred to their loop header's While body
            if deferred.contains(&bid) && !loop_headers.contains(&bid) {
                i += 1;
                continue;
            }

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

                // Collect body block IDs in layout order from ALL blocks in region
                // (not just from i.., since rotated loops have body before header)
                let body_block_ids: Vec<BlockId> = block_ids
                    .iter()
                    .copied()
                    .filter(|b| body.contains(b) && *b != bid)
                    .collect();

                // Determine loop condition and whether this is a do-while
                let mut while_exit_guard: Option<Expr> = None;
                let loop_node = match &block.terminator {
                    Terminator::Branch(cond, t, f) => {
                        // Pre-tested loop: header has condition check
                        let t_in_loop = body.contains(t);
                        let f_in_loop = body.contains(f);

                        // Self-loop: header is the only block in the body.
                        // The header's stmts execute before the condition,
                        // so this is a do-while.
                        if body_block_ids.is_empty() && (t_in_loop || f_in_loop) {
                            let do_cond = if t_in_loop && !f_in_loop {
                                cond.clone()
                            } else {
                                negate_condition(cond)
                            };
                            let exit = if t_in_loop && !f_in_loop {
                                Some(*f)
                            } else if !t_in_loop && f_in_loop {
                                Some(*t)
                            } else {
                                None
                            };
                            StructuredNode::DoWhile {
                                header: bid,
                                exit,
                                condition: do_cond,
                                body: vec![],
                            }
                        } else if t_in_loop && !f_in_loop {
                            // Check if we can fold a latch condition into the while
                            let header_exit = *f;
                            let latch_fold = back_edge_sources.get(&bid).and_then(|sources| {
                                if sources.len() == 1 {
                                    let latch = sources[0];
                                    func.block(latch).and_then(|lb| {
                                        if let Terminator::Branch(lcond, lt, lf) = &lb.terminator {
                                            if *lt == bid && *lf == header_exit {
                                                // latch: if(lcond) goto header else goto exit
                                                // Continue condition is lcond
                                                Some((lcond.clone(), latch))
                                            } else if *lf == bid && *lt == header_exit {
                                                Some((negate_condition(lcond), latch))
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    })
                                } else {
                                    None
                                }
                            });

                            if let Some((latch_cond, latch_id)) = latch_fold {
                                // Fold: while (cond && latch_cond) { body_without_latch; latch_stmts; }
                                let inner_ids: Vec<BlockId> = body_block_ids
                                    .iter()
                                    .copied()
                                    .filter(|b| *b != latch_id)
                                    .collect();
                                let mut body_nodes = self.structure_region(
                                    func, cfg, &inner_ids, loop_headers, loop_bodies, back_edge_sources, Some(bid),
                                );
                                body_nodes.push(StructuredNode::Stmts(latch_id));
                                while_exit_guard = Some(negate_condition(cond));
                                StructuredNode::While {
                                    header: bid,
                                    exit: Some(header_exit),
                                    condition: Expr::LogicalAnd(
                                        Box::new(cond.clone()),
                                        Box::new(latch_cond),
                                    ),
                                    body: body_nodes,
                                }
                            } else {
                                let nodes = self.structure_region(
                                    func, cfg, &body_block_ids, loop_headers, loop_bodies, back_edge_sources, Some(bid),
                                );
                                // Guard for header_exit (f): while exits when !cond
                                while_exit_guard = Some(negate_condition(cond));
                                StructuredNode::While {
                                    header: bid,
                                    exit: Some(header_exit),
                                    condition: cond.clone(),
                                    body: nodes,
                                }
                            }
                        } else if !t_in_loop && f_in_loop {
                            // Check if we can fold a latch condition into the while
                            let header_exit = *t;
                            let latch_fold = back_edge_sources.get(&bid).and_then(|sources| {
                                if sources.len() == 1 {
                                    let latch = sources[0];
                                    func.block(latch).and_then(|lb| {
                                        if let Terminator::Branch(lcond, lt, lf) = &lb.terminator {
                                            if *lt == bid && *lf == header_exit {
                                                Some((lcond.clone(), latch))
                                            } else if *lf == bid && *lt == header_exit {
                                                Some((negate_condition(lcond), latch))
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    })
                                } else {
                                    None
                                }
                            });

                            if let Some((latch_cond, latch_id)) = latch_fold {
                                let inner_ids: Vec<BlockId> = body_block_ids
                                    .iter()
                                    .copied()
                                    .filter(|b| *b != latch_id)
                                    .collect();
                                let mut body_nodes = self.structure_region(
                                    func, cfg, &inner_ids, loop_headers, loop_bodies, back_edge_sources, Some(bid),
                                );
                                body_nodes.push(StructuredNode::Stmts(latch_id));
                                while_exit_guard = Some(cond.clone());
                                StructuredNode::While {
                                    header: bid,
                                    exit: Some(header_exit),
                                    condition: Expr::LogicalAnd(
                                        Box::new(negate_condition(cond)),
                                        Box::new(latch_cond),
                                    ),
                                    body: body_nodes,
                                }
                            } else {
                                let nodes = self.structure_region(
                                    func, cfg, &body_block_ids, loop_headers, loop_bodies, back_edge_sources, Some(bid),
                                );
                                // Guard for header_exit (t): while exits when cond
                                while_exit_guard = Some(cond.clone());
                                StructuredNode::While {
                                    header: bid,
                                    exit: Some(header_exit),
                                    condition: negate_condition(cond),
                                    body: nodes,
                                }
                            }
                        } else {
                            // Both targets in loop: header branch is an internal
                            // if-then, not the loop condition.  Check the latch
                            // for a do-while condition.

                            // OR-fold: header self-loops on cond1 and has a latch
                            // with cond2, producing `while (cond1 || cond2)`
                            // Pattern: header: if(cond) goto header else latch;
                            //          latch:  if(lcond) goto header else exit;
                            let or_fold: Option<(Expr, BlockId, BlockId)> = if *t == bid || *f == bid {
                                let (self_cond, other) = if *t == bid {
                                    (cond.clone(), *f)
                                } else {
                                    (negate_condition(cond), *t)
                                };
                                back_edge_sources.get(&bid).and_then(|sources| {
                                    // Expect exactly 2 back-edge sources: header (self) and latch
                                    if sources.len() != 2 { return None; }
                                    let &latch = sources.iter().find(|&&s| s != bid)?;
                                    if latch != other { return None; }
                                    func.block(latch).and_then(|lb| {
                                        if let Terminator::Branch(lcond, lt, lf) = &lb.terminator {
                                            if *lt == bid && !body.contains(lf) {
                                                Some((
                                                    Expr::LogicalOr(
                                                        Box::new(self_cond.clone()),
                                                        Box::new(lcond.clone()),
                                                    ),
                                                    latch,
                                                    *lf,
                                                ))
                                            } else if *lf == bid && !body.contains(lt) {
                                                Some((
                                                    Expr::LogicalOr(
                                                        Box::new(self_cond.clone()),
                                                        Box::new(negate_condition(lcond)),
                                                    ),
                                                    latch,
                                                    *lt,
                                                ))
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    })
                                })
                            } else {
                                None
                            };

                            if let Some((or_cond, latch_id, _exit_bid)) = or_fold {
                                // while (cond1 || cond2) { body_without_latch; latch_stmts; }
                                let inner_ids: Vec<BlockId> = body_block_ids
                                    .iter()
                                    .copied()
                                    .filter(|b| *b != latch_id)
                                    .collect();
                                let mut body_nodes = self.structure_region(
                                    func, cfg, &inner_ids, loop_headers, loop_bodies, back_edge_sources, Some(bid),
                                );
                                body_nodes.push(StructuredNode::Stmts(latch_id));
                                StructuredNode::While {
                                    header: bid,
                                    exit: Some(_exit_bid),
                                    condition: or_cond,
                                    body: body_nodes,
                                }
                            } else {

                            let latch_cond = back_edge_sources.get(&bid).and_then(|sources| {
                                if sources.len() == 1 {
                                    let latch = sources[0];
                                    func.block(latch).and_then(|lb| {
                                        if let Terminator::Branch(lcond, lt, lf) = &lb.terminator {
                                            let lt_in = body.contains(lt) || *lt == bid;
                                            let lf_in = body.contains(lf) || *lf == bid;
                                            if lt_in && !lf_in {
                                                Some((lcond.clone(), latch))
                                            } else if !lt_in && lf_in {
                                                Some((negate_condition(lcond), latch))
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    })
                                } else {
                                    None
                                }
                            });

                            if let Some((do_cond, latch_id)) = latch_cond {
                                // do-while: the header's branch is an internal
                                // if-then inside the body.  Exclude the latch
                                // from inner processing (its stmts will be
                                // appended, its branch becomes the condition).
                                let inner_ids: Vec<BlockId> = body_block_ids
                                    .iter()
                                    .copied()
                                    .filter(|b| *b != latch_id)
                                    .collect();
                                let inner_nodes = self.structure_region(
                                    func, cfg, &inner_ids, loop_headers, loop_bodies, back_edge_sources, Some(bid),
                                );
                                // Build body: try to split header branches into
                                // prefix path + common tail before falling back to
                                // the older linear wrapping heuristic.
                                let body_nodes = if let Some(nodes) = self.structure_loop_internal_branch(
                                    func,
                                    cfg,
                                    bid,
                                    cond,
                                    *t,
                                    *f,
                                    latch_id,
                                    &inner_ids,
                                    loop_headers,
                                    loop_bodies,
                                    back_edge_sources,
                                ) {
                                    nodes
                                } else {
                                    let mut nodes = Vec::new();
                                    if !inner_nodes.is_empty() {
                                        if inner_ids.first() == Some(t) {
                                            nodes.push(StructuredNode::IfThen {
                                                condition: cond.clone(),
                                                then_body: inner_nodes,
                                            });
                                        } else if inner_ids.first() == Some(f) {
                                            nodes.push(StructuredNode::IfThen {
                                                condition: negate_condition(cond),
                                                then_body: inner_nodes,
                                            });
                                        } else {
                                            nodes.extend(inner_nodes);
                                        }
                                    }
                                    nodes.push(StructuredNode::Stmts(latch_id));
                                    nodes
                                };
                                StructuredNode::DoWhile {
                                    header: bid,
                                    exit: None,
                                    condition: do_cond,
                                    body: body_nodes,
                                }
                            } else {
                                let nodes = self.structure_region(
                                    func, cfg, &body_block_ids, loop_headers, loop_bodies, back_edge_sources, Some(bid),
                                );
                                StructuredNode::While {
                                    header: bid,
                                    exit: None,
                                    condition: Expr::const_val(1, BitWidth::Bit32),
                                    body: nodes,
                                }
                            }
                            } // or_fold else
                        }
                    }
                    _ => {
                        // Header has Jump (not Branch); check for a do-while pattern.
                        // If the latch block (back-edge source) has a Branch that
                        // exits the loop, extract its condition for do-while.
                        let latch_cond = back_edge_sources.get(&bid).and_then(|sources| {
                            if sources.len() == 1 {
                                let latch = sources[0];
                                func.block(latch).and_then(|lb| {
                                    if let Terminator::Branch(cond, t, f) = &lb.terminator {
                                        let t_in = body.contains(t);
                                        let f_in = body.contains(f);
                                        if t_in && !f_in {
                                            // true goes to loop and false exits; this is the loop-continue condition.
                                            Some((cond.clone(), latch))
                                        } else if !t_in && f_in {
                                            // false goes to loop and true exits, so negate the condition.
                                            Some((negate_condition(cond), latch))
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                })
                            } else {
                                None
                            }
                        });

                        if let Some((cond, latch_id)) = latch_cond {
                            // do-while: body blocks EXCEPT the latch (its branch
                            // becomes the do-while condition).  The latch's stmts
                            // are still emitted inside the body.
                            let inner_ids: Vec<BlockId> = body_block_ids
                                .iter()
                                .copied()
                                .filter(|b| *b != latch_id)
                                .collect();
                            let mut body_nodes = self.structure_region(
                                func, cfg, &inner_ids, loop_headers, loop_bodies, back_edge_sources, Some(bid),
                            );
                            // Append latch stmts (but not its branch terminator)
                            body_nodes.push(StructuredNode::Stmts(latch_id));
                            StructuredNode::DoWhile {
                                header: bid,
                                exit: None,
                                condition: cond,
                                body: body_nodes,
                            }
                        } else {
                            let body_nodes = self.structure_region(
                                func, cfg, &body_block_ids, loop_headers, loop_bodies, back_edge_sources, Some(bid),
                            );
                            StructuredNode::While {
                                header: bid,
                                exit: None,
                                condition: Expr::const_val(1, BitWidth::Bit32),
                                body: body_nodes,
                            }
                        }
                    }
                };

                result.push(loop_node);

                // When a while-loop body has an internal exit (NOT the
                // header's own exit) that was inlined as a return (via
                // loop_exit_node as Block), so the corresponding block should
                // be skipped in the outer region.  Only applies to pre-
                // tested while loops where the header has a clear exit
                // target; do-while latch exits are the natural continuation
                // and must NOT be skipped.
                let header_exit: Option<BlockId> = match &block.terminator {
                    Terminator::Branch(_, t, f) => {
                        if body.contains(t) && !body.contains(f) { Some(*f) }
                        else if body.contains(f) && !body.contains(t) { Some(*t) }
                        else { None }
                    }
                    _ => None,
                };
                let mut body_inlined: HashSet<BlockId> = HashSet::new();
                if let Some(h_exit) = header_exit {
                    let inner_exit = self.find_loop_exit(func, body);
                    if let Some(exit_bid) = inner_exit {
                        // Only skip if this is NOT the header's own exit
                        if exit_bid != h_exit {
                            let was_inlined = func.block(exit_bid).is_some_and(|b| {
                                match &b.terminator {
                                    Terminator::Return(_) => true,
                                    Terminator::Jump(j) => {
                                        let tail = self.collect_goto_tail(func, *j);
                                        tail.last().and_then(|&tb| func.block(tb))
                                            .is_some_and(|tb| matches!(tb.terminator, Terminator::Return(_)))
                                    }
                                    _ => false,
                                }
                            });
                            if was_inlined {
                                body_inlined.insert(exit_bid);
                            }

                            // While loop has both a header_exit (condition-false path)
                            // and an inner break exit (to `exit_bid`, not `h_exit`).
                            // When the header_exit is NOT in the current region
                            // (e.g. inside a nested loop where the exit would
                            // otherwise be lost), emit it as a conditional return.
                            if let Some(guard) = while_exit_guard.take() {
                                if !block_set.contains(&h_exit) {
                                    // Header exit is outside this region, so inline it.
                                    let h_exit_returns = func.block(h_exit).is_some_and(|b| {
                                        match &b.terminator {
                                            Terminator::Return(_) => true,
                                            Terminator::Jump(j) => {
                                                let tail = self.collect_goto_tail(func, *j);
                                                tail.last().and_then(|&tb| func.block(tb))
                                                    .is_some_and(|tb| matches!(tb.terminator, Terminator::Return(_)))
                                            }
                                            _ => false,
                                        }
                                    });
                                    if h_exit_returns {
                                        result.push(StructuredNode::IfThen {
                                            condition: guard,
                                            then_body: vec![StructuredNode::Block(h_exit)],
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                // Skip past all body blocks and body-inlined exit blocks
                while i < block_ids.len()
                    && (body.contains(&block_ids[i]) || body_inlined.contains(&block_ids[i]))
                {
                    i += 1;
                }
                continue;
            }

            // Compute next_in_layout skipping deferred blocks (they'll be
            // consumed by their loop header's While body, not at their
            // natural position).
            let next_in_layout = {
                let mut j = i + 1;
                while j < block_ids.len()
                    && deferred.contains(&block_ids[j])
                    && !loop_headers.contains(&block_ids[j])
                {
                    j += 1;
                }
                block_ids.get(j).copied()
            };

            match &block.terminator {
                Terminator::Jump(target) => {
                    let target = *target;
                    // Jump to loop header: implicit continue.
                    if Some(target) == enclosing_loop {
                        result.push(StructuredNode::Stmts(bid));
                    }
                    // Jump to loop exit: break (or return if exit is a return block).
                    else if enclosing_exit == Some(target) {
                        result.push(StructuredNode::Stmts(bid));
                        result.push(self.loop_exit_node(func, target));
                    }
                    // Jump to the next block in layout: fallthrough.
                    else if next_in_layout == Some(target) {
                        result.push(StructuredNode::Stmts(bid));
                    }
                    // Jump to a loop header in this region: fall through to
                    // the upcoming While node (guard jump before loop entry).
                    else if loop_headers.contains(&target)
                        && block_set.contains(&target)
                        && Some(target) != enclosing_loop
                    {
                        result.push(StructuredNode::Stmts(bid));
                    }
                    // Jump outside region: check whether the target chain leads to return.
                    else if !block_set.contains(&target) {
                        // If the goto-tail chain ends with a return, inline it;
                        // otherwise treat as implicit structured exit (merge/parent).
                        let tail = self.collect_goto_tail(func, target);
                        let ends_with_return = tail.last().and_then(|&b| func.block(b))
                            .is_some_and(|b| matches!(b.terminator, Terminator::Return(_)));
                        if ends_with_return {
                            result.push(StructuredNode::Block(bid));
                            break; // goto-tail ends with return; subsequent blocks are dead
                        } else {
                            result.push(StructuredNode::Stmts(bid));
                        }
                    }
                    // Jump within region but not to the next block: emit with goto-tail.
                    else {
                        result.push(StructuredNode::Block(bid));
                    }
                }

                Terminator::Branch(cond, t, f) => {
                    let mut t = *t;
                    let mut f = *f;
                    let mut cond = cond.clone();
                    let mut sc_skip: HashSet<BlockId> = HashSet::new();

                    // Short-circuit chain folding: detect chains of empty
                    // Branch blocks sharing a common target (AND/OR patterns).
                    // E.g. bb0: if(!A) goto M else bb1; bb1: if(!B) goto M else bb2
                    //   combined form: if(!A || !B) goto M else bb2
                    // This eliminates multi-entry diamonds that cause gotos.
                    if block.stmts.is_empty() {
                        let mut chain_f = f;
                        loop {
                            if !block_set.contains(&chain_f)
                                || loop_headers.contains(&chain_f)
                                || deferred.contains(&chain_f)
                            {
                                break;
                            }
                            let next_blk = match func.block(chain_f) {
                                Some(b) => b,
                                None => break,
                            };
                            if !next_blk.stmts.is_empty() {
                                break;
                            }
                            match &next_blk.terminator {
                                Terminator::Branch(nc, nt, nf) => {
                                    if *nt == t {
                                        // f: if(nc) goto t else nf, so this is an OR chain.
                                        cond = Expr::LogicalOr(
                                            Box::new(cond),
                                            Box::new(nc.clone()),
                                        );
                                        sc_skip.insert(chain_f);
                                        chain_f = *nf;
                                        f = *nf;
                                    } else if *nf == t {
                                        // f: if(nc) goto nt else t, so this is an OR chain (negate nc).
                                        cond = Expr::LogicalOr(
                                            Box::new(cond),
                                            Box::new(negate_condition(nc)),
                                        );
                                        sc_skip.insert(chain_f);
                                        chain_f = *nt;
                                        f = *nt;
                                    } else {
                                        break;
                                    }
                                }
                                _ => break,
                            }
                        }
                        // Also try folding with t as the fallthrough target
                        if sc_skip.is_empty() {
                            let mut chain_t = t;
                            loop {
                                if !block_set.contains(&chain_t)
                                    || loop_headers.contains(&chain_t)
                                    || deferred.contains(&chain_t)
                                {
                                    break;
                                }
                                let next_blk = match func.block(chain_t) {
                                    Some(b) => b,
                                    None => break,
                                };
                                if !next_blk.stmts.is_empty() {
                                    break;
                                }
                                match &next_blk.terminator {
                                    Terminator::Branch(nc, nt, nf) => {
                                        if *nt == f {
                                            // t: if(nc) goto f else nf, continue the chain.
                                            cond = Expr::LogicalAnd(
                                                Box::new(cond),
                                                Box::new(negate_condition(nc)),
                                            );
                                            sc_skip.insert(chain_t);
                                            chain_t = *nf;
                                            t = *nf;
                                        } else if *nf == f {
                                            // t: if(nc) goto nt else f, continue the chain.
                                            cond = Expr::LogicalAnd(
                                                Box::new(cond),
                                                Box::new(nc.clone()),
                                            );
                                            sc_skip.insert(chain_t);
                                            chain_t = *nt;
                                            t = *nt;
                                        } else {
                                            break;
                                        }
                                    }
                                    _ => break,
                                }
                            }
                        }
                        // Mark skipped blocks as deferred so they're not processed again
                        for &sb in &sc_skip {
                            deferred.insert(sb);
                        }
                    }

                    // Recompute next_in_layout if short-circuit folding changed deferred set
                    let next_in_layout = if !sc_skip.is_empty() {
                        let mut j = i + 1;
                        while j < block_ids.len()
                            && deferred.contains(&block_ids[j])
                            && !loop_headers.contains(&block_ids[j])
                        {
                            j += 1;
                        }
                        block_ids.get(j).copied()
                    } else {
                        next_in_layout
                    };

                    // Check for loop back-edge branches
                    if Some(t) == enclosing_loop && Some(f) == enclosing_loop {
                        result.push(StructuredNode::Block(bid));
                    }
                    // Branch to loop exit: break (or return if exit is a return block).
                    else if enclosing_exit == Some(t) && Some(f) == enclosing_loop {
                        // if(cond) break/return; else continue (implicit)
                        result.push(StructuredNode::Stmts(bid));
                        let exit_node = self.loop_exit_node(func, t);
                        result.push(StructuredNode::IfThen {
                            condition: cond,
                            then_body: vec![exit_node],
                        });
                    }
                    else if enclosing_exit == Some(f) && Some(t) == enclosing_loop {
                        // if(!cond) break/return; else continue (implicit)
                        result.push(StructuredNode::Stmts(bid));
                        let exit_node = self.loop_exit_node(func, f);
                        result.push(StructuredNode::IfThen {
                            condition: negate_condition(&cond),
                            then_body: vec![exit_node],
                        });
                    }
                    else if enclosing_exit == Some(t) {
                        // if(cond) break/return; then fallthrough
                        result.push(StructuredNode::Stmts(bid));
                        let exit_node = self.loop_exit_node(func, t);
                        result.push(StructuredNode::IfThen {
                            condition: cond,
                            then_body: vec![exit_node],
                        });
                        // f block is next (or goto)
                        if next_in_layout != Some(f) && block_set.contains(&f) {
                            // Need to handle the false branch
                        }
                    }
                    else if enclosing_exit == Some(f) {
                        // if(!cond) break/return; then fallthrough
                        result.push(StructuredNode::Stmts(bid));
                        let exit_node = self.loop_exit_node(func, f);
                        result.push(StructuredNode::IfThen {
                            condition: negate_condition(&cond),
                            then_body: vec![exit_node],
                        });
                    }
                    else if Some(f) == enclosing_loop {
                        // if(cond) { ... } then loop back
                        result.push(StructuredNode::Stmts(bid));
                        let then_body = self.structure_arm_inline(
                            func, cfg, t, &block_set, loop_headers, loop_bodies, back_edge_sources, enclosing_loop,
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
                            func, cfg, f, &block_set, loop_headers, loop_bodies, back_edge_sources, enclosing_loop,
                        );
                        let new_i = self.advance_past_arm(block_ids, i + 1, &then_body);
                        result.push(StructuredNode::IfThen {
                            condition: negate_condition(&cond),
                            then_body,
                        });
                        i = new_i;
                        continue;
                    }
                    // One branch is the next block: this is an if-then pattern.
                    else if next_in_layout == Some(f) {
                        result.push(StructuredNode::Stmts(bid));
                        let merge = self.find_merge_point(func, t, f, &block_set);

                        // Diamond: if merge == t, the true branch jumps straight to
                        // merge and the false branch (f, which is next_in_layout) is
                        // the actual "then" body under a negated condition.
                        if merge == Some(t) {
                            let then_blocks = self.collect_arm_blocks(func, f, merge, &block_set, enclosing_loop);
                            let then_body = if then_blocks.is_empty() {
                                vec![StructuredNode::Block(f)]
                            } else {
                                self.structure_region(func, cfg, &then_blocks, loop_headers, loop_bodies, back_edge_sources, enclosing_loop)
                            };
                            result.push(StructuredNode::IfThen {
                                condition: negate_condition(&cond),
                                then_body,
                            });
                            let skip: HashSet<BlockId> = then_blocks.iter().copied().collect();
                            i += 1;
                            while i < block_ids.len() && skip.contains(&block_ids[i]) {
                                i += 1;
                            }
                            continue;
                        }

                        let then_blocks = self.collect_arm_blocks(func, t, merge, &block_set, enclosing_loop);

                        let then_body = if then_blocks.is_empty() {
                            vec![StructuredNode::Block(t)]
                        } else {
                            self.structure_region(func, cfg, &then_blocks, loop_headers, loop_bodies, back_edge_sources, enclosing_loop)
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
                                let else_body = self.structure_region(func, cfg, &else_blocks, loop_headers, loop_bodies, back_edge_sources, enclosing_loop);
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
                        // If both arms terminate (no merge, or merge is a pure return relay),
                        // remaining blocks are dead code.
                        if (merge.is_none() || self.is_return_relay(func, merge))
                            && !skip.is_empty() && !else_skip.is_empty()
                        {
                            break;
                        }
                        continue;
                    } else if next_in_layout == Some(t) {
                        result.push(StructuredNode::Stmts(bid));
                        let merge = self.find_merge_point(func, f, t, &block_set);

                        // Diamond: if merge == f, the false branch jumps straight to
                        // merge and the true branch (t, which is next_in_layout) is
                        // the actual "then" body under the original condition.
                        if merge == Some(f) {
                            let then_blocks = self.collect_arm_blocks(func, t, merge, &block_set, enclosing_loop);
                            let then_body = if then_blocks.is_empty() {
                                vec![StructuredNode::Block(t)]
                            } else {
                                self.structure_region(func, cfg, &then_blocks, loop_headers, loop_bodies, back_edge_sources, enclosing_loop)
                            };
                            result.push(StructuredNode::IfThen {
                                condition: cond.clone(),
                                then_body,
                            });
                            let skip: HashSet<BlockId> = then_blocks.iter().copied().collect();
                            i += 1;
                            while i < block_ids.len() && skip.contains(&block_ids[i]) {
                                i += 1;
                            }
                            continue;
                        }

                        let then_blocks = self.collect_arm_blocks(func, f, merge, &block_set, enclosing_loop);

                        let then_body = if then_blocks.is_empty() {
                            vec![StructuredNode::Block(f)]
                        } else {
                            self.structure_region(func, cfg, &then_blocks, loop_headers, loop_bodies, back_edge_sources, enclosing_loop)
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
                                let else_body = self.structure_region(func, cfg, &else_blocks, loop_headers, loop_bodies, back_edge_sources, enclosing_loop);
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
                        // If both arms terminate (no merge, or merge is a pure return relay),
                        // remaining blocks are dead code.
                        if (merge.is_none() || self.is_return_relay(func, merge))
                            && !skip.is_empty() && !else_skip.is_empty()
                        {
                            break;
                        }
                        continue;
                    } else {
                        // Neither branch is next, so emit as a raw block with gotos.
                        result.push(StructuredNode::Block(bid));
                    }
                }

                Terminator::Return(_) => {
                    result.push(StructuredNode::Block(bid));
                    break; // remaining blocks after return are dead code
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
    pub(crate) fn collect_arm_blocks(
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
    pub(crate) fn find_merge_point(
        &self,
        func: &Function,
        branch_a: BlockId,
        branch_b: BlockId,
        region: &HashSet<BlockId>,
    ) -> Option<BlockId> {
        // Try post-dominator first: the immediate post-dominator of the
        // branch block is the natural merge point.
        // Find the block that branches to a and b (i.e., the block
        // whose successors include both branch_a and branch_b).
        let branch_block = region.iter().find(|bid| {
            let succs = func.successors(**bid);
            succs.contains(&branch_a) && succs.contains(&branch_b)
        });
        if let Some(&bb) = branch_block {
            if let Some(ipdom) = self.compute_ipdom(func, bb, region) {
                if region.contains(&ipdom) {
                    return Some(ipdom);
                }
            }
        }

        // Fallback: reachability intersection
        let reach_a = self.reachable_from(func, branch_a, region);
        let reach_b = self.reachable_from(func, branch_b, region);

        let mut common: Vec<BlockId> = reach_a.intersection(&reach_b).copied().collect();
        common.sort_by_key(|bid| func.block(*bid).map(|b| b.addr).unwrap_or(u64::MAX));
        common.first().copied()
    }

    /// Compute the immediate post-dominator of `block` within `region`.
    /// Uses the Cooper-Harvey-Kennedy algorithm on the reverse CFG.
    pub(crate) fn compute_ipdom(
        &self,
        func: &Function,
        block: BlockId,
        region: &HashSet<BlockId>,
    ) -> Option<BlockId> {
        // Build reverse CFG predecessors (= successors in the reverse graph)
        let mut rev_succs: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for &bid in region {
            for succ in func.successors(bid) {
                if region.contains(&succ) {
                    rev_succs.entry(succ).or_default().push(bid);
                }
            }
        }

        // Find exit nodes (blocks with no successors in the region, or Return blocks)
        let exits: Vec<BlockId> = region
            .iter()
            .filter(|bid| {
                let succs: Vec<_> = func.successors(**bid)
                    .into_iter()
                    .filter(|s| region.contains(s))
                    .collect();
                succs.is_empty()
                    || matches!(
                        func.block(**bid).map(|b| &b.terminator),
                        Some(Terminator::Return(_))
                    )
            })
            .copied()
            .collect();

        if exits.is_empty() {
            return None;
        }

        // Add a virtual exit node that all exits connect to
        let virtual_exit = BlockId(u32::MAX);
        let mut all_blocks: Vec<BlockId> = region.iter().copied().collect();
        all_blocks.push(virtual_exit);

        // Build reverse-postorder on the reverse CFG (starting from virtual_exit)
        let mut rpo_visited = HashSet::new();
        let mut rpo = Vec::new();

        fn rev_dfs(
            node: BlockId,
            rev_succs: &HashMap<BlockId, Vec<BlockId>>,
            exits: &[BlockId],
            virtual_exit: BlockId,
            visited: &mut HashSet<BlockId>,
            order: &mut Vec<BlockId>,
        ) {
            if !visited.insert(node) {
                return;
            }
            let children: Vec<BlockId> = if node == virtual_exit {
                exits.to_vec()
            } else {
                rev_succs.get(&node).cloned().unwrap_or_default()
            };
            for child in children {
                rev_dfs(child, rev_succs, exits, virtual_exit, visited, order);
            }
            order.push(node);
        }

        rev_dfs(
            virtual_exit,
            &rev_succs,
            &exits,
            virtual_exit,
            &mut rpo_visited,
            &mut rpo,
        );
        rpo.reverse(); // reverse postorder

        // Map each block to its index in RPO
        let rpo_index: HashMap<BlockId, usize> = rpo.iter().enumerate().map(|(i, b)| (*b, i)).collect();

        // Initialize idom: virtual_exit dominates itself
        let mut idom: HashMap<BlockId, Option<BlockId>> = HashMap::new();
        for &b in &rpo {
            idom.insert(b, None);
        }
        idom.insert(virtual_exit, Some(virtual_exit));

        // Predecessors in the reverse CFG = successors in the forward CFG
        // (for a node N, its reverse-CFG predecessors are nodes that N points to in
        // the forward CFG, i.e., forward successors)
        let rev_preds = |node: BlockId| -> Vec<BlockId> {
            if node == virtual_exit {
                return Vec::new(); // virtual exit has no predecessors
            }
            // Predecessors in reverse CFG = forward successors that are in region
            let mut preds: Vec<BlockId> = func
                .successors(node)
                .into_iter()
                .filter(|s| region.contains(s))
                .collect();
            // Also exits connect to virtual_exit
            if exits.contains(&node) {
                preds.push(virtual_exit);
            }
            preds
        };

        fn ipdom_intersect(
            mut b1: BlockId,
            mut b2: BlockId,
            idom: &HashMap<BlockId, Option<BlockId>>,
            rpo_index: &HashMap<BlockId, usize>,
        ) -> BlockId {
            loop {
                if b1 == b2 {
                    return b1;
                }
                let i1 = rpo_index.get(&b1).copied().unwrap_or(usize::MAX);
                let i2 = rpo_index.get(&b2).copied().unwrap_or(usize::MAX);
                if i1 > i2 {
                    b1 = idom.get(&b1).copied().flatten().unwrap_or(b1);
                } else {
                    b2 = idom.get(&b2).copied().flatten().unwrap_or(b2);
                }
            }
        }

        // Iterative fixed-point
        let mut changed = true;
        while changed {
            changed = false;
            for &node in &rpo[1..] {
                let preds = rev_preds(node);
                let mut new_idom: Option<BlockId> = None;
                for pred in &preds {
                    if idom.get(pred).is_some_and(|d| d.is_some()) {
                        new_idom = Some(match new_idom {
                            Some(current) => ipdom_intersect(current, *pred, &idom, &rpo_index),
                            None => *pred,
                        });
                    }
                }
                if new_idom != idom[&node] {
                    idom.insert(node, new_idom);
                    changed = true;
                }
            }
        }

        // The immediate post-dominator of `block` is idom[block]
        idom.get(&block)
            .copied()
            .flatten()
            .filter(|&b| b != virtual_exit)
    }

    /// Compute set of blocks reachable from `start` within `region`.
    pub(crate) fn reachable_from(
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn structure_loop_internal_branch(
        &self,
        func: &Function,
        cfg: &Cfg,
        header: BlockId,
        cond: &Expr,
        t: BlockId,
        f: BlockId,
        latch_id: BlockId,
        inner_ids: &[BlockId],
        loop_headers: &BTreeSet<BlockId>,
        loop_bodies: &HashMap<BlockId, BTreeSet<BlockId>>,
        back_edge_sources: &HashMap<BlockId, Vec<BlockId>>,
    ) -> Option<Vec<StructuredNode>> {
        let region: HashSet<BlockId> = inner_ids.iter().copied().collect();

        if region.is_empty() {
            return Some(vec![StructuredNode::Stmts(latch_id)]);
        }

        if t == latch_id || f == latch_id {
            let prefix_start = if t == latch_id { f } else { t };
            if region.contains(&prefix_start) {
                let prefix_cond = if t == latch_id {
                    negate_condition(cond)
                } else {
                    cond.clone()
                };
                let prefix_body = self.structure_region(
                    func,
                    cfg,
                    inner_ids,
                    loop_headers,
                    loop_bodies,
                    back_edge_sources,
                    Some(header),
                );
                let mut body_nodes = Vec::new();
                if !prefix_body.is_empty() {
                    body_nodes.push(StructuredNode::IfThen {
                        condition: prefix_cond,
                        then_body: prefix_body,
                    });
                }
                body_nodes.push(StructuredNode::Stmts(latch_id));
                return Some(body_nodes);
            }
        }

        if !region.contains(&t) || !region.contains(&f) {
            return None;
        }

        let t_reaches_f = self.reachable_from(func, t, &region).contains(&f);
        let f_reaches_t = self.reachable_from(func, f, &region).contains(&t);
        let (prefix_start, common_start, prefix_cond) = if f_reaches_t && !t_reaches_f {
            (f, t, negate_condition(cond))
        } else if t_reaches_f && !f_reaches_t {
            (t, f, cond.clone())
        } else {
            return None;
        };

        let prefix_blocks = self.collect_arm_blocks(
            func,
            prefix_start,
            Some(common_start),
            &region,
            Some(header),
        );
        let prefix_set: HashSet<BlockId> = prefix_blocks.iter().copied().collect();
        let common_blocks: Vec<BlockId> = inner_ids
            .iter()
            .copied()
            .filter(|bid| !prefix_set.contains(bid))
            .collect();

        let mut body_nodes = Vec::new();
        if !prefix_blocks.is_empty() {
            let then_body = self.structure_region(
                func,
                cfg,
                &prefix_blocks,
                loop_headers,
                loop_bodies,
                back_edge_sources,
                Some(header),
            );
            if !then_body.is_empty() {
                body_nodes.push(StructuredNode::IfThen {
                    condition: prefix_cond,
                    then_body,
                });
            }
        }

        if !common_blocks.is_empty() {
            body_nodes.extend(self.structure_region(
                func,
                cfg,
                &common_blocks,
                loop_headers,
                loop_bodies,
                back_edge_sources,
                Some(header),
            ));
        }
        body_nodes.push(StructuredNode::Stmts(latch_id));
        Some(body_nodes)
    }

    /// Structure a single arm for inline emission (e.g., loop-back-edge branches).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn structure_arm_inline(
        &self,
        func: &Function,
        cfg: &Cfg,
        start: BlockId,
        region: &HashSet<BlockId>,
        loop_headers: &BTreeSet<BlockId>,
        loop_bodies: &HashMap<BlockId, BTreeSet<BlockId>>,
        back_edge_sources: &HashMap<BlockId, Vec<BlockId>>,
        enclosing_loop: Option<BlockId>,
    ) -> Vec<StructuredNode> {
        let arm_blocks = self.collect_linear_arm(func, start, region, enclosing_loop);
        if arm_blocks.is_empty() {
            vec![StructuredNode::Block(start)]
        } else {
            self.structure_region(func, cfg, &arm_blocks, loop_headers, loop_bodies, back_edge_sources, enclosing_loop)
        }
    }

    pub(crate) fn collect_linear_arm(
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
    pub(crate) fn collect_goto_tail(&self, func: &Function, start: BlockId) -> Vec<BlockId> {
        let mut chain = Vec::new();
        let mut current = start;
        let mut visited = HashSet::new();

        while let Some(block) = func.block(current) {
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
                _ => break, // Branch or other complex terminator: stop here.
            }
        }

        chain
    }

    pub(crate) fn collect_emitted_block_ids(nodes: &[StructuredNode]) -> HashSet<BlockId> {
        let mut ids = HashSet::new();
        for node in nodes {
            match node {
                StructuredNode::Block(id) | StructuredNode::Stmts(id) => {
                    ids.insert(*id);
                }
                StructuredNode::IfThen { then_body, .. } => {
                    ids.extend(Self::collect_emitted_block_ids(then_body));
                }
                StructuredNode::IfThenElse { then_body, else_body, .. } => {
                    ids.extend(Self::collect_emitted_block_ids(then_body));
                    ids.extend(Self::collect_emitted_block_ids(else_body));
                }
                StructuredNode::While { header, body, .. }
                | StructuredNode::DoWhile { header, body, .. } => {
                    ids.insert(*header);
                    ids.extend(Self::collect_emitted_block_ids(body));
                }
                StructuredNode::For { header, init_block, body, .. } => {
                    ids.insert(*header);
                    ids.insert(*init_block);
                    ids.extend(Self::collect_emitted_block_ids(body));
                }
                StructuredNode::Break => {}
            }
        }
        ids
    }

    pub(crate) fn collect_label_targets(&self, nodes: &[StructuredNode], func: &Function) -> HashSet<BlockId> {
        let mut targets = HashSet::new();

        for node in nodes {
            match node {
                StructuredNode::Block(id) => {
                    let Some(block) = func.block(*id) else {
                        continue;
                    };
                    match &block.terminator {
                        Terminator::Jump(target) => {
                            let tail = self.collect_goto_tail(func, *target);
                            let ends_with_return = tail.last().and_then(|&bid| func.block(bid))
                                .is_some_and(|tb| matches!(tb.terminator, Terminator::Return(_)));
                            if !ends_with_return {
                                targets.insert(*target);
                            }
                        }
                        Terminator::Branch(_, t, f) => {
                            targets.insert(*t);
                            targets.insert(*f);
                        }
                        Terminator::Switch(_, cases, default) => {
                            for (_, bid) in cases {
                                targets.insert(*bid);
                            }
                            if let Some(bid) = default {
                                targets.insert(*bid);
                            }
                        }
                        Terminator::IndirectJump(_)
                        | Terminator::Return(_)
                        | Terminator::Unreachable => {}
                    }
                }
                StructuredNode::IfThen { then_body, .. } => {
                    targets.extend(self.collect_label_targets(then_body, func));
                }
                StructuredNode::IfThenElse { then_body, else_body, .. } => {
                    targets.extend(self.collect_label_targets(then_body, func));
                    targets.extend(self.collect_label_targets(else_body, func));
                }
                StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::For { body, .. } => {
                    targets.extend(self.collect_label_targets(body, func));
                }
                StructuredNode::Stmts(_) | StructuredNode::Break => {}
            }
        }

        targets
    }

    pub(crate) fn emit_label_if_needed(&mut self, out: &mut String, id: BlockId) {
        if self.label_targets.contains(&id) && self.emitted_labels.insert(id) {
            let label = self.label_map.get(&id).map_or_else(
                || format!("{id}"),
                |s| s.clone(),
            );
            let _ = writeln!(out, "{}{}:", self.indent_str(), label);
        }
    }

    /// Advance index past blocks that were consumed by an arm.
    pub(crate) fn advance_past_arm(&self, block_ids: &[BlockId], start_idx: usize, arm_nodes: &[StructuredNode]) -> usize {
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
}


