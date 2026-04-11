use crate::disasm::DisasmInsn;
use crate::ir::BlockId;
use std::collections::{BTreeMap, BTreeSet};

/// Control flow graph built from disassembled instructions.
#[derive(Debug)]
pub struct Cfg {
    /// Basic blocks keyed by their start address.
    pub blocks: BTreeMap<u64, CfgBlock>,
    /// Entry address.
    pub entry: u64,
}

/// A basic block in the CFG (pre-lifting, still at machine code level).
#[derive(Debug)]
pub struct CfgBlock {
    pub start_addr: u64,
    pub end_addr: u64,
    pub instructions: Vec<DisasmInsn>,
    pub successors: Vec<u64>,
    pub block_id: BlockId,
}

impl Cfg {
    /// Build a CFG from a linear sequence of disassembled instructions.
    ///
    /// Algorithm:
    /// 1. Identify leaders (block starts): first instruction, targets of jumps/branches,
    ///    instructions following branches/jumps.
    /// 2. Partition instructions into basic blocks.
    /// 3. Compute edges.
    pub fn build(instructions: &[DisasmInsn]) -> Self {
        if instructions.is_empty() {
            return Cfg {
                blocks: BTreeMap::new(),
                entry: 0,
            };
        }

        let entry = instructions[0].addr;

        // Collect all instruction addresses for quick lookup
        let insn_addrs: BTreeSet<u64> = instructions.iter().map(|i| i.addr).collect();

        // Step 1: Identify leaders
        let mut leaders = BTreeSet::new();
        leaders.insert(entry);

        for (i, insn) in instructions.iter().enumerate() {
            if insn.is_terminator() {
                // The instruction after a terminator is a leader
                if let Some(next) = instructions.get(i + 1) {
                    leaders.insert(next.addr);
                }
                // Branch targets are leaders
                if let Some(target) = insn.branch_target()
                    && insn_addrs.contains(&target) {
                        leaders.insert(target);
                    }
            }
            // Call targets: the instruction after a call is also a leader for clean splits
            if insn.is_call()
                && let Some(next) = instructions.get(i + 1) {
                    leaders.insert(next.addr);
                }
        }

        // Step 2: Partition into blocks
        let leaders_vec: Vec<u64> = leaders.iter().copied().collect();
        let mut blocks = BTreeMap::new();

        // Map from leader address to block ID
        let mut addr_to_block_id: BTreeMap<u64, BlockId> = BTreeMap::new();
        for (block_id_counter, &leader) in leaders_vec.iter().enumerate() {
            addr_to_block_id.insert(leader, BlockId(block_id_counter as u32));
        }

        let mut current_block_insns: Vec<DisasmInsn> = Vec::new();
        let mut current_leader = entry;

        for insn in instructions {
            if leaders.contains(&insn.addr) && !current_block_insns.is_empty() {
                // Finish previous block
                let block_id = addr_to_block_id[&current_leader];
                let end_addr = current_block_insns.last().map_or(current_leader, |i| i.addr + i.len as u64);
                blocks.insert(
                    current_leader,
                    CfgBlock {
                        start_addr: current_leader,
                        end_addr,
                        instructions: std::mem::take(&mut current_block_insns),
                        successors: Vec::new(),
                        block_id,
                    },
                );
                current_leader = insn.addr;
            }
            current_block_insns.push(insn.clone());
        }

        // Finish last block
        if !current_block_insns.is_empty() {
            let block_id = addr_to_block_id[&current_leader];
            let end_addr = current_block_insns.last().map_or(current_leader, |i| i.addr + i.len as u64);
            blocks.insert(
                current_leader,
                CfgBlock {
                    start_addr: current_leader,
                    end_addr,
                    instructions: std::mem::take(&mut current_block_insns),
                    successors: Vec::new(),
                    block_id,
                },
            );
        }

        // Step 3: Compute edges
        let block_addrs: Vec<u64> = blocks.keys().copied().collect();
        for &addr in &block_addrs {
            let last_insn = match blocks[&addr].instructions.last() {
                Some(i) => i.clone(),
                None => continue,
            };

            let mut successors = Vec::new();

            match last_insn.insn.flow_control() {
                iced_x86::FlowControl::ConditionalBranch => {
                    // Fall-through
                    let next_addr = last_insn.addr + last_insn.len as u64;
                    if blocks.contains_key(&next_addr) {
                        successors.push(next_addr);
                    }
                    // Branch target
                    if let Some(target) = last_insn.branch_target()
                        && blocks.contains_key(&target) {
                            successors.push(target);
                        }
                }
                iced_x86::FlowControl::UnconditionalBranch => {
                    if let Some(target) = last_insn.branch_target()
                        && blocks.contains_key(&target) {
                            successors.push(target);
                        }
                }
                iced_x86::FlowControl::Return => {
                    // No successors
                }
                iced_x86::FlowControl::IndirectBranch => {
                    // Cannot determine statically
                }
                _ => {
                    // Fall through to next block
                    let next_addr = last_insn.addr + last_insn.len as u64;
                    if blocks.contains_key(&next_addr) {
                        successors.push(next_addr);
                    }
                }
            }

            blocks.get_mut(&addr).unwrap().successors = successors;
        }

        Cfg { blocks, entry }
    }

    /// Get a topological ordering of blocks (reverse post-order).
    pub fn reverse_postorder(&self) -> Vec<u64> {
        let mut visited = BTreeSet::new();
        let mut order = Vec::new();
        self.dfs_postorder(self.entry, &mut visited, &mut order);
        order.reverse();
        order
    }

    fn dfs_postorder(&self, addr: u64, visited: &mut BTreeSet<u64>, order: &mut Vec<u64>) {
        if !visited.insert(addr) {
            return;
        }
        if let Some(block) = self.blocks.get(&addr) {
            for &succ in &block.successors {
                self.dfs_postorder(succ, visited, order);
            }
            order.push(addr);
        }
    }

    /// Compute dominator tree using a simple iterative algorithm.
    /// Returns a map from block address to its immediate dominator.
    pub fn compute_dominators(&self) -> BTreeMap<u64, u64> {
        let rpo = self.reverse_postorder();
        if rpo.is_empty() {
            return BTreeMap::new();
        }

        let mut idom: BTreeMap<u64, Option<u64>> = BTreeMap::new();
        let mut rpo_index: BTreeMap<u64, usize> = BTreeMap::new();

        for (i, &addr) in rpo.iter().enumerate() {
            rpo_index.insert(addr, i);
            idom.insert(addr, None);
        }
        idom.insert(self.entry, Some(self.entry));

        let predecessors: BTreeMap<u64, Vec<u64>> = {
            let mut preds: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
            for (&addr, block) in &self.blocks {
                for &succ in &block.successors {
                    preds.entry(succ).or_default().push(addr);
                }
            }
            preds
        };

        let intersect = |mut b1: u64, mut b2: u64, idom: &BTreeMap<u64, Option<u64>>, rpo_index: &BTreeMap<u64, usize>| -> u64 {
            while b1 != b2 {
                while rpo_index.get(&b1).copied().unwrap_or(usize::MAX)
                    > rpo_index.get(&b2).copied().unwrap_or(usize::MAX)
                {
                    b1 = idom.get(&b1).copied().flatten().unwrap_or(b1);
                }
                while rpo_index.get(&b2).copied().unwrap_or(usize::MAX)
                    > rpo_index.get(&b1).copied().unwrap_or(usize::MAX)
                {
                    b2 = idom.get(&b2).copied().flatten().unwrap_or(b2);
                }
            }
            b1
        };

        let mut changed = true;
        while changed {
            changed = false;
            for &addr in &rpo[1..] {
                let preds = predecessors.get(&addr).cloned().unwrap_or_default();
                let mut new_idom: Option<u64> = None;

                for pred in &preds {
                    if idom.get(pred).is_some_and(|d| d.is_some()) {
                        new_idom = Some(match new_idom {
                            Some(current) => intersect(current, *pred, &idom, &rpo_index),
                            None => *pred,
                        });
                    }
                }

                if new_idom != idom[&addr] {
                    idom.insert(addr, new_idom);
                    changed = true;
                }
            }
        }

        idom.into_iter()
            .filter_map(|(addr, dom)| dom.map(|d| (addr, d)))
            .collect()
    }

    /// Detect back edges (edges where the target dominates the source).
    /// These indicate loops.
    pub fn back_edges(&self) -> Vec<(u64, u64)> {
        let doms = self.compute_dominators();
        let mut edges = Vec::new();

        for (&addr, block) in &self.blocks {
            for &succ in &block.successors {
                // succ dominates addr => back edge
                if dominates(&doms, succ, addr) {
                    edges.push((addr, succ));
                }
            }
        }
        edges
    }
}

/// Check if `a` dominates `b` in the dominator tree.
fn dominates(idom: &BTreeMap<u64, u64>, a: u64, b: u64) -> bool {
    let mut current = b;
    loop {
        if current == a {
            return true;
        }
        match idom.get(&current) {
            Some(&dom) if dom != current => current = dom,
            _ => return false,
        }
    }
}
