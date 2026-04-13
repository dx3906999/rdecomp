use crate::cfg::Cfg;
use crate::interprocedural::{FunctionSummary, InterproceduralInfo};
use crate::ir::*;
use crate::loader::{Binary, FunctionSymbol};
use crate::struct_recovery::{self, StructMap};
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
    /// Inferred buffer sizes: stack offset → byte count.
    /// Set per-function from `Function::buffer_sizes`.
    buffer_sizes: HashMap<i64, u64>,
    /// Per-function name mapping: stack offset → friendly name (e.g. `var_1`, `arg_1`).
    var_names: HashMap<i64, String>,
    /// Inferred struct layouts for pointer-typed variables.
    struct_map: StructMap,
    /// Interprocedural function summaries (address → summary).
    func_summaries: HashMap<u64, FunctionSummary>,
    /// Temp variable IDs that are never read — suppress declaration and assignment.
    dead_temps: HashSet<u32>,
    /// Register → parameter name mapping for leaf functions (e.g. Rdi → "arg_1").
    reg_params: HashMap<RegId, String>,
    /// Contextual rax value from the most recently emitted parent block.
    /// Used to resolve `return rax` in relay blocks where the value comes
    /// from a predecessor that was emitted as a Stmts node.
    rax_context: Option<Expr>,
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
            buffer_sizes: HashMap::new(),
            var_names: HashMap::new(),
            struct_map: HashMap::new(),
            func_summaries: HashMap::new(),
            dead_temps: HashSet::new(),
            reg_params: HashMap::new(),
            rax_context: None,
        }
    }

    /// Set interprocedural analysis results.
    pub fn set_interprocedural(&mut self, info: &InterproceduralInfo) {
        self.func_summaries = info.summaries.clone();
    }

    /// Generate pseudo-C code for a function.
    pub fn generate(&mut self, func: &Function, cfg: &Cfg) -> String {
        let mut out = String::new();

        self.buffer_sizes = func.buffer_sizes.clone();
        self.var_names.clear();
        self.struct_map = struct_recovery::recover_structs(func);

        // ── Detect parameter offsets ─────────────────────────────
        let param_regs = func.calling_conv.param_regs();
        // param_offsets: BTreeSet of (offset, width) for stack slots that are parameters
        let mut param_offsets: BTreeSet<(i64, BitWidth)> = BTreeSet::new();
        // For 64-bit ABIs: map offset → register index in calling convention
        let mut offset_to_reg_idx: HashMap<i64, usize> = HashMap::new();

        if func.calling_conv.is_32bit() {
            let mut positive_offs: BTreeSet<(i64, BitWidth)> = BTreeSet::new();
            for block in &func.blocks {
                for stmt in &block.stmts {
                    Self::collect_stack_param_candidates(stmt, &mut positive_offs);
                }
                Self::collect_stack_param_candidates_from_term(&block.terminator, &mut positive_offs);
            }
            for item in positive_offs {
                if item.0 > 4 {
                    param_offsets.insert(item);
                }
            }
        } else {
            if let Some(entry) = func.blocks.first() {
                for stmt in &entry.stmts {
                    if let Stmt::Assign(Var::Stack(off, w), Expr::Var(Var::Reg(reg, _))) = stmt
                        && param_regs.contains(reg) {
                            param_offsets.insert((*off, *w));
                            if let Some(idx) = param_regs.iter().position(|r| r == reg) {
                                offset_to_reg_idx.insert(*off, idx);
                            }
                        }
                }
            }
        }

        // ── Leaf function parameter detection ────────────────────
        // For optimized leaf functions with no stack frame, detect parameter
        // registers that are read before being written in the function body.
        self.reg_params.clear();
        if param_offsets.is_empty() && !func.calling_conv.is_32bit() {
            let used_param_regs = Self::detect_reg_params(func, &param_regs);
            let mut arg_idx = 1;
            for reg in param_regs {
                if used_param_regs.contains(reg) {
                    self.reg_params.insert(*reg, format!("arg_{arg_idx}"));
                    arg_idx += 1;
                }
            }
        }

        // ── Collect all stack offsets used in the function ────────
        let mut all_offsets: BTreeMap<i64, BitWidth> = BTreeMap::new();
        for (off, w) in &param_offsets {
            all_offsets.entry(*off).or_insert(*w);
        }
        // Scan statements for assigned/used stack vars
        for block in &func.blocks {
            for stmt in &block.stmts {
                let var = match stmt {
                    Stmt::Assign(v, _) => Some(v),
                    Stmt::Call(Some(v), _, _) => Some(v),
                    _ => None,
                };
                if let Some(Var::Stack(off, w)) = var {
                    all_offsets.entry(*off).or_insert(*w);
                }
            }
        }

        // ── Build friendly name map ──────────────────────────────
        let param_off_set: HashSet<i64> = param_offsets.iter().map(|(o, _)| *o).collect();

        // Parameters: sorted by register order (for 64-bit) or offset ascending (for 32-bit) → arg_1, arg_2, ...
        let mut param_list: Vec<(i64, BitWidth)> = param_offsets.iter().copied().collect();
        if !offset_to_reg_idx.is_empty() {
            // Sort by register index in calling convention (rdi=0, rsi=1, rdx=2, ...)
            param_list.sort_by_key(|(off, _)| offset_to_reg_idx.get(off).copied().unwrap_or(usize::MAX));
        } else {
            // 32-bit: positive offsets sorted ascending (stack parameters)
            param_list.sort_by_key(|(off, _)| *off);
        }
        for (i, (off, _w)) in param_list.iter().enumerate() {
            self.var_names.insert(*off, format!("arg_{}", i + 1));
        }

        // Locals: negative offsets sorted by absolute value ascending → var_1, var_2, ...
        let mut local_offs: Vec<(i64, BitWidth)> = all_offsets.iter()
            .filter(|(off, _)| !param_off_set.contains(off))
            .map(|(off, w)| (*off, *w))
            .collect();
        local_offs.sort_by_key(|(off, _)| off.unsigned_abs());
        for (i, (off, _w)) in local_offs.iter().enumerate() {
            self.var_names.insert(*off, format!("var_{}", i + 1));
        }

        // ── Semantic variable naming ─────────────────────────────
        self.improve_var_names(func);

        // ── Build params and param_var_names ─────────────────────
        let mut params: Vec<(String, i64, BitWidth)> = Vec::new();
        let mut param_var_names: HashSet<String> = HashSet::new();
        for (off, w) in &param_list {
            let name = self.stack_name(*off);
            param_var_names.insert(name.clone());
            params.push((name, *off, *w));
        }

        // Determine return type from type inference
        let ret_type = func.return_type.to_c_str();

        // Function signature with parameters
        if params.is_empty() && self.reg_params.is_empty() {
            let _ = writeln!(out, "{ret_type} {}() {{", func.name);
        } else if !self.reg_params.is_empty() && params.is_empty() {
            // Leaf function: parameters are register-based
            let param_str: Vec<String> = {
                let mut rp: Vec<_> = self.reg_params.iter().collect();
                rp.sort_by_key(|(_, name)| (*name).clone());
                rp.iter().map(|(reg, name)| {
                    let reg_key = format!("{reg}");
                    let ty = func.var_types.get(&reg_key)
                        .map(|t| t.to_c_str())
                        .unwrap_or("uint64_t");
                    format!("{ty} {name}")
                }).collect()
            };
            let _ = writeln!(out, "{ret_type} {}({}) {{", func.name, param_str.join(", "));
        } else {
            let param_str: Vec<String> = params.iter()
                .map(|(name, off, w)| {
                    let type_key = stack_type_key(*off);
                    let ty = func.var_types.get(&type_key)
                        .map(|t| t.to_c_str())
                        .unwrap_or_else(|| c_type(*w));
                    format!("{} {}", ty, name)
                })
                .collect();
            let _ = writeln!(out, "{ret_type} {}({}) {{", func.name, param_str.join(", "));
        }

        self.param_vars = param_var_names.clone();

        self.indent = 1;

        // Find dead temp variables (defined but never read)
        self.dead_temps = Self::find_dead_temps(func);

        // Build call-result map: temp vars that hold single-use call return values
        // These will be inlined as `func(args)` instead of displaying as `t0`.
        // Only inline when the temp is used exactly once — multi-use call results
        // must be stored in a named local to avoid repeating the call.
        let temp_read_counts = Self::count_temp_reads(func);
        self.call_results.clear();
        for block in &func.blocks {
            for stmt in &block.stmts {
                if let Stmt::Call(Some(var @ Var::Temp(id, _)), target, args) = stmt {
                    if temp_read_counts.get(id).copied().unwrap_or(0) != 1 {
                        continue;
                    }
                    let key = format!("{var}");
                    let target_str = self.resolve_call_target(target);
                    let args_str: Vec<String> = args.iter().map(|a| self.expr_to_c(a)).collect();
                    let call_str = format!("{}({})", target_str, args_str.join(", "));
                    self.call_results.insert(key, call_str);
                }
            }
        }

        // Declare local variables (only stack/temp vars, not registers, excluding params)
        let locals = self.collect_locals(func);
        if !locals.is_empty() {
            let filtered: Vec<_> = locals.iter()
                .filter(|(name, _, _, _)| !param_var_names.contains(name))
                .collect();
            for (name, type_key, width, buf_size) in &filtered {
                if let Some(size) = buf_size {
                    let _ = writeln!(out, "{}char  {}[{}];", self.indent_str(), name, size);
                } else {
                    let ty = func.var_types.get(type_key.as_str())
                        .map(|t| t.to_c_str())
                        .unwrap_or_else(|| c_type(*width));
                    let _ = writeln!(out, "{}{}  {};", self.indent_str(), ty, name);
                }
            }
            if !filtered.is_empty() {
                let _ = writeln!(out);
            }
        }

        // Structured control flow recovery
        let all_ids: Vec<BlockId> = func.blocks.iter().map(|b| b.id).collect();
        let (loop_headers, back_edge_sources) = self.find_loop_info(func, cfg);
        let loop_bodies = self.compute_all_loop_bodies(func, &loop_headers, &back_edge_sources);
        let mut nodes = self.structure_region(func, cfg, &all_ids, &loop_headers, &loop_bodies, &back_edge_sources, None);
        // Post-process: convert while-loops to for-loops when pattern matches
        Self::convert_for_loops(&mut nodes, func);
        // Post-process: collapse nested if-then into short-circuit (&&)
        Self::collapse_short_circuit(&mut nodes);
        let code = self.emit_structured(&nodes, func);
        let code = Self::fold_temp_return_lines(&code);
        out.push_str(&code);

        let _ = writeln!(out, "}}");
        out
    }

    fn indent_str(&self) -> String {
        "    ".repeat(self.indent)
    }

    /// Post-process: fold `tN = expr; ... return tN;` into `return expr;`.
    ///
    /// Scans the emitted code line-by-line, tracking the last assignment to
    /// each temp variable. When `return tN;` is found and there's a tracked
    /// assignment, the assignment line is removed and the return inlines the
    /// value. This handles the Branch→relay pattern where the assignment and
    /// return come from different IR blocks.
    fn fold_temp_return_lines(code: &str) -> String {
        let lines: Vec<&str> = code.lines().collect();
        let len = lines.len();

        // First pass: count how many unique lines reference each temp `tN`.
        // Only fold a temp if it appears on exactly 2 lines (assignment + return).
        // This prevents removing assignments for temps used in conditions, stores, etc.
        let mut temp_line_set: HashMap<String, HashSet<usize>> = HashMap::new();
        for (line_idx, line) in lines.iter().enumerate() {
            let bytes = line.trim().as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b't' {
                    // Require word boundary before 't'
                    if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
                        i += 1;
                        continue;
                    }
                    let mut j = i + 1;
                    while j < bytes.len() && bytes[j].is_ascii_digit() {
                        j += 1;
                    }
                    if j > i + 1 {
                        // Require word boundary after digits
                        if j < bytes.len()
                            && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_')
                        {
                            i = j;
                            continue;
                        }
                        let temp_name =
                            std::str::from_utf8(&bytes[i..j]).unwrap().to_string();
                        temp_line_set.entry(temp_name).or_default().insert(line_idx);
                    }
                    i = j;
                } else {
                    i += 1;
                }
            }
        }

        // Second pass: fold only temps that appear on exactly 2 unique lines.
        // last_temp: temp_name → stack of (output_line_index, rhs_expression)
        let mut last_temp: HashMap<String, Vec<(usize, String)>> = HashMap::new();
        let mut result: Vec<Option<String>> = Vec::with_capacity(len);

        for line in &lines {
            let trimmed = line.trim();
            // Detect `tN = expr;`
            if let Some(rest) = trimmed.strip_prefix('t') {
                if let Some(eq_pos) = rest.find(" = ") {
                    let maybe_id = &rest[..eq_pos];
                    if maybe_id.chars().all(|c| c.is_ascii_digit()) && trimmed.ends_with(';') {
                        let temp_name = format!("t{maybe_id}");
                        let unique_lines = temp_line_set
                            .get(&temp_name)
                            .map_or(0, |s| s.len());
                        if unique_lines == 2 {
                            let expr = &rest[eq_pos + 3..rest.len() - 1]; // strip trailing ;
                            last_temp.entry(temp_name).or_default()
                                .push((result.len(), expr.to_string()));
                        }
                        result.push(Some(line.to_string()));
                        continue;
                    }
                }
            }
            // Detect `return tN;`
            if let Some(rest) = trimmed.strip_prefix("return t") {
                if rest.ends_with(';') {
                    let maybe_id = &rest[..rest.len() - 1];
                    if maybe_id.chars().all(|c| c.is_ascii_digit()) {
                        let temp_name = format!("t{maybe_id}");
                        if let Some(stack) = last_temp.get_mut(&temp_name) {
                            if let Some((assign_idx, expr)) = stack.pop() {
                                result[assign_idx] = None;
                                let indent = &line[..line.len() - trimmed.len()];
                                result.push(Some(format!("{indent}return {expr};")));
                                continue;
                            }
                        }
                    }
                }
            }
            result.push(Some(line.to_string()));
        }

        let mut out = String::new();
        for line in result.into_iter().flatten() {
            out.push_str(&line);
            out.push('\n');
        }
        out
    }

    /// Convert `init; while(cond) { body; step; }` → `for(init; cond; step) { body; }`
    ///
    /// Criteria:
    /// - A `Stmts(block_id)` node immediately precedes a `While` node.
    /// - The init block's last non-Nop statement is an assignment to a stack variable
    ///   with a constant value (e.g. `i = 0`).
    /// - The while body's last effective statement (from a Stmts/Block node) is an
    ///   increment of the same variable (e.g. `i = i + 1`).
    fn convert_for_loops(nodes: &mut Vec<StructuredNode>, func: &Function) {
        // Recursively process children first
        for node in nodes.iter_mut() {
            match node {
                StructuredNode::IfThen { then_body, .. } => {
                    Self::convert_for_loops(then_body, func);
                }
                StructuredNode::IfThenElse { then_body, else_body, .. } => {
                    Self::convert_for_loops(then_body, func);
                    Self::convert_for_loops(else_body, func);
                }
                StructuredNode::While { body, .. } => {
                    Self::convert_for_loops(body, func);
                }
                StructuredNode::DoWhile { body, .. } => {
                    Self::convert_for_loops(body, func);
                }
                StructuredNode::For { body, .. } => {
                    Self::convert_for_loops(body, func);
                }
                _ => {}
            }
        }

        // Now look for Stmts + While pairs at this level
        let mut i = 0;
        while i + 1 < nodes.len() {
            let is_candidate = matches!(&nodes[i], StructuredNode::Stmts(_))
                && matches!(&nodes[i + 1], StructuredNode::While { .. });

            if !is_candidate {
                i += 1;
                continue;
            }

            let init_block_id = if let StructuredNode::Stmts(id) = &nodes[i] {
                *id
            } else {
                unreachable!()
            };

            // Get the init block and find a qualifying init statement
            let init_stmt = func.block(init_block_id).and_then(|block| {
                // Find the last non-Nop assignment to a stack variable
                block.stmts.iter().rev()
                    .find(|s| !matches!(s, Stmt::Nop))
                    .and_then(|s| {
                        if let Stmt::Assign(Var::Stack(_, _), _) = s {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
            });

            let Some(init_stmt) = init_stmt else {
                i += 1;
                continue;
            };

            // Get the init variable
            let init_var = if let Stmt::Assign(var, _) = &init_stmt {
                var.clone()
            } else {
                i += 1;
                continue;
            };

            // Check the while body for a step statement
            let (header, condition, mut body) = if let StructuredNode::While { header, condition, body } = nodes[i + 1].clone() {
                (header, condition, body)
            } else {
                unreachable!()
            };

            // Find the last effective statement in the body. It could be:
            // 1. The last statement of a Stmts(block) node at the end of body
            // 2. The last statement of a Block(block) node at the end of body
            let step_stmt = Self::extract_step_stmt(&body, func, &init_var);
            let Some(step_stmt) = step_stmt else {
                i += 1;
                continue;
            };

            // Remove the step statement from the body
            Self::remove_last_step(&mut body, func, &init_var);

            // Replace the Stmts(init) + While pair with a single For node
            nodes.remove(i); // Remove Stmts (init)
            nodes[i] = StructuredNode::For {
                header,
                init_block: init_block_id,
                init: init_stmt,
                condition,
                step: step_stmt,
                body,
            };
            // Don't advance i — check the new node's position for further patterns
        }
    }

    /// Extract a step statement from the last body node if it matches `var = var ± const`.
    fn extract_step_stmt(body: &[StructuredNode], func: &Function, init_var: &Var) -> Option<Stmt> {
        let last = body.last()?;
        let block_id = match last {
            StructuredNode::Stmts(id) | StructuredNode::Block(id) => *id,
            _ => return None,
        };
        let block = func.block(block_id)?;
        let stmt = block.stmts.iter().rev()
            .find(|s| !matches!(s, Stmt::Nop))?;

        // Check: Assign(same_var, BinOp(Add|Sub, Var(same_var), Const(1, _)))
        if let Stmt::Assign(var, expr) = stmt {
            if var != init_var {
                return None;
            }
            match expr {
                Expr::BinOp(BinOp::Add | BinOp::Sub, lhs, rhs) => {
                    // var = var + const
                    if let Expr::Var(v) = lhs.as_ref() {
                        if v == init_var && matches!(rhs.as_ref(), Expr::Const(_, _)) {
                            return Some(stmt.clone());
                        }
                    }
                }
                _ => return None,
            }
        }
        None
    }

    /// No-op: the For rendering handles skipping the step via `emit_block_skip_last`.
    fn remove_last_step(_body: &mut Vec<StructuredNode>, _func: &Function, _init_var: &Var) {
    }

    /// Collapse nested `if(A) { if(B) { body } }` into `if(A && B) { body }`.
    ///
    /// Also collapses simple IfThen inside IfThenElse when the else-body is empty
    /// or matches the inner pattern.
    fn collapse_short_circuit(nodes: &mut Vec<StructuredNode>) {
        // Recursively process children first
        for node in nodes.iter_mut() {
            match node {
                StructuredNode::IfThen { then_body, .. } => {
                    Self::collapse_short_circuit(then_body);
                }
                StructuredNode::IfThenElse { then_body, else_body, .. } => {
                    Self::collapse_short_circuit(then_body);
                    Self::collapse_short_circuit(else_body);
                }
                StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::For { body, .. } => {
                    Self::collapse_short_circuit(body);
                }
                _ => {}
            }
        }

        // Now look for collapsible patterns at this level
        for node in nodes.iter_mut() {
            // Pattern 1: if(A) { if(B) { body } } → if(A && B) { body }
            if let StructuredNode::IfThen { condition, then_body } = node {
                if then_body.len() == 1 {
                    if let StructuredNode::IfThen { condition: inner_cond, then_body: inner_body } = &then_body[0] {
                        let combined = Expr::LogicalAnd(
                            Box::new(condition.clone()),
                            Box::new(inner_cond.clone()),
                        );
                        *condition = combined;
                        *then_body = inner_body.clone();
                    }
                }
            }
            // Pattern 2: if(A) { if(B) { then } else { else } } else { else }
            //          → if(A && B) { then } else { else }
            //
            // When both the outer else and the inner else are identical, the
            // outer condition just short-circuits to the common else path.
            if let StructuredNode::IfThenElse { condition, then_body, else_body } = node {
                if then_body.len() == 1 {
                    if let StructuredNode::IfThenElse {
                        condition: inner_cond,
                        then_body: inner_then,
                        else_body: inner_else,
                    } = &then_body[0]
                    {
                        if format!("{inner_else:?}") == format!("{else_body:?}") {
                            let combined = Expr::LogicalAnd(
                                Box::new(condition.clone()),
                                Box::new(inner_cond.clone()),
                            );
                            *condition = combined;
                            *then_body = inner_then.clone();
                        }
                    }
                }
            }
        }
    }

    fn collect_stack_param_candidates(stmt: &Stmt, out: &mut BTreeSet<(i64, BitWidth)>) {
        if let Stmt::Assign(Var::Stack(off, w), _) = stmt
            && *off > 4 {
                out.insert((*off, *w));
            }
        // Also check expressions within (e.g. reads of arg_8)
        Self::collect_stack_param_candidates_from_expr(
            match stmt {
                Stmt::Assign(_, expr) => Some(expr),
                _ => None,
            },
            out,
        );
    }

    fn collect_stack_param_candidates_from_term(term: &Terminator, out: &mut BTreeSet<(i64, BitWidth)>) {
        match term {
            Terminator::Branch(cond, _, _) => Self::collect_stack_param_candidates_from_expr(Some(cond), out),
            Terminator::Return(Some(val)) => Self::collect_stack_param_candidates_from_expr(Some(val), out),
            _ => {}
        }
    }

    fn collect_stack_param_candidates_from_expr(expr: Option<&Expr>, out: &mut BTreeSet<(i64, BitWidth)>) {
        let Some(expr) = expr else { return };
        match expr {
            Expr::Var(Var::Stack(off, w)) => {
                if *off > 4 {
                    out.insert((*off, *w));
                }
            }
            Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs) => {
                Self::collect_stack_param_candidates_from_expr(Some(lhs), out);
                Self::collect_stack_param_candidates_from_expr(Some(rhs), out);
            }
            Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
                Self::collect_stack_param_candidates_from_expr(Some(inner), out);
            }
            Expr::Select(c, t, f) => {
                Self::collect_stack_param_candidates_from_expr(Some(c), out);
                Self::collect_stack_param_candidates_from_expr(Some(t), out);
                Self::collect_stack_param_candidates_from_expr(Some(f), out);
            }
            _ => {}
        }
    }

    /// Improve variable names based on usage patterns.
    ///
    /// Detects:
    /// - Loop induction variables (init to 0/small, incremented by 1) → i, j, k
    /// - Accumulators (updated via += in loops) → sum, total, acc
    fn improve_var_names(&mut self, func: &Function) {
        let mut induction_candidates: Vec<i64> = Vec::new();
        let mut accumulator_candidates: Vec<i64> = Vec::new();
        let mut used_names: HashSet<String> = self.var_names.values().cloned().collect();

        for block in &func.blocks {
            for stmt in &block.stmts {
                // Detect: var = var + 1 (or var = var - 1) → increment pattern
                if let Stmt::Assign(Var::Stack(off, _), expr) = stmt {
                    if self.is_increment_pattern(*off, expr) {
                        if !induction_candidates.contains(off) {
                            induction_candidates.push(*off);
                        }
                    }
                    // Detect: var = var + other (accumulator pattern)
                    else if self.is_accumulate_pattern(*off, expr) {
                        if !accumulator_candidates.contains(off)
                            && !induction_candidates.contains(off)
                        {
                            accumulator_candidates.push(*off);
                        }
                    }
                }
            }
        }

        // Rename induction variables → i, j, k, ...
        let loop_var_names = ["i", "j", "k", "l", "m", "n"];
        for (idx, off) in induction_candidates.iter().enumerate() {
            if idx < loop_var_names.len() {
                let name = loop_var_names[idx].to_string();
                if !used_names.contains(&name) {
                    used_names.insert(name.clone());
                    self.var_names.insert(*off, name);
                }
            }
        }

        // Rename accumulators → sum, total, acc, ...
        let acc_names = ["sum", "total", "acc"];
        for (idx, off) in accumulator_candidates.iter().enumerate() {
            // Don't rename if it became an induction var
            if induction_candidates.contains(off) {
                continue;
            }
            if idx < acc_names.len() {
                let name = acc_names[idx].to_string();
                if !used_names.contains(&name) {
                    used_names.insert(name.clone());
                    self.var_names.insert(*off, name);
                }
            }
        }
    }

    /// Check if expr is `Stack(off) + 1` or `Stack(off) - (-1)`.
    fn is_increment_pattern(&self, off: i64, expr: &Expr) -> bool {
        if let Expr::BinOp(BinOp::Add, lhs, rhs) = expr {
            if let Expr::Var(Var::Stack(o, _)) = lhs.as_ref() {
                if *o == off {
                    if let Expr::Const(1, _) = rhs.as_ref() {
                        return true;
                    }
                }
            }
            if let Expr::Var(Var::Stack(o, _)) = rhs.as_ref() {
                if *o == off {
                    if let Expr::Const(1, _) = lhs.as_ref() {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if expr is `Stack(off) + something` (accumulation pattern).
    fn is_accumulate_pattern(&self, off: i64, expr: &Expr) -> bool {
        if let Expr::BinOp(BinOp::Add, lhs, rhs) = expr {
            if let Expr::Var(Var::Stack(o, _)) = lhs.as_ref() {
                if *o == off {
                    return true;
                }
            }
            if let Expr::Var(Var::Stack(o, _)) = rhs.as_ref() {
                if *o == off {
                    return true;
                }
            }
        }
        false
    }

    /// Collect all local variables declared in the function.
    /// Returns (name, type_key, width, optional buffer size).
    fn collect_locals(&self, func: &Function) -> Vec<(String, String, BitWidth, Option<u64>)> {
        let mut locals: BTreeMap<String, (String, BitWidth, Option<u64>)> = BTreeMap::new();

        for block in &func.blocks {
            for stmt in &block.stmts {
                let var = match stmt {
                    Stmt::Assign(v, _) => Some(v),
                    Stmt::Call(Some(v), _, _) => Some(v),
                    _ => None,
                };
                if let Some(var) = var {
                    match var {
                        Var::Stack(off, w) => {
                            let name = self.stack_name(*off);
                            let type_key = stack_type_key(*off);
                            let buf_size = self.buffer_sizes.get(off).copied();
                            locals.entry(name).or_insert((type_key, *w, buf_size));
                        }
                        Var::Temp(id, w) => {
                            let key = format!("t{id}");
                            if !self.dead_temps.contains(id)
                                && !self.call_results.contains_key(&key)
                            {
                                locals.entry(key.clone()).or_insert((key, *w, None));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        locals.into_iter().map(|(name, (tk, w, buf))| (name, tk, w, buf)).collect()
    }

    /// Find temp variable IDs that are never referenced in any expression or
    /// terminator.  These are dead assignments (e.g. `t3 = rsp`) that clutter
    /// the output and can be suppressed.
    fn find_dead_temps(func: &Function) -> HashSet<u32> {
        // Step 1: collect all temp IDs that are assigned (defined).
        let mut defined = HashSet::new();
        for block in &func.blocks {
            for stmt in &block.stmts {
                match stmt {
                    Stmt::Assign(Var::Temp(id, _), _) => { defined.insert(*id); }
                    Stmt::Call(Some(Var::Temp(id, _)), _, _) => { defined.insert(*id); }
                    _ => {}
                }
            }
        }

        // Step 2: count reads of each temp ID across all expressions.
        let mut read = HashSet::new();
        for block in &func.blocks {
            for stmt in &block.stmts {
                match stmt {
                    Stmt::Assign(_, expr) => Self::collect_temp_reads(expr, &mut read),
                    Stmt::Store(addr, val, _) => {
                        Self::collect_temp_reads(addr, &mut read);
                        Self::collect_temp_reads(val, &mut read);
                    }
                    Stmt::Call(_, target, args) => {
                        Self::collect_temp_reads(target, &mut read);
                        for a in args {
                            Self::collect_temp_reads(a, &mut read);
                        }
                    }
                    _ => {}
                }
            }
            // Terminators
            match &block.terminator {
                Terminator::Branch(cond, _, _) => Self::collect_temp_reads(cond, &mut read),
                Terminator::Return(Some(expr)) => Self::collect_temp_reads(expr, &mut read),
                Terminator::Switch(val, _, _) => Self::collect_temp_reads(val, &mut read),
                Terminator::IndirectJump(expr) => Self::collect_temp_reads(expr, &mut read),
                _ => {}
            }
        }

        // Dead = defined but never read
        defined.difference(&read).copied().collect()
    }

    /// Count how many times each temp variable is read across the function.
    fn count_temp_reads(func: &Function) -> HashMap<u32, usize> {
        let mut counts: HashMap<u32, usize> = HashMap::new();
        fn count_in_expr(expr: &Expr, counts: &mut HashMap<u32, usize>) {
            match expr {
                Expr::Var(Var::Temp(id, _)) => { *counts.entry(*id).or_insert(0) += 1; }
                Expr::BinOp(_, l, r) | Expr::Cmp(_, l, r)
                | Expr::LogicalAnd(l, r) | Expr::LogicalOr(l, r) => {
                    count_in_expr(l, counts);
                    count_in_expr(r, counts);
                }
                Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
                    count_in_expr(inner, counts);
                }
                Expr::Select(c, t, f) => {
                    count_in_expr(c, counts);
                    count_in_expr(t, counts);
                    count_in_expr(f, counts);
                }
                _ => {}
            }
        }
        for block in &func.blocks {
            for stmt in &block.stmts {
                match stmt {
                    Stmt::Assign(_, expr) => count_in_expr(expr, &mut counts),
                    Stmt::Store(addr, val, _) => {
                        count_in_expr(addr, &mut counts);
                        count_in_expr(val, &mut counts);
                    }
                    Stmt::Call(_, target, args) => {
                        count_in_expr(target, &mut counts);
                        for a in args { count_in_expr(a, &mut counts); }
                    }
                    _ => {}
                }
            }
            match &block.terminator {
                Terminator::Branch(cond, _, _) => count_in_expr(cond, &mut counts),
                Terminator::Return(Some(expr)) => count_in_expr(expr, &mut counts),
                Terminator::Switch(val, _, _) => count_in_expr(val, &mut counts),
                Terminator::IndirectJump(expr) => count_in_expr(expr, &mut counts),
                _ => {}
            }
        }
        counts
    }

    /// Recursively collect temp variable IDs referenced in an expression.
    fn collect_temp_reads(expr: &Expr, out: &mut HashSet<u32>) {
        match expr {
            Expr::Var(Var::Temp(id, _)) => { out.insert(*id); }
            Expr::BinOp(_, lhs, rhs) => {
                Self::collect_temp_reads(lhs, out);
                Self::collect_temp_reads(rhs, out);
            }
            Expr::UnaryOp(_, inner) => Self::collect_temp_reads(inner, out),
            Expr::Load(addr, _) => Self::collect_temp_reads(addr, out),
            Expr::Cmp(_, lhs, rhs) => {
                Self::collect_temp_reads(lhs, out);
                Self::collect_temp_reads(rhs, out);
            }
            Expr::LogicalAnd(lhs, rhs) | Expr::LogicalOr(lhs, rhs) => {
                Self::collect_temp_reads(lhs, out);
                Self::collect_temp_reads(rhs, out);
            }
            Expr::Select(c, t, f) => {
                Self::collect_temp_reads(c, out);
                Self::collect_temp_reads(t, out);
                Self::collect_temp_reads(f, out);
            }
            _ => {}
        }
    }

    /// Detect which parameter registers are actually used in a leaf function.
    ///
    /// Scans the function body for reads of parameter registers (rdi, rsi, ...)
    /// that are not preceded by a local write.  Returns the set of parameter
    /// registers that appear to be function arguments.
    fn detect_reg_params(func: &Function, param_regs: &[RegId]) -> HashSet<RegId> {
        // Collect all registers written to anywhere in the function
        let mut written: HashSet<RegId> = HashSet::new();
        // Collect all registers read from expressions
        let mut read_before_write: HashSet<RegId> = HashSet::new();

        // Walk blocks in order; for the entry block we track read-before-write
        // precisely.  For other blocks we just check if param regs appear as
        // reads without being written first in the function body.
        for block in &func.blocks {
            for stmt in &block.stmts {
                // Collect reads from the RHS / args first (before recording write)
                match stmt {
                    Stmt::Assign(_, expr) => {
                        Self::collect_reg_reads_from_expr(expr, param_regs, &written, &mut read_before_write);
                    }
                    Stmt::Store(addr, val, _) => {
                        Self::collect_reg_reads_from_expr(addr, param_regs, &written, &mut read_before_write);
                        Self::collect_reg_reads_from_expr(val, param_regs, &written, &mut read_before_write);
                    }
                    Stmt::Call(_, target, args) => {
                        Self::collect_reg_reads_from_expr(target, param_regs, &written, &mut read_before_write);
                        for a in args {
                            Self::collect_reg_reads_from_expr(a, param_regs, &written, &mut read_before_write);
                        }
                    }
                    Stmt::Nop => {}
                }

                // Now record the write
                match stmt {
                    Stmt::Assign(Var::Reg(reg, _), _) => { written.insert(*reg); }
                    Stmt::Call(Some(Var::Reg(reg, _)), _, _) => { written.insert(*reg); }
                    _ => {}
                }
            }
            // Check terminator reads
            match &block.terminator {
                Terminator::Branch(cond, _, _) => {
                    Self::collect_reg_reads_from_expr(cond, param_regs, &written, &mut read_before_write);
                }
                Terminator::Return(Some(expr)) => {
                    Self::collect_reg_reads_from_expr(expr, param_regs, &written, &mut read_before_write);
                }
                Terminator::Switch(val, _, _) => {
                    Self::collect_reg_reads_from_expr(val, param_regs, &written, &mut read_before_write);
                }
                Terminator::IndirectJump(expr) => {
                    Self::collect_reg_reads_from_expr(expr, param_regs, &written, &mut read_before_write);
                }
                _ => {}
            }
        }

        read_before_write
    }

    /// Recursively find parameter register reads in an expression that have not
    /// been written yet.
    fn collect_reg_reads_from_expr(
        expr: &Expr,
        param_regs: &[RegId],
        written: &HashSet<RegId>,
        out: &mut HashSet<RegId>,
    ) {
        match expr {
            Expr::Var(Var::Reg(reg, _)) => {
                if param_regs.contains(reg) && !written.contains(reg) {
                    out.insert(*reg);
                }
            }
            Expr::BinOp(_, lhs, rhs) | Expr::Cmp(_, lhs, rhs)
            | Expr::LogicalAnd(lhs, rhs) | Expr::LogicalOr(lhs, rhs) => {
                Self::collect_reg_reads_from_expr(lhs, param_regs, written, out);
                Self::collect_reg_reads_from_expr(rhs, param_regs, written, out);
            }
            Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
                Self::collect_reg_reads_from_expr(inner, param_regs, written, out);
            }
            Expr::Select(c, t, f) => {
                Self::collect_reg_reads_from_expr(c, param_regs, written, out);
                Self::collect_reg_reads_from_expr(t, param_regs, written, out);
                Self::collect_reg_reads_from_expr(f, param_regs, written, out);
            }
            _ => {}
        }
    }

    // ── Loop detection ───────────────────────────────────────────

    /// Find all loop headers and their back-edge sources from the CFG.
    /// Returns (set of header BlockIds, map from header → list of back-edge source BlockIds).
    fn find_loop_info(
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
    fn compute_all_loop_bodies(
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
    ///
    /// Uses the standard algorithm: seed from known back-edge sources (determined
    /// by dominance in `cfg.back_edges()`), then walk predecessors backwards.
    fn natural_loop_body(
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
    fn is_return_relay(&self, func: &Function, merge: Option<BlockId>) -> bool {
        let Some(bid) = merge else { return false };
        let Some(block) = func.block(bid) else { return false };
        if !matches!(block.terminator, Terminator::Return(_)) {
            return false;
        }
        // All stmts must be register assignments or nops (no meaningful computation)
        block.stmts.iter().all(|s| matches!(s, Stmt::Nop | Stmt::Assign(Var::Reg(_, _), _)))
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

    /// Decide what node to emit for a loop exit: if the exit target (or its
    /// goto-tail chain) ends with a return, inline the block as a return
    /// statement; otherwise emit a break.
    fn loop_exit_node(&self, func: &Function, target: BlockId) -> StructuredNode {
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
                            StructuredNode::DoWhile {
                                header: bid,
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
                                    condition: negate_condition(cond),
                                    body: nodes,
                                }
                            }
                        } else {
                            // Both targets in loop: header branch is an internal
                            // if-then, not the loop condition.  Check the latch
                            // for a do-while condition.

                            // OR-fold: header self-loops on cond1 and has a latch
                            // with cond2 → while (cond1 || cond2)
                            // Pattern: header: if(cond) goto header else latch;
                            //          latch:  if(lcond) goto header else exit;
                            let or_fold: Option<(Expr, BlockId, BlockId)> = if (*t == bid || *f == bid) {
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
                                // Build body: header's conditional branch as if-then,
                                // then latch stmts.
                                let mut body_nodes = Vec::new();
                                if !inner_nodes.is_empty() {
                                    if inner_ids.first() == Some(t) {
                                        body_nodes.push(StructuredNode::IfThen {
                                            condition: cond.clone(),
                                            then_body: inner_nodes,
                                        });
                                    } else if inner_ids.first() == Some(f) {
                                        body_nodes.push(StructuredNode::IfThen {
                                            condition: negate_condition(cond),
                                            then_body: inner_nodes,
                                        });
                                    } else {
                                        body_nodes.extend(inner_nodes);
                                    }
                                }
                                body_nodes.push(StructuredNode::Stmts(latch_id));
                                StructuredNode::DoWhile {
                                    header: bid,
                                    condition: do_cond,
                                    body: body_nodes,
                                }
                            } else {
                                let nodes = self.structure_region(
                                    func, cfg, &body_block_ids, loop_headers, loop_bodies, back_edge_sources, Some(bid),
                                );
                                StructuredNode::While {
                                    header: bid,
                                    condition: Expr::const_val(1, BitWidth::Bit32),
                                    body: nodes,
                                }
                            }
                            } // or_fold else
                        }
                    }
                    _ => {
                        // Header has Jump (not Branch) → check for do-while pattern.
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
                                            // true → loop, false → exit: condition is the loop-continue condition
                                            Some((cond.clone(), latch))
                                        } else if !t_in && f_in {
                                            // false → loop, true → exit: negate
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
                                condition: cond,
                                body: body_nodes,
                            }
                        } else {
                            let body_nodes = self.structure_region(
                                func, cfg, &body_block_ids, loop_headers, loop_bodies, back_edge_sources, Some(bid),
                            );
                            StructuredNode::While {
                                header: bid,
                                condition: Expr::const_val(1, BitWidth::Bit32),
                                body: body_nodes,
                            }
                        }
                    }
                };

                result.push(loop_node);

                // When a while-loop body has an internal exit (NOT the
                // header's own exit) that was inlined as a return (via
                // loop_exit_node → Block), the corresponding block should
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
                            // and an inner break exit (to exit_bid ≠ h_exit).
                            // When the header_exit is NOT in the current region
                            // (e.g. inside a nested loop where the exit would
                            // otherwise be lost), emit it as a conditional return.
                            if let Some(guard) = while_exit_guard.take() {
                                if !block_set.contains(&h_exit) {
                                    // Header_exit is outside this region — inline it
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
                    // Jump to loop header → implicit continue
                    if Some(target) == enclosing_loop {
                        result.push(StructuredNode::Stmts(bid));
                    }
                    // Jump to loop exit → break (or return if exit is a return block)
                    else if enclosing_exit == Some(target) {
                        result.push(StructuredNode::Stmts(bid));
                        result.push(self.loop_exit_node(func, target));
                    }
                    // Jump to next block in layout → fallthrough
                    else if next_in_layout == Some(target) {
                        result.push(StructuredNode::Stmts(bid));
                    }
                    // Jump to a loop header in this region → fallthrough to
                    // the upcoming While node (guard jump before loop entry).
                    else if loop_headers.contains(&target)
                        && block_set.contains(&target)
                        && Some(target) != enclosing_loop
                    {
                        result.push(StructuredNode::Stmts(bid));
                    }
                    // Jump outside region → check if target chain leads to return
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
                    // Jump to somewhere in region but not next → emit with goto-tail
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
                    //   → combined: if(!A || !B) goto M else bb2
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
                                        // f: if(nc) goto t else nf → OR
                                        cond = Expr::LogicalOr(
                                            Box::new(cond),
                                            Box::new(nc.clone()),
                                        );
                                        sc_skip.insert(chain_f);
                                        chain_f = *nf;
                                        f = *nf;
                                    } else if *nf == t {
                                        // f: if(nc) goto nt else t → OR (negate nc)
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
                                            // t: if(nc) goto f else nf → chain
                                            cond = Expr::LogicalAnd(
                                                Box::new(cond),
                                                Box::new(negate_condition(nc)),
                                            );
                                            sc_skip.insert(chain_t);
                                            chain_t = *nf;
                                            t = *nf;
                                        } else if *nf == f {
                                            // t: if(nc) goto nt else f → chain
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
                    // Branch to loop exit → break (or return if exit is a return block)
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
                    // One branch is the next block → if-then pattern
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
                        // Neither branch is next → emit as raw block with gotos
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
    ///
    /// Uses the Cooper-Harvey-Kennedy algorithm on the reverse CFG.
    fn compute_ipdom(
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
    #[allow(clippy::too_many_arguments)]
    fn structure_arm_inline(
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
                        // Stop emitting if this block ends with a return
                        // (directly or via goto-tail); subsequent nodes are dead code.
                        match &block.terminator {
                            Terminator::Return(_) => break,
                            Terminator::Jump(target) => {
                                let tail = self.collect_goto_tail(func, *target);
                                let ends_return = tail.last().and_then(|&b| func.block(b))
                                    .is_some_and(|b| matches!(b.terminator, Terminator::Return(_)));
                                if ends_return { break; }
                            }
                            _ => {}
                        }
                    }
                }
                StructuredNode::Stmts(id) => {
                    if let Some(block) = func.block(*id) {
                        // Track rax assignment for relay block resolution
                        if let Some(expr) = self.last_rax_assignment_expr(block) {
                            self.rax_context = Some(expr);
                        }
                        self.emit_stmts_only(&mut out, block);
                        if self.block_has_noreturn(block) {
                            break;
                        }
                    }
                }
                StructuredNode::IfThen { condition, then_body } => {
                    let _ = writeln!(out, "{}if ({}) {{", self.indent_str(), self.expr_to_c(condition));
                    self.indent += 1;
                    let saved_rax = self.rax_context.clone();
                    out.push_str(&self.emit_structured(then_body, func));
                    self.rax_context = saved_rax;
                    self.indent -= 1;
                    let _ = writeln!(out, "{}}}", self.indent_str());
                }
                StructuredNode::IfThenElse { condition, then_body, else_body } => {
                    let saved_rax = self.rax_context.clone();
                    let _ = writeln!(out, "{}if ({}) {{", self.indent_str(), self.expr_to_c(condition));
                    self.indent += 1;
                    out.push_str(&self.emit_structured(then_body, func));
                    self.rax_context = saved_rax.clone();
                    self.indent -= 1;
                    // Check for else-if chain
                    if else_body.len() == 1 {
                        match &else_body[0] {
                            StructuredNode::IfThen { condition: ec, then_body: et } => {
                                let _ = writeln!(out, "{}}} else if ({}) {{", self.indent_str(), self.expr_to_c(ec));
                                self.indent += 1;
                                out.push_str(&self.emit_structured(et, func));
                                self.rax_context = saved_rax;
                                self.indent -= 1;
                                let _ = writeln!(out, "{}}}", self.indent_str());
                                continue;
                            }
                            StructuredNode::IfThenElse { condition: ec, then_body: et, else_body: ee } => {
                                let _ = writeln!(out, "{}}} else if ({}) {{", self.indent_str(), self.expr_to_c(ec));
                                self.indent += 1;
                                out.push_str(&self.emit_structured(et, func));
                                self.rax_context = saved_rax.clone();
                                self.indent -= 1;
                                let _ = writeln!(out, "{}}} else {{", self.indent_str());
                                self.indent += 1;
                                out.push_str(&self.emit_structured(ee, func));
                                self.rax_context = saved_rax;
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
                    self.rax_context = saved_rax;
                    self.indent -= 1;
                    let _ = writeln!(out, "{}}}", self.indent_str());
                }
                StructuredNode::While { header, condition, body, .. } => {
                    let header_has_stmts = func.block(*header)
                        .is_some_and(|b| b.stmts.iter().any(|s| !matches!(s, Stmt::Nop)));
                    if body.is_empty() && !header_has_stmts {
                        continue;
                    }
                    // Emit header statements before the loop (initial evaluation).
                    // For pre-tested loops the header usually has no stmts (CMP
                    // fused into the branch), so this is typically a no-op.
                    if let Some(block) = func.block(*header) {
                        self.emit_stmts_only(&mut out, block);
                    }
                    let cond_str = self.expr_to_c(condition);
                    let _ = writeln!(out, "{}while ({}) {{", self.indent_str(), cond_str);
                    self.indent += 1;
                    out.push_str(&self.emit_structured(body, func));
                    // Re-emit header statements at end of loop body so that
                    // condition-setup code runs before the next check.
                    if let Some(block) = func.block(*header) {
                        if !block.stmts.iter().all(|s| matches!(s, Stmt::Nop)) {
                            self.emit_stmts_only(&mut out, block);
                        }
                    }
                    self.indent -= 1;
                    let _ = writeln!(out, "{}}}", self.indent_str());
                }
                StructuredNode::DoWhile { header, condition, body, .. } => {
                    let header_has_stmts = func.block(*header)
                        .is_some_and(|b| b.stmts.iter().any(|s| !matches!(s, Stmt::Nop)));
                    if body.is_empty() && !header_has_stmts {
                        continue;
                    }
                    let _ = writeln!(out, "{}do {{", self.indent_str());
                    self.indent += 1;
                    // Emit header statements as part of the loop body
                    if let Some(block) = func.block(*header) {
                        self.emit_stmts_only(&mut out, block);
                    }
                    out.push_str(&self.emit_structured(body, func));
                    self.indent -= 1;
                    let cond_str = self.expr_to_c(condition);
                    let _ = writeln!(out, "{}}} while ({});", self.indent_str(), cond_str);
                }
                StructuredNode::For { header, init_block, init, condition, step, body, .. } => {
                    // Emit other stmts from the init block (e.g. sum = 0) excluding the for-init
                    if let Some(block) = func.block(*init_block) {
                        self.emit_stmts_skip(block, init, &mut out);
                    }
                    // Emit header stmts (usually empty)
                    if let Some(block) = func.block(*header) {
                        self.emit_stmts_only(&mut out, block);
                    }
                    let init_str = self.stmt_to_c(init);
                    let cond_str = self.expr_to_c(condition);
                    let step_str = self.stmt_to_c(step);
                    let _ = writeln!(out, "{}for ({}; {}; {}) {{", self.indent_str(), init_str, cond_str, step_str);
                    self.indent += 1;
                    // Emit body, skipping the step stmt from the last block
                    out.push_str(&self.emit_structured_for_body(body, func, step));
                    self.indent -= 1;
                    let _ = writeln!(out, "{}}}", self.indent_str());
                }
                StructuredNode::Break => {
                    let _ = writeln!(out, "{}break;", self.indent_str());
                }
                StructuredNode::Continue => {
                    let _ = writeln!(out, "{}continue;", self.indent_str());
                }
            }
        }

        out
    }

    /// Emit for-loop body, skipping the step statement from the last Stmts/Block node.
    fn emit_structured_for_body(&mut self, nodes: &[StructuredNode], func: &Function, step: &Stmt) -> String {
        let mut out = String::new();
        let last_idx = nodes.len().saturating_sub(1);

        for (idx, node) in nodes.iter().enumerate() {
            let is_last = idx == last_idx;
            match node {
                StructuredNode::Stmts(id) if is_last => {
                    if let Some(block) = func.block(*id) {
                        self.emit_stmts_skip(block, step, &mut out);
                    }
                }
                StructuredNode::Block(id) if is_last => {
                    if let Some(block) = func.block(*id) {
                        self.emit_stmts_skip(block, step, &mut out);
                    }
                }
                _ => {
                    // Render normally via emit_structured for non-last nodes
                    out.push_str(&self.emit_structured(std::slice::from_ref(node), func));
                }
            }
        }
        out
    }

    /// Emit block statements, skipping the one that matches `skip_stmt`.
    fn emit_stmts_skip(&self, block: &BasicBlock, skip_stmt: &Stmt, out: &mut String) {
        // Find the last non-Nop stmt index
        let last_non_nop = block.stmts.iter().rposition(|s| !matches!(s, Stmt::Nop));
        for (i, stmt) in block.stmts.iter().enumerate() {
            // Skip the step statement (last non-Nop that matches)
            if Some(i) == last_non_nop && stmt == skip_stmt {
                continue;
            }
            let line = self.stmt_to_c(stmt);
            if !line.is_empty() {
                let _ = writeln!(out, "{}{};", self.indent_str(), line);
            }
        }
    }

    /// Emit a block with its statements AND terminator.
    fn emit_block_full(&mut self, block: &BasicBlock, func: &Function) -> String {
        let mut out = String::new();
        let mut hit_noreturn = false;
        let mut rax_return_expr = self.last_rax_assignment_expr(block);

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
                // If we have `return rax` but no local rax value, try predecessors,
                // then fall back to the rax_context from the parent Stmts block.
                if rax_return_expr.is_none() {
                    if matches!(val, Some(Expr::Var(Var::Reg(RegId::Rax, _)))) {
                        rax_return_expr = self.find_predecessor_rax(block.id, func)
                            .or_else(|| self.rax_context.take());
                    }
                }
                let _ = match val {
                    Some(Expr::Var(Var::Reg(RegId::Rax, _))) if rax_return_expr.is_some() => {
                        let v = rax_return_expr.as_ref().expect("checked is_some");
                        writeln!(out, "{}return {};", self.indent_str(), self.expr_to_c(v))
                    }
                    // Bare `return rax` with no concrete value — suppress to `return;`
                    Some(Expr::Var(Var::Reg(RegId::Rax, _))) => {
                        writeln!(out, "{}return;", self.indent_str())
                    }
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
                            if let Some(expr) = self.last_rax_assignment_expr(tail_block) {
                                rax_return_expr = Some(expr);
                            }
                            // Emit stmts for all blocks
                            self.emit_stmts_only(&mut out, tail_block);
                            if self.block_has_noreturn(tail_block) {
                                return out;
                            }
                            // Emit terminator only for the last block
                            if idx == tail.len() - 1
                                && let Terminator::Return(val) = &tail_block.terminator {
                                    let _ = match val {
                                        Some(Expr::Var(Var::Reg(RegId::Rax, _))) if rax_return_expr.is_some() => {
                                            let v = rax_return_expr.as_ref().expect("checked is_some");
                                            writeln!(out, "{}return {};", self.indent_str(), self.expr_to_c(v))
                                        }
                                        Some(Expr::Var(Var::Reg(RegId::Rax, _))) => {
                                            writeln!(out, "{}return;", self.indent_str())
                                        }
                                        Some(v) => writeln!(out, "{}return {};", self.indent_str(), self.expr_to_c(v)),
                                        None => writeln!(out, "{}return;", self.indent_str()),
                                    };
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
            Terminator::Switch(val, cases, default) => {
                let _ = writeln!(out, "{}switch ({}) {{", self.indent_str(), self.expr_to_c(val));
                self.indent += 1;
                for (case_val, target) in cases {
                    let _ = writeln!(out, "{}case {}: goto {};", self.indent_str(), case_val, target);
                }
                if let Some(def) = default {
                    let _ = writeln!(out, "{}default: goto {};", self.indent_str(), def);
                }
                self.indent -= 1;
                let _ = writeln!(out, "{}}}", self.indent_str());
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

    fn last_rax_assignment_expr(&self, block: &BasicBlock) -> Option<Expr> {
        let mut last = None;
        for stmt in &block.stmts {
            match stmt {
                Stmt::Assign(Var::Reg(RegId::Rax, _), expr) => {
                    last = Some(expr.clone());
                }
                Stmt::Call(Some(Var::Reg(RegId::Rax, _)), _, _) => {
                    // Unknown concrete value here; keep previous explicit expression only
                    // if a later Assign rewrites rax.
                    last = None;
                }
                _ => {}
            }
        }
        last
    }

    /// Search predecessor blocks for the rax value when the current block
    /// is a return relay (`return rax` with no local rax assignment).
    /// Returns Some(expr) if exactly one unique value is found across all
    /// predecessors, so we can resolve `return rax` → `return <expr>`.
    fn find_predecessor_rax(&self, block_id: BlockId, func: &Function) -> Option<Expr> {
        let mut values: Vec<Expr> = Vec::new();
        for b in &func.blocks {
            let targets_this = match &b.terminator {
                Terminator::Jump(t) => *t == block_id,
                Terminator::Branch(_, t, f) => *t == block_id || *f == block_id,
                _ => false,
            };
            if targets_this {
                if let Some(expr) = self.last_rax_assignment_expr(b) {
                    values.push(expr);
                }
            }
        }
        // If all predecessors agree on the same rax value, use it.
        if !values.is_empty() && values.iter().all(|v| *v == values[0]) {
            return Some(values[0].clone());
        }
        // If there are multiple different values, we can't resolve.
        None
    }

    // ── Statement/expression rendering ───────────────────────────

    fn is_noreturn_call(&self, stmt: &Stmt) -> bool {
        if let Stmt::Call(_, target, _) = stmt {
            let name = self.resolve_call_target(target);
            if is_noreturn_name(&name) {
                return true;
            }
            // Check interprocedural summary for internal noreturn functions
            if let Expr::Const(addr, _) = target {
                if let Some(summary) = self.func_summaries.get(addr) {
                    return summary.noreturn;
                }
            }
        }
        false
    }

    fn stmt_to_c(&self, stmt: &Stmt) -> String {
        match stmt {
            Stmt::Assign(var, expr) => {
                // Suppress register assignments UNLESS the register is a
                // detected parameter — those get rendered as arg_N updates.
                if let Var::Reg(r, _) = var {
                    if !self.reg_params.contains_key(r) {
                        return String::new();
                    }
                }
                // Suppress assignments to dead temp variables.
                if let Var::Temp(id, _) = var {
                    if self.dead_temps.contains(id) {
                        return String::new();
                    }
                }
                // Detect folded zero-init buffer: Var::Stack(off, Bit8) = Const(total, Bit64)
                if let (Var::Stack(off, BitWidth::Bit8), Expr::Const(total, BitWidth::Bit64)) = (var, expr)
                    && *total >= 16 {
                        let name = self.stack_name(*off);
                        // Arrays decay to pointers — no & needed
                        let prefix = if self.buffer_sizes.contains_key(off) { "" } else { "&" };
                        return format!("memset({prefix}{name}, 0, {total})");
                    }
                // Suppress parameter assignments (var_N = param_reg)
                if let Var::Stack(off, _) = var {
                    let name = self.stack_name(*off);
                    if self.param_vars.contains(&name)
                        && matches!(expr, Expr::Var(Var::Reg(_, _))) {
                            return String::new();
                        }
                }
                // Suppress SSE zero-init: stack_var = xmm0 (from pxor xmm0,xmm0)
                if matches!(var, Var::Stack(_, _))
                    && matches!(expr, Expr::Var(Var::Reg(reg, _)) if reg.is_xmm()) {
                        let name = self.var_to_c(var);
                        return format!("{name} = 0");
                    }
                format!("{} = {}", self.var_to_c(var), self.expr_to_c(expr))
            }
            Stmt::Store(addr, val, width) => {
                // Struct field store: ptr->field_N = val
                if let Some(access) = self.try_struct_field(addr) {
                    return format!("{} = {}", access, self.expr_to_c(val));
                }
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
                // Trim extra arguments based on interprocedural analysis
                let trimmed_args = self.trim_call_args(target, args);
                let args_str: Vec<String> = trimmed_args.iter().map(|a| self.expr_to_c(a)).collect();
                // Omit assignment if return var is a dead temp
                let dead_ret = matches!(ret, Some(Var::Temp(id, _)) if self.dead_temps.contains(id));
                match ret {
                    Some(r) if !dead_ret => format!("{} = {}({})", self.var_to_c(r), target_str, args_str.join(", ")),
                    _ => format!("{}({})", target_str, args_str.join(", ")),
                }
            }
            Stmt::Nop => String::new(),
        }
    }

    fn resolve_call_target(&self, target: &Expr) -> String {
        match target {
            Expr::Const(addr, _) => {
                // Synthetic library calls
                if *addr == crate::lift::SYNTHETIC_MEMCPY {
                    return "memcpy".to_string();
                }
                if *addr == crate::lift::SYNTHETIC_MEMSET {
                    return "memset".to_string();
                }
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

    /// Trim extra arguments for calls to internal functions with known param count.
    fn trim_call_args<'b>(&self, target: &Expr, args: &'b [Expr]) -> &'b [Expr] {
        if let Expr::Const(addr, _) = target {
            if let Some(summary) = self.func_summaries.get(addr) {
                if summary.param_count > 0 && summary.param_count < args.len() {
                    return &args[..summary.param_count];
                }
            }
        }
        args
    }

    fn expr_to_c(&self, expr: &Expr) -> String {
        match expr {
            Expr::Var(v) => self.var_to_c(v),
            Expr::Const(val, width) => {
                // Try to resolve as a string constant
                if *val > 0x1000
                    && let Some(s) = self.binary.read_cstring_at(*val) {
                        return format!("\"{}\"", escape_c_string(&s));
                    }
                // Character literal for byte/dword-sized printable ASCII
                if matches!(width, BitWidth::Bit8) && *val >= 0x20 && *val <= 0x7e {
                    let ch = *val as u8 as char;
                    return format!("'{ch}'");
                }
                // Special characters (only for byte-width)
                if matches!(width, BitWidth::Bit8) && *val == 0x0a {
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
                // Detect negative values (high bit set) and display as signed
                let is_negative = match width {
                    BitWidth::Bit8 => *val > 0x7F && *val <= 0xFF,
                    BitWidth::Bit16 => *val > 0x7FFF && *val <= 0xFFFF,
                    BitWidth::Bit32 => *val > 0x7FFF_FFFF && *val <= 0xFFFF_FFFF,
                    BitWidth::Bit64 => *val > 0x7FFF_FFFF_FFFF_FFFF,
                };
                if is_negative {
                    let signed = match width {
                        BitWidth::Bit8 => (*val as u8) as i8 as i64,
                        BitWidth::Bit16 => (*val as u16) as i16 as i64,
                        BitWidth::Bit32 => (*val as u32) as i32 as i64,
                        BitWidth::Bit64 => *val as i64,
                    };
                    return format!("{signed}");
                }
                if *val > 9 {
                    format!("0x{val:x}")
                } else {
                    format!("{val}")
                }
            }
            Expr::BinOp(op, lhs, rhs) => {
                // rip + const → just the const (address)
                if matches!(op, BinOp::Add)
                    && let Expr::Var(Var::Reg(RegId::Rip, _)) = lhs.as_ref() {
                        return self.expr_to_c(rhs);
                    }
                // rbp-relative expressions → &var_N (simple) or (&var_N + dynamic)
                if matches!(op, BinOp::Add | BinOp::Sub)
                    && let Some((offset, dynamic)) = self.extract_rbp_base(expr) {
                        let base = if offset != 0 {
                            format!("&{}", self.stack_name(offset))
                        } else {
                            "rbp".to_string()
                        };
                        return match dynamic {
                            Some(dyn_expr) => format!("({} + {})", base, self.expr_to_c(&dyn_expr)),
                            None => base,
                        };
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
                    BinOp::Rol => "<<<",
                    BinOp::Ror => ">>>",
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
                UnaryOp::AddrOf => {
                    // Arrays decay to pointers in C — emit `var_XX` not `&var_XX`
                    if let Expr::Var(Var::Stack(off, BitWidth::Bit8)) = inner.as_ref()
                        && self.buffer_sizes.contains_key(off) {
                            return self.expr_to_c(inner);
                        }
                    format!("&{}", self.expr_to_c(inner))
                }
            },
            Expr::Load(addr, width) => {
                // Resolve rip-relative loads as globals/strings
                if let Expr::BinOp(BinOp::Add, lhs, rhs) = addr.as_ref()
                    && let Expr::Var(Var::Reg(RegId::Rip, _)) = lhs.as_ref()
                        && let Expr::Const(target_addr, _) = rhs.as_ref() {
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
                // Direct constant address → global
                if let Expr::Const(addr_val, _) = addr.as_ref()
                    && let Some(name) = self.binary.resolve_global_name(*addr_val) {
                        return name;
                    }
                // Struct field access: ptr->field_N
                if let Some(access) = self.try_struct_field(addr) {
                    return access;
                }
                // Stack loads: *(type*)(rbp + offset) → var_N / arg_N
                if let Some((offset, dynamic)) = self.extract_rbp_base(addr) {
                    if let Some(dyn_expr) = &dynamic {
                        // rbp + const + dynamic → *(type*)(&var_N + dynamic)
                        let base = if offset != 0 {
                            format!("&{}", self.stack_name(offset))
                        } else {
                            "rbp".to_string()
                        };
                        let dyn_str = self.expr_to_c(dyn_expr);
                        return format!("*({}*)(({} + {}))", c_type(*width), base, dyn_str);
                    } else {
                        // Simple rbp + const → direct stack variable
                        if offset != 0 {
                            return self.stack_name(offset);
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
                let is_unsigned = matches!(cc, CondCode::Below | CondCode::BelowEq | CondCode::Above | CondCode::AboveEq);
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
                // For unsigned comparisons, render high-bit-set constants as hex
                let rhs_str = if is_unsigned {
                    if let Expr::Const(val, width) = rhs.as_ref() {
                        let high_bit = match width {
                            BitWidth::Bit8 => *val > 0x7F && *val <= 0xFF,
                            BitWidth::Bit16 => *val > 0x7FFF && *val <= 0xFFFF,
                            BitWidth::Bit32 => *val > 0x7FFF_FFFF && *val <= 0xFFFF_FFFF,
                            BitWidth::Bit64 => *val > 0x7FFF_FFFF_FFFF_FFFF,
                        };
                        if high_bit {
                            format!("0x{val:x}")
                        } else {
                            self.expr_to_c(rhs)
                        }
                    } else {
                        self.expr_to_c(rhs)
                    }
                } else {
                    self.expr_to_c(rhs)
                };
                format!("{} {} {}", self.expr_to_c(lhs), op, rhs_str)
            }
            Expr::LogicalAnd(lhs, rhs) => {
                format!("({} && {})", self.expr_to_c(lhs), self.expr_to_c(rhs))
            }
            Expr::LogicalOr(lhs, rhs) => {
                format!("({} || {})", self.expr_to_c(lhs), self.expr_to_c(rhs))
            }
            Expr::Select(cond, t, f) => {
                // Recognize abs() patterns
                if let Some(abs_expr) = self.try_simplify_abs(cond, t, f) {
                    return abs_expr;
                }
                format!("({} ? {} : {})", self.expr_to_c(cond), self.expr_to_c(t), self.expr_to_c(f))
            }
        }
    }

    /// Try to simplify a Select into abs(x).
    /// Recognizes variants:
    ///   Select(Cmp(Lt, -x, 0), x, -x) → abs(x)
    ///   Select(Cmp(Ge, -x, 0), -x, x) → abs(x)
    ///   Select(Cmp(Lt, x, 0), -x, x)  → abs(x)
    ///   Select(Cmp(Ge, x, 0), x, -x)  → abs(x)
    fn try_simplify_abs(&self, cond: &Expr, t: &Expr, f: &Expr) -> Option<String> {
        if let Expr::Cmp(cc, cmp_lhs, cmp_rhs) = cond {
            let is_zero = matches!(cmp_rhs.as_ref(), Expr::Const(0, _));
            if !is_zero { return None; }

            match cc {
                // Select(Cmp(Lt, -x, 0), x, -x) → abs(x)
                // Select(Cmp(Sign, -x, 0), x, -x) → abs(x)
                CondCode::Lt | CondCode::Sign => {
                    if let Expr::UnaryOp(UnaryOp::Neg, inner) = cmp_lhs.as_ref() {
                        if inner.as_ref() == t {
                            if let Expr::UnaryOp(UnaryOp::Neg, f_inner) = f {
                                if f_inner.as_ref() == t {
                                    return Some(format!("abs({})", self.expr_to_c(t)));
                                }
                            }
                        }
                    }
                    // Select(Cmp(Lt, x, 0), -x, x) → abs(x)
                    if cmp_lhs.as_ref() == f {
                        if let Expr::UnaryOp(UnaryOp::Neg, t_inner) = t {
                            if t_inner.as_ref() == f {
                                return Some(format!("abs({})", self.expr_to_c(f)));
                            }
                        }
                    }
                }
                // Select(Cmp(Ge, -x, 0), -x, x) → abs(x)
                // Select(Cmp(NotSign, -x, 0), -x, x) → abs(x)
                CondCode::Ge | CondCode::NotSign => {
                    if let Expr::UnaryOp(UnaryOp::Neg, inner) = cmp_lhs.as_ref() {
                        if inner.as_ref() == f {
                            if let Expr::UnaryOp(UnaryOp::Neg, t_inner) = t {
                                if t_inner.as_ref() == f {
                                    return Some(format!("abs({})", self.expr_to_c(f)));
                                }
                            }
                        }
                    }
                    // Select(Cmp(Ge, x, 0), x, -x) → abs(x)
                    if cmp_lhs.as_ref() == t {
                        if let Expr::UnaryOp(UnaryOp::Neg, f_inner) = f {
                            if f_inner.as_ref() == t {
                                return Some(format!("abs({})", self.expr_to_c(t)));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Get the struct map key for a Var if it's in our struct_map.
    fn var_stack_off_for_struct(&self, v: &Var) -> Option<i64> {
        if let Var::Stack(off, BitWidth::Bit64) = v {
            if self.struct_map.contains_key(off) {
                return Some(*off);
            }
        }
        None
    }

    /// Check if an expression is a stack pointer load that we have struct info for.
    /// Matches `Var::Stack(off, 64)` or `Load(rbp ± const, 64)`.
    fn expr_struct_off(&self, expr: &Expr) -> Option<i64> {
        match expr {
            Expr::Var(v) => self.var_stack_off_for_struct(v),
            Expr::Load(addr, BitWidth::Bit64) => {
                let off = self.extract_rbp_base(addr)
                    .and_then(|(off, dyn_part)| if dyn_part.is_none() && off != 0 { Some(off) } else { None });
                off.filter(|o| self.struct_map.contains_key(o))
            }
            _ => None,
        }
    }

    /// Try to recognise `addr` as a struct field access through a pointer variable.
    ///
    /// Patterns:
    ///   - `Var::Stack(off, 64)` → `var->field_0`
    ///   - `BinOp(Add, Var::Stack(off, 64), Const(F))` → `var->field_F`
    ///   - Same with `Load(rbp+off, 64)` instead of `Var::Stack`
    fn try_struct_field(&self, addr: &Expr) -> Option<String> {
        let (stack_off, field_off) = match addr {
            _ if self.expr_struct_off(addr).is_some() => {
                (self.expr_struct_off(addr).unwrap(), 0i64)
            }
            Expr::BinOp(BinOp::Add, lhs, rhs) => {
                if let Some(off) = self.expr_struct_off(lhs) {
                    if let Expr::Const(f, _) = rhs.as_ref() {
                        (off, *f as i64)
                    } else {
                        return None;
                    }
                } else if let Some(off) = self.expr_struct_off(rhs) {
                    if let Expr::Const(f, _) = lhs.as_ref() {
                        (off, *f as i64)
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            _ => return None,
        };

        let layout = self.struct_map.get(&stack_off)?;
        let field = layout.fields.iter().find(|f| f.offset == field_off)?;
        let base_name = self.stack_name(stack_off);
        Some(format!("{}->{}", base_name, field.name))
    }

    /// Decompose an expression tree to extract `rbp + const_offset + dynamic_part`.
    ///
    /// Returns `Some((stack_offset_as_i64, Option<dynamic_expr>))` if the tree
    /// contains `rbp` and additive constant(s).  The dynamic part is `None` when
    /// the expression is a plain `rbp ± const`.
    fn extract_rbp_base(&self, expr: &Expr) -> Option<(i64, Option<Expr>)> {
        // Flatten the additive tree: collect (sign, node) pairs.
        let mut const_sum: i64 = 0;
        let mut dynamic_parts: Vec<Expr> = Vec::new();
        let mut has_rbp = false;

        self.flatten_add(expr, true, &mut const_sum, &mut dynamic_parts, &mut has_rbp);

        if !has_rbp {
            return None;
        }

        let dynamic = if dynamic_parts.is_empty() {
            None
        } else {
            // Rebuild the dynamic expression as a sum
            let mut acc = dynamic_parts.remove(0);
            for part in dynamic_parts {
                acc = Expr::binop(BinOp::Add, acc, part);
            }
            Some(acc)
        };

        Some((const_sum, dynamic))
    }

    /// Recursively flatten an additive expression tree.
    /// Collects: constants into `const_sum`, `rbp` flag, everything else into `dynamic`.
    fn flatten_add(
        &self,
        expr: &Expr,
        positive: bool,
        const_sum: &mut i64,
        dynamic: &mut Vec<Expr>,
        has_rbp: &mut bool,
    ) {
        match expr {
            Expr::BinOp(BinOp::Add, lhs, rhs) => {
                self.flatten_add(lhs, positive, const_sum, dynamic, has_rbp);
                self.flatten_add(rhs, positive, const_sum, dynamic, has_rbp);
            }
            Expr::BinOp(BinOp::Sub, lhs, rhs) => {
                self.flatten_add(lhs, positive, const_sum, dynamic, has_rbp);
                self.flatten_add(rhs, !positive, const_sum, dynamic, has_rbp);
            }
            Expr::Var(Var::Reg(RegId::Rbp, _)) => {
                *has_rbp = true;
            }
            Expr::Const(val, _) => {
                let v = *val as i64;
                if positive {
                    *const_sum = const_sum.wrapping_add(v);
                } else {
                    *const_sum = const_sum.wrapping_sub(v);
                }
            }
            _ => {
                dynamic.push(expr.clone());
            }
        }
    }

    /// Look up the friendly name for a stack offset, falling back to offset-based names.
    fn stack_name(&self, off: i64) -> String {
        if let Some(name) = self.var_names.get(&off) {
            return name.clone();
        }
        if off >= 0 {
            format!("arg_{off:x}")
        } else {
            format!("var_{:x}", off.unsigned_abs())
        }
    }

    fn var_to_c(&self, var: &Var) -> String {
        match var {
            Var::Reg(reg, _) => {
                // Use parameter name if this is a detected register parameter
                if let Some(name) = self.reg_params.get(reg) {
                    return name.clone();
                }
                format!("{reg}")
            }
            Var::Stack(off, _) => self.stack_name(*off),
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

/// Produce the type-map key for a stack variable (matching typing.rs var_key).
fn stack_type_key(off: i64) -> String {
    if off >= 0 {
        format!("arg_{off:x}")
    } else {
        format!("var_{:x}", off.unsigned_abs())
    }
}

/// Negate a condition expression.
fn negate_condition(cond: &Expr) -> Expr {
    match cond {
        Expr::Cmp(cc, lhs, rhs) => Expr::Cmp(cc.negate(), lhs.clone(), rhs.clone()),
        Expr::Cond(cc) => Expr::Cond(cc.negate()),
        // De Morgan: !(A && B) → (!A || !B)
        Expr::LogicalAnd(lhs, rhs) => Expr::LogicalOr(
            Box::new(negate_condition(lhs)),
            Box::new(negate_condition(rhs)),
        ),
        // De Morgan: !(A || B) → (!A && !B)
        Expr::LogicalOr(lhs, rhs) => Expr::LogicalAnd(
            Box::new(negate_condition(lhs)),
            Box::new(negate_condition(rhs)),
        ),
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
    DoWhile {
        header: BlockId,
        condition: Expr,
        body: Vec<StructuredNode>,
    },
    For {
        header: BlockId,
        /// Block ID of the pre-loop init block (emit all stmts except `init`).
        init_block: BlockId,
        init: Stmt,
        condition: Expr,
        step: Stmt,
        body: Vec<StructuredNode>,
    },
    Break,
    Continue,
}
