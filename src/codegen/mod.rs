use crate::cfg::Cfg;
use crate::interprocedural::{FunctionSummary, InterproceduralInfo};
use crate::ir::*;
use crate::loader::{Binary, FunctionSymbol};
use crate::struct_recovery::{self, StructMap};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write;

mod control_flow;
mod emit;


/// Generate pseudo-C code from an IR function.
pub struct CodeGenerator<'a> {
    /// Known function symbols for resolving call targets.
    symbols: HashMap<u64, String>,
    /// Reference to the loaded binary for string constant extraction.
    binary: &'a Binary,
    indent: usize,
    /// Parameter stack variable names to suppress in output.
    param_vars: HashSet<String>,
    /// Temp vars that hold call results (temp_name to call expression string).
    /// Used to inline `t0 >= 0` as `seccomp_rule_add(...) >= 0`.
    call_results: HashMap<String, String>,
    /// Inferred buffer sizes: stack offset to byte count.
    /// Set per-function from `Function::buffer_sizes`.
    buffer_sizes: HashMap<i64, u64>,
    /// Per-function name mapping: stack offset to friendly name (e.g. `var_1`, `arg_1`).
    var_names: HashMap<i64, String>,
    /// Inferred struct layouts for pointer-typed variables.
    struct_map: StructMap,
    /// Interprocedural function summaries (address to summary).
    func_summaries: HashMap<u64, FunctionSummary>,
    /// Temp variable IDs that are never read; declaration and assignment are suppressed.
    dead_temps: HashSet<u32>,
    /// Register to parameter name mapping for leaf functions (e.g. Rdi to "arg_1").
    reg_params: HashMap<RegId, String>,
    /// Fallback names for any remaining raw registers that survived analysis.
    reg_var_names: HashMap<RegId, String>,
    /// Stack offsets known to be parameters for the current function.
    stack_param_offsets: HashSet<i64>,
    /// Contextual rax value from the most recently emitted parent block.
    /// Used to resolve `return rax` in relay blocks where the value comes
    /// from a predecessor that was emitted as a Stmts node.
    rax_context: Option<Expr>,
    /// Block IDs that need labels because a fallback goto still references them.
    label_targets: HashSet<BlockId>,
    /// Labels already emitted for the current function.
    emitted_labels: HashSet<BlockId>,
    /// Active loop contexts from outermost to innermost while emitting.
    loop_context: Vec<(BlockId, Option<BlockId>)>,
    /// Use IDA Hex-Rays style types and naming.
    ida_style: bool,
    /// Map from BlockId to label string for consistent goto/label naming.
    label_map: HashMap<BlockId, String>,
}

impl<'a> CodeGenerator<'a> {
    pub fn new(symbols: &[FunctionSymbol], binary: &'a Binary, ida_style: bool) -> Self {
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
            reg_var_names: HashMap::new(),
            stack_param_offsets: HashSet::new(),
            rax_context: None,
            label_targets: HashSet::new(),
            emitted_labels: HashSet::new(),
            loop_context: Vec::new(),
            ida_style,
            label_map: HashMap::new(),
        }
    }

    /// Set interprocedural analysis results.
    pub fn set_interprocedural(&mut self, info: &InterproceduralInfo) {
        self.func_summaries = info.summaries.clone();
    }

    fn block_indices_by_addr(func: &Function) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..func.blocks.len()).collect();
        indices.sort_by_key(|&idx| (func.blocks[idx].addr, idx));
        indices
    }

    /// Generate pseudo-C code for a function.
    pub fn generate(&mut self, func: &Function, cfg: &Cfg) -> String {
        let mut out = String::new();

        self.buffer_sizes = func.buffer_sizes.clone();
        self.var_names.clear();
        self.stack_param_offsets.clear();
        self.reg_var_names.clear();
        self.struct_map = struct_recovery::recover_structs(func);

        // Detect parameter offsets.
        let param_regs = func.calling_conv.param_regs();
        // param_offsets: BTreeSet of (offset, width) for stack slots that are parameters
        let mut param_offsets: BTreeSet<(i64, BitWidth)> = BTreeSet::new();
        // For 64-bit ABIs, map stack offset to calling-convention register index.
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

        // Leaf function parameter detection.
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

        // Find dead temp variables (defined but never read) before stack-slot
        // collection so dead `tN = &stack_base` scaffolding doesn't create
        // phantom locals like `var_1`.
        self.dead_temps = Self::find_dead_temps(func);

        // Collect all stack offsets used in the function.
        let mut all_offsets = Self::collect_stack_slots(func, &self.dead_temps);
        for (off, w) in &param_offsets {
            match all_offsets.get_mut(off) {
                Some(existing) if *w > *existing => *existing = *w,
                Some(_) => {}
                None => {
                    all_offsets.insert(*off, *w);
                }
            }
        }

        // Build the friendly name map.
        let param_off_set: HashSet<i64> = param_offsets.iter().map(|(o, _)| *o).collect();
        self.stack_param_offsets = param_off_set.clone();

        // Parameters: sorted by register order (64-bit) or offset ascending (32-bit), then named arg_1, arg_2, ...
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

        // Locals: named by actual stack offset (hex), e.g. var_8 for [rbp-0x8]
        let mut local_offs: Vec<(i64, BitWidth)> = all_offsets.iter()
            .filter(|(off, _)| !param_off_set.contains(off))
            .map(|(off, w)| (*off, *w))
            .collect();
        local_offs.sort_by_key(|(off, _)| *off);
        for (off, _w) in local_offs.iter() {
            let abs_off = off.unsigned_abs();
            self.var_names.insert(*off, format!("var_{abs_off:x}"));
        }

        // Semantic variable naming.
        self.improve_var_names(func);
        self.assign_remaining_reg_names(func);

        // Build params and param_var_names.
        let mut params: Vec<(String, i64, BitWidth)> = Vec::new();
        let mut param_var_names: HashSet<String> = HashSet::new();
        for (off, w) in &param_list {
            let name = self.stack_name(*off);
            param_var_names.insert(name.clone());
            params.push((name, *off, *w));
        }

        // Determine return type from type inference
        let ret_type = if self.ida_style {
            ida_type(func.return_type.to_c_str())
        } else {
            func.return_type.to_c_str().to_string()
        };

        // Calling convention annotation
        let cc_str = match func.calling_conv {
            CallingConv::SystemV => if self.ida_style { " __fastcall" } else { "" },
            CallingConv::Win64 => if self.ida_style { " __fastcall" } else { "" },
            CallingConv::Cdecl => if self.ida_style { " __cdecl" } else { "" },
        };

        // __noreturn attribute for known noreturn functions
        let noreturn_prefix = if is_noreturn_name(&func.name) { "__noreturn " } else { "" };

        // Function signature with parameters
        if params.is_empty() && self.reg_params.is_empty() {
            let void_params = if self.ida_style { "void" } else { "" };
            let _ = writeln!(out, "{noreturn_prefix}{ret_type}{cc_str} {}({void_params}) {{", func.name);
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
                    let ty = if self.ida_style { ida_type(ty) } else { ty.to_string() };
                    format!("{ty} {name}")
                }).collect()
            };
            let _ = writeln!(out, "{noreturn_prefix}{ret_type}{cc_str} {}({}) {{", func.name, param_str.join(", "));
        } else {
            let param_str: Vec<String> = params.iter()
                .map(|(name, off, w)| {
                    let type_key = stack_type_key(*off);
                    let ty = func.var_types.get(&type_key)
                        .map(|t| t.to_c_str())
                        .unwrap_or_else(|| c_type(*w));
                    let ty = if self.ida_style { ida_type(ty) } else { ty.to_string() };
                    format!("{} {}", ty, name)
                })
                .collect();
            let _ = writeln!(out, "{noreturn_prefix}{ret_type}{cc_str} {}({}) {{", func.name, param_str.join(", "));
        }

        self.param_vars = param_var_names.clone();

        self.indent = 1;

        // Build call-result map: temp vars that hold single-use call return values
        // These will be inlined as `func(args)` instead of displaying as `t0`.
        // Only inline when the temp is used exactly once; multi-use call results
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
            // Build reverse map: variable name → register name (for reg-promoted vars)
            let reg_name_rev: HashMap<&str, &RegId> = self.reg_var_names.iter()
                .map(|(reg, name)| (name.as_str(), reg))
                .collect();

            for (name, type_key, width, buf_size) in &filtered {
                // Determine the annotation comment for this variable
                let annotation: Option<String> = if let Some(loc) = Self::stack_location_comment(type_key, func.has_frame_pointer, func.frame_size) {
                    Some(loc)
                } else if let Some(id_str) = type_key.strip_prefix('t') {
                    // Temp variable: look up source register
                    if let Ok(id) = id_str.parse::<u32>() {
                        func.temp_reg_origins.get(&id).map(|reg| format!("// {reg}"))
                    } else {
                        None
                    }
                } else if let Some(reg) = reg_name_rev.get(name.as_str()) {
                    // Register-promoted variable
                    Some(format!("// {reg}"))
                } else {
                    None
                };

                if let Some(size) = buf_size {
                    match annotation {
                        Some(ann) => {
                            let _ = writeln!(out, "{}char  {}[{}]; {}", self.indent_str(), name, size, ann);
                        }
                        None => {
                            let _ = writeln!(out, "{}char  {}[{}];", self.indent_str(), name, size);
                        }
                    }
                } else {
                    let ty = func.var_types.get(type_key.as_str())
                        .map(|t| t.to_c_str())
                        .unwrap_or_else(|| c_type(*width));
                    let ty = if self.ida_style { ida_type(ty) } else { ty.to_string() };
                    match annotation {
                        Some(ann) => {
                            let _ = writeln!(out, "{}{}  {}; {}", self.indent_str(), ty, name, ann);
                        }
                        None => {
                            let _ = writeln!(out, "{}{}  {};", self.indent_str(), ty, name);
                        }
                    }
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
        let emittable_ids = Self::collect_emitted_block_ids(&nodes);
        self.label_targets = self.collect_label_targets(&nodes, func)
            .into_iter()
            .filter(|id| emittable_ids.contains(id))
            .collect();
        // Build a consistent label name map for goto/label references
        self.label_map.clear();
        let mut sorted_targets: Vec<BlockId> = self.label_targets.iter().copied().collect();
        sorted_targets.sort_by_key(|id| id.0);
        for (i, id) in sorted_targets.iter().enumerate() {
            let name = if self.ida_style {
                format!("LABEL_{}", i + 1)
            } else {
                format!("{id}")
            };
            self.label_map.insert(*id, name);
        }
        self.emitted_labels.clear();
        let code = self.emit_structured(&nodes, func);
        let code = Self::fold_temp_return_lines(&code);
        let code = Self::fold_conditional_goto_fallthrough(&code);
        out.push_str(&code);

        let _ = writeln!(out, "}}");
        out
    }

    fn indent_str(&self) -> String {
        "    ".repeat(self.indent)
    }

    /// Get the label name for a BlockId (uses label_map if available).
    fn label_name(&self, id: BlockId) -> String {
        self.label_map.get(&id).cloned().unwrap_or_else(|| format!("{id}"))
    }

    /// Post-process: fold `tN = expr; ... return tN;` into `return expr;`.
    /// Scans the emitted code line-by-line, tracking the last assignment to
    /// each temp variable. When `return tN;` is found and there's a tracked
    /// assignment, the assignment line is removed and the return inlines the
    /// value. This handles the branch-relay pattern where the assignment and
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
        // last_temp: temp_name to stack of (output_line_index, rhs_expression)
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

    /// Fold `if (cond) goto A; else goto B;` when either `A:` or `B:` is the
    /// next emitted label (fallthrough arm). This keeps semantics while
    /// removing one redundant goto in each matched case.
    fn fold_conditional_goto_fallthrough(code: &str) -> String {
        let lines: Vec<&str> = code.lines().collect();
        let mut out: Vec<String> = Vec::with_capacity(lines.len());

        // Collect labels that map to a short tail ending in return.
        // This captures common relay blocks like:
        //   bb37:
        //     t0 = ...;
        //     return t0;
        let mut label_return_tail: HashMap<String, Vec<String>> = HashMap::new();
        for i in 0..lines.len() {
            let t = lines[i].trim();
            if !t.ends_with(':') {
                continue;
            }
            let label = t.trim_end_matches(':').trim().to_string();
            let mut j = i + 1;
            let mut body: Vec<String> = Vec::new();
            while j < lines.len() {
                let s = lines[j].trim();
                if s.is_empty() {
                    j += 1;
                    continue;
                }
                if s.ends_with(':') {
                    break;
                }
                body.push(s.to_string());
                j += 1;
            }
            if body.is_empty() || body.len() > 2 {
                continue;
            }
            if body.iter().any(|s| s.contains("goto ")) {
                continue;
            }
            let Some(last) = body.last() else { continue; };
            if last.starts_with("return ") || last == "return;" {
                label_return_tail.insert(label, body);
            }
        }

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let indent = &line[..line.len() - trimmed.len()];

            if let Some(rest) = trimmed.strip_prefix("if (")
                && let Some(mid) = rest.find("; else goto ")
                && let Some(rhs) = rest[mid + "; else goto ".len()..].strip_suffix(';')
            {
                let lhs = &rest[..mid]; // `cond) goto L1`
                if let Some(pos) = lhs.rfind(") goto ") {
                    let cond = &lhs[..pos];
                    let l1 = lhs[pos + ") goto ".len()..].trim();
                    let l2 = rhs.trim();

                    let mut next_label: Option<&str> = None;
                    for next in lines.iter().skip(i + 1) {
                        let t = next.trim();
                        if t.is_empty() {
                            continue;
                        }
                        if t.ends_with(':') {
                            next_label = Some(t.trim_end_matches(':').trim());
                        }
                        break;
                    }

                    if next_label == Some(l1) {
                        out.push(format!("{indent}if (!({cond})) goto {l2};"));
                        continue;
                    }
                    if next_label == Some(l2) {
                        out.push(format!("{indent}if ({cond}) goto {l1};"));
                        continue;
                    }

                    // Inline a return-only destination to avoid one goto.
                    if let Some(ret_tail) = label_return_tail.get(l1) {
                        out.push(format!("{indent}if (!({cond})) goto {l2};"));
                        for stmt in ret_tail {
                            out.push(format!("{indent}{stmt}"));
                        }
                        continue;
                    }
                    if let Some(ret_tail) = label_return_tail.get(l2) {
                        out.push(format!("{indent}if ({cond}) goto {l1};"));
                        for stmt in ret_tail {
                            out.push(format!("{indent}{stmt}"));
                        }
                        continue;
                    }
                }
            }

            out.push((*line).to_string());
        }

        out.join("\n") + "\n"
    }

    /// Convert `init; while(cond) { body; step; }` into `for(init; cond; step) { body; }`.
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
            let (header, exit, condition, mut body) = if let StructuredNode::While { header, exit, condition, body } = nodes[i + 1].clone() {
                (header, exit, condition, body)
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
                exit,
                init_block: init_block_id,
                init: init_stmt,
                condition,
                step: step_stmt,
                body,
            };
            // Do not advance `i`; check the new node position for further patterns.
        }
    }

    /// Extract a step statement from the last body node if it matches `var = var +/-const`.
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
            // Pattern 1: `if (A) { if (B) { body } }` becomes `if (A && B) { body }`.
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
            //          becomes `if (A && B) { then } else { else }`.
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
            Expr::LogicalAnd(lhs, rhs) | Expr::LogicalOr(lhs, rhs) => {
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

    fn record_stack_slot(slots: &mut BTreeMap<i64, BitWidth>, off: i64, width: BitWidth) {
        match slots.get_mut(&off) {
            Some(existing) if width > *existing => *existing = width,
            Some(_) => {}
            None => {
                slots.insert(off, width);
            }
        }
    }

    fn collect_stack_slots(func: &Function, dead_temps: &HashSet<u32>) -> BTreeMap<i64, BitWidth> {
        let mut slots = BTreeMap::new();
        for block in &func.blocks {
            for stmt in &block.stmts {
                Self::collect_stack_slots_from_stmt(stmt, dead_temps, &mut slots);
            }
            Self::collect_stack_slots_from_term(&block.terminator, &mut slots);
        }
        slots
    }

    fn collect_stack_slots_from_stmt(
        stmt: &Stmt,
        dead_temps: &HashSet<u32>,
        slots: &mut BTreeMap<i64, BitWidth>,
    ) {
        match stmt {
            Stmt::Assign(var, expr) => {
                if let Var::Temp(id, _) = var
                    && dead_temps.contains(id) {
                        return;
                    }
                Self::collect_stack_slots_from_var(var, slots);
                Self::collect_stack_slots_from_expr(expr, slots);
            }
            Stmt::Store(addr, val, width) => {
                if let Some((off, _)) = Self::extract_stack_addr_base(addr) {
                    Self::record_stack_slot(slots, off, *width);
                }
                Self::collect_stack_slots_from_expr(addr, slots);
                Self::collect_stack_slots_from_expr(val, slots);
            }
            Stmt::Call(ret, target, args) => {
                if let Some(var) = ret {
                    if !matches!(var, Var::Temp(id, _) if dead_temps.contains(id)) {
                        Self::collect_stack_slots_from_var(var, slots);
                    }
                }
                Self::collect_stack_slots_from_expr(target, slots);
                for arg in args {
                    Self::collect_stack_slots_from_expr(arg, slots);
                }
            }
            Stmt::Nop => {}
        }
    }

    fn collect_stack_slots_from_term(term: &Terminator, slots: &mut BTreeMap<i64, BitWidth>) {
        match term {
            Terminator::Branch(cond, _, _) => Self::collect_stack_slots_from_expr(cond, slots),
            Terminator::Return(Some(val)) => Self::collect_stack_slots_from_expr(val, slots),
            Terminator::IndirectJump(target) => Self::collect_stack_slots_from_expr(target, slots),
            Terminator::Switch(val, _, _) => Self::collect_stack_slots_from_expr(val, slots),
            _ => {}
        }
    }

    fn collect_stack_slots_from_var(var: &Var, slots: &mut BTreeMap<i64, BitWidth>) {
        if let Var::Stack(off, width) = var {
            Self::record_stack_slot(slots, *off, *width);
        }
    }

    fn collect_stack_slots_from_expr(expr: &Expr, slots: &mut BTreeMap<i64, BitWidth>) {
        if let Some((off, _)) = Self::extract_stack_addr_base(expr) {
            Self::record_stack_slot(slots, off, BitWidth::Bit8);
        }

        match expr {
            Expr::Var(var) => Self::collect_stack_slots_from_var(var, slots),
            Expr::Load(addr, width) => {
                if let Some((off, _)) = Self::extract_stack_addr_base(addr) {
                    Self::record_stack_slot(slots, off, *width);
                }
                Self::collect_stack_slots_from_expr(addr, slots);
            }
            Expr::BinOp(_, lhs, rhs)
            | Expr::Cmp(_, lhs, rhs)
            | Expr::LogicalAnd(lhs, rhs)
            | Expr::LogicalOr(lhs, rhs) => {
                Self::collect_stack_slots_from_expr(lhs, slots);
                Self::collect_stack_slots_from_expr(rhs, slots);
            }
            Expr::UnaryOp(_, inner) => Self::collect_stack_slots_from_expr(inner, slots),
            Expr::Select(cond, then_expr, else_expr) => {
                Self::collect_stack_slots_from_expr(cond, slots);
                Self::collect_stack_slots_from_expr(then_expr, slots);
                Self::collect_stack_slots_from_expr(else_expr, slots);
            }
            Expr::Intrinsic(_, args) => {
                for a in args { Self::collect_stack_slots_from_expr(a, slots); }
            }
            Expr::Const(..) | Expr::Cond(_) => {}
        }
    }

    /// Improve variable names based on usage patterns.
    /// Detects:
    /// - Loop induction variables (init to 0/small, incremented by 1) become i, j, k
    /// - Accumulators (updated via += in loops) become sum, total, acc
    fn improve_var_names(&mut self, func: &Function) {
        let mut induction_candidates: Vec<i64> = Vec::new();
        let mut accumulator_candidates: Vec<i64> = Vec::new();
        let mut used_names: HashSet<String> = self.var_names.values().cloned().collect();

        for block in &func.blocks {
            for stmt in &block.stmts {
                // Detect `var = var + 1` (or `var = var - 1`) as an increment pattern.
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

        // Rename induction variables to i, j, k, ...
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

        // Rename accumulators to sum, total, acc, ...
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
        let mut seen: HashSet<String> = HashSet::new();
        // Stack variables: sorted by actual offset
        let mut stack_locals: Vec<(i64, String, String, BitWidth, Option<u64>)> = Vec::new();
        for (off, width) in Self::collect_stack_slots(func, &self.dead_temps) {
            let name = self.stack_name(off);
            if seen.insert(name.clone()) {
                let type_key = stack_type_key(off);
                let buf_size = self.buffer_sizes.get(&off).copied();
                stack_locals.push((off, name, type_key, width, buf_size));
            }
        }
        stack_locals.sort_by_key(|(off, _, _, _, _)| *off);

        // Merge overlapping stack slots into buffer declarations.
        // When a slot's byte range overlaps with a preceding slot, the preceding
        // slot is expanded into a buffer covering the whole region. Sub-offset
        // slots are suppressed from declarations (the body may still reference
        // them as pseudocode aliases).
        let mut merged_ends: Vec<(usize, i64)> = Vec::new(); // (group_start_idx, end_offset)
        {
            let mut i = 0;
            while i < stack_locals.len() {
                let (base_off, _, _, base_w, base_buf) = &stack_locals[i];
                let base_bytes = base_buf.unwrap_or(base_w.bytes() as u64) as i64;
                let mut end = *base_off + base_bytes;
                let mut j = i + 1;
                while j < stack_locals.len() {
                    let (next_off, _, _, next_w, next_buf) = &stack_locals[j];
                    if *next_off < end {
                        let next_bytes = next_buf.unwrap_or(next_w.bytes() as u64) as i64;
                        let next_end = *next_off + next_bytes;
                        if next_end > end {
                            end = next_end;
                        }
                        j += 1;
                    } else {
                        break;
                    }
                }
                if j > i + 1 {
                    // This group has overlapping entries; record merge info
                    merged_ends.push((i, end));
                }
                i = j;
            }
            // Apply merges: set buffer_size on base, mark sub-entries for removal
            let mut suppress: HashSet<usize> = HashSet::new();
            for (group_start, end) in &merged_ends {
                let base_off = stack_locals[*group_start].0;
                let total_size = (*end - base_off) as u64;
                stack_locals[*group_start].4 = Some(total_size);
                for k in (*group_start + 1)..stack_locals.len() {
                    if stack_locals[k].0 < *end {
                        suppress.insert(k);
                    } else {
                        break;
                    }
                }
            }
            if !suppress.is_empty() {
                let mut idx = 0;
                stack_locals.retain(|_| {
                    let keep = !suppress.contains(&idx);
                    idx += 1;
                    keep
                });
            }
        }
        // Register-promoted variables
        let mut reg_locals: Vec<(String, String, BitWidth)> = Vec::new();
        for (reg, name) in &self.reg_var_names {
            if seen.insert(name.clone()) {
                let type_key = format!("{reg}");
                let width = if reg.is_xmm() { BitWidth::Bit128 } else { BitWidth::Bit64 };
                reg_locals.push((name.clone(), type_key, width));
            }
        }
        reg_locals.sort_by(|a, b| a.0.cmp(&b.0));

        // Temp variables
        let mut temp_locals: Vec<(u32, String, BitWidth)> = Vec::new();
        for block in &func.blocks {
            for stmt in &block.stmts {
                let var = match stmt {
                    Stmt::Assign(v, _) => Some(v),
                    Stmt::Call(Some(v), _, _) => Some(v),
                    _ => None,
                };
                if let Some(Var::Temp(id, w)) = var {
                    let key = format!("t{id}");
                    if !self.dead_temps.contains(id)
                        && !self.call_results.contains_key(&key)
                        && seen.insert(key.clone())
                    {
                        temp_locals.push((*id, key, *w));
                    }
                }
            }
        }
        temp_locals.sort_by_key(|(id, _, _)| *id);

        // Assemble: stack vars (by offset) → temp vars (by id) → reg vars (by name)
        let mut result: Vec<(String, String, BitWidth, Option<u64>)> = Vec::new();
        for (_, name, tk, w, buf) in stack_locals {
            result.push((name, tk, w, buf));
        }
        for (id, key, w) in temp_locals {
            let _ = id;
            result.push((key.clone(), key, w, None));
        }
        for (name, tk, w) in reg_locals {
            result.push((name, tk, w, None));
        }
        result
    }

    fn assign_remaining_reg_names(&mut self, func: &Function) {
        let param_regs = func.calling_conv.param_regs();
        let mut seen: HashSet<RegId> = HashSet::new();
        let mut used_names: HashSet<String> = self.var_names.values().cloned().collect();
        used_names.extend(self.reg_params.values().cloned());

        let mut next_arg_idx = self.reg_params.values()
            .filter_map(|name| name.strip_prefix("arg_").and_then(|n| n.parse::<usize>().ok()))
            .max()
            .unwrap_or(0)
            + 1;
        // Offset-based stack vars use hex names (var_8, var_1c, ...); register-promoted
        // vars use decimal names (var_100, var_101, ...) starting above 255 to avoid
        // collisions with any hex offset.
        let mut next_var_idx = 256.max(
            used_names.iter()
                .filter_map(|name| name.strip_prefix("var_").and_then(|n| n.parse::<usize>().ok()))
                .max()
                .unwrap_or(0)
                + 1
        );

        for reg in self.collect_remaining_regs(func) {
            if !seen.insert(reg) {
                continue;
            }

            if self.reg_params.contains_key(&reg) || self.reg_var_names.contains_key(&reg) {
                continue;
            }

            if param_regs.contains(&reg) && !self.reg_is_defined(func, reg) {
                let name = format!("arg_{next_arg_idx}");
                next_arg_idx += 1;
                used_names.insert(name.clone());
                self.reg_params.insert(reg, name);
                continue;
            }

            loop {
                let name = format!("var_{next_var_idx}");
                next_var_idx += 1;
                if used_names.insert(name.clone()) {
                    self.reg_var_names.insert(reg, name);
                    break;
                }
            }
        }
    }

    fn collect_remaining_regs(&self, func: &Function) -> Vec<RegId> {
        let mut regs = Vec::new();
        let mut seen = HashSet::new();

        for block_idx in Self::block_indices_by_addr(func) {
            let block = &func.blocks[block_idx];
            for stmt in &block.stmts {
                Self::collect_regs_from_stmt(stmt, &mut regs, &mut seen);
            }
            Self::collect_regs_from_terminator(&block.terminator, &mut regs, &mut seen);
        }

        regs.into_iter()
            .filter(|reg| !matches!(reg, RegId::Rsp | RegId::Rbp | RegId::Rip))
            .collect()
    }

    fn collect_regs_from_stmt(stmt: &Stmt, out: &mut Vec<RegId>, seen: &mut HashSet<RegId>) {
        match stmt {
            Stmt::Assign(var, expr) => {
                Self::collect_regs_from_var(var, out, seen);
                Self::collect_regs_from_expr(expr, out, seen);
            }
            Stmt::Store(addr, val, _) => {
                Self::collect_regs_from_expr(addr, out, seen);
                Self::collect_regs_from_expr(val, out, seen);
            }
            Stmt::Call(ret, target, args) => {
                if let Some(var) = ret {
                    Self::collect_regs_from_var(var, out, seen);
                }
                Self::collect_regs_from_expr(target, out, seen);
                for arg in args {
                    Self::collect_regs_from_expr(arg, out, seen);
                }
            }
            Stmt::Nop => {}
        }
    }

    fn collect_regs_from_terminator(term: &Terminator, out: &mut Vec<RegId>, seen: &mut HashSet<RegId>) {
        match term {
            Terminator::Branch(cond, _, _) => Self::collect_regs_from_expr(cond, out, seen),
            Terminator::Return(Some(val)) => Self::collect_regs_from_expr(val, out, seen),
            Terminator::IndirectJump(target) => Self::collect_regs_from_expr(target, out, seen),
            Terminator::Switch(val, _, _) => Self::collect_regs_from_expr(val, out, seen),
            _ => {}
        }
    }

    fn collect_regs_from_var(var: &Var, out: &mut Vec<RegId>, seen: &mut HashSet<RegId>) {
        if let Var::Reg(reg, _) = var
            && seen.insert(*reg) {
                out.push(*reg);
            }
    }

    fn collect_regs_from_expr(expr: &Expr, out: &mut Vec<RegId>, seen: &mut HashSet<RegId>) {
        match expr {
            Expr::Var(var) => Self::collect_regs_from_var(var, out, seen),
            Expr::BinOp(_, lhs, rhs)
            | Expr::Cmp(_, lhs, rhs)
            | Expr::LogicalAnd(lhs, rhs)
            | Expr::LogicalOr(lhs, rhs) => {
                Self::collect_regs_from_expr(lhs, out, seen);
                Self::collect_regs_from_expr(rhs, out, seen);
            }
            Expr::UnaryOp(_, inner) | Expr::Load(inner, _) => {
                Self::collect_regs_from_expr(inner, out, seen);
            }
            Expr::Select(cond, then_expr, else_expr) => {
                Self::collect_regs_from_expr(cond, out, seen);
                Self::collect_regs_from_expr(then_expr, out, seen);
                Self::collect_regs_from_expr(else_expr, out, seen);
            }
            Expr::Intrinsic(_, args) => {
                for a in args { Self::collect_regs_from_expr(a, out, seen); }
            }
            Expr::Const(..) | Expr::Cond(_) => {}
        }
    }

    fn reg_is_defined(&self, func: &Function, reg: RegId) -> bool {
        func.blocks.iter().any(|block| {
            block.stmts.iter().any(|stmt| match stmt {
                Stmt::Assign(Var::Reg(r, _), _) if *r == reg => true,
                Stmt::Call(Some(Var::Reg(r, _)), _, _) if *r == reg => true,
                _ => false,
            })
        })
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
        for block_idx in Self::block_indices_by_addr(func) {
            let block = &func.blocks[block_idx];
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

    fn stack_location_comment(type_key: &str, has_frame_pointer: bool, frame_size: u64) -> Option<String> {
        let off = stack_offset_from_type_key(type_key)?;
        if has_frame_pointer {
            if off >= 0 {
                Some(format!("// [rbp+0x{:x}]", off))
            } else {
                Some(format!("// [rbp-0x{:x}]", off.unsigned_abs()))
            }
        } else {
            // Convert normalized offset back to RSP-relative displacement.
            let rsp_disp = off + frame_size as i64;
            if rsp_disp >= 0 {
                Some(format!("// [rsp+0x{:x}]", rsp_disp))
            } else {
                Some(format!("// [rsp-0x{:x}]", rsp_disp.unsigned_abs()))
            }
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
        BitWidth::Bit128 => "__m128i",
    }
}

/// Map a C99 type string to IDA Hex-Rays style type name.
fn ida_type(c99: &str) -> String {
    match c99 {
        "uint8_t" => "_BYTE".into(),
        "uint16_t" => "_WORD".into(),
        "uint32_t" => "_DWORD".into(),
        "uint64_t" => "_QWORD".into(),
        "int8_t" => "__int8".into(),
        "int16_t" => "__int16".into(),
        "int32_t" => "__int32".into(),
        "int64_t" => "__int64".into(),
        "void" => "void".into(),
        "void*" => "void*".into(),
        "char" => "char".into(),
        "bool" => "_BOOL".into(),
        "float" => "float".into(),
        "double" => "double".into(),
        "__m128i" => "__m128i".into(),
        other => other.into(),
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

fn stack_offset_from_type_key(key: &str) -> Option<i64> {
    if let Some(hex) = key.strip_prefix("arg_") {
        let v = i64::from_str_radix(hex, 16).ok()?;
        return Some(v);
    }
    if let Some(hex) = key.strip_prefix("var_") {
        let v = i64::from_str_radix(hex, 16).ok()?;
        return Some(-v);
    }
    None
}

fn signed_const(val: u64, width: BitWidth) -> i64 {
    match width {
        BitWidth::Bit8 => val as i8 as i64,
        BitWidth::Bit16 => val as i16 as i64,
        BitWidth::Bit32 => val as i32 as i64,
        BitWidth::Bit64 | BitWidth::Bit128 => val as i64,
    }
}

/// Negate a condition expression.
fn negate_condition(cond: &Expr) -> Expr {
    match cond {
        Expr::Cmp(cc, lhs, rhs) => Expr::Cmp(cc.negate(), lhs.clone(), rhs.clone()),
        Expr::Cond(cc) => Expr::Cond(cc.negate()),
        // De Morgan: `!(A && B)` becomes `(!A || !B)`.
        Expr::LogicalAnd(lhs, rhs) => Expr::LogicalOr(
            Box::new(negate_condition(lhs)),
            Box::new(negate_condition(rhs)),
        ),
        // De Morgan: `!(A || B)` becomes `(!A && !B)`.
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
pub(crate) enum StructuredNode {
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
        exit: Option<BlockId>,
        condition: Expr,
        body: Vec<StructuredNode>,
    },
    DoWhile {
        header: BlockId,
        exit: Option<BlockId>,
        condition: Expr,
        body: Vec<StructuredNode>,
    },
    For {
        header: BlockId,
        exit: Option<BlockId>,
        /// Block ID of the pre-loop init block (emit all stmts except `init`).
        init_block: BlockId,
        init: Stmt,
        condition: Expr,
        step: Stmt,
        body: Vec<StructuredNode>,
    },
    Break,
}


