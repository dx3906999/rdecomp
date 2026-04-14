use std::fmt::Write;
use crate::ir::*;
use super::{CodeGenerator, StructuredNode, c_type, signed_const, escape_c_string};

impl<'a> CodeGenerator<'a> {

    // Code emission.

    pub(crate) fn block_has_noreturn(&self, block: &BasicBlock) -> bool {
        block.stmts.iter().any(|s| self.is_noreturn_call(s))
    }

    pub(crate) fn emit_structured(&mut self, nodes: &[StructuredNode], func: &Function) -> String {
        let mut out = String::new();

        for node in nodes {
            match node {
                StructuredNode::Block(id) => {
                    self.emit_label_if_needed(&mut out, *id);
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
                    self.emit_label_if_needed(&mut out, *id);
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
                StructuredNode::While { header, exit, condition, body, .. } => {
                    self.emit_label_if_needed(&mut out, *header);
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
                    self.loop_context.push((*header, *exit));
                    out.push_str(&self.emit_structured(body, func));
                    self.loop_context.pop();
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
                StructuredNode::DoWhile { header, exit, condition, body, .. } => {
                    self.emit_label_if_needed(&mut out, *header);
                    let header_has_stmts = func.block(*header)
                        .is_some_and(|b| b.stmts.iter().any(|s| !matches!(s, Stmt::Nop)));
                    if body.is_empty() && !header_has_stmts {
                        continue;
                    }
                    let _ = writeln!(out, "{}do {{", self.indent_str());
                    self.indent += 1;
                    self.loop_context.push((*header, *exit));
                    // Emit header statements as part of the loop body
                    if let Some(block) = func.block(*header) {
                        self.emit_stmts_only(&mut out, block);
                    }
                    out.push_str(&self.emit_structured(body, func));
                    self.loop_context.pop();
                    self.indent -= 1;
                    let cond_str = self.expr_to_c(condition);
                    let _ = writeln!(out, "{}}} while ({});", self.indent_str(), cond_str);
                }
                StructuredNode::For { header, exit, init_block, init, condition, step, body, .. } => {
                    self.emit_label_if_needed(&mut out, *init_block);
                    // Emit other stmts from the init block (e.g. sum = 0) excluding the for-init
                    if let Some(block) = func.block(*init_block) {
                        self.emit_stmts_skip(block, init, &mut out);
                    }
                    self.emit_label_if_needed(&mut out, *header);
                    // Emit header stmts (usually empty)
                    if let Some(block) = func.block(*header) {
                        self.emit_stmts_only(&mut out, block);
                    }
                    let init_str = self.stmt_to_c(init);
                    let cond_str = self.expr_to_c(condition);
                    let step_str = self.stmt_to_c(step);
                    let _ = writeln!(out, "{}for ({}; {}; {}) {{", self.indent_str(), init_str, cond_str, step_str);
                    self.indent += 1;
                    self.loop_context.push((*header, *exit));
                    // Emit body, skipping the step stmt from the last block
                    out.push_str(&self.emit_structured_for_body(body, func, step));
                    self.loop_context.pop();
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

    /// Emit for-loop body, skipping the step statement from the last Stmts/Block node.
    pub(crate) fn emit_structured_for_body(&mut self, nodes: &[StructuredNode], func: &Function, step: &Stmt) -> String {
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
    pub(crate) fn emit_stmts_skip(&self, block: &BasicBlock, skip_stmt: &Stmt, out: &mut String) {
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
    pub(crate) fn emit_block_full(&mut self, block: &BasicBlock, func: &Function) -> String {
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
                    // Bare `return rax` with no concrete value is emitted as `return;`.
                    Some(Expr::Var(Var::Reg(RegId::Rax, _))) => {
                        writeln!(out, "{}return;", self.indent_str())
                    }
                    Some(v) => writeln!(out, "{}return {};", self.indent_str(), self.expr_to_c(v)),
                    None => writeln!(out, "{}return;", self.indent_str()),
                };
            }
            Terminator::Jump(target) => {
                if let Some((loop_header, loop_exit)) = self.loop_context.last().copied() {
                    if *target == loop_header {
                        let _ = writeln!(out, "{}continue;", self.indent_str());
                        return out;
                    }
                    if loop_exit == Some(*target) {
                        let exit_node = self.loop_exit_node(func, *target);
                        match exit_node {
                            StructuredNode::Break => {
                                let _ = writeln!(out, "{}break;", self.indent_str());
                            }
                            StructuredNode::Block(exit_bid) => {
                                if let Some(exit_block) = func.block(exit_bid) {
                                    out.push_str(&self.emit_block_full(exit_block, func));
                                }
                            }
                            _ => {
                                let _ = writeln!(out, "{}break;", self.indent_str());
                            }
                        }
                        return out;
                    }
                }
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
                    let _ = writeln!(out, "{}goto {};", self.indent_str(), self.label_name(*target));
                }
            }
            Terminator::Branch(cond, t, f) => {
                let _ = writeln!(
                    out,
                    "{}if ({}) goto {}; else goto {};",
                    self.indent_str(),
                    self.expr_to_c(cond),
                    self.label_name(*t),
                    self.label_name(*f)
                );
            }
            Terminator::IndirectJump(target) => {
                let _ = writeln!(out, "{}goto *{};", self.indent_str(), self.expr_to_c(target));
            }
            Terminator::Switch(val, cases, default) => {
                let _ = writeln!(out, "{}switch ({}) {{", self.indent_str(), self.expr_to_c(val));
                self.indent += 1;
                for (case_val, target) in cases {
                    let _ = writeln!(out, "{}case {}: goto {};", self.indent_str(), case_val, self.label_name(*target));
                }
                if let Some(def) = default {
                    let _ = writeln!(out, "{}default: goto {};", self.indent_str(), self.label_name(*def));
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

    pub(crate) fn emit_stmts_only(&mut self, out: &mut String, block: &BasicBlock) {
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

    pub(crate) fn last_rax_assignment_expr(&self, block: &BasicBlock) -> Option<Expr> {
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
    /// predecessors, so we can resolve `return rax` into `return <expr>`.
    pub(crate) fn find_predecessor_rax(&self, block_id: BlockId, func: &Function) -> Option<Expr> {
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

    // Statement and expression rendering.

    pub(crate) fn is_noreturn_call(&self, stmt: &Stmt) -> bool {
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

    pub(crate) fn stmt_to_c(&self, stmt: &Stmt) -> String {
        match stmt {
            Stmt::Assign(var, expr) => {
                // Suppress register assignments UNLESS the register is a
                // detected parameter, so it is rendered as an arg_N update.
                if let Var::Reg(r, _) = var {
                    if !self.reg_params.contains_key(r)
                        && !self.reg_var_names.contains_key(r) {
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
                        // Arrays decay to pointers, so `&` is unnecessary.
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
                if let Some((offset, None)) = Self::extract_stack_addr_base(addr) {
                    return format!("{} = {}", self.stack_name(offset), self.expr_to_c(val));
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

    pub(crate) fn resolve_call_target(&self, target: &Expr) -> String {
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
    pub(crate) fn trim_call_args<'b>(&self, target: &Expr, args: &'b [Expr]) -> &'b [Expr] {
        if let Expr::Const(addr, _) = target {
            if let Some(summary) = self.func_summaries.get(addr) {
                if summary.param_count > 0 && summary.param_count < args.len() {
                    return &args[..summary.param_count];
                }
            }
        }
        args
    }

    pub(crate) fn expr_to_c(&self, expr: &Expr) -> String {
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
                // `rip + const` simplifies to just the constant address.
                if matches!(op, BinOp::Add)
                    && let Expr::Var(Var::Reg(RegId::Rip, _)) = lhs.as_ref() {
                        return self.expr_to_c(rhs);
                    }
                if matches!(op, BinOp::Add | BinOp::Sub)
                    && let Some((offset, dynamic)) = Self::extract_stack_addr_base(expr) {
                        let base = self.stack_addr_base_to_c(offset, dynamic.is_some());
                        return match dynamic {
                            Some(dyn_expr) => format!("({} + {})", base, self.expr_to_c(&dyn_expr)),
                            None => base,
                        };
                    }
                // rbp-relative expressions become `&var_N` or `(&var_N + dynamic)`.
                if matches!(op, BinOp::Add | BinOp::Sub)
                    && let Some((offset, dynamic)) = self.extract_rbp_base(expr) {
                        let base = if offset != 0 {
                            self.stack_addr_base_to_c(offset, dynamic.is_some())
                        } else {
                            "rbp".to_string()
                        };
                        return match dynamic {
                            Some(dyn_expr) => format!("({} + {})", base, self.expr_to_c(&dyn_expr)),
                            None => base,
                        };
                    }
                let is_shift = matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar | BinOp::Rol | BinOp::Ror);
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
                // Shift amounts must never be rendered as char literals.
                let rhs_str = if is_shift {
                    Self::const_to_numeric(rhs).unwrap_or_else(|| self.expr_to_c(rhs))
                } else {
                    self.expr_to_c(rhs)
                };
                format!("({} {} {})", self.expr_to_c(lhs), op_str, rhs_str)
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
                    // Arrays decay to pointers in C, so emit `var_XX` instead of `&var_XX`.
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
                // A direct constant address resolves to a global symbol when possible.
                if let Expr::Const(addr_val, _) = addr.as_ref()
                    && let Some(name) = self.binary.resolve_global_name(*addr_val) {
                        return name;
                    }
                // Struct field access: ptr->field_N
                if let Some(access) = self.try_struct_field(addr) {
                    return access;
                }
                if let Some((offset, dynamic)) = Self::extract_stack_addr_base(addr) {
                    if let Some(dyn_expr) = dynamic {
                        let base = self.stack_addr_base_to_c(offset, true);
                        return format!("*({}*)({} + {})", c_type(*width), base, self.expr_to_c(&dyn_expr));
                    }
                    return self.stack_name(offset);
                }
                // Stack loads like `*(type*)(rbp + offset)` resolve to `var_N` / `arg_N`.
                if let Some((offset, dynamic)) = self.extract_rbp_base(addr) {
                    if let Some(dyn_expr) = &dynamic {
                        // `rbp + const + dynamic` becomes `*(type*)(&var_N + dynamic)`.
                        let base = if offset != 0 {
                            format!("&{}", self.stack_name(offset))
                        } else {
                            "rbp".to_string()
                        };
                        let dyn_str = self.expr_to_c(dyn_expr);
                        return format!("*({}*)(({} + {}))", c_type(*width), base, dyn_str);
                    } else {
                        // Simple `rbp + const` resolves to a direct stack variable.
                        if offset != 0 {
                            return self.stack_name(offset);
                        }
                    }
                }
                format!("*({}*)({})", c_type(*width), self.expr_to_c(addr))
            }
            // A bare Cond can appear when the lifter lost track of which
            // operands set the flag (e.g. optimized code with flag reuse).
            // Emit a symbolic placeholder instead of a constant so branch
            // structure is preserved in generated pseudocode.
            Expr::Cond(cc) => {
                let cc_name = match cc {
                    CondCode::Eq       => "eq",
                    CondCode::Ne       => "ne",
                    CondCode::Lt | CondCode::Sign => "lt",
                    CondCode::Le       => "le",
                    CondCode::Gt | CondCode::NotSign => "gt",
                    CondCode::Ge       => "ge",
                    CondCode::Below    => "b",
                    CondCode::BelowEq  => "be",
                    CondCode::Above    => "a",
                    CondCode::AboveEq  => "ae",
                };
                format!("flag_{cc_name} /* unresolved condition */")
            }
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
    ///   Select(Cmp(Lt, -x, 0), x, -x) folds to abs(x)
    ///   Select(Cmp(Ge, -x, 0), -x, x) folds to abs(x)
    ///   Select(Cmp(Lt, x, 0), -x, x)  folds to abs(x)
    ///   Select(Cmp(Ge, x, 0), x, -x)  folds to abs(x)
    pub(crate) fn try_simplify_abs(&self, cond: &Expr, t: &Expr, f: &Expr) -> Option<String> {
        if let Expr::Cmp(cc, cmp_lhs, cmp_rhs) = cond {
            let is_zero = matches!(cmp_rhs.as_ref(), Expr::Const(0, _));
            if !is_zero { return None; }

            match cc {
                // Select(Cmp(Lt, -x, 0), x, -x) folds to abs(x)
                // Select(Cmp(Sign, -x, 0), x, -x) folds to abs(x)
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
                    // Select(Cmp(Lt, x, 0), -x, x) folds to abs(x)
                    if cmp_lhs.as_ref() == f {
                        if let Expr::UnaryOp(UnaryOp::Neg, t_inner) = t {
                            if t_inner.as_ref() == f {
                                return Some(format!("abs({})", self.expr_to_c(f)));
                            }
                        }
                    }
                }
                // Select(Cmp(Ge, -x, 0), -x, x) folds to abs(x)
                // Select(Cmp(NotSign, -x, 0), -x, x) folds to abs(x)
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
                    // Select(Cmp(Ge, x, 0), x, -x) folds to abs(x)
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
    pub(crate) fn var_stack_off_for_struct(&self, v: &Var) -> Option<i64> {
        if let Var::Stack(off, BitWidth::Bit64) = v {
            if self.struct_map.contains_key(off) {
                return Some(*off);
            }
        }
        None
    }

    /// Check if an expression is a stack pointer load that we have struct info for.
    /// Matches `Var::Stack(off, 64)` or `Load(rbp +/-const, 64)`.
    pub(crate) fn expr_struct_off(&self, expr: &Expr) -> Option<i64> {
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
    /// Patterns:
    ///   - `Var::Stack(off, 64)` becomes `var->field_0`
    ///   - `BinOp(Add, Var::Stack(off, 64), Const(F))` becomes `var->field_F`
    ///   - Same with `Load(rbp+off, 64)` instead of `Var::Stack`
    pub(crate) fn try_struct_field(&self, addr: &Expr) -> Option<String> {
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
    /// Returns `Some((stack_offset_as_i64, Option<dynamic_expr>))` if the tree
    /// contains `rbp` and additive constant(s).  The dynamic part is `None` when
    /// the expression is a plain `rbp +/-const`.
    pub(crate) fn extract_rbp_base(&self, expr: &Expr) -> Option<(i64, Option<Expr>)> {
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
    pub(crate) fn flatten_add(
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

    pub(crate) fn extract_stack_addr_base(expr: &Expr) -> Option<(i64, Option<Expr>)> {
        let mut base_offset: Option<i64> = None;
        let mut const_sum = 0i64;
        let mut dynamic_parts: Vec<Expr> = Vec::new();
        let mut valid = true;

        Self::flatten_stack_addr_base(
            expr,
            true,
            &mut base_offset,
            &mut const_sum,
            &mut dynamic_parts,
            &mut valid,
        );

        if !valid {
            return None;
        }

        let offset = base_offset?.wrapping_add(const_sum);
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

        Some((offset, dynamic))
    }

    pub(crate) fn flatten_stack_addr_base(
        expr: &Expr,
        positive: bool,
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
                Self::flatten_stack_addr_base(lhs, positive, base_offset, const_sum, dynamic_parts, valid);
                Self::flatten_stack_addr_base(rhs, positive, base_offset, const_sum, dynamic_parts, valid);
            }
            Expr::BinOp(BinOp::Sub, lhs, rhs) => {
                Self::flatten_stack_addr_base(lhs, positive, base_offset, const_sum, dynamic_parts, valid);
                Self::flatten_stack_addr_base(rhs, !positive, base_offset, const_sum, dynamic_parts, valid);
            }
            Expr::UnaryOp(UnaryOp::AddrOf, inner) => {
                if let Expr::Var(Var::Stack(off, _)) = inner.as_ref() {
                    if !positive {
                        *valid = false;
                        return;
                    }
                    match base_offset {
                        Some(existing) if *existing != *off => *valid = false,
                        Some(_) => {}
                        None => *base_offset = Some(*off),
                    }
                } else if positive {
                    dynamic_parts.push(expr.clone());
                } else {
                    *valid = false;
                }
            }
            Expr::Const(val, width) => {
                let signed = signed_const(*val, *width);
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

    /// Format a constant expression purely as a number, bypassing char-literal
    /// and string-pointer heuristics.  Returns `None` if `expr` is not a Const.
    pub(crate) fn const_to_numeric(expr: &Expr) -> Option<String> {
        if let Expr::Const(val, _) = expr {
            if *val > 9 {
                Some(format!("0x{val:x}"))
            } else {
                Some(format!("{val}"))
            }
        } else {
            None
        }
    }

    pub(crate) fn stack_addr_base_to_c(&self, off: i64, byte_pointer: bool) -> String {
        let name = self.stack_name(off);
        if byte_pointer {
            if self.buffer_sizes.contains_key(&off) {
                format!("((uint8_t*){})", name)
            } else {
                format!("((uint8_t*)&{})", name)
            }
        } else if self.buffer_sizes.contains_key(&off) {
            name
        } else {
            format!("&{}", name)
        }
    }

    /// Look up the friendly name for a stack offset, falling back to offset-based names.
    pub(crate) fn stack_name(&self, off: i64) -> String {
        if let Some(name) = self.var_names.get(&off) {
            return name.clone();
        }
        if self.stack_param_offsets.contains(&off) {
            format!("arg_{off:x}")
        } else {
            format!("var_{:x}", off.unsigned_abs())
        }
    }

    pub(crate) fn var_to_c(&self, var: &Var) -> String {
        match var {
            Var::Reg(reg, _) => {
                // Use parameter name if this is a detected register parameter
                if let Some(name) = self.reg_params.get(reg) {
                    return name.clone();
                }
                if let Some(name) = self.reg_var_names.get(reg) {
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


