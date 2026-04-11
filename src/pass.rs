//! Analysis pass framework.
//!
//! Provides a `Pass` trait and `PassManager` that replaces the hard-coded
//! pass ordering in `analysis::optimize`.  Each pass is self-describing
//! (name, phase, iterability) so the manager can orchestrate execution
//! and the CLI can selectively disable or dump after individual passes.

use crate::ir::Function;
use std::collections::HashSet;
use std::fmt::Write;

// ── Pass trait ───────────────────────────────────────────────────

/// Which phase of the pipeline a pass belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassPhase {
    /// Runs once before the fixpoint loop.
    Early,
    /// Participates in the iterative fixpoint loop.
    Iterative,
    /// Runs repeatedly (its own mini-loop, not the main fixpoint).
    Repeated,
    /// Runs once after the fixpoint loop.
    Late,
}

/// A single analysis/transformation pass.
pub trait Pass {
    /// Human-readable name (used by CLI `--disable-pass`, `--dump-after`).
    fn name(&self) -> &'static str;

    /// Which phase this pass runs in.
    fn phase(&self) -> PassPhase;

    /// Run the pass on `func`. Returns `true` if anything changed.
    fn run(&self, func: &mut Function, ctx: &PassContext) -> bool;
}

/// Shared context available to all passes.
pub struct PassContext {
    /// Addresses of known noreturn functions.
    pub noreturn_addrs: HashSet<u64>,
}

// ── PassManager ──────────────────────────────────────────────────

/// Orchestrates pass execution with support for disabling passes and
/// dumping IR after specific passes.
pub struct PassManager {
    passes: Vec<Box<dyn Pass>>,
    /// Pass names to skip.
    pub disabled: HashSet<String>,
    /// Pass names after which to dump IR.
    pub dump_after: HashSet<String>,
    /// Maximum fixpoint iterations.
    pub max_iterations: usize,
    /// Number of times to run Repeated-phase passes.
    pub repeat_count: usize,
}

impl PassManager {
    pub fn new() -> Self {
        Self {
            passes: Vec::new(),
            disabled: HashSet::new(),
            dump_after: HashSet::new(),
            max_iterations: 10,
            repeat_count: 5,
        }
    }

    /// Register a pass.
    pub fn add(&mut self, pass: Box<dyn Pass>) {
        self.passes.push(pass);
    }

    /// Run all passes on a function, respecting phases and disabled set.
    pub fn run_all(&self, func: &mut Function, ctx: &PassContext) {
        // Phase 1: Early passes (run once)
        for pass in self.passes.iter().filter(|p| p.phase() == PassPhase::Early) {
            if self.disabled.contains(pass.name()) {
                continue;
            }
            pass.run(func, ctx);
            self.maybe_dump(pass.name(), func);
        }

        // Phase 2: Iterative fixpoint
        let iterative: Vec<&dyn Pass> = self
            .passes
            .iter()
            .filter(|p| p.phase() == PassPhase::Iterative)
            .map(|p| p.as_ref())
            .collect();

        for _ in 0..self.max_iterations {
            let mut changed = false;
            for pass in &iterative {
                if self.disabled.contains(pass.name()) {
                    continue;
                }
                changed |= pass.run(func, ctx);
                self.maybe_dump(pass.name(), func);
            }
            if !changed {
                break;
            }
        }

        // Phase 3: Repeated passes (own loop)
        for pass in self.passes.iter().filter(|p| p.phase() == PassPhase::Repeated) {
            if self.disabled.contains(pass.name()) {
                continue;
            }
            for _ in 0..self.repeat_count {
                pass.run(func, ctx);
            }
            self.maybe_dump(pass.name(), func);
        }

        // Phase 4: Late passes (run once)
        for pass in self.passes.iter().filter(|p| p.phase() == PassPhase::Late) {
            if self.disabled.contains(pass.name()) {
                continue;
            }
            pass.run(func, ctx);
            self.maybe_dump(pass.name(), func);
        }
    }

    /// List all registered pass names and their phases.
    pub fn list_passes(&self) -> Vec<(&'static str, PassPhase)> {
        self.passes.iter().map(|p| (p.name(), p.phase())).collect()
    }

    fn maybe_dump(&self, name: &str, func: &Function) {
        if self.dump_after.contains(name) {
            let mut buf = String::new();
            let _ = writeln!(buf, "=== IR after pass '{}' ===", name);
            let _ = write!(buf, "{func}");
            eprintln!("{buf}");
        }
    }
}
