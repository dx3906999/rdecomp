use clap::Parser;
use rdecomp::analysis;
use rdecomp::arch::{ArchDisasm, ArchLifter};
use rdecomp::arch::x86::{X86Disasm, X86Lifter};
use rdecomp::cfg::Cfg;
use rdecomp::codegen::CodeGenerator;
use rdecomp::ir::{CallingConv, Function, Stmt, Terminator};
use rdecomp::loader::Binary;
use rdecomp::project::{AnalyzedFunction, ProjectDb, hash_bytes};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rdecomp", version, about = "High-performance x86/x64 decompiler")]
struct Cli {
    /// Path to the binary file to decompile.
    binary: Option<PathBuf>,

    /// Decompile a specific function by name.
    #[arg(short, long)]
    function: Option<String>,

    /// Decompile a function at a specific address (hex, e.g. 0x401000).
    #[arg(short, long, value_parser = parse_hex)]
    address: Option<u64>,

    /// List all detected functions and exit.
    #[arg(short, long)]
    list_functions: bool,

    /// Show disassembly instead of decompiled output.
    #[arg(short = 'D', long)]
    disasm: bool,

    /// Show IR instead of decompiled output.
    #[arg(long)]
    ir: bool,

    /// Disable optimization passes.
    #[arg(long)]
    no_opt: bool,

    /// Maximum bytes to disassemble per function (default: 65536).
    #[arg(long, default_value_t = 65536)]
    max_size: u64,

    /// Use/create a project file (.rdb) to cache analysis results.
    /// The project file is stored next to the binary with a .rdb extension
    /// unless an explicit path is given.
    #[arg(short, long)]
    project: bool,

    /// Disable specific analysis passes (comma-separated).
    /// Use --list-passes to see available pass names.
    #[arg(long, value_delimiter = ',')]
    disable_pass: Vec<String>,

    /// Dump IR to stderr after specific passes (comma-separated).
    #[arg(long, value_delimiter = ',')]
    dump_after: Vec<String>,

    /// List all analysis passes and exit.
    #[arg(long)]
    list_passes: bool,
}

fn parse_hex(s: &str) -> Result<u64, String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| format!("invalid hex address: {e}"))
}

fn is_runtime_scaffold_name(name: &str) -> bool {
    matches!(
        name,
        "_init"
            | "_start"
            | "_fini"
            | "__do_global_dtors_aux"
            | "register_tm_clones"
            | "deregister_tm_clones"
            | "frame_dummy"
    )
}

fn is_trivial_thunk(func: &Function) -> bool {
    func.blocks.len() == 1
        && func.blocks[0].stmts.iter().all(|stmt| matches!(stmt, Stmt::Nop))
        && matches!(func.blocks[0].terminator, Terminator::IndirectJump(_) | Terminator::Unreachable)
}

fn should_skip_function_output(name: &str, addr: u64, func: Option<&Function>, binary: &Binary) -> bool {
    if binary.plt_map.contains_key(&addr) || is_runtime_scaffold_name(name) {
        return true;
    }
    func.is_some_and(is_trivial_thunk)
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    // Handle --list-passes early (no binary needed)
    if cli.list_passes {
        let pm = rdecomp::analysis::default_pass_manager();
        println!("Available analysis passes:");
        for (name, phase) in pm.list_passes() {
            let phase_str = match phase {
                rdecomp::pass::PassPhase::Early => "early",
                rdecomp::pass::PassPhase::Iterative => "iterative",
                rdecomp::pass::PassPhase::Repeated => "repeated",
                rdecomp::pass::PassPhase::Late => "late",
            };
            println!("  {:<36} [{}]", name, phase_str);
        }
        return;
    }

    let binary_path = match &cli.binary {
        Some(p) => p.clone(),
        None => {
            eprintln!("Error: no binary file specified. Use: rdecomp <BINARY>");
            std::process::exit(1);
        }
    };

    let mut binary = match Binary::from_path(&binary_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error loading binary: {e}");
            std::process::exit(1);
        }
    };

    // Discover internal functions by scanning for call targets
    binary.discover_functions();

    println!("Loaded: {:?} binary, entry=0x{:x}", binary.arch, binary.entry_point);
    println!(
        "Sections: {}",
        binary
            .sections
            .iter()
            .map(|s| format!("{}(0x{:x}{})", s.name, s.vaddr, if s.executable { " X" } else { "" }))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("Functions detected: {}", binary.functions.len());

    // --- Project file handling ---
    let rdb_path = binary_path.with_extension("rdb");
    let mut project: Option<ProjectDb> = if cli.project {
        if rdb_path.exists() {
            match ProjectDb::open(&rdb_path) {
                Ok(p) => {
                    eprintln!("Project loaded: {} ({} cached functions)",
                        rdb_path.display(), p.cached_count());
                    Some(p)
                }
                Err(e) => {
                    eprintln!("Warning: could not open project file, creating new: {e}");
                    Some(ProjectDb::create(
                        &rdb_path,
                        &binary_path.to_string_lossy(),
                        &binary,
                    ))
                }
            }
        } else {
            eprintln!("Creating project: {}", rdb_path.display());
            Some(ProjectDb::create(
                &rdb_path,
                &binary_path.to_string_lossy(),
                &binary,
            ))
        }
    } else {
        None
    };

    if cli.list_functions {
        println!("\nFunctions:");
        for func in &binary.functions {
            println!(
                "  0x{:08x}  {:>6}  {}",
                func.addr,
                if func.size > 0 {
                    format!("{}B", func.size)
                } else {
                    "?".to_string()
                },
                func.name
            );
        }
        return;
    }

    // Determine which functions to decompile
    let targets: Vec<(String, u64, u64)> = if let Some(ref name) = cli.function {
        binary
            .functions
            .iter()
            .filter(|f| f.name == *name)
            .map(|f| (f.name.clone(), f.addr, f.size))
            .collect()
    } else if let Some(addr) = cli.address {
        let name = binary
            .functions
            .iter()
            .find(|f| f.addr == addr)
            .map(|f| f.name.clone())
            .unwrap_or_else(|| format!("sub_{addr:x}"));
        vec![(name, addr, 0)]
    } else if !binary.functions.is_empty() {
        binary
            .functions
            .iter()
            .filter(|f| f.size > 0 || f.addr != 0)
            .map(|f| (f.name.clone(), f.addr, f.size))
            .collect()
    } else {
        vec![(
            "entry".to_string(),
            binary.entry_point,
            cli.max_size,
        )]
    };

    if targets.is_empty() {
        eprintln!("No functions found to decompile.");
        std::process::exit(1);
    }

    let disasm: Box<dyn ArchDisasm> = Box::new(X86Disasm);
    let mut lifter: Box<dyn ArchLifter> = Box::new(X86Lifter::new(binary.arch));
    match (binary.arch, binary.format) {
        (rdecomp::loader::Arch::X86, _) => lifter.set_calling_conv(CallingConv::Cdecl),
        (_, rdecomp::loader::BinaryFormat::Pe) => lifter.set_calling_conv(CallingConv::Win64),
        _ => {}
    }
    let mut codegen = CodeGenerator::new(&binary.functions, &binary);

    let noreturn_addrs: HashSet<u64> = binary
        .plt_map
        .iter()
        .filter(|(_, name)| rdecomp::ir::is_noreturn_name(name))
        .map(|(addr, _)| *addr)
        .collect();

    // ── Interprocedural pre-pass ───────────────────────────────
    // Lift and optimize all target functions first, then run cross-function
    // analysis before codegen.  Functions are stored as (addr, cfg, func).
    let mut lifted: Vec<(String, u64, Cfg, Function, Option<u64>)> = Vec::new();
    let mut cached_outputs: HashMap<u64, String> = HashMap::new();

    for (name, addr, size) in &targets {
        let func_size = if *size > 0 {
            *size
        } else {
            binary
                .functions
                .iter()
                .map(|f| f.addr)
                .filter(|&a| a > *addr)
                .min()
                .map(|next| next - addr)
                .unwrap_or(cli.max_size)
        };

        let func_size_usize = usize::try_from(func_size).unwrap_or(cli.max_size as usize);
        let bytes_hash = binary.read_bytes(*addr, func_size_usize).map(hash_bytes);

        // Try cache hit (only for normal C output mode)
        if !cli.ir && !cli.disasm && !cli.no_opt
            && let Some(ref proj) = project
                && let Some(hash) = bytes_hash
                    && let Some(cached) = proj.get(*addr, hash) {
                        cached_outputs.insert(*addr, cached.c_code.clone());
                        continue;
                    }

        // Disassemble
        let instructions = match disasm.disassemble_function(&binary, *addr, func_size) {
            Ok(insns) => insns,
            Err(e) => {
                eprintln!("  Disassembly failed for {} @ 0x{:x}: {e}", name, addr);
                continue;
            }
        };
        if instructions.is_empty() {
            continue;
        }

        if cli.disasm {
            // Disassembly-only mode: print and skip
            println!("\n{}", "=".repeat(60));
            println!("// {} @ 0x{:x}", name, addr);
            println!("{}", "=".repeat(60));
            for insn in &instructions {
                println!("  0x{:08x}:  {}", insn.addr, insn.text);
            }
            continue;
        }

        let cfg = Cfg::build(&instructions);
        let func = lifter.lift_function(name, *addr, &cfg, &binary);

        lifted.push((name.clone(), *addr, cfg, func, bytes_hash));
    }

    if cli.disasm {
        // Already printed disassembly above
        return;
    }

    // ── Pre-pass: detect parameter counts for all lifted functions ──
    // Skip PLT stubs (single block with only an indirect jump) since their
    // body doesn't reveal parameter usage.
    let callee_param_counts: HashMap<u64, usize> = lifted
        .iter()
        .filter(|(_, _, _, func, _)| {
            // A PLT stub has 1 block, no statements (or only Nop), and an IndirectJump terminator
            let is_plt = func.blocks.len() == 1
                && func.blocks[0].stmts.iter().all(|s| matches!(s, rdecomp::ir::Stmt::Nop))
                && matches!(func.blocks[0].terminator, rdecomp::ir::Terminator::IndirectJump(_));
            !is_plt
        })
        .map(|(_, addr, _, func, _)| (*addr, analysis::detect_param_count(func)))
        .collect();

    // ── Optimization pass ──────────────────────────────────────
    for (_, _, _, func, _) in &mut lifted {
        if !cli.no_opt {
            if cli.disable_pass.is_empty() && cli.dump_after.is_empty() {
                analysis::optimize(func, &noreturn_addrs, &callee_param_counts);
            } else {
                let mut pm = analysis::default_pass_manager();
                for name in &cli.disable_pass {
                    pm.disabled.insert(name.clone());
                }
                for name in &cli.dump_after {
                    pm.dump_after.insert(name.clone());
                }
                analysis::optimize_with(func, &pm, &noreturn_addrs, &callee_param_counts);
            }
        }
    }

    // Run interprocedural analysis on all lifted functions
    {
        let func_refs: Vec<(u64, &Function)> = lifted.iter()
            .map(|(_, addr, _, func, _)| (*addr, func))
            .collect();
        if func_refs.len() > 1 {
            let ipa = rdecomp::interprocedural::analyze(&func_refs, &binary);
            codegen.set_interprocedural(&ipa);
        }
    }

    // ── Output pass ────────────────────────────────────────────
    let mut cache_hits = 0u32;
    let mut cache_misses = 0u32;
    let print_all_mode = cli.function.is_none() && cli.address.is_none();

    // Print cached outputs first, in target order
    for (name, addr, _size) in &targets {
        if print_all_mode && should_skip_function_output(name, *addr, None, &binary) {
            continue;
        }
        if let Some(cached_code) = cached_outputs.get(addr) {
            println!("\n{}", "=".repeat(60));
            println!("// {} @ 0x{:x}", name, addr);
            println!("{}", "=".repeat(60));
            println!("{}", cached_code);
            cache_hits += 1;
        }
    }

    // Print newly decompiled functions
    for (name, addr, cfg, func, bytes_hash) in &lifted {
        if print_all_mode && should_skip_function_output(name, *addr, Some(func), &binary) {
            continue;
        }
        println!("\n{}", "=".repeat(60));
        println!("// {} @ 0x{:x}", name, addr);
        println!("{}", "=".repeat(60));

        if cli.ir {
            println!("{func}");
            continue;
        }

        let code = codegen.generate(func, cfg);
        println!("{code}");

        // Cache the result
        if !cli.no_opt
            && let Some(ref mut proj) = project
                && let Some(hash) = bytes_hash {
                    proj.insert(*addr, AnalyzedFunction {
                        ir: func.clone(),
                        c_code: code,
                        bytes_hash: *hash,
                    });
                    cache_misses += 1;
                }
    }

    // Save project if dirty
    if let Some(ref mut proj) = project {
        if proj.is_dirty() {
            if let Err(e) = proj.save() {
                eprintln!("Warning: could not save project file: {e}");
            } else {
                eprintln!("Project saved: {} (hits={}, misses={}, total cached={})",
                    proj.project_path().display(), cache_hits, cache_misses, proj.cached_count());
            }
        } else if cache_hits > 0 {
            eprintln!("Project: all {} functions served from cache", cache_hits);
        }
    }
}

