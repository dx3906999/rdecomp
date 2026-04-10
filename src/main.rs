use clap::Parser;
use rdecomp::analysis;
use rdecomp::cfg::Cfg;
use rdecomp::codegen::CodeGenerator;
use rdecomp::disasm;
use rdecomp::ir::CallingConv;
use rdecomp::lift::Lifter;
use rdecomp::loader::Binary;
use rdecomp::project::{AnalyzedFunction, ProjectDb, hash_bytes};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rdecomp", version, about = "High-performance x86/x64 decompiler")]
struct Cli {
    /// Path to the binary file to decompile.
    binary: PathBuf,

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
}

fn parse_hex(s: &str) -> Result<u64, String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| format!("invalid hex address: {e}"))
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    let mut binary = match Binary::from_path(&cli.binary) {
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
    let rdb_path = cli.binary.with_extension("rdb");
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
                        &cli.binary.to_string_lossy(),
                        &binary,
                    ))
                }
            }
        } else {
            eprintln!("Creating project: {}", rdb_path.display());
            Some(ProjectDb::create(
                &rdb_path,
                &cli.binary.to_string_lossy(),
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

    let mut lifter = Lifter::new(binary.arch);
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

    let mut cache_hits = 0u32;
    let mut cache_misses = 0u32;

    for (name, addr, size) in &targets {
        println!("\n{}", "=".repeat(60));
        println!("// {} @ 0x{:x}", name, addr);
        println!("{}", "=".repeat(60));

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

        // Compute hash of raw bytes for cache validation
        let bytes_hash = binary.read_bytes(*addr, func_size_usize)
            .map(|b| hash_bytes(b));

        // --- Try cache hit (only for normal C output mode) ---
        if !cli.ir && !cli.disasm && !cli.no_opt {
            if let Some(ref proj) = project {
                if let Some(hash) = bytes_hash {
                    if let Some(cached) = proj.get(*addr, hash) {
                        println!("{}", cached.c_code);
                        cache_hits += 1;
                        continue;
                    }
                }
            }
        }

        // Step 1: Disassemble
        let instructions = match disasm::disassemble_function(&binary, *addr, func_size) {
            Ok(insns) => insns,
            Err(e) => {
                eprintln!("  Disassembly failed: {e}");
                continue;
            }
        };

        if instructions.is_empty() {
            eprintln!("  No instructions found.");
            continue;
        }

        log::info!("Disassembled {} instructions for {}", instructions.len(), name);

        if cli.disasm {
            for insn in &instructions {
                println!("  0x{:08x}:  {}", insn.addr, insn.text);
            }
            continue;
        }

        // Step 2: Build CFG
        let cfg = Cfg::build(&instructions);
        log::info!("CFG: {} blocks", cfg.blocks.len());

        // Step 3: Lift to IR
        let mut func = lifter.lift_function(name, *addr, &cfg);
        log::info!("Lifted {} blocks", func.blocks.len());

        // Step 4: Optimize
        if !cli.no_opt {
            analysis::optimize(&mut func, &noreturn_addrs);
        }

        if cli.ir {
            println!("{func}");
            continue;
        }

        // Step 5: Generate pseudo-C
        let code = codegen.generate(&func, &cfg);
        println!("{code}");

        // Step 6: Cache the result
        if !cli.no_opt {
            if let Some(ref mut proj) = project {
                if let Some(hash) = bytes_hash {
                    proj.insert(*addr, AnalyzedFunction {
                        ir: func,
                        c_code: code,
                        bytes_hash: hash,
                    });
                    cache_misses += 1;
                }
            }
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

