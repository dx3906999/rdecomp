use clap::Parser;
use rdecomp::analysis;
use rdecomp::cfg::Cfg;
use rdecomp::codegen::CodeGenerator;
use rdecomp::disasm;
use rdecomp::ir::CallingConv;
use rdecomp::lift::Lifter;
use rdecomp::loader::Binary;
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
        // Decompile all functions
        binary
            .functions
            .iter()
            .filter(|f| f.size > 0 || f.addr != 0)
            .map(|f| (f.name.clone(), f.addr, f.size))
            .collect()
    } else {
        // Fallback: decompile from entry point
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
    // PE/Win64 calling convention vs SystemV for ELF
    if binary.format == rdecomp::loader::BinaryFormat::Pe {
        lifter.set_calling_conv(CallingConv::Win64);
    }
    let mut codegen = CodeGenerator::new(&binary.functions, &binary);

    // Build set of known noreturn function addresses from PLT
    let noreturn_addrs: HashSet<u64> = binary
        .plt_map
        .iter()
        .filter(|(_, name)| rdecomp::ir::is_noreturn_name(name))
        .map(|(addr, _)| *addr)
        .collect();

    for (name, addr, size) in &targets {
        println!("\n{}", "=".repeat(60));
        println!("// {} @ 0x{:x}", name, addr);
        println!("{}", "=".repeat(60));

        let func_size = if *size > 0 {
            *size
        } else {
            // Infer size from the next known function
            binary
                .functions
                .iter()
                .map(|f| f.addr)
                .filter(|&a| a > *addr)
                .min()
                .map(|next| next - addr)
                .unwrap_or(cli.max_size)
        };

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
    }
}

