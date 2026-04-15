<div align="center">

# rdecomp

**A Rust-based x86/x64 decompiler for ELF and PE binaries**  
**一个面向 ELF / PE 二进制的 Rust x86/x64 反编译器**

<p>
  <img alt="Rust" src="https://img.shields.io/badge/Rust-2024%20edition-orange" />
  <img alt="Platform" src="https://img.shields.io/badge/Arch-x86%20%2F%20x64-blue" />
  <img alt="Format" src="https://img.shields.io/badge/Format-ELF%20%2F%20PE-success" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green" />
  <img alt="Status" src="https://img.shields.io/badge/Status-Experimental-critical" />
</p>

<p>
  <strong>English</strong> · <strong>中文</strong>
</p>

</div>

---

## Overview / 项目简介

**rdecomp** is an experimental decompiler written in Rust for **x86/x64** binaries. It provides an end-to-end pipeline for loading binaries, discovering functions, disassembling code, building CFGs, lifting to IR, running analysis passes, and generating C-like pseudocode.

**rdecomp** 是一个使用 Rust 编写的、面向 **x86/x64** 二进制程序的实验性反编译器。它提供了从二进制加载、函数发现、反汇编、控制流图构建、IR 提升、分析优化，到 C 风格伪代码生成的一整套流程。

The project is especially suitable for **reverse engineering research, compiler/program analysis experiments, teaching demos, and decompiler pipeline prototyping**.

该项目尤其适合用于**逆向工程研究、编译原理与程序分析实验、教学演示，以及反编译管线原型开发**。

---

## Highlights / 特性亮点

### English

- **x86 / x86_64 focused** decompilation pipeline
- Loads **ELF** and **PE** binaries
- Multiple output modes:
  - decompiled C-like pseudocode
  - disassembly
  - IR
- Function discovery from symbols and code references
- CFG construction and structured analysis
- Interprocedural analysis support
- Configurable analysis pass manager
- Optional **IDA Hex-Rays-style** output formatting
- Optional **`.rdb` project cache** for analysis reuse

### 中文

- 面向 **x86 / x86_64** 的反编译流程
- 支持加载 **ELF** 与 **PE** 二进制
- 支持多种输出模式：
  - C 风格伪代码
  - 反汇编
  - IR 中间表示
- 支持基于符号与代码引用的函数发现
- 支持控制流图构建与结构化分析
- 支持跨函数分析
- 支持可配置的分析 Pass 管理
- 支持 **IDA Hex-Rays 风格**输出
- 支持 **`.rdb` 项目缓存**，减少重复分析开销

---

## Why rdecomp / 为什么使用 rdecomp

### English

`rdecomp` aims to be a **clean, hackable, Rust-native decompiler codebase** rather than just a black-box CLI. The code structure is small enough to study, while still covering many of the pieces that matter in a real decompiler:

- binary loading
- architecture-aware disassembly
- CFG recovery
- IR lifting
- optimization and analysis passes
- interprocedural reasoning
- pseudocode generation

### 中文

`rdecomp` 的价值不仅在于“能跑一个 CLI”，更在于它是一个**结构相对清晰、便于研究和修改的 Rust 原生反编译器代码库**。它覆盖了真实反编译器中最关键的若干环节：

- 二进制加载
- 架构相关反汇编
- 控制流恢复
- IR 提升
- 优化与分析 Pass
- 跨函数分析
- 伪代码生成

---

## Project Status / 项目状态

### English

This project is currently **experimental**. It already implements a complete baseline workflow, but the generated result should be treated as **recovered pseudocode**, not source-equivalent reconstruction.

### 中文

该项目目前处于**实验性阶段**。虽然它已经实现了较完整的基础工作流，但输出结果应理解为**恢复出来的伪代码**，而不是对原始源码的等价还原。

---

## Architecture / 架构概览

```text
Binary Loader
    ↓
Function Discovery
    ↓
Disassembly
    ↓
CFG Construction
    ↓
IR Lifting
    ↓
Optimization / Analysis Passes
    ↓
Interprocedural Analysis
    ↓
Code Generation (C-like pseudocode / IR / disasm)
```

### 中文说明

整体流程可以理解为：先把程序读进来，识别函数与可执行区段，再把机器指令组织成 CFG，提升到统一的 IR 表示，然后运行一组分析/优化 Pass，最后生成更易读的伪代码输出。

---

## Repository Layout / 仓库结构

```text
src/
├── arch/                 # Architecture-specific disassembly/lifting
├── codegen/              # C-like code generation
├── analysis.rs           # Analysis and optimization passes
├── cfg.rs                # Control Flow Graph construction
├── dataflow.rs           # Data-flow utilities
├── disasm.rs             # Disassembly abstractions
├── error.rs              # Error definitions
├── interprocedural.rs    # Cross-function analysis
├── ir.rs                 # Intermediate Representation
├── lift.rs               # Instruction lifting helpers
├── loader.rs             # ELF / PE loading and symbol discovery
├── main.rs               # CLI entry point
├── pass.rs               # Pass manager infrastructure
├── project.rs            # .rdb cache/project database
├── struct_recovery.rs    # Structure recovery logic
└── typing.rs             # Type recovery / typing

tests/
├── common/              # Shared test helpers
│   └── mod.rs
├── case_basic.rs         # Structural tests for cases 1–6
├── case_complex.rs       # Structural tests for cases 7–10
├── cfg_tests.rs          # CFG construction tests
├── ida_style.rs          # IDA Hex-Rays style output tests
├── interprocedural.rs    # Cross-function analysis tests
├── ir_structure.rs       # IR lifting structure tests
├── loader.rs             # Binary loader tests
└── opt_matrix.rs         # Cross-platform × optimization level smoke tests

test_file/
├── cases/               # C source files (10 cases + test_project)
├── bin/
│   ├── wsl/             # ELF binaries (default)
│   ├── win/             # PE binaries (default)
│   ├── wsl_opt/         # ELF binaries at O1/O2/O3
│   │   ├── O1/
│   │   ├── O2/
│   │   └── O3/
│   └── win_opt/         # PE binaries at O1/O2/O3
│       ├── O1/
│       ├── O2/
│       └── O3/
└── results/             # Decompilation output snapshots
```

---

## Installation / 安装

### Requirements / 环境要求

- Rust toolchain
- Cargo

### Build from source / 从源码构建

```bash
cargo build --release
```

The binary will usually be available at:

```bash
./target/release/rdecomp
```

构建完成后，可执行文件通常位于：

```bash
./target/release/rdecomp
```

---

## Quick Start / 快速开始

### 1. List available passes / 列出可用分析 Pass

```bash
rdecomp --list-passes
```

### 2. List detected functions / 列出识别到的函数

```bash
rdecomp ./a.out --list-functions
```

### 3. Decompile a function by name / 按函数名反编译

```bash
rdecomp ./a.out --function main
```

### 4. Decompile by address / 按地址反编译

```bash
rdecomp ./a.out --address 0x401000
```

### 5. Show disassembly / 输出反汇编

```bash
rdecomp ./a.out --function main --disasm
```

### 6. Show IR / 输出 IR

```bash
rdecomp ./a.out --function main --ir
```

### 7. Enable analysis cache / 启用分析缓存

```bash
rdecomp ./a.out --project
```

### 8. Use IDA-style formatting / 使用 IDA 风格输出

```bash
rdecomp ./a.out --function main --ida-style
```

---

## Example Workflow / 示例工作流

### English

A common workflow when exploring a binary:

1. Load the binary and list functions.
2. Pick one function by name or address.
3. Start with disassembly.
4. Switch to IR if you want to inspect lifting quality.
5. Switch to pseudocode for higher-level understanding.
6. Enable `.rdb` caching for repeated runs.

### 中文

在分析一个二进制时，推荐的使用顺序通常是：

1. 先加载程序并列出函数；
2. 选择一个目标函数名或地址；
3. 先看反汇编；
4. 若要检查提升质量，再切到 IR；
5. 若要快速理解语义，再切到伪代码；
6. 反复调试时启用 `.rdb` 缓存以加快迭代。

---

## CLI Reference / 命令行参数

| Option | Description (EN) | 说明（中文） |
|---|---|---|
| `binary` | Path to the input binary | 输入二进制路径 |
| `-f, --function <NAME>` | Decompile a specific function by name | 按函数名反编译 |
| `-a, --address <HEX>` | Decompile a function at a hex address | 按十六进制地址反编译 |
| `-l, --list-functions` | List detected functions and exit | 列出已识别函数后退出 |
| `-D, --disasm` | Show disassembly instead of pseudocode | 输出反汇编而不是伪代码 |
| `--ir` | Show IR instead of pseudocode | 输出 IR 而不是伪代码 |
| `--no-opt` | Disable optimization passes | 禁用优化 Pass |
| `--max-size <N>` | Limit bytes disassembled per function | 限制单函数反汇编字节数 |
| `-p, --project` | Use/create `.rdb` cache project | 使用/创建 `.rdb` 缓存项目 |
| `--disable-pass <A,B,...>` | Disable selected analysis passes | 禁用指定分析 Pass |
| `--dump-after <A,B,...>` | Dump IR after selected passes | 在指定 Pass 后输出 IR |
| `--list-passes` | List all available analysis passes | 列出所有分析 Pass |
| `--ida-style` | Use IDA Hex-Rays-style formatting | 使用 IDA 风格输出 |

---

## Output Modes / 输出模式

### Pseudocode / 伪代码
Best for quickly understanding function behavior.  
最适合快速理解函数语义。

### Disassembly / 反汇编
Best for inspecting exact machine-level behavior.  
最适合查看机器级指令细节。

### IR
Best for debugging the lifting and optimization pipeline.  
最适合调试 IR 提升与分析优化流程。

### IDA-style
Best for users who prefer a Hex-Rays-like presentation style.  
适合偏好 Hex-Rays 风格展示形式的用户。

---

## Current Scope / 当前能力边界

### English

`rdecomp` already covers a useful baseline, but users should expect an experimental tool rather than a finished industrial decompiler.

### 中文

`rdecomp` 已经具备可用的基础能力，但它更接近一个研究型工具，而不是成熟的工业级反编译器。

### What it does well / 当前较擅长的部分

- x86/x64 function-oriented analysis
- ELF/PE loading
- CFG-oriented recovery
- IR inspection and pass experimentation
- readable C-like output for many small to medium functions

### What is still hard / 当前仍然困难的部分

- heavily optimized binaries
- highly obfuscated control flow
- aggressive compiler transformations
- perfect type recovery
- full source-equivalent reconstruction

---

## Testing / 测试

Run the full test suite:

```bash
cargo test
```

### Test Coverage / 测试覆盖

| Test File | Count | Description |
|---|---|---|
| `case_basic.rs` | 22 | Structural tests for cases 1–6 (control, calls, memory, loops, switch, string) |
| `case_complex.rs` | 40 | Structural tests for cases 7–10 (complex, state machine, algorithms, mixed) |
| `opt_matrix.rs` | 450 | Cross-platform smoke tests across 2 platforms × 3 optimization levels (O1/O2/O3) |
| `cfg_tests.rs` | 1 | CFG construction verification |
| `ida_style.rs` | 3 | IDA Hex-Rays style formatting |
| `interprocedural.rs` | 2 | Cross-function call graph analysis |
| `ir_structure.rs` | 2 | IR lifting structure checks |
| `loader.rs` | 6 | ELF/PE loading, symbols, sections |
| **Unit tests** | **33** | Internal module tests |
| **Total** | **559** | |

### Platforms / 平台

Tests cover **ELF** (WSL/Linux) and **PE** (Windows) binaries at three gcc optimization levels (**-O1**, **-O2**, **-O3**), totaling 6 platform × optimization combinations per function.

### 中文

测试覆盖了 **ELF**（WSL/Linux）和 **PE**（Windows）两种平台的二进制文件，在 **-O1**、**-O2**、**-O3** 三个 gcc 优化级别下共 6 种组合。10 个 C 测试案例（约 75 个函数），加上装载器、CFG、IR、跨函数分析等核心路径的结构化测试，全部 559 个测试通过。

---

## Development / 开发建议

### English

Useful commands during development:

```bash
cargo test
cargo run -- --list-passes
cargo run -- ./a.out --list-functions
cargo run -- ./a.out --function main --disasm
cargo run -- ./a.out --function main --ir
cargo run -- ./a.out --function main --ida-style
```

### 中文

开发调试时常用命令：

```bash
cargo test
cargo run -- --list-passes
cargo run -- ./a.out --list-functions
cargo run -- ./a.out --function main --disasm
cargo run -- ./a.out --function main --ir
cargo run -- ./a.out --function main --ida-style
```

---

## Roadmap / 路线图

### English

Potential future directions:

- better structuring and control-flow recovery
- stronger type inference
- more complete calling convention support
- better output quality on optimized binaries
- richer examples and benchmark corpus
- CI, packaged releases, and documentation polish

### 中文

后续可演进方向包括：

- 更强的结构化恢复与控制流整理
- 更完善的类型推断
- 更完整的调用约定支持
- 提升对优化后二进制的输出质量
- 增加样例与基准测试集
- 补充 CI、发布包与文档工程化建设

---

## Contributing / 贡献

Contributions are welcome.

If you want to contribute, a good starting point is:

- adding analysis passes
- improving IR lifting rules
- refining code generation
- expanding tests
- improving documentation

欢迎贡献代码与文档。

如果你希望参与贡献，可以从以下方向入手：

- 新增分析 Pass
- 改进 IR 提升规则
- 优化代码生成质量
- 补充测试
- 完善文档

---

## Development Note / 开发说明

### English

This project is developed with collaborative AI assistance, primarily using **Claude** and **GPT** model workflows alongside human direction and review.

### 中文

本项目在开发过程中采用了协作式 AI 辅助，主要使用 **Claude** 与 **GPT** 模型工作流，并结合人工指导与审阅。

---

## License / 许可证

### English

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

### 中文

本项目采用 **MIT 许可证**。详见仓库中的 `LICENSE` 文件。

---

## Acknowledgements / 致谢

### English

This project builds on the Rust ecosystem for binary parsing, disassembly, graph analysis, serialization, and CLI tooling.

It is also developed through Claude and GPT model-assisted engineering workflows.

### 中文

本项目受益于 Rust 生态中的二进制解析、反汇编、图结构、序列化与命令行工具链。

同时，本项目使用了 Claude 与 GPT 模型辅助的工程开发流程。

