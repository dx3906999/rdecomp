use crate::error::{DecompError, Result};
use goblin::Object;
use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};
use std::collections::HashSet;
use std::path::Path;

/// Represents an executable section loaded from a binary.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub vaddr: u64,
    pub data: Vec<u8>,
    pub executable: bool,
}

/// A detected function symbol with name and address.
#[derive(Debug, Clone)]
pub struct FunctionSymbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
}

/// Target architecture of the loaded binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
}

/// Binary format type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Elf,
    Pe,
}

/// Loaded binary representation.
#[derive(Debug)]
pub struct Binary {
    pub arch: Arch,
    pub format: BinaryFormat,
    pub entry_point: u64,
    pub sections: Vec<Section>,
    pub functions: Vec<FunctionSymbol>,
    pub base_address: u64,
    /// PLT stub address → dynamic symbol name (ELF only).
    pub plt_map: std::collections::HashMap<u64, String>,
    /// Address → global object name (e.g. stdin, stdout, stderr from R_*_COPY/GLOB_DAT).
    pub globals_map: std::collections::HashMap<u64, String>,
}

impl Binary {
    /// Load a binary from file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    /// Load a binary from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        match Object::parse(data).map_err(|e| DecompError::ParseError(e.to_string()))? {
            Object::Elf(elf) => Self::load_elf(&elf, data),
            Object::PE(pe) => Self::load_pe(&pe, data),
            _ => Err(DecompError::UnsupportedFormat),
        }
    }

    fn load_elf(elf: &goblin::elf::Elf<'_>, data: &[u8]) -> Result<Self> {
        let arch = match elf.header.e_machine {
            goblin::elf::header::EM_386 => Arch::X86,
            goblin::elf::header::EM_X86_64 => Arch::X86_64,
            other => return Err(DecompError::UnsupportedArch(format!("ELF e_machine={other}"))),
        };

        let mut sections = Vec::new();
        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            let executable =
                sh.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0;
            if sh.sh_type == goblin::elf::section_header::SHT_PROGBITS && sh.sh_size > 0 {
                let offset = sh.sh_offset as usize;
                let size = sh.sh_size as usize;
                if offset + size <= data.len() {
                    sections.push(Section {
                        name: name.to_string(),
                        vaddr: sh.sh_addr,
                        data: data[offset..offset + size].to_vec(),
                        executable,
                    });
                }
            }
        }

        let mut functions = Vec::new();
        for sym in &elf.syms {
            if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
                let name = elf.strtab.get_at(sym.st_name).unwrap_or("unknown");
                functions.push(FunctionSymbol {
                    name: name.to_string(),
                    addr: sym.st_value,
                    size: sym.st_size,
                });
            }
        }
        // Also check dynamic symbols
        for sym in &elf.dynsyms {
            if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
                let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("unknown");
                functions.push(FunctionSymbol {
                    name: name.to_string(),
                    addr: sym.st_value,
                    size: sym.st_size,
                });
            }
        }

        functions.sort_by_key(|f| f.addr);
        functions.dedup_by_key(|f| f.addr);

        // Resolve PLT stubs via relocations
        // Build GOT-address → symbol-name map from pltrelocs
        let mut got_to_name: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
        for rel in &elf.pltrelocs {
            if let Some(sym) = elf.dynsyms.get(rel.r_sym) {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        got_to_name.insert(rel.r_offset, name.to_string());
                    }
                }
            }
        }

        // Scan .plt.sec (or .plt) sections for PLT stubs:
        // each stub is 16 bytes containing an indirect jmp through the GOT
        let mut plt_map = std::collections::HashMap::new();
        for sec in &sections {
            if sec.name == ".plt.sec" || sec.name == ".plt" {
                let stub_size: u64 = 16;
                let num_stubs = sec.data.len() as u64 / stub_size;
                for i in 0..num_stubs {
                    let stub_addr = sec.vaddr + i * stub_size;
                    let off = (i * stub_size) as usize;
                    let end = (off + stub_size as usize).min(sec.data.len());
                    let stub = &sec.data[off..end];
                    if let Some(got_addr) = extract_plt_got_target(stub, stub_addr) {
                        if let Some(name) = got_to_name.get(&got_addr) {
                            plt_map.insert(stub_addr, name.clone());
                            if !functions.iter().any(|f| f.addr == stub_addr) {
                                functions.push(FunctionSymbol {
                                    name: name.clone(),
                                    addr: stub_addr,
                                    size: stub_size,
                                });
                            }
                        }
                    }
                }
            }
        }

        functions.sort_by_key(|f| f.addr);
        functions.dedup_by_key(|f| f.addr);

        // Build globals map from .rela.dyn (R_X86_64_COPY, R_X86_64_GLOB_DAT for data objects)
        let mut globals_map = std::collections::HashMap::new();
        for rel in &elf.dynrelas {
            if let Some(sym) = elf.dynsyms.get(rel.r_sym) {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() && sym.st_type() == goblin::elf::sym::STT_OBJECT {
                        globals_map.insert(rel.r_offset, name.to_string());
                    }
                }
            }
        }

        Ok(Binary {
            arch,
            format: BinaryFormat::Elf,
            entry_point: elf.entry,
            sections,
            functions,
            base_address: 0,
            plt_map,
            globals_map,
        })
    }

    fn load_pe(pe: &goblin::pe::PE<'_>, data: &[u8]) -> Result<Self> {
        let arch = if pe.is_64 { Arch::X86_64 } else { Arch::X86 };
        let image_base = pe.image_base as u64;

        let mut sections = Vec::new();
        for sec in &pe.sections {
            let name = String::from_utf8_lossy(
                &sec.name[..sec.name.iter().position(|&b| b == 0).unwrap_or(sec.name.len())],
            )
            .to_string();
            let executable = sec.characteristics
                & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE
                != 0;
            let offset = sec.pointer_to_raw_data as usize;
            let size = sec.size_of_raw_data as usize;
            if offset + size <= data.len() {
                sections.push(Section {
                    name,
                    vaddr: image_base + u64::from(sec.virtual_address),
                    data: data[offset..offset + size].to_vec(),
                    executable,
                });
            }
        }

        let mut functions = Vec::new();
        for export in &pe.exports {
            if let Some(name) = &export.name {
                functions.push(FunctionSymbol {
                    name: name.to_string(),
                    addr: image_base + export.rva as u64,
                    size: 0,
                });
            }
        }

        functions.sort_by_key(|f| f.addr);

        Ok(Binary {
            arch,
            format: BinaryFormat::Pe,
            entry_point: image_base + pe.entry as u64,
            sections,
            functions,
            base_address: image_base,
            plt_map: std::collections::HashMap::new(),
            globals_map: std::collections::HashMap::new(),
        })
    }

    /// Get all executable sections.
    pub fn executable_sections(&self) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.executable).collect()
    }

    /// Find which section contains the given virtual address.
    pub fn section_at(&self, addr: u64) -> Option<&Section> {
        self.sections.iter().find(|s| {
            addr >= s.vaddr && addr < s.vaddr + s.data.len() as u64
        })
    }

    /// Read bytes at a virtual address.
    pub fn read_bytes(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let sec = self.section_at(addr)?;
        let offset = (addr - sec.vaddr) as usize;
        if offset + len <= sec.data.len() {
            Some(&sec.data[offset..offset + len])
        } else {
            None
        }
    }

    /// Read a null-terminated C string at a virtual address (max 256 bytes).
    pub fn read_cstring_at(&self, addr: u64) -> Option<String> {
        let sec = self.section_at(addr)?;
        let offset = (addr - sec.vaddr) as usize;
        let remaining = &sec.data[offset..];
        let end = remaining.iter().position(|&b| b == 0).unwrap_or(remaining.len().min(256));
        if end == 0 || end > 256 {
            return None;
        }
        let bytes = &remaining[..end];
        // Only accept printable ASCII strings
        if bytes.iter().all(|&b| b == b'\t' || b == b'\n' || (b >= 0x20 && b < 0x7f)) {
            Some(String::from_utf8_lossy(bytes).into_owned())
        } else {
            None
        }
    }

    /// Discover internal functions by scanning executable code for `call` instructions
    /// whose targets land in executable sections. Unknown targets are registered as `sub_{addr:x}`.
    /// Discover internal functions by scanning executable code.
    ///
    /// Uses three strategies:
    /// 1. **Entry point** — always registered.
    /// 2. **Code references** — direct `call` targets (unconditionally) and
    ///    immediate operands (`mov reg, imm` / `lea reg, [addr]`) that point
    ///    into executable sections AND start with a function prologue.
    /// 3. **Gap-fill** — scan gaps between known functions in `.text` for
    ///    standard function prologues (`endbr64`, `push rbp`, etc.).
    pub fn discover_functions(&mut self) {
        let bitness = match self.arch {
            Arch::X86 => 32,
            Arch::X86_64 => 64,
        };

        let mut known: HashSet<u64> = self.functions.iter().map(|f| f.addr).collect();

        // Phase 1: entry point
        if !known.contains(&self.entry_point) && self.addr_in_exec(self.entry_point) {
            self.functions.push(FunctionSymbol {
                name: format!("sub_{:x}", self.entry_point),
                addr: self.entry_point,
                size: 0,
            });
            known.insert(self.entry_point);
        }

        // Collect exec ranges for fast lookup
        let exec_ranges: Vec<(u64, u64)> = self
            .sections
            .iter()
            .filter(|s| s.executable)
            .map(|s| (s.vaddr, s.vaddr + s.data.len() as u64))
            .collect();
        let in_exec = |addr: u64| exec_ranges.iter().any(|&(lo, hi)| addr >= lo && addr < hi);

        let mut new_addrs: HashSet<u64> = HashSet::new();

        // Phase 2: scan instructions for code references
        for sec in &self.sections {
            if !sec.executable {
                continue;
            }
            let mut decoder =
                Decoder::with_ip(bitness, &sec.data, sec.vaddr, DecoderOptions::NONE);
            let mut insn = iced_x86::Instruction::default();
            while decoder.can_decode() {
                decoder.decode_out(&mut insn);

                // 2a: direct call targets — always trustworthy
                if insn.flow_control() == FlowControl::Call {
                    let target = match insn.op0_kind() {
                        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                            Some(insn.near_branch_target())
                        }
                        _ => None,
                    };
                    if let Some(t) = target {
                        if !known.contains(&t) && in_exec(t) {
                            new_addrs.insert(t);
                        }
                    }
                }

                // 2b: immediate code references (mov reg, imm / lea reg, [rip+disp])
                //     Only register if the target has a function prologue.
                for i in 0..insn.op_count() {
                    let addr = match insn.op_kind(i) {
                        OpKind::Immediate64 => insn.immediate64(),
                        OpKind::Immediate32to64 => insn.immediate32to64() as u64,
                        OpKind::Memory => {
                            if insn.is_ip_rel_memory_operand() {
                                insn.ip_rel_memory_address()
                            } else {
                                continue;
                            }
                        }
                        _ => continue,
                    };
                    if known.contains(&addr) || new_addrs.contains(&addr) || !in_exec(addr) {
                        continue;
                    }
                    if let Some(bytes) = self.read_bytes(addr, 8) {
                        if self.is_function_prologue(bytes, bitness) {
                            new_addrs.insert(addr);
                        }
                    } else if let Some(bytes) = self.read_bytes(addr, 5) {
                        // Near end of section — try smaller read
                        if self.is_function_prologue(bytes, bitness) {
                            new_addrs.insert(addr);
                        }
                    }
                }
            }
        }

        for addr in &new_addrs {
            known.insert(*addr);
        }

        // Phase 3: gap-fill — scan .text for function prologues between known functions
        let text_sec = self
            .sections
            .iter()
            .find(|s| s.executable && s.name == ".text");
        if let Some(text) = text_sec {
            let text_start = text.vaddr;
            let text_end = text_start + text.data.len() as u64;

            // Sorted known addresses within .text
            let mut anchors: Vec<u64> = known
                .iter()
                .copied()
                .filter(|&a| a >= text_start && a < text_end)
                .collect();
            anchors.push(text_end); // sentinel
            anchors.sort();

            // Scan gaps — look for function prologues after padding/alignment
            let mut pos = text_start;
            for &next_func in &anchors {
                if pos >= next_func {
                    pos = next_func + 1;
                    continue;
                }
                // First, scan for ret/hlt that ends the previous function,
                // then skip padding (nop/int3/00), then check for prologue.
                let mut scan = pos;
                // Walk instructions to find the end of the previous function's code
                // (ret/hlt), then look for a prologue after padding.
                let mut found_ret = false;
                while scan < next_func && scan < text_end {
                    let off = (scan - text_start) as usize;
                    if off >= text.data.len() {
                        break;
                    }
                    let remainder = &text.data[off..];

                    // After a ret/hlt, skip padding bytes and check for prologue
                    if found_ret {
                        // Skip NOP (0x90), INT3 (0xCC), zero (0x00) padding
                        if matches!(remainder[0], 0x90 | 0xCC | 0x00) {
                            scan += 1;
                            continue;
                        }
                        // Skip multi-byte NOPs (decoded via iced-x86 for robustness)
                        {
                            let mut dec =
                                Decoder::with_ip(bitness, remainder, scan, DecoderOptions::NONE);
                            let mut tmp = iced_x86::Instruction::default();
                            if dec.can_decode() {
                                dec.decode_out(&mut tmp);
                                if tmp.mnemonic() == iced_x86::Mnemonic::Nop {
                                    scan += tmp.len().max(1) as u64;
                                    continue;
                                }
                            }
                        }
                        // Non-padding after ret — check for prologue
                        if self.is_function_prologue(remainder, bitness)
                            && !known.contains(&scan)
                        {
                            new_addrs.insert(scan);
                            known.insert(scan);
                        }
                        // Reset and continue scanning for more functions
                        found_ret = false;
                    }

                    // Decode instruction and check for ret/hlt
                    let mut dec =
                        Decoder::with_ip(bitness, remainder, scan, DecoderOptions::NONE);
                    let mut tmp = iced_x86::Instruction::default();
                    if dec.can_decode() {
                        dec.decode_out(&mut tmp);
                        if matches!(
                            tmp.mnemonic(),
                            iced_x86::Mnemonic::Ret
                                | iced_x86::Mnemonic::Retf
                                | iced_x86::Mnemonic::Hlt
                        ) {
                            found_ret = true;
                        }
                        scan += tmp.len().max(1) as u64;
                    } else {
                        scan += 1;
                    }
                }
                pos = next_func + 1;
            }
        }

        for addr in new_addrs {
            if !self.functions.iter().any(|f| f.addr == addr) {
                self.functions.push(FunctionSymbol {
                    name: format!("sub_{addr:x}"),
                    addr,
                    size: 0,
                });
            }
        }

        self.functions.sort_by_key(|f| f.addr);
        self.functions.dedup_by_key(|f| f.addr);
    }

    /// Check whether `addr` falls within any executable section.
    fn addr_in_exec(&self, addr: u64) -> bool {
        self.sections
            .iter()
            .any(|s| s.executable && addr >= s.vaddr && addr < s.vaddr + s.data.len() as u64)
    }

    /// Detect common function prologues at the start of `bytes`.
    fn is_function_prologue(&self, bytes: &[u8], bitness: u32) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        // endbr64 (F3 0F 1E FA) followed by push rbp (55) or push r12..r15
        if bytes.len() >= 5 && bytes[0..4] == [0xF3, 0x0F, 0x1E, 0xFA] {
            // endbr64 + push rbp
            if bytes[4] == 0x55 {
                return true;
            }
            // endbr64 + push r12..r15 (41 54..41 57)
            if bytes.len() >= 6 && bytes[4] == 0x41 && (0x54..=0x57).contains(&bytes[5]) {
                return true;
            }
            // endbr64 + sub rsp / mov ... (likely a leaf function)
            // endbr64 alone at an aligned address after a NOP/ret gap is enough
            if bitness == 64 {
                return true;
            }
        }
        // endbr32 (F3 0F 1E FB)
        if bytes[0..4] == [0xF3, 0x0F, 0x1E, 0xFB] {
            return true;
        }
        // push rbp; mov rbp, rsp (55 48 89 E5)
        if bitness == 64 && bytes.len() >= 4 && bytes[0..4] == [0x55, 0x48, 0x89, 0xE5] {
            return true;
        }
        // push ebp; mov ebp, esp (55 89 E5)
        if bitness == 32 && bytes[0..3] == [0x55, 0x89, 0xE5] {
            return true;
        }
        false
    }

    /// Resolve a call target address to a human-readable name.
    /// Checks function symbols, PLT map, etc.
    pub fn resolve_func_name(&self, addr: u64) -> Option<String> {
        // Check PLT map first (dynamic symbols)
        if let Some(name) = self.plt_map.get(&addr) {
            return Some(name.clone());
        }
        // Check known function symbols
        self.functions.iter().find(|f| f.addr == addr).map(|f| f.name.clone())
    }

    /// Resolve a data address to a global variable name (stdin/stdout/stderr/etc.).
    pub fn resolve_global_name(&self, addr: u64) -> Option<String> {
        self.globals_map.get(&addr).cloned()
    }
}

/// Extract the GOT target address from a PLT stub.
/// Recognizes patterns like: `endbr64; bnd jmp [rip+disp32]` or `jmp [rip+disp32]`.
fn extract_plt_got_target(stub: &[u8], stub_addr: u64) -> Option<u64> {
    // Search for FF 25 xx xx xx xx (jmp [rip+disp32]) within the stub
    for i in 0..stub.len().saturating_sub(5) {
        if stub[i] == 0xFF && stub[i + 1] == 0x25 {
            let disp = i32::from_le_bytes([stub[i + 2], stub[i + 3], stub[i + 4], stub[i + 5]]);
            let insn_end = stub_addr + (i as u64) + 6; // RIP points past this instruction
            let got_addr = (insn_end as i64 + disp as i64) as u64;
            return Some(got_addr);
        }
    }
    None
}
