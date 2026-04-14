//! Loader tests: binary format detection, function discovery, sections.

mod common;

use rdecomp::loader::{Arch, Binary, BinaryFormat, Section};
use std::collections::HashMap;
use std::path::Path;

#[test]
fn loader_detects_elf_format() {
    let binary = common::load_wsl_binary("case1_control");
    assert_eq!(binary.format, rdecomp::loader::BinaryFormat::Elf);
    assert_eq!(binary.arch, rdecomp::loader::Arch::X86_64);
}

#[test]
fn loader_finds_functions() {
    let binary = common::load_wsl_binary("case1_control");
    let names: Vec<&str> = binary.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"classify"), "should find classify");
    assert!(names.contains(&"sum_to_n"), "should find sum_to_n");
    assert!(names.contains(&"main"), "should find main");
}

#[test]
fn loader_has_text_section() {
    let binary = common::load_wsl_binary("case1_control");
    let text = binary.sections.iter().find(|s| s.name == ".text");
    assert!(text.is_some(), "should have .text section");
    assert!(text.unwrap().executable, ".text should be executable");
}

#[test]
fn loader_from_path_accepts_canonicalized_relative_segments() {
    let binary = Binary::from_path(Path::new("test_file/bin/wsl/../wsl/case1_control"))
        .expect("canonicalized path should load");
    assert_eq!(binary.format, BinaryFormat::Elf);
}

#[test]
fn loader_reads_utf8_cstrings() {
    let binary = Binary {
        arch: Arch::X86_64,
        format: BinaryFormat::Elf,
        entry_point: 0,
        sections: vec![Section {
            name: ".rodata".to_string(),
            vaddr: 0x1000,
            data: "hello-世界\0tail".as_bytes().to_vec(),
            executable: false,
        }],
        functions: vec![],
        base_address: 0,
        plt_map: HashMap::new(),
        globals_map: HashMap::new(),
    };

    assert_eq!(binary.read_cstring_at(0x1000).as_deref(), Some("hello-世界"));
}

#[test]
fn loader_rejects_control_chars_in_cstrings() {
    let binary = Binary {
        arch: Arch::X86_64,
        format: BinaryFormat::Elf,
        entry_point: 0,
        sections: vec![Section {
            name: ".rodata".to_string(),
            vaddr: 0x2000,
            data: vec![b'a', 0x01, b'b', 0],
            executable: false,
        }],
        functions: vec![],
        base_address: 0,
        plt_map: HashMap::new(),
        globals_map: HashMap::new(),
    };

    assert_eq!(binary.read_cstring_at(0x2000), None);
}
