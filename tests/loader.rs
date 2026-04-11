//! Loader tests: binary format detection, function discovery, sections.

mod common;

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
