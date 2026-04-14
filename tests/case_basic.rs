//! Pipeline tests for basic cases (case1–case5).

mod common;

// ═══════════════════════════════════════════════════════════════
// case1_control: classify, sum_to_n
// ═══════════════════════════════════════════════════════════════

#[test]
fn case1_classify_decompiles() {
    let binary = common::load_wsl_binary("case1_control");
    let output = common::decompile_function(&binary, "classify");
    // Verify function signature
    assert!(output.contains("classify("), "should have function signature");
    assert!(output.contains("arg_1"), "should have parameter");
    // Verify all four return paths exist
    assert!(output.contains("return 0"), "should return 0 for zero input");
    assert!(output.contains("return 1"), "should return 1 for small positive");
    assert!(output.contains("return 2"), "should return 2 for large number");
    assert!(output.contains("return -1") || output.contains("return 0xffffffff"),
        "should return -1 for negative input");
    // Verify structured control flow (no gotos)
    assert!(!output.contains("goto"), "should have clean control flow without gotos");
}

#[test]
fn case1_classify_returns_correct_values() {
    let binary = common::load_wsl_binary("case1_control");
    let output = common::decompile_function(&binary, "classify");
    // Should have exactly one parameter
    let param_count = output.lines()
        .find(|l| l.contains("classify("))
        .map(|l| l.matches("arg_").count())
        .unwrap_or(0);
    assert_eq!(param_count, 1, "classify should have exactly 1 parameter");
}

#[test]
fn case1_sum_to_n_has_loop() {
    let binary = common::load_wsl_binary("case1_control");
    let output = common::decompile_function(&binary, "sum_to_n");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "sum_to_n should have a loop construct, got:\n{output}");
    // Should have exactly one parameter and a return
    assert!(output.contains("arg_1"), "should have a parameter");
    assert!(output.contains("return"), "should have a return statement");
    // Should not have any gotos (clean structured output)
    assert!(!output.contains("goto"), "loop should be structured without gotos");
}

// ═══════════════════════════════════════════════════════════════
// case2_calls: pipeline
// ═══════════════════════════════════════════════════════════════

#[test]
fn case2_pipeline_decompiles() {
    let binary = common::load_wsl_binary("case2_calls");
    let output = common::decompile_function(&binary, "pipeline");
    assert!(output.contains("pipeline"), "should contain function name");
    assert!(
        output.contains("helper") || output.contains("call"),
        "should have call to helper"
    );
}

// ═══════════════════════════════════════════════════════════════
// case3_memory: update_pair
// ═══════════════════════════════════════════════════════════════

#[test]
fn case3_update_pair_decompiles() {
    let binary = common::load_wsl_binary("case3_memory");
    let output = common::decompile_function(&binary, "update_pair");
    assert!(output.contains("update_pair"), "should contain function name");
    assert!(
        output.contains("*") || output.contains("->"),
        "should have memory access"
    );
}

// ═══════════════════════════════════════════════════════════════
// case4_loops: sum_squares, count_bits, find_pair_sum
// ═══════════════════════════════════════════════════════════════

#[test]
fn case4_sum_squares_has_for_loop() {
    let binary = common::load_wsl_binary("case4_loops");
    let output = common::decompile_function(&binary, "sum_squares");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "sum_squares should have a loop, got:\n{output}");
    assert!(output.contains("return"), "should have return");
}

#[test]
fn case4_count_bits_decompiles() {
    let binary = common::load_wsl_binary("case4_loops");
    let output = common::decompile_function(&binary, "count_bits");
    let has_loop = output.contains("while") || output.contains("do");
    assert!(
        has_loop,
        "count_bits should have a loop, got:\n{output}"
    );
}

#[test]
fn case4_find_pair_sum_nested_loops() {
    let binary = common::load_wsl_binary("case4_loops");
    let output = common::decompile_function(&binary, "find_pair_sum");
    let loop_count = output.matches("while").count() + output.matches("for").count();
    assert!(
        loop_count >= 2,
        "find_pair_sum should have >=2 loops, got {loop_count} in:\n{output}"
    );
}

// ═══════════════════════════════════════════════════════════════
// case5_switch: clamp, encode_flags, safe_div
// ═══════════════════════════════════════════════════════════════

#[test]
fn case5_clamp_decompiles() {
    let binary = common::load_wsl_binary("case5_switch");
    let output = common::decompile_function(&binary, "clamp");
    assert!(output.contains("if"), "clamp should have conditionals");
    assert!(output.contains("return"), "should have returns");
}

#[test]
fn case5_encode_flags_decompiles() {
    let binary = common::load_wsl_binary("case5_switch");
    let output = common::decompile_function(&binary, "encode_flags");
    assert!(output.contains("if"), "encode_flags should have if statements");
}

#[test]
fn case5_safe_div_decompiles() {
    let binary = common::load_wsl_binary("case5_switch");
    let output = common::decompile_function(&binary, "safe_div");
    assert!(output.contains("if"), "safe_div should have conditionals");
    assert!(output.contains("/"), "safe_div should contain division");
}

// ═══════════════════════════════════════════════════════════════
// Smoke tests: main functions of basic cases
// ═══════════════════════════════════════════════════════════════

#[test]
fn smoke_case1_main() {
    let binary = common::load_wsl_binary("case1_control");
    let output = common::decompile_function(&binary, "main");
    assert!(!output.is_empty(), "main output should not be empty");
}

#[test]
fn smoke_case4_main() {
    let binary = common::load_wsl_binary("case4_loops");
    let output = common::decompile_function(&binary, "main");
    assert!(!output.is_empty(), "main output should not be empty");
}

#[test]
fn smoke_case5_main() {
    let binary = common::load_wsl_binary("case5_switch");
    let output = common::decompile_function(&binary, "main");
    assert!(!output.is_empty(), "main output should not be empty");
}
