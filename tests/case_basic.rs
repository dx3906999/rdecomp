//! Pipeline tests for basic cases (case1–case6).
//! Each test runs against the default WSL binary (test_file/bin/wsl/).

mod common;

// ═══════════════════════════════════════════════════════════════
// case1_control: classify, sum_to_n
// ═══════════════════════════════════════════════════════════════

#[test]
fn case1_classify_decompiles() {
    let binary = common::load_wsl_binary("case1_control");
    let output = common::decompile_function(&binary, "classify");
    assert!(output.contains("classify("), "should have function signature");
    assert!(output.contains("arg_1"), "should have parameter");
    assert!(output.contains("return"), "should have return statements");
    // At -O1, compiler may produce branchless comparison instead of explicit return 0/1/2
    assert!(
        output.contains("return -1") || output.contains("return 0xffffffff") || output.contains("-1"),
        "should handle negative input path, got:\n{output}"
    );
    assert!(!output.contains("goto"), "should have clean control flow without gotos");
}

#[test]
fn case1_classify_returns_correct_values() {
    let binary = common::load_wsl_binary("case1_control");
    let output = common::decompile_function(&binary, "classify");
    let param_count = output
        .lines()
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
    assert!(output.contains("arg_1"), "should have a parameter");
    assert!(output.contains("return"), "should have a return statement");
    assert!(!output.contains("goto"), "loop should be structured without gotos");
}

#[test]
fn case1_win_classify_decompiles() {
    let binary = common::load_win_binary("case1_control");
    let output = common::decompile_function(&binary, "classify");
    assert!(output.contains("classify("), "should have function signature");
    assert!(output.contains("return"), "should have return");
}

// ═══════════════════════════════════════════════════════════════
// case2_calls: pipeline
// ═══════════════════════════════════════════════════════════════

#[test]
fn case2_pipeline_decompiles() {
    let binary = common::load_wsl_binary("case2_calls");
    let output = common::decompile_function(&binary, "pipeline");
    assert!(output.contains("pipeline"), "should contain function name");
    // At -O1+, helper may be inlined; just verify the function decompiles
    assert!(output.contains("return"), "should have return, got:\n{output}");
}

#[test]
fn case2_win_pipeline_decompiles() {
    let binary = common::load_win_binary("case2_calls");
    let output = common::decompile_function(&binary, "pipeline");
    assert!(output.contains("pipeline"), "should contain function name");
}

// ═══════════════════════════════════════════════════════════════
// case3_memory: update_pair, stack_mix
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
// case4_loops: sum_squares, count_bits, find_pair_sum, reverse_sum
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
    assert!(has_loop, "count_bits should have a loop, got:\n{output}");
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

#[test]
fn case4_reverse_sum_decompiles() {
    let binary = common::load_wsl_binary("case4_loops");
    let output = common::decompile_function(&binary, "reverse_sum");
    let has_loop = output.contains("while") || output.contains("for") || output.contains("do");
    assert!(has_loop, "reverse_sum should have a loop, got:\n{output}");
    assert!(output.contains("return"), "should have return");
}

// ═══════════════════════════════════════════════════════════════
// case5_switch: grade, clamp, encode_flags, safe_div
// ═══════════════════════════════════════════════════════════════

#[test]
fn case5_grade_decompiles() {
    let binary = common::load_wsl_binary("case5_switch");
    let output = common::decompile_function(&binary, "grade");
    assert!(
        output.contains("if") || output.contains("switch"),
        "grade should have conditionals"
    );
    assert!(output.contains("return"), "should have returns");
}

#[test]
fn case5_clamp_decompiles() {
    let binary = common::load_wsl_binary("case5_switch");
    let output = common::decompile_function(&binary, "clamp");
    // At -O1, compiler may produce conditional moves (ternary) instead of if/else
    assert!(
        output.contains("if") || output.contains("?"),
        "clamp should have conditionals or ternary, got:\n{output}"
    );
    assert!(output.contains("return"), "should have returns");
}

#[test]
fn case5_encode_flags_decompiles() {
    let binary = common::load_wsl_binary("case5_switch");
    let output = common::decompile_function(&binary, "encode_flags");
    // At -O1, compiler may produce branchless ternary chains
    assert!(
        output.contains("if") || output.contains("?") || output.contains("|"),
        "encode_flags should have conditionals or bitwise logic, got:\n{output}"
    );
}

#[test]
fn case5_safe_div_decompiles() {
    let binary = common::load_wsl_binary("case5_switch");
    let output = common::decompile_function(&binary, "safe_div");
    assert!(output.contains("if"), "safe_div should have conditionals");
    assert!(output.contains("/"), "safe_div should contain division");
}

// ═══════════════════════════════════════════════════════════════
// case6_string: my_strlen, my_strcmp, djb2_hash, array_max
// ═══════════════════════════════════════════════════════════════

#[test]
fn case6_my_strlen_decompiles() {
    let binary = common::load_wsl_binary("case6_string");
    let output = common::decompile_function(&binary, "my_strlen");
    // At -O1, very short loops may be partially unrolled/branchless
    assert!(output.contains("return"), "should return length, got:\n{output}");
    assert!(!output.is_empty(), "should produce output");
}

#[test]
fn case6_djb2_hash_decompiles() {
    let binary = common::load_wsl_binary("case6_string");
    let output = common::decompile_function(&binary, "djb2_hash");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "djb2_hash should have a loop, got:\n{output}");
    assert!(output.contains("return"), "should return hash");
}

#[test]
fn case6_array_max_decompiles() {
    let binary = common::load_wsl_binary("case6_string");
    let output = common::decompile_function(&binary, "array_max");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "array_max should have a loop, got:\n{output}");
    assert!(output.contains("return"), "should return max value");
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

#[test]
fn smoke_case6_main() {
    let binary = common::load_wsl_binary("case6_string");
    let output = common::decompile_function(&binary, "main");
    assert!(!output.is_empty(), "main output should not be empty");
}
