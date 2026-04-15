//! Pipeline tests for complex cases (case7–case10).

mod common;

fn has_unresolved_block_gotos(output: &str) -> bool {
    for line in output.lines() {
        let mut rest = line;
        while let Some(idx) = rest.find("goto bb") {
            let suffix = &rest[idx + 5..];
            let label_len = suffix
                .chars()
                .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                .count();
            if label_len == 0 {
                break;
            }
            let label = &suffix[..label_len];
            if !output.contains(&format!("{label}:")) {
                return true;
            }
            rest = &suffix[label_len..];
        }
    }
    false
}

fn has_raw_registers(output: &str) -> bool {
    const REGS: &[&str] = &[
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    ];

    output.lines().any(|line| {
        let code = line.split_once("//").map_or(line, |(head, _)| head);
        code.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .any(|token| REGS.contains(&token))
    })
}

// ═══════════════════════════════════════════════════════════════
// case7_complex: linked list, recursion, bit operations, sorting
// ═══════════════════════════════════════════════════════════════

#[test]
fn case7_fibonacci_recursive() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "fibonacci");
    assert!(output.contains("fibonacci("), "should have function signature, got:\n{output}");
    assert!(output.contains("return"), "should have return, got:\n{output}");
    assert!(!output.contains("goto"), "recursive output should stay structured, got:\n{output}");
}

#[test]
fn case7_list_sum_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "list_sum");
    assert!(
        output.contains("return"),
        "list_sum should have return, got:\n{output}"
    );
}

#[test]
fn case7_list_reverse_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "list_reverse");
    assert!(
        output.contains("return"),
        "should return a value, got:\n{output}"
    );
}

#[test]
fn case7_list_length_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "list_length");
    assert!(output.contains("return"), "should return length, got:\n{output}");
}

#[test]
fn case7_power_recursive() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "power");
    assert!(output.contains("power"), "should have recursive call");
}

#[test]
fn case7_hanoi_recursive() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "hanoi");
    assert!(output.contains("hanoi"), "should have recursive call");
}

#[test]
fn case7_bubble_sort_nested_loops() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "bubble_sort");
    let loop_kw = output.matches("while").count() + output.matches("for").count();
    assert!(loop_kw >= 2, "bubble_sort should have >=2 loops, got {loop_kw}");
}

#[test]
fn case7_binary_search_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "binary_search");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "binary_search should have a loop");
    assert!(output.contains("return"), "binary_search should have return, got:\n{output}");
}

#[test]
fn case7_complex_condition_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "complex_condition");
    assert!(output.contains("if"), "should have conditionals");
    assert!(output.contains("return"), "should have return, got:\n{output}");
}

#[test]
fn case7_ternary_chain_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "ternary_chain");
    assert!(output.contains("return"), "should have return, got:\n{output}");
}

#[test]
fn case7_hamming_distance_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "hamming_distance");
    assert!(
        output.contains("return") || output.contains("hamming"),
        "should produce output, got:\n{output}"
    );
}

#[test]
fn case7_reverse_bits_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "reverse_bits");
    assert!(output.contains("return"), "should return result, got:\n{output}");
}

#[test]
fn smoke_case7_main() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "main");
    assert!(!output.is_empty(), "main output should not be empty");
}

// ═══════════════════════════════════════════════════════════════
// case8_state_machine: parser, lexer, recursive descent
// ═══════════════════════════════════════════════════════════════

#[test]
fn case8_parser_feed_decompiles() {
    let binary = common::load_wsl_binary("case8_state_machine");
    let output = common::decompile_function(&binary, "parser_feed");
    assert!(output.contains("if"), "state machine should have branch conditions");
    assert!(
        output.contains("return"),
        "should have return values for state transitions"
    );
}

#[test]
fn case8_next_token_decompiles() {
    let binary = common::load_wsl_binary("case8_state_machine");
    let output = common::decompile_function(&binary, "next_token");
    assert!(
        output.contains("return") || output.contains("next_token"),
        "should generate output"
    );
}

#[test]
fn case8_parse_expr_recursive() {
    let binary = common::load_wsl_binary("case8_state_machine");
    let output = common::decompile_function(&binary, "parse_expr");
    assert!(!output.is_empty(), "parse_expr should decompile");
}

#[test]
fn case8_parse_term_decompiles() {
    let binary = common::load_wsl_binary("case8_state_machine");
    let output = common::decompile_function(&binary, "parse_term");
    assert!(!output.is_empty(), "parse_term should decompile");
}

#[test]
fn case8_parse_factor_decompiles() {
    let binary = common::load_wsl_binary("case8_state_machine");
    let output = common::decompile_function(&binary, "parse_factor");
    assert!(!output.is_empty(), "parse_factor should decompile");
}

#[test]
fn case8_matrix_trace_decompiles() {
    let binary = common::load_wsl_binary("case8_state_machine");
    let output = common::decompile_function(&binary, "matrix_trace");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "matrix_trace should have a loop, got:\n{output}");
    assert!(output.contains("return"), "should return trace, got:\n{output}");
}

#[test]
fn case8_find_saddle_point_nested() {
    let binary = common::load_wsl_binary("case8_state_machine");
    let output = common::decompile_function(&binary, "find_saddle_point");
    let loop_kw = output.matches("while").count() + output.matches("for").count();
    assert!(
        loop_kw >= 2,
        "find_saddle_point should have >=2 loops, got {loop_kw}"
    );
    assert!(
        !has_raw_registers(&output),
        "find_saddle_point should not leak raw registers, got:\n{output}"
    );
}

#[test]
fn smoke_case8_main() {
    let binary = common::load_wsl_binary("case8_state_machine");
    let output = common::decompile_function(&binary, "main");
    assert!(!output.is_empty(), "main output should not be empty");
}

// ═══════════════════════════════════════════════════════════════
// case9_algorithms: hash table, KMP, DP, BFS
// ═══════════════════════════════════════════════════════════════

#[test]
fn case9_kmp_search_decompiles() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "kmp_search");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "KMP should have loops");
    assert!(
        output.contains("compute_prefix("),
        "kmp_search should call compute_prefix, got:\n{output}"
    );
}

#[test]
fn case9_ht_insert_decompiles() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "ht_insert");
    assert!(output.contains("return"), "should have return values (1/0)");
}

#[test]
fn case9_ht_get_decompiles() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "ht_get");
    assert!(output.contains("return"), "should have return");
}

#[test]
fn case9_compute_prefix_resolves_block_gotos() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "compute_prefix");
    assert!(
        !has_unresolved_block_gotos(&output),
        "compute_prefix should resolve block gotos with emitted labels, got:\n{output}"
    );
    assert!(
        output.contains("while") || output.contains("for"),
        "compute_prefix should preserve loop structure, got:\n{output}"
    );
    assert!(
        !has_raw_registers(&output),
        "compute_prefix should not leak raw registers, got:\n{output}"
    );
}

#[test]
fn case9_is_palindrome_decompiles() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "is_palindrome");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "palindrome check should have a loop");
}

#[test]
fn case9_lcs_length_nested_loops() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "lcs_length");
    let loop_kw = output.matches("while").count() + output.matches("for").count();
    assert!(
        loop_kw >= 2,
        "LCS should have >=2 nested loops, got {loop_kw}"
    );
}

#[test]
fn case9_knapsack_decompiles() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "knapsack");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "knapsack should have loops, got:\n{output}");
    assert!(output.contains("return"), "should return result, got:\n{output}");
}

#[test]
fn case9_bfs_shortest_decompiles() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "bfs_shortest");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "BFS should have a loop");
    assert!(
        !has_raw_registers(&output),
        "bfs_shortest should not leak raw registers, got:\n{output}"
    );
}

#[test]
fn smoke_case9_main() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "main");
    assert!(!output.is_empty(), "main output should not be empty");
}

// ═══════════════════════════════════════════════════════════════
// case10_mixed: function pointers, structs, arrays
// ═══════════════════════════════════════════════════════════════

#[test]
fn case10_array_map_decompiles() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "array_map");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "array_map should have a loop");
}

#[test]
fn case10_rect_area_decompiles() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "rect_area");
    assert!(output.contains("return"), "should return area");
    assert!(
        output.contains("*") || output.contains("->"),
        "should access struct fields"
    );
}

#[test]
fn case10_rect_contains_decompiles() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "rect_contains");
    assert!(output.contains("if") || output.contains("&&") || output.contains("return"),
        "should have conditionals, got:\n{output}");
}

#[test]
fn case10_rects_overlap_decompiles() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "rects_overlap");
    assert!(output.contains("return"), "should return result, got:\n{output}");
}

#[test]
fn case10_dot_product_decompiles() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "dot_product");
    assert!(!output.is_empty(), "dot_product should produce output");
    assert!(
        output.contains("return") || output.contains("*"),
        "should have computation"
    );
    assert!(
        !has_raw_registers(&output),
        "dot_product should not leak raw registers, got:\n{output}"
    );
}

#[test]
fn case10_find_2d_decompiles() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "find_2d");
    assert!(output.contains("return"), "should return result, got:\n{output}");
}

#[test]
fn case10_count_primes_decompiles() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "count_primes");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "sieve should have loops");
}

#[test]
fn case10_dispatch_decompiles() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "dispatch");
    assert!(!output.is_empty(), "dispatch should produce output");
}

#[test]
fn case10_fast_inv_sqrt_decompiles() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "fast_inv_sqrt");
    assert!(output.contains("return"), "should return result, got:\n{output}");
}

#[test]
fn smoke_case10_main() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "main");
    assert!(!output.is_empty(), "main output should not be empty");
}
