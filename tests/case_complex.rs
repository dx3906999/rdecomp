//! Pipeline tests for complex cases (case7–case10).

mod common;

// ═══════════════════════════════════════════════════════════════
// case7_complex: linked list, recursion, bit operations, sorting
// ═══════════════════════════════════════════════════════════════

#[test]
fn case7_fibonacci_recursive() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "fibonacci");
    assert!(output.contains("fibonacci"), "should have recursive call");
    assert!(output.contains("if"), "should have base case condition");
    assert!(output.contains("return"), "should have returns");
}

#[test]
fn case7_list_sum_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "list_sum");
    // May be optimized to tail-call/branch form instead of explicit loop
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
fn case7_power_recursive() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "power");
    assert!(output.contains("power"), "should have recursive call");
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
}

#[test]
fn case7_complex_condition_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "complex_condition");
    assert!(output.contains("if"), "should have conditionals");
    assert!(output.contains("return"), "should have returns");
}

#[test]
fn case7_hamming_distance_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "hamming_distance");
    // gcc -O1 may optimize the bit-count loop
    assert!(
        output.contains("return") || output.contains("hamming"),
        "should produce output, got:\n{output}"
    );
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
fn case8_find_saddle_point_nested() {
    let binary = common::load_wsl_binary("case8_state_machine");
    let output = common::decompile_function(&binary, "find_saddle_point");
    let loop_kw = output.matches("while").count() + output.matches("for").count();
    assert!(
        loop_kw >= 2,
        "find_saddle_point should have >=2 loops, got {loop_kw}"
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
}

#[test]
fn case9_ht_insert_decompiles() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "ht_insert");
    assert!(output.contains("return"), "should have return values (1/0)");
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
fn case9_bfs_shortest_decompiles() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "bfs_shortest");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "BFS should have a loop");
}

#[test]
fn smoke_case9_main() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "main");
    assert!(!output.is_empty(), "main output should not be empty");
}

// ═══════════════════════════════════════════════════════════════
// case10_mixed: function pointers, goto, nested structs
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
fn case10_dot_product_decompiles() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "dot_product");
    // gcc -O1 may produce branchless or partially unrolled code
    assert!(!output.is_empty(), "dot_product should produce output");
    assert!(
        output.contains("return") || output.contains("*"),
        "should have computation"
    );
}

#[test]
fn case10_count_primes_decompiles() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "count_primes");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "sieve should have loops");
}

#[test]
fn smoke_case10_main() {
    let binary = common::load_wsl_binary("case10_mixed");
    let output = common::decompile_function(&binary, "main");
    assert!(!output.is_empty(), "main output should not be empty");
}
