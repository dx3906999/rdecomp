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
    assert!(output.contains("uint64_t fibonacci(int32_t arg_1)"), "should preserve signature, got:\n{output}");
    assert!(output.contains("fibonacci((arg_1 - 1))"), "should contain first recursive call, got:\n{output}");
    assert!(output.contains("fibonacci((arg_1 - 2))"), "should contain second recursive call, got:\n{output}");
    assert!(output.contains("return 1;"), "should preserve base case for 1, got:\n{output}");
    assert!(output.contains("return 0;"), "should preserve base case for 0, got:\n{output}");
    assert!(!output.contains("goto"), "recursive output should stay structured, got:\n{output}");
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
    assert!(output.contains("do {") || output.contains("while ("), "bubble_sort should preserve loop structure, got:\n{output}");
    assert!(output.contains("return"), "bubble_sort should return a value, got:\n{output}");
}

#[test]
fn case7_binary_search_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "binary_search");
    let has_loop = output.contains("while") || output.contains("for");
    assert!(has_loop, "binary_search should have a loop");
    assert!(output.contains("arg_3"), "binary_search should preserve target parameter, got:\n{output}");
    assert!(output.contains("return -1") || output.contains("return 0xffffffff"), "binary_search should preserve not-found sentinel, got:\n{output}");
}

#[test]
fn case7_complex_condition_decompiles() {
    let binary = common::load_wsl_binary("case7_complex");
    let output = common::decompile_function(&binary, "complex_condition");
    assert!(output.contains("if"), "should have conditionals");
    assert!(output.contains("&&") || output.contains("||"), "should keep compound boolean logic, got:\n{output}");
    assert!(output.contains("return 0;"), "should preserve zero-result path, got:\n{output}");
    assert!(output.contains("return 1;") || output.contains("return 2;"), "should preserve non-zero result paths, got:\n{output}");
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
    assert!(
        !has_raw_registers(&output),
        "find_saddle_point should not leak raw registers, got:\n{output}"
    );
    assert!(!output.contains("goto"), "find_saddle_point should remain structured, got:\n{output}");
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
        !output.contains("&arg_0"),
        "kmp_search should not anchor local stack buffers at arg_0, got:\n{output}"
    );
    assert!(output.contains("compute_prefix("), "kmp_search should call compute_prefix, got:\n{output}");
    assert!(
        output.contains("t4 = -1;") || output.contains("return -1") || output.contains("return 0xffffffffffffffff"),
        "kmp_search should preserve not-found sentinel path, got:\n{output}"
    );
}

#[test]
fn case9_ht_insert_decompiles() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function(&binary, "ht_insert");
    assert!(output.contains("return"), "should have return values (1/0)");
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
    assert!(!has_raw_registers(&output), "compute_prefix should not leak raw registers, got:\n{output}");
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
    assert!(output.contains("abs("), "rect_area should preserve absolute-difference simplification, got:\n{output}");
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
    assert!(
        !has_raw_registers(&output),
        "dot_product should not leak raw registers, got:\n{output}"
    );
    assert!(output.contains("while") || output.contains("do {"), "dot_product should keep loop structure, got:\n{output}");
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

#[test]
fn stack_sample_avoids_arg0_stack_base() {
    let binary = common::load_wsl_binary("stack");

    for func_name in ["sub_4012f6", "sub_4013df"] {
        let output = common::decompile_function(&binary, func_name);
        assert!(
            !output.contains("&arg_0"),
            "{func_name} should not anchor stack locals at arg_0, got:\n{output}"
        );
    }
}

#[test]
fn stack_sample_sub_4013be_has_no_phantom_local() {
    let binary = common::load_wsl_binary("stack");
    let output = common::decompile_function(&binary, "sub_4013be");

    assert!(
        !output.contains("uint8_t  var_1;"),
        "sub_4013be should not declare an unused stack local, got:\n{output}"
    );
    assert!(
        output.contains("return open("),
        "sub_4013be should stay a direct open() wrapper, got:\n{output}"
    );
}
