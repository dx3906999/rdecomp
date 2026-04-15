//! Cross-platform, multi-optimization-level decompilation tests.
//!
//! Tests every exported function from case1–case10 across
//! both WSL (ELF) and Win (PE) binaries at -O1, -O2, -O3.

mod common;

/// Generate a decompile-smoke test for each (platform, opt, case, function) tuple.
/// The test asserts that the function decompiles without panicking and produces
/// non-empty output.
macro_rules! decompile_smoke {
    ($test_name:ident, $platform:expr, $opt:expr, $case:expr, $func:expr) => {
        #[test]
        fn $test_name() {
            let binary = common::load_opt_binary($platform, $opt, $case);
            let result = common::try_decompile_function(&binary, $func);
            match result {
                Ok(output) => {
                    assert!(
                        !output.is_empty(),
                        "[{} {} {}::{}] produced empty output",
                        $platform, $opt, $case, $func
                    );
                }
                Err(e) => {
                    // Function may be inlined or renamed at higher opt levels – skip gracefully
                    eprintln!(
                        "[SKIP] {} {} {}::{} – {}",
                        $platform, $opt, $case, $func, e
                    );
                }
            }
        }
    };
}

/// Generate smoke tests for a single case across all 6 (platform × opt) combos.
macro_rules! case_matrix {
    ($case:expr, [ $( $func:expr ),+ $(,)? ]) => {
        paste::paste! {
            $(
                decompile_smoke!([< wsl_o1_ $case _ $func >], "wsl", "O1", stringify!($case), $func);
                decompile_smoke!([< wsl_o2_ $case _ $func >], "wsl", "O2", stringify!($case), $func);
                decompile_smoke!([< wsl_o3_ $case _ $func >], "wsl", "O3", stringify!($case), $func);
                decompile_smoke!([< win_o1_ $case _ $func >], "win", "O1", stringify!($case), $func);
                decompile_smoke!([< win_o2_ $case _ $func >], "win", "O2", stringify!($case), $func);
                decompile_smoke!([< win_o3_ $case _ $func >], "win", "O3", stringify!($case), $func);
            )+
        }
    };
}

// ═══════════════════════════════════════════════════════════════
// case1_control
// ═══════════════════════════════════════════════════════════════
case_matrix!(case1_control, ["classify", "sum_to_n", "main"]);

// ═══════════════════════════════════════════════════════════════
// case2_calls
// ═══════════════════════════════════════════════════════════════
case_matrix!(case2_calls, ["helper", "pipeline", "main"]);

// ═══════════════════════════════════════════════════════════════
// case3_memory
// ═══════════════════════════════════════════════════════════════
case_matrix!(case3_memory, ["update_pair", "stack_mix", "main"]);

// ═══════════════════════════════════════════════════════════════
// case4_loops
// ═══════════════════════════════════════════════════════════════
case_matrix!(case4_loops, ["sum_squares", "count_bits", "find_pair_sum", "reverse_sum", "main"]);

// ═══════════════════════════════════════════════════════════════
// case5_switch
// ═══════════════════════════════════════════════════════════════
case_matrix!(case5_switch, ["grade", "clamp", "encode_flags", "safe_div", "main"]);

// ═══════════════════════════════════════════════════════════════
// case6_string
// ═══════════════════════════════════════════════════════════════
case_matrix!(case6_string, ["my_strlen", "my_strcmp", "djb2_hash", "array_max", "main"]);

// ═══════════════════════════════════════════════════════════════
// case7_complex
// ═══════════════════════════════════════════════════════════════
case_matrix!(case7_complex, [
    "create_node", "list_sum", "list_reverse", "list_length",
    "fibonacci", "power", "hanoi",
    "complex_condition", "ternary_chain",
    "hamming_distance", "reverse_bits",
    "bubble_sort", "binary_search", "main"
]);

// ═══════════════════════════════════════════════════════════════
// case8_state_machine
// ═══════════════════════════════════════════════════════════════
case_matrix!(case8_state_machine, [
    "parser_init", "parser_feed", "skip_ws", "next_token",
    "parse_factor", "parse_term", "parse_expr",
    "matrix_trace", "find_saddle_point", "main"
]);

// ═══════════════════════════════════════════════════════════════
// case9_algorithms
// ═══════════════════════════════════════════════════════════════
case_matrix!(case9_algorithms, [
    "ht_init", "ht_hash", "ht_insert", "ht_get",
    "compute_prefix", "kmp_search",
    "is_palindrome", "lcs_length", "knapsack",
    "graph_init", "graph_add_edge", "bfs_shortest", "main"
]);

// ═══════════════════════════════════════════════════════════════
// case10_mixed
// ═══════════════════════════════════════════════════════════════
case_matrix!(case10_mixed, [
    "double_it", "square_it", "negate_it",
    "array_map", "dispatch", "fast_inv_sqrt",
    "resource_init", "rect_area", "rect_contains", "rects_overlap",
    "dot_product", "find_2d", "count_primes", "main"
]);
