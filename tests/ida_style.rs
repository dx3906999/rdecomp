mod common;

#[test]
fn ida_style_uses_hexrays_signature_types() {
    let binary = common::load_wsl_binary("case1_control");
    let output = common::decompile_function_with_style(&binary, "classify", true);

    assert!(
        output.contains("__fastcall classify(__int32 arg_1)"),
        "IDA style should use Hex-Rays signature formatting, got:\n{output}"
    );
    assert!(!output.contains("uint32_t classify("), "IDA style should not fall back to C99 signature, got:\n{output}");
}

#[test]
fn ida_style_uses_void_for_empty_parameter_lists() {
    let binary = common::load_wsl_binary("case1_control");
    let output = common::decompile_function_with_style(&binary, "main", true);

    assert!(output.contains("(void)"), "IDA style should render empty parameter list as (void), got:\n{output}");
}

#[test]
fn ida_style_relabels_block_labels() {
    let binary = common::load_wsl_binary("case9_algorithms");
    let output = common::decompile_function_with_style(&binary, "kmp_search", true);

    assert!(output.contains("LABEL_"), "IDA style should emit LABEL_N labels, got:\n{output}");
    assert!(!output.contains("goto bb"), "IDA style should not expose raw bb labels, got:\n{output}");
}