//! IR structure tests: lift functions and verify IR properties.

mod common;

#[test]
fn lifted_classify_has_multiple_blocks() {
    let binary = common::load_wsl_binary("case1_control");
    let func = common::lift_function(&binary, "classify");
    assert!(
        func.blocks.len() >= 3,
        "classify should have >=3 IR blocks after optimization"
    );
}

#[test]
fn lifted_sum_to_n_has_return() {
    let binary = common::load_wsl_binary("case1_control");
    let func = common::lift_function(&binary, "sum_to_n");
    let has_return = func
        .blocks
        .iter()
        .any(|b| matches!(&b.terminator, rdecomp::ir::Terminator::Return(Some(_))));
    assert!(has_return, "sum_to_n should have a Return(Some) terminator");
}
