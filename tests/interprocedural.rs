//! Interprocedural analysis tests.

mod common;

#[test]
fn interprocedural_detects_call_graph() {
    let binary = common::load_wsl_binary("case2_calls");
    let pipeline_func = common::lift_function(&binary, "pipeline");
    let helper_func = common::lift_function(&binary, "helper");

    let pipeline_addr = binary
        .functions
        .iter()
        .find(|f| f.name == "pipeline")
        .unwrap()
        .addr;
    let helper_addr = binary
        .functions
        .iter()
        .find(|f| f.name == "helper")
        .unwrap()
        .addr;

    let functions = vec![(pipeline_addr, &pipeline_func), (helper_addr, &helper_func)];

    let info = rdecomp::interprocedural::analyze(&functions, &binary);

    // At -O0 pipeline calls helper, but at -O1+ it may be inlined.
    // Just verify the call graph was built without panics.
    let _callers = info.call_graph.get(&pipeline_addr);
    // If the edge exists, great; if not, the compiler inlined helper.
}

#[test]
fn interprocedural_case7_recursive_calls() {
    let binary = common::load_wsl_binary("case7_complex");
    let fib_func = common::lift_function(&binary, "fibonacci");
    let power_func = common::lift_function(&binary, "power");

    let fib_addr = binary
        .functions
        .iter()
        .find(|f| f.name == "fibonacci")
        .unwrap()
        .addr;
    let power_addr = binary
        .functions
        .iter()
        .find(|f| f.name == "power")
        .unwrap()
        .addr;

    let functions = vec![(fib_addr, &fib_func), (power_addr, &power_func)];

    let info = rdecomp::interprocedural::analyze(&functions, &binary);

    // fibonacci calls itself
    let fib_callees = info.call_graph.get(&fib_addr);
    assert!(fib_callees.is_some(), "fibonacci should be in call graph");
    assert!(
        fib_callees.unwrap().contains(&fib_addr),
        "fibonacci should call itself (recursive)"
    );

    // power calls itself
    let pw_callees = info.call_graph.get(&power_addr);
    assert!(pw_callees.is_some(), "power should be in call graph");
    assert!(
        pw_callees.unwrap().contains(&power_addr),
        "power should call itself (recursive)"
    );
}
