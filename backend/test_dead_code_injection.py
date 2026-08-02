"""
test_dead_code_injection.py
Unit tests and end-to-end integration tests for fallback function dead code injection.
"""
import os
import sys
import re
import subprocess
import clang.cindex as ci

_CANDIDATE_LIBCLANG_PATHS = [
    "/usr/lib/x86_64-linux-gnu/libclang-18.so.1",
    "/usr/lib/llvm-18/lib/libclang.so",
    "/opt/homebrew/opt/llvm/lib/libclang.dylib",
    "/usr/local/opt/llvm/lib/libclang.dylib",
    "/Library/Developer/CommandLineTools/usr/lib/libclang.dylib",
]
for p in _CANDIDATE_LIBCLANG_PATHS:
    if os.path.exists(p):
        ci.Config.set_library_file(p)
        break

sys.path.insert(0, os.path.dirname(__file__))

from codegen import obfuscate
from pipeline import generate_always_true_condition, generate_junk_code


def test_always_true_condition_correctness():
    conditions = [generate_always_true_condition() for _ in range(60)]

    # 1. Python evaluation
    py_passed = 0
    for cond in conditions:
        if eval(cond) is True:
            py_passed += 1
    assert py_passed == 60, f"Python evaluation failed for some conditions: {py_passed}/60 passed"

    # 2. C++ static_assert compilation check
    assert_checks = "\n".join([f'static_assert({cond}, "condition failed");' for cond in conditions])
    cpp_code = f"""#include <iostream>

int main() {{
{assert_checks}
    return 0;
}}
"""
    tmp_cpp = "/tmp/test_dci_static_assert.cpp"
    tmp_bin = "/tmp/test_dci_static_assert_bin"
    with open(tmp_cpp, "w") as f:
        f.write(cpp_code)

    comp = subprocess.run(["g++", "-std=c++17", tmp_cpp, "-o", tmp_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"C++ static_assert compilation failed: {comp.stderr}"

    print(f"[PASS] test_always_true_condition_correctness: 60/60 conditions verified via Python eval and C++ static_assert")


def test_behavior_preservation():
    src = """#include <iostream>

void printStatus(int code) {
    std::cout << "Status code: " << code << std::endl;
    std::cout << "Operation completed." << std::endl;
}

int main() {
    printStatus(200);
    return 0;
}
"""
    tmp_src = "/tmp/test_dci_preserv_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    # Verify dead code injection occurred (if ( or else present in printStatus body)
    assert "if (" in obf_code and "else {" in obf_code, "Expected dead code injection in fallback function"

    out_cpp = "/tmp/test_dci_preserv.cpp"
    out_bin = "/tmp/test_dci_preserv_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    lines = run_res.stdout.strip().splitlines()
    expected = ["Status code: 200", "Operation completed."]
    assert lines == expected, f"Expected {expected}, got {lines}"

    print(f"[PASS] test_behavior_preservation: output match confirmed {lines}")


def test_dead_branch_never_executes():
    # Empirical proof: test an instrumented decoy branch to confirm condition is strictly true
    cond = generate_always_true_condition()
    instrumented_code = f"""#include <iostream>

int main() {{
    bool dead_branch_hit = false;
    if ({cond}) {{
        // Real branch
    }} else {{
        dead_branch_hit = true;
    }}
    if (dead_branch_hit) {{
        std::cout << "DEAD_BRANCH_EXECUTED" << std::endl;
    }} else {{
        std::cout << "REAL_BRANCH_EXECUTED" << std::endl;
    }}
    return 0;
}}
"""
    tmp_cpp = "/tmp/test_dci_instrumented.cpp"
    tmp_bin = "/tmp/test_dci_instrumented_bin"
    with open(tmp_cpp, "w") as f:
        f.write(instrumented_code)

    comp = subprocess.run(["g++", "-std=c++17", tmp_cpp, "-o", tmp_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([tmp_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"
    assert run_res.stdout.strip() == "REAL_BRANCH_EXECUTED", f"Dead branch was unexpectedly taken! Output: {run_res.stdout}"

    # Also verify that generate_junk_code() produces strictly side-effect-free code
    junk = generate_junk_code()
    assert "(void)" in junk, "Junk code should include (void) cast to prevent unused variable warning"
    assert "std::cout" not in junk and "return" not in junk, "Junk code must be side-effect-free"

    print("[PASS] test_dead_branch_never_executes: empirically proved always-true condition never takes decoy path")


def test_skip_already_flattened_functions():
    src = """#include <iostream>

void processSteps(int a, int b) {
    std::cout << "Step 1" << std::endl;
    std::cout << "Step 2" << std::endl;
    std::cout << "Step 3" << std::endl;
    std::cout << "Step 4" << std::endl;
    std::cout << "Step 5" << std::endl;
}

int main() {
    processSteps(1, 2);
    return 0;
}
"""
    tmp_src = "/tmp/test_dci_skip_flat_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    # Extract processSteps body
    func_match = re.search(r"void processSteps[^{]+\{([^}]+)\}", obf_code)

    # Function should be flattened (contains while(true) and switch)
    assert "while (true)" in obf_code and "switch (" in obf_code, "processSteps should be flattened"
    
    # Function body should NOT contain injected dead code blocks (else { int dead_)
    if func_match:
        func_body = func_match.group(1)
        assert "else { int dead_" not in func_body, "Flattened function should NOT receive dead code injection"

    out_cpp = "/tmp/test_dci_skip_flat.cpp"
    out_bin = "/tmp/test_dci_skip_flat_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    print("[PASS] test_skip_already_flattened_functions: flattened function correctly skipped dead code injection")


if __name__ == "__main__":
    test_always_true_condition_correctness()
    test_behavior_preservation()
    test_dead_branch_never_executes()
    test_skip_already_flattened_functions()
