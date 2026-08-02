"""
test_control_flow_flattening.py
Unit tests and end-to-end integration tests for fallback function control-flow flattening.
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


def test_basic_control_flow_flattening():
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
    tmp_src = "/tmp/test_cf_basic_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    # Verify structural flattening presence: while (true) and switch (cf_state_)
    assert "while (true)" in obf_code, "Expected 'while (true)' state machine loop in flattened output"
    assert "switch (" in obf_code, "Expected 'switch (' state machine dispatcher in flattened output"

    out_cpp = "/tmp/test_cf_basic.cpp"
    out_bin = "/tmp/test_cf_basic_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    lines = run_res.stdout.strip().splitlines()
    expected = ["Step 1", "Step 2", "Step 3", "Step 4", "Step 5"]
    assert lines == expected, f"Expected {expected}, got {lines}"

    print(f"[PASS] test_basic_control_flow_flattening: output lines={lines}")


def test_variable_scope_crossing():
    src = """#include <iostream>

void processData(int a, int b) {
    int v1 = a + 10;
    int v2 = b + 20;
    std::cout << "Inter: " << v1 << std::endl;
    int v3 = v1 * v2;
    std::cout << "Final: " << v3 << std::endl;
}

int main() {
    processData(3, 4);
    return 0;
}
"""
    tmp_src = "/tmp/test_cf_vars_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    assert "while (true)" in obf_code, "Expected control-flow flattening with variable lifting"

    out_cpp = "/tmp/test_cf_vars.cpp"
    out_bin = "/tmp/test_cf_vars_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    lines = run_res.stdout.strip().splitlines()
    assert lines == ["Inter: 13", "Final: 312"], f"Expected ['Inter: 13', 'Final: 312'], got {lines}"

    print(f"[PASS] test_variable_scope_crossing: clean compilation and correct execution {lines}")


def test_threshold_skipping():
    src = """#include <iostream>

void shortFunc(int a) {
    std::cout << "Line 1" << std::endl;
    std::cout << "Line 2" << std::endl;
    std::cout << "Line 3" << std::endl;
}

int main() {
    shortFunc(5);
    return 0;
}
"""
    tmp_src = "/tmp/test_cf_thresh_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    # Extract shortFunc function text from output
    short_func_match = re.search(r"void shortFunc[^{]+\{([^}]+)\}", obf_code)
    if short_func_match:
        func_body = short_func_match.group(1)
        assert "while (true)" not in func_body, "shortFunc (<4 stmts) should NOT be flattened"

    out_cpp = "/tmp/test_cf_thresh.cpp"
    out_bin = "/tmp/test_cf_thresh_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    print("[PASS] test_threshold_skipping: function with <4 statements safely skipped")


def test_interaction_with_existing_transforms():
    src = """#include <iostream>

void combinedTransform(int x) {
    std::cout << "Starting computation..." << std::endl;
    int a = x + 100;
    std::cout << "Base value: " << a << std::endl;
    int b = a * 2 + 50;
    std::cout << "Combined total: " << b << std::endl;
}

int main() {
    combinedTransform(10);
    return 0;
}
"""
    tmp_src = "/tmp/test_cf_combo_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    # Verify all 3 transforms present in output:
    # 1. Flattening
    assert "while (true)" in obf_code and "switch (" in obf_code, "Control flow flattening missing"
    # 2. String encryption (plain strings hidden)
    assert '"Starting computation..."' not in obf_code, "String literal 'Starting computation...' should be encrypted"
    # 3. Number literal obfuscation (plain 100 or 50 hidden)
    assert " 100;" not in obf_code and " 50;" not in obf_code, "Integer literals 100/50 should be obfuscated"

    out_cpp = "/tmp/test_cf_combo.cpp"
    out_bin = "/tmp/test_cf_combo_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    lines = run_res.stdout.strip().splitlines()
    assert lines == ["Starting computation...", "Base value: 110", "Combined total: 270"], f"Unexpected output: {lines}"

    print(f"[PASS] test_interaction_with_existing_transforms: verified flattening + numbers + strings ({lines})")


def test_multi_variable_decl_skipping():
    src = """#include <iostream>

void multiDeclFunc(int x) {
    int a = 1, b = 2;
    std::cout << "Step A: " << a << std::endl;
    std::cout << "Step B: " << b << std::endl;
    std::cout << "Step C: " << (a + b + x) << std::endl;
}

int main() {
    multiDeclFunc(10);
    return 0;
}
"""
    tmp_src = "/tmp/test_cf_multidecl_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    # Extract multiDeclFunc from output
    func_match = re.search(r"void multiDeclFunc[^{]+\{([^}]+)\}", obf_code)
    if func_match:
        func_body = func_match.group(1)
        assert "while (true)" not in func_body, "multiDeclFunc (containing multi-var decl) should NOT be flattened"

    out_cpp = "/tmp/test_cf_multidecl.cpp"
    out_bin = "/tmp/test_cf_multidecl_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    lines = run_res.stdout.strip().splitlines()
    assert lines == ["Step A: 1", "Step B: 2", "Step C: 13"], f"Unexpected output: {lines}"

    print(f"[PASS] test_multi_variable_decl_skipping: multi-var decl function safely left unflattened with correct output ({lines})")


if __name__ == "__main__":
    test_basic_control_flow_flattening()
    test_variable_scope_crossing()
    test_threshold_skipping()
    test_interaction_with_existing_transforms()
    test_multi_variable_decl_skipping()
