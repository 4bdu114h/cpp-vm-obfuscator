"""
test_number_obfuscation.py
Unit tests and end-to-end integration tests for number literal obfuscation.
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

from pipeline import obfuscate_number_literal
from codegen import obfuscate


def test_math_evaluation():
    test_values = [0, -5, -100, 1, 7, 42, 100, 255, 1000, 65535, 123456, 2147483647]
    for val in test_values:
        expr = obfuscate_number_literal(val)
        # Evaluate C++ hex expression natively using Python eval
        evaluated = eval(expr)
        assert evaluated == val, f"Evaluation mismatch for {val}: got {evaluated} from expr {expr!r}"
    print("[PASS] test_math_evaluation")


def test_randomization():
    val = 100
    results = {obfuscate_number_literal(val) for _ in range(20)}
    assert len(results) > 1, f"Repeated calls for value {val} should produce randomized expressions, got: {results}"
    print("[PASS] test_randomization")


def test_literal_with_suffix():
    src = """#include <iostream>
int main() {
    unsigned int x = 100u;
    for (int i = 0; i < 1; i++) {
        x += i;
    }
    std::cout << x << std::endl;
    return 0;
}
"""
    tmp_src = "/tmp/test_suffix_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors on literal with suffix: {errs}"
    assert "main" in obf_code, "main function missing from obfuscated output"

    out_cpp = "/tmp/suffix_obf.cpp"
    out_bin = "/tmp/suffix_obf_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed for suffix literal: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed for suffix literal: {run_res.stderr}"
    assert run_res.stdout.strip() == "100", f"Expected output '100', got '{run_res.stdout.strip()}'"

    print("[PASS] test_literal_with_suffix")


def test_value_near_int_max():
    val = 2147483600  # 0x7FFFFCF0, close to 0x7FFFFFFF
    for _ in range(50):
        expr = obfuscate_number_literal(val)
        hex_literals = re.findall(r"0x[0-9a-fA-F]+", expr)
        for h in hex_literals:
            h_val = int(h, 16)
            assert h_val <= 0x7FFFFFFF, f"Hex literal {h} ({h_val}) in expression {expr!r} exceeds 0x7FFFFFFF"
    print("[PASS] test_value_near_int_max")


def test_end_to_end_fallback():
    src = """#include <iostream>
int main() {
    int arr[5] = {0, 0, 0, 0, 0};
    for (int i = 0; i < 5; i++) {
        arr[i] = i * 10 + 3;
    }
    std::cout << arr[4] << std::endl;
    return 0;
}
"""
    tmp_src = "/tmp/test_num_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    # Extract main() function section from output
    assert "main" in obf_code, "main function missing from obfuscated output"
    main_section = obf_code[obf_code.find("main"):]

    # Bare numbers 5, 10, 3 should be replaced in main body
    assert not re.search(r"\barr\[5\]\b", main_section), "Bare literal 5 still present in array declaration"
    assert not re.search(r"\*\s*10\b", main_section), "Bare literal 10 still present in multiplication"
    assert not re.search(r"\+\s*3\b", main_section), "Bare literal 3 still present in addition"

    # Compile and execute
    out_cpp = "/tmp/arr_obf.cpp"
    out_bin = "/tmp/arr_obf_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"
    output = run_res.stdout.strip()
    assert output == "43", f"Expected execution output '43', got '{output}'"

    print("[PASS] test_end_to_end_fallback")


if __name__ == "__main__":
    test_math_evaluation()
    test_randomization()
    test_literal_with_suffix()
    test_value_near_int_max()
    test_end_to_end_fallback()
