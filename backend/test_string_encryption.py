"""
test_string_encryption.py
Unit tests and end-to-end integration tests for fallback function string literal encryption.
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


def test_basic_cout_usage():
    src = """#include <iostream>

void printGreeting() {
    std::cout << "Hello, World!" << std::endl;
}

int main() {
    printGreeting();
    return 0;
}
"""
    tmp_src = "/tmp/test_str_cout_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    # Assert plain string literal does NOT appear in obfuscated output
    assert '"Hello, World!"' not in obf_code, "Plain string literal 'Hello, World!' still visible in output"

    out_cpp = "/tmp/test_str_cout.cpp"
    out_bin = "/tmp/test_str_cout_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    output = run_res.stdout.strip()
    assert output == "Hello, World!", f"Expected 'Hello, World!', got '{output}'"

    print(f"[PASS] test_basic_cout_usage: output='{output}'")


def test_escape_sequence_correctness():
    src = """#include <iostream>

void printEscaped() {
    std::cout << "Line1\\nLine2 says \\"hi\\"" << std::endl;
}

int main() {
    printEscaped();
    return 0;
}
"""
    tmp_src = "/tmp/test_str_esc_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    out_cpp = "/tmp/test_str_esc.cpp"
    out_bin = "/tmp/test_str_esc_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    output = run_res.stdout.strip()
    expected = 'Line1\nLine2 says "hi"'
    assert output == expected, f"Expected '{expected!r}', got '{output!r}'"

    print(f"[PASS] test_escape_sequence_correctness: verified newline and quote unescaping")


def test_function_call_argument_context():
    src = """#include <iostream>

void logMsg(const char* msg) {
    std::cout << msg << std::endl;
}

void testCall() {
    logMsg("Direct function arg");
}

int main() {
    testCall();
    return 0;
}
"""
    tmp_src = "/tmp/test_str_fn_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    assert '"Direct function arg"' not in obf_code, "String literal 'Direct function arg' should be encrypted"

    out_cpp = "/tmp/test_str_fn.cpp"
    out_bin = "/tmp/test_str_fn_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    output = run_res.stdout.strip()
    assert output == "Direct function arg", f"Expected 'Direct function arg', got '{output}'"

    print(f"[PASS] test_function_call_argument_context: output='{output}'")


def test_safe_skip_verification():
    src = """#include <iostream>

void testArrayInit() {
    char buf[] = "unsafe array";
    std::cout << buf << std::endl;
}

int main() {
    testArrayInit();
    return 0;
}
"""
    tmp_src = "/tmp/test_str_skip_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    # Safe-skip verification: array initializer string MUST remain unencrypted plain text
    assert '"unsafe array"' in obf_code, "Array initializer 'unsafe array' should be safely skipped (unencrypted)"

    out_cpp = "/tmp/test_str_skip.cpp"
    out_bin = "/tmp/test_str_skip_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    output = run_res.stdout.strip()
    assert output == "unsafe array", f"Expected 'unsafe array', got '{output}'"

    print("[PASS] test_safe_skip_verification: char buf[]='unsafe array' safely skipped")


def test_multiple_strings_multiple_keys():
    src = """#include <iostream>

void printMulti() {
    std::cout << "String Alpha" << std::endl;
    std::cout << "String Beta" << std::endl;
}

int main() {
    printMulti();
    return 0;
}
"""
    tmp_src = "/tmp/test_str_keys_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    # Extract all XOR key bytes from generated decode functions (const unsigned char key = 0xXX;)
    keys = re.findall(r"const unsigned char key = (0x[0-9a-fA-F]+);", obf_code)
    assert len(keys) >= 2, f"Expected at least 2 generated decode helper keys, found {len(keys)}"
    assert keys[0] != keys[1], f"Expected different random XOR keys for distinct strings, got identical key '{keys[0]}'"

    out_cpp = "/tmp/test_str_keys.cpp"
    out_bin = "/tmp/test_str_keys_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    lines = run_res.stdout.strip().splitlines()
    assert lines == ["String Alpha", "String Beta"], f"Unexpected output: {lines}"

    print(f"[PASS] test_multiple_strings_multiple_keys: distinct keys {keys[0]} and {keys[1]}")


def test_number_and_string_interaction():
    src = """#include <iostream>

void printCombined() {
    std::cout << "Value is: " << 100 << std::endl;
}

int main() {
    printCombined();
    return 0;
}
"""
    tmp_src = "/tmp/test_str_num_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    assert '"Value is: "' not in obf_code, "String literal 'Value is: ' should be encrypted"
    assert '<< 100 <<' not in obf_code, "Integer literal '100' should be obfuscated"

    out_cpp = "/tmp/test_str_num.cpp"
    out_bin = "/tmp/test_str_num_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    output = run_res.stdout.strip()
    assert output == "Value is: 100", f"Expected 'Value is: 100', got '{output}'"

    print(f"[PASS] test_number_and_string_interaction: output='{output}'")


if __name__ == "__main__":
    test_basic_cout_usage()
    test_escape_sequence_correctness()
    test_function_call_argument_context()
    test_safe_skip_verification()
    test_multiple_strings_multiple_keys()
    test_number_and_string_interaction()
