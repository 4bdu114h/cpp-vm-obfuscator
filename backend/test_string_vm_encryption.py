"""
test_string_vm_encryption.py
Tests encryption of string-VM constant pools in cpp-vm-obfuscator across 4 primary categories:
1. Constants are genuinely encrypted (plain string text absent from output, XOR byte array present)
2. Execution correctness preserved (compiles with g++ -std=c++17 and returns exact expected string)
3. Multiple constants get distinct XOR keys
4. Interaction with fallback string encryption (string VM + fallback encrypted string work seamlessly)
"""

import os
import re
import subprocess
import sys
from typing import Tuple
import clang.cindex as ci

_CANDIDATE_LIBCLANG_PATHS = [
    '/opt/homebrew/opt/llvm/lib/libclang.dylib',
    '/usr/lib/x86_64-linux-gnu/libclang-18.so.1',
]
for p in _CANDIDATE_LIBCLANG_PATHS:
    if os.path.exists(p):
        ci.Config.set_library_file(p)
        break

sys.path.insert(0, '.')
from codegen import obfuscate, _macos_clang_args


def build_and_run(source_code: str, tmp_prefix: str) -> Tuple[str, str]:
    src_path = f"/tmp/{tmp_prefix}_input.cpp"
    cpp_path = f"/tmp/{tmp_prefix}_obf.cpp"
    bin_path = f"/tmp/{tmp_prefix}_bin"

    with open(src_path, "w") as f:
        f.write(source_code)

    obf_code, report, errs = obfuscate(source_code, src_path)
    assert not errs, f"Obfuscation failed with errors: {errs}"

    with open(cpp_path, "w") as f:
        f.write(obf_code)

    cmd = ["g++", "-std=c++17"] + _macos_clang_args() + [cpp_path, "-o", bin_path]
    comp = subprocess.run(cmd, capture_output=True, text=True)
    assert comp.returncode == 0, f"g++ compilation failed:\n{comp.stderr}"

    run_res = subprocess.run([bin_path], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Runtime execution failed with code {run_res.returncode}"

    return obf_code, run_res.stdout.strip()


def test_constants_are_genuinely_encrypted():
    src = """#include <iostream>
#include <string>

std::string greet(std::string name) {
    return "Hello, " + name;
}

int main() {
    std::cout << greet("World") << std::endl;
    return 0;
}
"""
    obf_code, output = build_and_run(src, "test_str_enc_1")

    # Verify plain string "Hello, " is NOT in obf_code
    assert '"Hello, "' not in obf_code, "Plain string literal 'Hello, ' found in output!"

    # Verify str_dec_ helper function is present in pool_arr
    assert "str_dec_" in obf_code, "Expected str_dec_ decode function in output"
    assert "pool_str_greet_" in obf_code or "pool_str_" in obf_code, "Expected pool array in output"

    print("[PASS] test_constants_are_genuinely_encrypted")


def test_correctness_preserved():
    src = """#include <iostream>
#include <string>

std::string greet(std::string name) {
    return "Hello, " + name;
}

int main() {
    std::cout << greet("World") << std::endl;
    std::cout << greet("Developer") << std::endl;
    return 0;
}
"""
    obf_code, output = build_and_run(src, "test_str_enc_2")
    lines = output.splitlines()
    assert lines == ["Hello, World", "Hello, Developer"], f"Unexpected output: {lines}"
    print("[PASS] test_correctness_preserved")


def test_multiple_constants_different_keys():
    src = """#include <iostream>
#include <string>

std::string formatMsg(std::string name) {
    return "Welcome, " + name + "!";
}

int main() {
    std::cout << formatMsg("Alice") << std::endl;
    return 0;
}
"""
    obf_code, output = build_and_run(src, "test_str_enc_3")
    assert output == "Welcome, Alice!", f"Unexpected output: {output}"

    # Extract all XOR keys from generated str_dec_ helper functions
    keys = re.findall(r"const unsigned char key = (0x[0-9a-fA-F]+);", obf_code)
    assert len(keys) >= 2, f"Expected at least 2 XOR keys, found: {keys}"
    assert len(set(keys[:2])) == 2, f"XOR keys for multiple string VM constants should be distinct! Got: {keys[:2]}"
    print(f"[PASS] test_multiple_constants_different_keys: distinct keys {keys[0]} and {keys[1]}")


def test_interaction_with_fallback_string_encryption():
    src = """#include <iostream>
#include <string>

std::string formatStr(std::string input) {
    return "Prefix: " + input;
}

void printInfo(int val) {
    std::cout << "Calculated value: " << val << std::endl;
    int a = val + 1;
    int b = a * 2;
    int c = b + 3;
    std::cout << "Final result: " << c << std::endl;
}

int main() {
    std::cout << formatStr("Core") << std::endl;
    printInfo(10);
    return 0;
}
"""
    obf_code, output = build_and_run(src, "test_str_enc_4")

    # Plain strings should be absent
    assert '"Prefix: "' not in obf_code, "Plain string 'Prefix: ' should be encrypted"
    assert '"Calculated value: "' not in obf_code, "Plain string 'Calculated value: ' should be encrypted"
    assert '"Final result: "' not in obf_code, "Plain string 'Final result: ' should be encrypted"

    # Verify execution output match
    lines = output.splitlines()
    expected = ["Prefix: Core", "Calculated value: 10", "Final result: 25"]
    assert lines == expected, f"Unexpected output:\nGot: {lines}\nExpected: {expected}"
    print("[PASS] test_interaction_with_fallback_string_encryption")


if __name__ == "__main__":
    test_constants_are_genuinely_encrypted()
    test_correctness_preserved()
    test_multiple_constants_different_keys()
    test_interaction_with_fallback_string_encryption()
