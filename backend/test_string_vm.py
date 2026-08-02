"""
test_string_vm.py
Tests std::string VM virtualization support in cpp-vm-obfuscator across 7 test categories:
1. Basic concatenation correctness
2. Multi-part concatenation (3+ pieces)
3. String equality and inequality (==, !=)
4. String literal escape sequences (\n, \")
5. Correct fallback for out-of-scope string patterns (mixed int/string params, string loops)
6. Opcode shuffling interaction with string opcodes (0x18-0x1D)
7. Full regression verification
"""
import os
import sys
import subprocess
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
from pipeline import run_pipeline, generate_opcode_shuffle, apply_opcode_shuffle, apply_inverse_opcode_shuffle, PipelineContext, stage_parse, stage_eligibility_check, stage_virtualize, stage_shuffle_opcodes
from bytecode_gen import string_function_eligibility_check, StringFunctionCompiler, OP_STR_LOAD_ARG, OP_STR_LOAD_CONST, OP_STR_CONCAT, OP_STR_EQ, OP_STR_NE, OP_RET_STR, OP_RET_STR_INT


def build_and_run(source_code: str, tmp_prefix: str) -> str:
    cpp_path = f"/tmp/{tmp_prefix}.cpp"
    bin_path = f"/tmp/{tmp_prefix}"
    with open(cpp_path, "w") as f:
        f.write(source_code)

    obf_code, report, errs = obfuscate(source_code, cpp_path)
    assert not errs, f"Obfuscation errors: {errs}"

    obf_cpp_path = f"/tmp/{tmp_prefix}_obf.cpp"
    with open(obf_cpp_path, "w") as f:
        f.write(obf_code)

    comp_args = ["g++", "-std=c++17", obf_cpp_path, "-o", bin_path] + _macos_clang_args()
    comp = subprocess.run(comp_args, capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed:\n{comp.stderr}\nCode:\n{obf_code}"

    run_res = subprocess.run([bin_path], capture_output=True, text=True)
    return run_res.stdout


def test_basic_concatenation():
    src = """#include <iostream>
#include <string>

std::string greet(std::string name) {
    return "Hello, " + name;
}

int main() {
    std::cout << greet("World") << std::endl;
    std::cout << greet("Alice Bob") << std::endl;
    std::cout << greet("") << std::endl;
    return 0;
}
"""
    output = build_and_run(src, "test_str_concat")
    lines = [line.rstrip('\r\n') for line in output.strip('\r\n').splitlines()]
    assert lines == ["Hello, World", "Hello, Alice Bob", "Hello, "], f"Unexpected output: {lines}"
    print("[PASS] test_basic_concatenation")


def test_multipart_concatenation():
    src = """#include <iostream>
#include <string>

std::string formatName(std::string title, std::string first, std::string last) {
    return title + " " + first + " " + last + "!";
}

int main() {
    std::cout << formatName("Dr.", "Jane", "Doe") << std::endl;
    return 0;
}
"""
    output = build_and_run(src, "test_str_multipart")
    lines = [line.rstrip('\r\n') for line in output.strip('\r\n').splitlines()]
    assert lines == ["Dr. Jane Doe!"], f"Unexpected output: {lines}"
    print("[PASS] test_multipart_concatenation")


def test_string_equality():
    src = """#include <iostream>
#include <string>

bool isSame(std::string a, std::string b) {
    return a == b;
}

bool isDifferent(std::string a, std::string b) {
    return a != b;
}

int main() {
    std::cout << isSame("alpha", "alpha") << std::endl;
    std::cout << isSame("alpha", "beta") << std::endl;
    std::cout << isDifferent("alpha", "beta") << std::endl;
    std::cout << isDifferent("alpha", "alpha") << std::endl;
    return 0;
}
"""
    output = build_and_run(src, "test_str_eq")
    lines = [line.rstrip('\r\n') for line in output.strip('\r\n').splitlines()]
    assert lines == ["1", "0", "1", "0"], f"Unexpected output: {lines}"
    print("[PASS] test_string_equality")


def test_string_escape_sequences():
    src = r"""#include <iostream>
#include <string>

std::string formatQuote(std::string msg) {
    return "Line 1\n\"" + msg + "\"\nLine 2";
}

int main() {
    std::cout << formatQuote("Quoted Text") << std::endl;
    return 0;
}
"""
    output = build_and_run(src, "test_str_escape")
    expected = 'Line 1\n"Quoted Text"\nLine 2'
    assert output.strip() == expected, f"Unexpected output:\n{repr(output)}\nExpected:\n{repr(expected)}"
    print("[PASS] test_string_escape_sequences")


def test_out_of_scope_fallback():
    src = """#include <iostream>
#include <string>

std::string mixedParams(std::string s, int n) {
    return s;
}

std::string stringLoop(std::string s) {
    for (int i = 0; i < 3; i++) {
        s = s + "!";
    }
    return s;
}

int main() {
    std::cout << mixedParams("Test", 42) << std::endl;
    std::cout << stringLoop("Loop") << std::endl;
    return 0;
}
"""
    cpp_path = "/tmp/test_str_fallback.cpp"
    with open(cpp_path, "w") as f:
        f.write(src)

    obf_code, report, errs = obfuscate(src, cpp_path)
    assert not errs, f"Obfuscation errors: {errs}"

    # Verify neither function was virtualized
    report_str = "\n".join(report)
    assert "mixedParams: NOT virtualized" in report_str, f"mixedParams should fall back: {report_str}"
    assert "stringLoop: NOT virtualized" in report_str, f"stringLoop should fall back: {report_str}"

    output = build_and_run(src, "test_str_fallback")
    lines = [line.rstrip('\r\n') for line in output.strip('\r\n').splitlines()]
    assert lines == ["Test", "Loop!!!"], f"Unexpected execution output: {lines}"
    print("[PASS] test_out_of_scope_fallback")


def test_opcode_shuffling_interaction():
    mapping = generate_opcode_shuffle(seed=42)
    # Verify all string opcodes 0x18-0x1E are present in mapping
    for op in (OP_STR_LOAD_ARG, OP_STR_LOAD_CONST, OP_STR_CONCAT, OP_STR_EQ, OP_STR_NE, OP_RET_STR, OP_RET_STR_INT):
        assert op in mapping, f"Opcode 0x{op:02x} missing from shuffle mapping"

    # Verify round-trip shuffle for string bytecode buffer
    orig_bc = bytes([OP_STR_LOAD_CONST, 0, 0, OP_STR_LOAD_ARG, 1, 0, OP_STR_CONCAT, 2, 0, 1, OP_RET_STR, 2])
    shuffled_bc = apply_opcode_shuffle(orig_bc, mapping)
    unshuffled_bc = apply_inverse_opcode_shuffle(shuffled_bc, mapping)
    assert unshuffled_bc == orig_bc, f"Round-trip shuffle failed: {unshuffled_bc.hex()} != {orig_bc.hex()}"
    print("[PASS] test_opcode_shuffling_interaction")


if __name__ == "__main__":
    test_basic_concatenation()
    test_multipart_concatenation()
    test_string_equality()
    test_string_escape_sequences()
    test_out_of_scope_fallback()
    test_opcode_shuffling_interaction()
