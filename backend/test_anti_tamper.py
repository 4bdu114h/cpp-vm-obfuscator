"""
test_anti_tamper.py
Unit tests and end-to-end integration tests for bytecode integrity checking (anti-tamper).
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

from pipeline import fnv1a_32, PipelineContext, run_pipeline
from codegen import obfuscate


def test_hash_correctness_verification():
    # Verify FNV-1a 32-bit implementation against independently verified test vectors
    vectors = [
        (b"", 0x811c9dc5),
        (b"hello", 0x4f9f2cab),
        (b"123456789", 0xbb86b11c),
        (b"foo", 0xa9f37ed7),
    ]
    for data, expected in vectors:
        actual = fnv1a_32(data)
        assert actual == expected, f"fnv1a_32({data!r}) expected 0x{expected:08x}, got 0x{actual:08x}"
    print("[PASS] test_hash_correctness_verification: all 4 FNV-1a-32 test vectors matched")


def test_normal_untampered_execution():
    src = """#include <iostream>

int square(int x) {
    return x * x;
}

int main() {
    std::cout << square(7) << std::endl;
    return 0;
}
"""
    tmp_src = "/tmp/test_tamper_normal_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    out_cpp = "/tmp/test_tamper_normal.cpp"
    out_bin = "/tmp/test_tamper_normal_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    output = run_res.stdout.strip()
    assert output == "49", f"Expected '49', got '{output}'"

    print(f"[PASS] test_normal_untampered_execution: square(7) = {output}")


def test_tampering_is_detected():
    src = """#include <iostream>

int square(int x) {
    return x * x;
}

int main() {
    std::cout << square(7) << std::endl;
    return 0;
}
"""
    tmp_src = "/tmp/test_tamper_detect_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    # Programmatically tamper with one byte in the shared_bc_xxx array
    # Locate array definition static const unsigned char shared_bc_...[] = { ... };
    match = re.search(r"(static const unsigned char shared_bc_[a-zA-Z0-9_]+\s*\[\]\s*=\s*\{)([^}]+)(\};)", obf_code)
    assert match is not None, "Failed to locate shared_bc array in generated code"

    prefix, bytes_str, suffix = match.groups()
    byte_tokens = bytes_str.split(",")

    # Pick a byte token and modify it (e.g. change 0x01 to 0x02 or 0x00 to 0x01)
    tampered_tokens = list(byte_tokens)
    target_idx = 1 if len(tampered_tokens) > 1 else 0
    original_byte = tampered_tokens[target_idx].strip()
    tampered_byte = " 0xfe" if original_byte != "0xfe" else " 0x01"
    tampered_tokens[target_idx] = tampered_byte

    tampered_bytes_str = ",".join(tampered_tokens)
    tampered_obf_code = obf_code[:match.start()] + prefix + tampered_bytes_str + suffix + obf_code[match.end():]

    out_cpp = "/tmp/test_tamper_patched.cpp"
    out_bin = "/tmp/test_tamper_patched_bin"
    with open(out_cpp, "w") as f:
        f.write(tampered_obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    output = run_res.stdout.strip()
    # Expect safe sentinel return 0 instead of 49
    assert output == "0", f"Expected safe sentinel '0' on tampered bytecode, got '{output}'"

    print(f"[PASS] test_tampering_is_detected: tampered bytecode safely returned sentinel '{output}'")


def test_checksum_randomization_across_runs():
    src = """#include <iostream>

int calculate(int a, int b) {
    return (a + b) * (a - b);
}

int main() {
    std::cout << calculate(10, 5) << std::endl;
    return 0;
}
"""
    tmp_src1 = "/tmp/test_tamper_rand1.cpp"
    tmp_src2 = "/tmp/test_tamper_rand2.cpp"

    with open(tmp_src1, "w") as f:
        f.write(src)
    with open(tmp_src2, "w") as f:
        f.write(src)

    from pipeline import PIPELINE_STAGES

    ctx1 = PipelineContext(source_code=src, filename=tmp_src1)
    for stage in PIPELINE_STAGES:
        stage(ctx1)

    ctx2 = PipelineContext(source_code=src, filename=tmp_src2)
    for stage in PIPELINE_STAGES:
        stage(ctx2)

    checksum1 = ctx1.artifacts.get("bytecode_checksum")
    checksum2 = ctx2.artifacts.get("bytecode_checksum")

    assert checksum1 is not None and checksum2 is not None, "Bytecode checksum artifact missing"
    assert checksum1 != checksum2, f"Expected distinct checksums due to opcode shuffling, got identical {hex(checksum1)}"

    print(f"[PASS] test_checksum_randomization_across_runs: run1={hex(checksum1)}, run2={hex(checksum2)}")


if __name__ == "__main__":
    test_hash_correctness_verification()
    test_normal_untampered_execution()
    test_tampering_is_detected()
    test_checksum_randomization_across_runs()
