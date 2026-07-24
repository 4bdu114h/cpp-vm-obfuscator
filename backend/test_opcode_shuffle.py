"""
test_opcode_shuffle.py
Unit tests for per-build opcode shuffling determinism and round-trip byte inversion.
"""
import os
import clang.cindex as ci
import sys

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

from bytecode_gen import eligibility_check, FunctionCompiler
from pipeline import generate_opcode_shuffle, apply_opcode_shuffle, apply_inverse_opcode_shuffle


def test_determinism():
    m1 = generate_opcode_shuffle(seed=42)
    m2 = generate_opcode_shuffle(seed=42)
    assert m1 == m2, "Same seed must produce identical opcode mappings"

    s1 = generate_opcode_shuffle()
    s2 = generate_opcode_shuffle()
    assert s1 != s2, "Unseeded calls should produce different opcode mappings"
    print("[PASS] test_determinism")


def test_round_trip():
    source = """
    int calculateRiskScore(int a, int b) {
        int score = a * 7 + b * 3;
        if (score > 100) {
            return 1;
        }
        return 0;
    }
    """
    with open("/tmp/test_shuffle.cpp", "w") as f:
        f.write(source)

    index = ci.Index.create()
    tu = index.parse("/tmp/test_shuffle.cpp", args=["-std=c++17"])
    func_node = None
    for child in tu.cursor.get_children():
        if child.kind == ci.CursorKind.FUNCTION_DECL and child.spelling == "calculateRiskScore":
            func_node = child
            break
    assert func_node is not None, "Function node calculateRiskScore not found"

    ok, reason = eligibility_check(func_node)
    assert ok, f"Function not eligible: {reason}"

    compiler = FunctionCompiler()
    orig_bc = compiler.compile_function(func_node)

    shuffle_map = generate_opcode_shuffle(seed=123)
    shuffled_bc = apply_opcode_shuffle(orig_bc, shuffle_map)
    assert shuffled_bc != orig_bc, "Shuffled bytecode should differ from original"

    restored_bc = apply_inverse_opcode_shuffle(shuffled_bc, shuffle_map)
    assert restored_bc == orig_bc, "Round-trip inverted bytecode must equal original bytecode byte-for-byte"

    print("[PASS] test_round_trip")


if __name__ == "__main__":
    test_determinism()
    test_round_trip()
