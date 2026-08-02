"""
test_structs.py
Tests local struct (int-fields-only) support in cpp-vm-obfuscator across 6 primary categories:
1. Basic struct field read/write correctness & memory-aware interpreter verification
2. Multiple struct locals in one function (non-overlapping memory allocations)
3. Rejection tests (non-int field, struct parameter, nested struct/array field)
4. End-to-end compile-and-run binary test with g++ -std=c++17
5. Opcode shuffling interaction with struct field access (OP_ARR_LOAD/OP_ARR_STORE)
6. Struct + Array memory coexistence test in the same function
"""

import os
import sys
import subprocess
from typing import Tuple, List
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
from bytecode_gen import FunctionCompiler, eligibility_check, OP_ARR_LOAD, OP_ARR_STORE


def build_and_run(source_code: str, tmp_prefix: str, opcode_shuffle_seed=None) -> Tuple[str, str, int]:
    src_path = f"/tmp/{tmp_prefix}_input.cpp"
    cpp_path = f"/tmp/{tmp_prefix}_obf.cpp"
    bin_path = f"/tmp/{tmp_prefix}_bin"

    with open(src_path, "w") as f:
        f.write(source_code)

    obf_code, report, errs = obfuscate(source_code, src_path, opcode_shuffle_seed=opcode_shuffle_seed)
    assert not errs, f"Obfuscation failed with errors: {errs}"

    with open(cpp_path, "w") as f:
        f.write(obf_code)

    cmd = ["g++", "-std=c++17"] + _macos_clang_args() + [cpp_path, "-o", bin_path]
    comp = subprocess.run(cmd, capture_output=True, text=True)
    assert comp.returncode == 0, f"g++ compilation failed:\n{comp.stderr}"

    run_res = subprocess.run([bin_path], capture_output=True, text=True)
    return obf_code, run_res.stdout.strip(), run_res.returncode


def run_interpreter(bytecode: bytes, args: List[int]) -> int:
    """Python interpreter for testing bytecode execution with VM memory array."""
    regs = [0] * 16
    mem = [0] * 256
    pc = 0

    while pc < len(bytecode):
        op = bytecode[pc]
        pc += 1

        if op == 0x01:  # OP_LOAD_ARG r, idx
            r, idx = bytecode[pc], bytecode[pc + 1]
            pc += 2
            regs[r] = args[idx]
        elif op == 0x02:  # OP_LOAD_CONST r, val64
            r = bytecode[pc]
            val = int.from_bytes(bytecode[pc+1:pc+9], byteorder='little', signed=True)
            pc += 9
            regs[r] = val
        elif op == 0x03:  # OP_MOV r, s
            r, s = bytecode[pc], bytecode[pc+1]
            pc += 2
            regs[r] = regs[s]
        elif op == 0x04:  # OP_ADD dst, r1, r2
            dst, r1, r2 = bytecode[pc], bytecode[pc+1], bytecode[pc+2]
            pc += 3
            regs[dst] = regs[r1] + regs[r2]
        elif op == 0x05:  # OP_SUB dst, r1, r2
            dst, r1, r2 = bytecode[pc], bytecode[pc+1], bytecode[pc+2]
            pc += 3
            regs[dst] = regs[r1] - regs[r2]
        elif op == 0x06:  # OP_MUL dst, r1, r2
            dst, r1, r2 = bytecode[pc], bytecode[pc+1], bytecode[pc+2]
            pc += 3
            regs[dst] = regs[r1] * regs[r2]
        elif op == 0x12:  # OP_RET_CONST val64
            val = int.from_bytes(bytecode[pc:pc+8], byteorder='little', signed=True)
            return val
        elif op == 0x13:  # OP_RET_REG r
            r = bytecode[pc]
            return regs[r]
        elif op == 0x15:  # OP_ARR_LOAD dst, base_offset, idx_r
            dst, base_offset, idx_r = bytecode[pc], bytecode[pc+1], bytecode[pc+2]
            pc += 3
            regs[dst] = mem[base_offset + regs[idx_r]]
        elif op == 0x16:  # OP_ARR_STORE base_offset, idx_r, src_r
            base_offset, idx_r, src_r = bytecode[pc], bytecode[pc+1], bytecode[pc+2]
            pc += 3
            mem[base_offset + regs[idx_r]] = regs[src_r]
        else:
            raise RuntimeError(f"Unhandled opcode in interpreter: 0x{op:02x}")

    return 0


def test_basic_struct_correctness():
    src = """
struct Point {
    int x;
    int y;
};

int distanceSquared(int ax, int ay, int bx, int by) {
    Point a;
    a.x = ax;
    a.y = ay;
    Point b = {bx, by};
    int dx = a.x - b.x;
    int dy = a.y - b.y;
    return dx * dx + dy * dy;
}
"""
    tmp_path = "/tmp/test_struct_basic.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    funcs = {cur.spelling: cur for cur in tu.cursor.get_children() if cur.kind == ci.CursorKind.FUNCTION_DECL}
    func = funcs["distanceSquared"]

    el, reason = eligibility_check(func)
    assert el, f"distanceSquared should be eligible, got: {reason}"

    compiler = FunctionCompiler()
    bc = compiler.compile_function(func)

    # Test across input combinations using Python interpreter
    test_cases = [
        (0, 0, 3, 4),    # 3^2 + 4^2 = 25
        (1, 2, 4, 6),    # 3^2 + 4^2 = 25
        (10, 20, 5, 8),  # 5^2 + 12^2 = 169
        (-3, -4, 0, 0),  # 3^2 + 4^2 = 25
    ]

    for ax, ay, bx, by in test_cases:
        res = run_interpreter(bc, [ax, ay, bx, by])
        expected = (ax - bx) ** 2 + (ay - by) ** 2
        assert res == expected, f"Mismatch for ({ax},{ay}), ({bx},{by}): Got {res}, Expected {expected}"

    print("[PASS] test_basic_struct_correctness: Verified interpreter results across 4 test cases")


def test_multiple_struct_locals():
    src = """
struct Rect {
    int x;
    int y;
    int w;
    int h;
};

int rectAreaSum(int x1, int y1, int w1, int h1, int x2, int y2, int w2, int h2) {
    Rect r1 = {x1, y1, w1, h1};
    Rect r2;
    r2.x = x2;
    r2.y = y2;
    r2.w = w2;
    r2.h = h2;
    int a1 = r1.w * r1.h;
    int a2 = r2.w * r2.h;
    return a1 + a2;
}
"""
    tmp_path = "/tmp/test_struct_multi.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    funcs = {cur.spelling: cur for cur in tu.cursor.get_children() if cur.kind == ci.CursorKind.FUNCTION_DECL}
    func = funcs["rectAreaSum"]

    el, reason = eligibility_check(func)
    assert el, f"rectAreaSum should be eligible, got: {reason}"

    compiler = FunctionCompiler()
    bc = compiler.compile_function(func)

    res = run_interpreter(bc, [0, 0, 5, 10, 10, 10, 3, 4])
    assert res == 50 + 12, f"Area sum mismatch: Got {res}, Expected 62"
    print("[PASS] test_multiple_struct_locals: Verified non-overlapping memory for multiple structs")


def test_struct_rejections():
    # (a) Float field
    src_float = """
struct FloatPoint {
    int x;
    float y;
};
int badFloat(int x) {
    FloatPoint p;
    return x;
}
"""
    # (b) Struct parameter
    src_param = """
struct Point { int x; int y; };
int badParam(Point p) {
    return p.x;
}
"""
    # (c) Struct containing array field
    src_arr_field = """
struct ArrayStruct {
    int x;
    int data[5];
};
int badArrField(int x) {
    ArrayStruct s;
    return x;
}
"""

    index = ci.Index.create()

    # Test float field
    tu = index.parse("/tmp/rej_float.cpp", unsaved_files=[("/tmp/rej_float.cpp", src_float)], args=["-std=c++17"] + _macos_clang_args())
    funcs = {cur.spelling: cur for cur in tu.cursor.get_children() if cur.kind == ci.CursorKind.FUNCTION_DECL}
    el, reason = eligibility_check(funcs["badFloat"])
    assert not el, "Struct with float field should be ineligible"
    assert "non-int" in reason.lower(), f"Unexpected reason: {reason}"

    # Test struct param
    tu = index.parse("/tmp/rej_param.cpp", unsaved_files=[("/tmp/rej_param.cpp", src_param)], args=["-std=c++17"] + _macos_clang_args())
    funcs = {cur.spelling: cur for cur in tu.cursor.get_children() if cur.kind == ci.CursorKind.FUNCTION_DECL}
    el, reason = eligibility_check(funcs["badParam"])
    assert not el, "Struct parameter should be ineligible"
    assert "unsupported parameter" in reason.lower(), f"Unexpected reason: {reason}"

    # Test array inside struct
    tu = index.parse("/tmp/rej_arr.cpp", unsaved_files=[("/tmp/rej_arr.cpp", src_arr_field)], args=["-std=c++17"] + _macos_clang_args())
    funcs = {cur.spelling: cur for cur in tu.cursor.get_children() if cur.kind == ci.CursorKind.FUNCTION_DECL}
    el, reason = eligibility_check(funcs["badArrField"])
    assert not el, "Struct containing array field should be ineligible"
    assert "non-int" in reason.lower(), f"Unexpected reason: {reason}"

    print("[PASS] test_struct_rejections: All 3 rejection categories correctly flagged as ineligible")


def test_end_to_end_compile_and_run():
    src = """#include <iostream>

struct Point {
    int x;
    int y;
};

int distanceSquared(int ax, int ay, int bx, int by) {
    Point a;
    a.x = ax;
    a.y = ay;
    Point b = {bx, by};
    int dx = a.x - b.x;
    int dy = a.y - b.y;
    return dx * dx + dy * dy;
}

int main() {
    int res = distanceSquared(0, 0, 3, 4);
    std::cout << "DistanceSquared: " << res << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "test_struct_e2e")
    assert code == 0, f"Binary exited with code {code}"
    assert output == "DistanceSquared: 25", f"Output mismatch! Got: '{output}', Expected: 'DistanceSquared: 25'"
    print("[PASS] test_end_to_end_compile_and_run: distanceSquared(0,0,3,4) = 25")


def test_opcode_shuffling_interaction():
    src = """#include <iostream>

struct Vector2D {
    int dx;
    int dy;
};

int dotProduct(int x1, int y1, int x2, int y2) {
    Vector2D v1 = {x1, y1};
    Vector2D v2 = {x2, y2};
    return v1.dx * v2.dx + v1.dy * v2.dy;
}

int main() {
    std::cout << dotProduct(3, 4, 5, 6) << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "test_struct_shuffle", opcode_shuffle_seed=424242)
    assert code == 0, f"Binary exited with code {code}"
    assert output == "39", f"Opcode shuffle output mismatch! Got: '{output}', Expected: '39'"
    print("[PASS] test_opcode_shuffling_interaction: dotProduct(3,4,5,6) = 39 with seed 424242")


def test_struct_and_array_coexistence():
    src = """#include <iostream>

struct Point {
    int x;
    int y;
};

int structAndArrayCombo(int val) {
    int arr[3] = {10, 20, 30};
    Point p = {val, val * 2};
    arr[1] = p.x + p.y;
    return arr[0] + arr[1] + arr[2];
}

int main() {
    std::cout << structAndArrayCombo(5) << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "test_struct_array_coexistence")
    assert code == 0, f"Binary exited with code {code}"
    # arr = [10, 20, 30], p = {5, 10}, p.x + p.y = 15 -> arr[1] = 15 -> sum = 10 + 15 + 30 = 55
    assert output == "55", f"Coexistence output mismatch! Got: '{output}', Expected: '55'"
    print("[PASS] test_struct_and_array_coexistence: structAndArrayCombo(5) = 55")


if __name__ == "__main__":
    test_basic_struct_correctness()
    test_multiple_struct_locals()
    test_struct_rejections()
    test_end_to_end_compile_and_run()
    test_opcode_shuffling_interaction()
    test_struct_and_array_coexistence()
