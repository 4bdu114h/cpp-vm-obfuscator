"""
test_arrays.py
Unit tests and end-to-end integration tests for fixed-size local int array virtualization.
"""
import os
import sys
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

from bytecode_gen import (
    eligibility_check, FunctionCompiler,
    OP_LOAD_ARG, OP_LOAD_CONST, OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD,
    OP_CMP_GT, OP_CMP_GE, OP_CMP_LT, OP_CMP_LE, OP_CMP_EQ, OP_CMP_NE,
    OP_JMP, OP_JMP_IF_TRUE, OP_JMP_IF_FALSE, OP_RET_CONST, OP_RET_REG,
    OP_ARR_LOAD, OP_ARR_STORE
)
from pipeline import generate_opcode_shuffle
from codegen import obfuscate, _macos_clang_args


def run_bytecode_with_mem(code, args):
    regs = [0] * 16
    mem = [0] * 256
    pc = 0
    while pc < len(code):
        op = code[pc]
        pc += 1
        if op == OP_LOAD_ARG:
            r, a = code[pc], code[pc + 1]
            pc += 2
            regs[r] = args[a]
        elif op == OP_LOAD_CONST:
            r = code[pc]
            pc += 1
            val = int.from_bytes(code[pc:pc + 8], "little", signed=True)
            pc += 8
            regs[r] = val
        elif op in (OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD,
                    OP_CMP_GT, OP_CMP_GE, OP_CMP_LT, OP_CMP_LE, OP_CMP_EQ, OP_CMP_NE):
            r, a, b = code[pc], code[pc + 1], code[pc + 2]
            pc += 3
            av, bv = regs[a], regs[b]
            if op == OP_ADD:
                regs[r] = av + bv
            elif op == OP_SUB:
                regs[r] = av - bv
            elif op == OP_MUL:
                regs[r] = av * bv
            elif op == OP_DIV:
                regs[r] = int(av / bv)
            elif op == OP_MOD:
                regs[r] = av % bv
            elif op == OP_CMP_GT:
                regs[r] = 1 if av > bv else 0
            elif op == OP_CMP_GE:
                regs[r] = 1 if av >= bv else 0
            elif op == OP_CMP_LT:
                regs[r] = 1 if av < bv else 0
            elif op == OP_CMP_LE:
                regs[r] = 1 if av <= bv else 0
            elif op == OP_CMP_EQ:
                regs[r] = 1 if av == bv else 0
            elif op == OP_CMP_NE:
                regs[r] = 1 if av != bv else 0
        elif op == OP_JMP:
            target = int.from_bytes(code[pc:pc + 2], "little")
            pc = target
        elif op == OP_JMP_IF_TRUE:
            r = code[pc]
            target = int.from_bytes(code[pc + 1:pc + 3], "little")
            pc += 3
            if regs[r] != 0:
                pc = target
        elif op == OP_JMP_IF_FALSE:
            r = code[pc]
            target = int.from_bytes(code[pc + 1:pc + 3], "little")
            pc += 3
            if regs[r] == 0:
                pc = target
        elif op == OP_ARR_LOAD:
            r, base, idx_r = code[pc], code[pc + 1], code[pc + 2]
            pc += 3
            regs[r] = mem[base + regs[idx_r]]
        elif op == OP_ARR_STORE:
            base, idx_r, src_r = code[pc], code[pc + 1], code[pc + 2]
            pc += 3
            mem[base + regs[idx_r]] = regs[src_r]
        elif op == OP_RET_CONST:
            return int.from_bytes(code[pc:pc + 8], "little", signed=True)
        elif op == OP_RET_REG:
            r = code[pc]
            return regs[r]
        else:
            raise RuntimeError(f"unknown opcode {op} at pc {pc-1}")
    raise RuntimeError("fell off end of bytecode without returning")


def test_array_reversal():
    src = """
int sumReversed(int a, int b, int c, int d, int e) {
    int arr[5] = {0, 0, 0, 0, 0};
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d; arr[4] = e;
    int total = 0;
    int i = 0;
    while (i < 5) {
        total = total + arr[4 - i];
        i = i + 1;
    }
    return total;
}
"""
    tmp_path = "/tmp/test_arr_rev.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    fn = [cur for cur in tu.cursor.get_children() if cur.spelling == "sumReversed"][0]

    eligible, reason = eligibility_check(fn)
    assert eligible, f"sumReversed should be eligible, got: {reason}"

    compiler = FunctionCompiler()
    bytecode = compiler.compile_function(fn)

    test_inputs = [
        (1, 2, 3, 4, 5),
        (10, 20, 30, 40, 50),
        (-5, 0, 15, -2, 100),
    ]
    for inp in test_inputs:
        expected = sum(inp)
        actual = run_bytecode_with_mem(bytecode, list(inp))
        assert actual == expected, f"sumReversed{inp}: expected {expected}, got {actual}"
    print("[PASS] test_array_reversal")


def test_initializer_with_expressions():
    src = """
int initExprs(int a, int b, int c) {
    int arr[3] = {a + 1, b * 2, c - 3};
    return arr[0] + arr[1] + arr[2];
}
"""
    tmp_path = "/tmp/test_arr_init.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    fn = [cur for cur in tu.cursor.get_children() if cur.spelling == "initExprs"][0]

    eligible, reason = eligibility_check(fn)
    assert eligible, f"initExprs should be eligible, got: {reason}"

    compiler = FunctionCompiler()
    bytecode = compiler.compile_function(fn)

    # 10 + 1 + 20*2 + 30-3 = 11 + 40 + 27 = 78
    actual = run_bytecode_with_mem(bytecode, [10, 20, 30])
    assert actual == 78, f"initExprs(10, 20, 30): expected 78, got {actual}"
    print("[PASS] test_initializer_with_expressions")


def test_array_rejections():
    src = """
int testFloatArray() {
    float arr[5];
    return 0;
}

int testParamArray(int arr[5]) {
    return arr[0];
}

int testPointerVar() {
    int x = 5;
    int* p = &x;
    return *p;
}
"""
    tmp_path = "/tmp/test_arr_rej.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())

    fn_float = [cur for cur in tu.cursor.get_children() if cur.spelling == "testFloatArray"][0]
    fn_param = [cur for cur in tu.cursor.get_children() if cur.spelling == "testParamArray"][0]
    fn_ptr = [cur for cur in tu.cursor.get_children() if cur.spelling == "testPointerVar"][0]

    el_f, reason_f = eligibility_check(fn_float)
    assert not el_f, "Float array should be ineligible"
    assert "float" in reason_f.lower() or "unsupported" in reason_f.lower(), f"Unexpected reason: {reason_f}"

    el_p, reason_p = eligibility_check(fn_param)
    assert not el_p, "Array as parameter should be ineligible"
    assert "parameter" in reason_p.lower(), f"Unexpected reason: {reason_p}"

    el_ptr, reason_ptr = eligibility_check(fn_ptr)
    assert not el_ptr, "Pointer variable should be ineligible"

    print("[PASS] test_array_rejections")


def test_opcode_shuffling_interaction():
    shuffles = [generate_opcode_shuffle(seed=i) for i in range(5)]

    # Confirm OP_ARR_LOAD (0x15) and OP_ARR_STORE (0x16) are present in every shuffle
    for s in shuffles:
        assert 0x15 in s, "OP_ARR_LOAD missing from opcode shuffle"
        assert 0x16 in s, "OP_ARR_STORE missing from opcode shuffle"

    # Confirm shuffled target values vary across runs
    targets_load = {s[0x15] for s in shuffles}
    targets_store = {s[0x16] for s in shuffles}
    assert len(targets_load) > 1, f"OP_ARR_LOAD target opcode should vary, got {targets_load}"
    assert len(targets_store) > 1, f"OP_ARR_STORE target opcode should vary, got {targets_store}"

    print("[PASS] test_opcode_shuffling_interaction")


def test_end_to_end_arrays():
    src = """#include <iostream>

int sumReversed(int a, int b, int c, int d, int e) {
    int arr[5] = {0, 0, 0, 0, 0};
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d; arr[4] = e;
    int total = 0;
    int i = 0;
    while (i < 5) {
        total = total + arr[4 - i];
        i = i + 1;
    }
    return total;
}

int main() {
    std::cout << sumReversed(10, 20, 30, 40, 50) << std::endl;
    return 0;
}
"""
    tmp_src = "/tmp/test_arr_e2e_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    out_cpp = "/tmp/test_arr_e2e.cpp"
    out_bin = "/tmp/test_arr_e2e_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    output = run_res.stdout.strip()
    assert output == "150", f"Expected sumReversed(10,20,30,40,50) to output '150', got '{output}'"

    print(f"[PASS] test_end_to_end_arrays: sumReversed(10, 20, 30, 40, 50)={output}")


def test_array_stress_recycling():
    src = """
int stressArray(int scale) {
    int arr[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    int total = 0;
    for (int i = 0; i < 10; i = i + 1) {
        arr[i] = arr[i] * scale + i - 1;
        total = total + arr[i];
    }
    return total;
}
"""
    tmp_path = "/tmp/test_arr_stress.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    fn = [cur for cur in tu.cursor.get_children() if cur.spelling == "stressArray"][0]

    eligible, reason = eligibility_check(fn)
    assert eligible, f"stressArray should be eligible, got: {reason}"

    # 1. Verify that WITHOUT recycling, compilation fails with register exhaustion
    compiler_no_recycle = FunctionCompiler()
    compiler_no_recycle.free_scratch_regs = lambda: None
    failed_as_expected = False
    try:
        compiler_no_recycle.compile_function(fn)
    except RuntimeError as e:
        if "ran out of registers" in str(e):
            failed_as_expected = True
    assert failed_as_expected, "stressArray should fail without register recycling"

    # 2. Verify that WITH recycling, compilation succeeds and yields correct result
    compiler = FunctionCompiler()
    bytecode = compiler.compile_function(fn)

    for scale in range(-3, 6):
        expected = sum((i + 1) * scale + i - 1 for i in range(10))
        actual = run_bytecode_with_mem(bytecode, [scale])
        assert actual == expected, f"stressArray({scale}): expected {expected}, got {actual}"

    print("[PASS] test_array_stress_recycling (fails without recycling, passes range(-3, 6) with recycling)")


if __name__ == "__main__":
    test_array_reversal()
    test_initializer_with_expressions()
    test_array_rejections()
    test_opcode_shuffling_interaction()
    test_end_to_end_arrays()
    test_array_stress_recycling()
