"""
test_function_calls.py
Unit tests and end-to-end integration tests for single-level function call virtualization support.
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
    OP_ARR_LOAD, OP_ARR_STORE, OP_CALL
)
from pipeline import generate_opcode_shuffle
from codegen import obfuscate, _macos_clang_args


def run_bytecode_calls(code, args, entry_pc=0):
    regs = [0] * 16
    mem = [0] * 256
    saved_regs = [0] * 16
    saved_pc = 0
    in_call = False
    call_dst_reg = 0
    call_args = [0] * 4
    saved_args = args
    current_args = args
    pc = entry_pc

    while pc < len(code):
        op = code[pc]
        pc += 1
        if op == OP_LOAD_ARG:
            r, a = code[pc], code[pc + 1]
            pc += 2
            regs[r] = current_args[a]
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
        elif op == OP_CALL:
            target = int.from_bytes(code[pc:pc + 2], "little")
            a0, a1, a2, a3 = code[pc + 2], code[pc + 3], code[pc + 4], code[pc + 5]
            r_dst = code[pc + 6]
            pc += 7

            saved_regs = list(regs)
            saved_pc = pc
            in_call = True
            call_dst_reg = r_dst

            call_args = [0] * 4
            if a0 != 0xFF:
                call_args[0] = regs[a0]
            if a1 != 0xFF:
                call_args[1] = regs[a1]
            if a2 != 0xFF:
                call_args[2] = regs[a2]
            if a3 != 0xFF:
                call_args[3] = regs[a3]

            saved_args = current_args
            current_args = call_args

            regs = [0] * 16
            pc = target
        elif op == OP_RET_CONST:
            val = int.from_bytes(code[pc:pc + 8], "little", signed=True)
            if in_call:
                regs = list(saved_regs)
                regs[call_dst_reg] = val
                current_args = saved_args
                pc = saved_pc
                in_call = False
            else:
                return val
        elif op == OP_RET_REG:
            r = code[pc]
            val = regs[r]
            if in_call:
                regs = list(saved_regs)
                regs[call_dst_reg] = val
                current_args = saved_args
                pc = saved_pc
                in_call = False
            else:
                return val
        else:
            raise RuntimeError(f"unknown opcode {op} at pc {pc-1}")
    raise RuntimeError("fell off end of bytecode without returning")


def test_basic_call_correctness():
    src = """
int square(int x) {
    return x * x;
}
int sumOfSquares(int a, int b) {
    return square(a) + square(b);
}
"""
    tmp_path = "/tmp/test_call_basic.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    funcs = {cur.spelling: cur for cur in tu.cursor.get_children() if cur.kind == ci.CursorKind.FUNCTION_DECL}

    el_sq, r_sq = eligibility_check(funcs["square"], known_leaf_functions=set())
    assert el_sq, f"square should pass Pass 1 (leaf), got: {r_sq}"

    el_sum_p1, _ = eligibility_check(funcs["sumOfSquares"], known_leaf_functions=set())
    assert not el_sum_p1, "sumOfSquares should fail Pass 1 (contains call)"

    el_sum_p2, r_sum = eligibility_check(funcs["sumOfSquares"], known_leaf_functions={"square"})
    assert el_sum_p2, f"sumOfSquares should pass Pass 2, got: {r_sum}"

    # Compile leaf first, then caller
    offsets = {}
    shared_bytecode = bytearray()

    offsets["square"] = len(shared_bytecode)
    compiler_sq = FunctionCompiler(func_entry_offsets=offsets)
    bc_sq = compiler_sq.compile_function(funcs["square"])
    shared_bytecode.extend(bc_sq)

    offsets["sumOfSquares"] = len(shared_bytecode)
    compiler_sum = FunctionCompiler(func_entry_offsets=offsets)
    bc_sum = compiler_sum.compile_function(funcs["sumOfSquares"])
    shared_bytecode.extend(bc_sum)

    full_bc = bytes(shared_bytecode)
    for a in range(-5, 6):
        for b in range(-5, 6):
            expected = a * a + b * b
            actual = run_bytecode_calls(full_bc, [a, b], entry_pc=offsets["sumOfSquares"])
            assert actual == expected, f"sumOfSquares({a}, {b}): expected {expected}, got {actual}"

    print("[PASS] test_basic_call_correctness")


def test_caller_local_state_preservation():
    """Canary test verifying caller's local variables (e.g. 'keep') are not clobbered across calls."""
    src = """
int addOne(int x) {
    return x + 1;
}
int callTwiceKeepState(int n) {
    int keep = n * 100;
    int a = addOne(n);
    int b = addOne(a);
    return keep + b;
}
"""
    tmp_path = "/tmp/test_call_canary.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    funcs = {cur.spelling: cur for cur in tu.cursor.get_children() if cur.kind == ci.CursorKind.FUNCTION_DECL}

    el_add, _ = eligibility_check(funcs["addOne"], known_leaf_functions=set())
    assert el_add

    el_canary, _ = eligibility_check(funcs["callTwiceKeepState"], known_leaf_functions={"addOne"})
    assert el_canary

    offsets = {}
    shared_bytecode = bytearray()

    offsets["addOne"] = len(shared_bytecode)
    c_add = FunctionCompiler(func_entry_offsets=offsets)
    shared_bytecode.extend(c_add.compile_function(funcs["addOne"]))

    offsets["callTwiceKeepState"] = len(shared_bytecode)
    c_canary = FunctionCompiler(func_entry_offsets=offsets)
    shared_bytecode.extend(c_canary.compile_function(funcs["callTwiceKeepState"]))

    full_bc = bytes(shared_bytecode)
    for n in range(1, 11):
        expected = n * 100 + (n + 2)
        actual = run_bytecode_calls(full_bc, [n], entry_pc=offsets["callTwiceKeepState"])
        assert actual == expected, f"callTwiceKeepState({n}): expected {expected}, got {actual}"

    print("[PASS] test_caller_local_state_preservation (canary test)")


def test_multiple_distinct_callees():
    src = """
int doubleVal(int x) {
    return x * 2;
}
int tripleVal(int x) {
    return x * 3;
}
int combine(int a, int b) {
    return doubleVal(a) + tripleVal(b);
}
"""
    tmp_path = "/tmp/test_call_multi.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    funcs = {cur.spelling: cur for cur in tu.cursor.get_children() if cur.kind == ci.CursorKind.FUNCTION_DECL}

    known_leafs = {"doubleVal", "tripleVal"}
    el_comb, _ = eligibility_check(funcs["combine"], known_leaf_functions=known_leafs)
    assert el_comb

    offsets = {}
    shared_bytecode = bytearray()

    for name in ["doubleVal", "tripleVal"]:
        offsets[name] = len(shared_bytecode)
        comp = FunctionCompiler(func_entry_offsets=offsets)
        shared_bytecode.extend(comp.compile_function(funcs[name]))

    offsets["combine"] = len(shared_bytecode)
    comp_comb = FunctionCompiler(func_entry_offsets=offsets)
    shared_bytecode.extend(comp_comb.compile_function(funcs["combine"]))

    full_bc = bytes(shared_bytecode)
    for a in range(1, 6):
        for b in range(1, 6):
            expected = a * 2 + b * 3
            actual = run_bytecode_calls(full_bc, [a, b], entry_pc=offsets["combine"])
            assert actual == expected, f"combine({a}, {b}): expected {expected}, got {actual}"

    print("[PASS] test_multiple_distinct_callees")


def test_call_rejections():
    src = """
int recurse(int n) {
    if (n <= 1) return 1;
    return n + recurse(n - 1);
}

int leaf(int x) {
    return x + 1;
}

int mid(int x) {
    return leaf(x);
}

int topChain(int x) {
    return mid(x);
}

int takeFive(int a, int b, int c, int d, int e) {
    return a + b + c + d + e;
}

int callFive(int x) {
    return takeFive(x, x, x, x, x);
}
"""
    tmp_path = "/tmp/test_call_rej.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    funcs = {cur.spelling: cur for cur in tu.cursor.get_children() if cur.kind == ci.CursorKind.FUNCTION_DECL}

    # 1. Recursion (now supported)
    el_rec, r_rec = eligibility_check(funcs["recurse"], all_func_names={"recurse"})
    assert el_rec, f"Recursion should now be eligible: {r_rec}"

    # 2. Multi-level call chain (now supported)
    el_leaf, _ = eligibility_check(funcs["leaf"], all_func_names={"leaf", "mid", "topChain"})
    assert el_leaf

    el_mid, _ = eligibility_check(funcs["mid"], all_func_names={"leaf", "mid", "topChain"})
    assert el_mid

    el_top, r_top = eligibility_check(funcs["topChain"], all_func_names={"leaf", "mid", "topChain"})
    assert el_top, f"Multi-level call chain should now be eligible: {r_top}"

    # 3. Call with 5 args (still ineligible, max 4 supported)
    el_5, r_5 = eligibility_check(funcs["callFive"], all_func_names={"takeFive", "callFive"})
    assert not el_5, "Call with > 4 args should be ineligible"
    assert "5 args" in r_5.lower() or "max 4" in r_5.lower(), f"Unexpected reason: {r_5}"

    print("[PASS] test_call_rejections")


def test_opcode_shuffling_interaction():
    shuffles = [generate_opcode_shuffle(seed=i) for i in range(5)]

    # Confirm OP_CALL (0x17) is present in every shuffle
    for s in shuffles:
        assert 0x17 in s, "OP_CALL missing from opcode shuffle"

    targets_call = {s[0x17] for s in shuffles}
    assert len(targets_call) > 1, f"OP_CALL target opcode should vary, got {targets_call}"

    print("[PASS] test_opcode_shuffling_interaction")


def test_end_to_end_function_calls():
    src = """#include <iostream>

int square(int x) {
    return x * x;
}

int sumOfSquares(int a, int b) {
    return square(a) + square(b);
}

int addOne(int x) {
    return x + 1;
}

int callTwiceKeepState(int n) {
    int keep = n * 100;
    int a = addOne(n);
    int b = addOne(a);
    return keep + b;
}

int main() {
    std::cout << sumOfSquares(3, 4) << " " << callTwiceKeepState(5) << std::endl;
    return 0;
}
"""
    tmp_src = "/tmp/test_call_e2e_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    out_cpp = "/tmp/test_call_e2e.cpp"
    out_bin = "/tmp/test_call_e2e_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    output = run_res.stdout.strip()
    # sumOfSquares(3, 4) = 25; callTwiceKeepState(5) = 500 + (5+2) = 507
    expected = "25 507"
    assert output == expected, f"Expected '{expected}', got '{output}'"

    print(f"[PASS] test_end_to_end_function_calls: sumOfSquares(3, 4) callTwiceKeepState(5) = '{output}'")


if __name__ == "__main__":
    test_basic_call_correctness()
    test_caller_local_state_preservation()
    test_multiple_distinct_callees()
    test_call_rejections()
    test_opcode_shuffling_interaction()
    test_end_to_end_function_calls()
