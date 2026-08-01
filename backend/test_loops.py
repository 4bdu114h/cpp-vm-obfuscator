"""
test_loops.py
Unit tests and end-to-end integration tests for while-loop and for-loop virtualization.
"""
import os
import sys
import math
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
    OP_JMP, OP_JMP_IF_TRUE, OP_JMP_IF_FALSE, OP_RET_CONST, OP_RET_REG
)
from codegen import obfuscate, _macos_clang_args


def run_bytecode(code, args):
    regs = [0] * 16
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
        elif op == OP_RET_CONST:
            return int.from_bytes(code[pc:pc + 8], "little", signed=True)
        elif op == OP_RET_REG:
            r = code[pc]
            return regs[r]
        else:
            raise RuntimeError(f"unknown opcode {op} at pc {pc-1}")
    raise RuntimeError("fell off end of bytecode without returning")


def test_while_loop():
    src = """
int sumUpTo(int n) {
    int total = 0;
    int i = 1;
    while (i <= n) {
        total = total + i;
        i = i + 1;
    }
    return total;
}
"""
    tmp_path = "/tmp/test_while.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    fn = [c for c in tu.cursor.get_children() if c.spelling == "sumUpTo"][0]

    eligible, reason = eligibility_check(fn)
    assert eligible, f"sumUpTo should be eligible, got: {reason}"

    compiler = FunctionCompiler()
    bytecode = compiler.compile_function(fn)

    for n in range(0, 51):
        expected = sum(range(1, n + 1))
        actual = run_bytecode(bytecode, [n])
        assert actual == expected, f"sumUpTo({n}): expected {expected}, got {actual}"
    print("[PASS] test_while_loop")


def test_for_loop():
    src = """
int factorial(int n) {
    int result = 1;
    for (int i = 1; i <= n; i = i + 1) {
        result = result * i;
    }
    return result;
}
"""
    tmp_path = "/tmp/test_for.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    fn = [c for c in tu.cursor.get_children() if c.spelling == "factorial"][0]

    eligible, reason = eligibility_check(fn)
    assert eligible, f"factorial should be eligible, got: {reason}"

    compiler = FunctionCompiler()
    bytecode = compiler.compile_function(fn)

    for n in range(0, 11):
        expected = math.factorial(n)
        actual = run_bytecode(bytecode, [n])
        assert actual == expected, f"factorial({n}): expected {expected}, got {actual}"
    print("[PASS] test_for_loop")


def test_zero_iterations():
    src = """
int sumUpTo(int n) {
    int total = 0;
    int i = 1;
    while (i <= n) {
        total = total + i;
        i = i + 1;
    }
    return total;
}
"""
    tmp_path = "/tmp/test_zero.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    fn = [c for c in tu.cursor.get_children() if c.spelling == "sumUpTo"][0]

    compiler = FunctionCompiler()
    bytecode = compiler.compile_function(fn)

    actual = run_bytecode(bytecode, [0])
    assert actual == 0, f"sumUpTo(0) should return 0, got {actual}"
    print("[PASS] test_zero_iterations")


def test_rejection_break_continue():
    src = """
int withBreak(int n) {
    int total = 0;
    for (int i = 0; i < n; i = i + 1) {
        if (i == 5) break;
        total = total + i;
    }
    return total;
}

int withContinue(int n) {
    int total = 0;
    for (int i = 0; i < n; i = i + 1) {
        if (i == 5) continue;
        total = total + i;
    }
    return total;
}
"""
    tmp_path = "/tmp/test_break_continue.cpp"
    with open(tmp_path, "w") as f:
        f.write(src)

    index = ci.Index.create()
    tu = index.parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())

    fn_break = [c for c in tu.cursor.get_children() if c.spelling == "withBreak"][0]
    fn_continue = [c for c in tu.cursor.get_children() if c.spelling == "withContinue"][0]

    el_b, reason_b = eligibility_check(fn_break)
    assert not el_b, "Function with break should be ineligible"
    assert "BREAK_STMT" in reason_b, f"Reason should mention BREAK_STMT, got: {reason_b}"

    el_c, reason_c = eligibility_check(fn_continue)
    assert not el_c, "Function with continue should be ineligible"
    assert "CONTINUE_STMT" in reason_c, f"Reason should mention CONTINUE_STMT, got: {reason_c}"

    print("[PASS] test_rejection_break_continue")


def test_end_to_end_loops():
    src = """#include <iostream>

int sumUpTo(int n) {
    int total = 0;
    int i = 1;
    while (i <= n) {
        total = total + i;
        i = i + 1;
    }
    return total;
}

int factorial(int n) {
    int result = 1;
    for (int i = 1; i <= n; i = i + 1) {
        result = result * i;
    }
    return result;
}

int main() {
    std::cout << sumUpTo(10) << std::endl;
    std::cout << factorial(5) << std::endl;
    return 0;
}
"""
    tmp_src = "/tmp/test_loops_e2e_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    out_cpp = "/tmp/test_loops_e2e.cpp"
    out_bin = "/tmp/test_loops_e2e_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    lines = run_res.stdout.strip().splitlines()
    assert len(lines) == 2, f"Expected 2 lines of output, got: {lines}"
    assert lines[0] == "55", f"sumUpTo(10) expected '55', got '{lines[0]}'"
    assert lines[1] == "120", f"factorial(5) expected '120', got '{lines[1]}'"

    print(f"[PASS] test_end_to_end_loops: sumUpTo(10)={lines[0]}, factorial(5)={lines[1]}")


def test_parameter_mutation():
    src = """#include <iostream>

int countdown(int n) {
    int steps = 0;
    while (n > 0) {
        n--;
        steps++;
    }
    return steps;
}

int main() {
    std::cout << countdown(5) << std::endl;
    return 0;
}
"""
    tmp_src = "/tmp/test_param_mut_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    out_cpp = "/tmp/test_param_mut.cpp"
    out_bin = "/tmp/test_param_mut_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"
    output = run_res.stdout.strip()
    assert output == "5", f"Expected countdown(5) to output '5', got '{output}'"

    print(f"[PASS] test_parameter_mutation: countdown(5)={output}")


if __name__ == "__main__":
    test_while_loop()
    test_for_loop()
    test_zero_iterations()
    test_rejection_break_continue()
    test_end_to_end_loops()
    test_parameter_mutation()
