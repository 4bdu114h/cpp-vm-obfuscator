import os
import sys
import tempfile
import subprocess
import clang.cindex as ci

# Locate libclang
_CANDIDATE_LIBCLANG_PATHS = [
    "/opt/homebrew/opt/llvm/lib/libclang.dylib",
    "/usr/lib/x86_64-linux-gnu/libclang-18.so.1",
]
for p in _CANDIDATE_LIBCLANG_PATHS:
    if os.path.exists(p):
        ci.Config.set_library_file(p)
        break

sys.path.insert(0, os.path.dirname(__file__))

from codegen import obfuscate, _macos_clang_args
from pipeline import PipelineContext, stage_parse, stage_eligibility_check, stage_virtualize, stage_assemble_output
from bytecode_gen import eligibility_check


def build_and_run(source_code, exe_name="test_runner", opcode_shuffle_seed=None):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.cpp', delete=False) as f:
        f.write(source_code)
        src_file = f.name

    obf_code, _, _ = obfuscate(source_code, filename=src_file, opcode_shuffle_seed=opcode_shuffle_seed)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.cpp', delete=False) as f:
        f.write(obf_code)
        obf_file = f.name

    bin_file = obf_file + ".out"
    try:
        cmd_compile = ["g++", "-std=c++17", obf_file, "-o", bin_file]
        res = subprocess.run(cmd_compile, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert res.returncode == 0, f"Compilation failed!\nStderr: {res.stderr}\nCode:\n{obf_code}"

        run_res = subprocess.run([bin_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert run_res.returncode == 0, f"Execution failed! Return code: {run_res.returncode}"
        return obf_code, run_res.stdout.strip(), run_res.returncode
    finally:
        for p in [src_file, obf_file, bin_file]:
            if os.path.exists(p):
                os.remove(p)


def test_reference_parameter():
    src = """#include <iostream>

void increment(int& x) {
    x = x + 1;
}

int testIncrement(int start) {
    int val = start;
    increment(val);
    increment(val);
    return val;
}

int main() {
    std::cout << "testIncrement(5) start=5 final=" << testIncrement(5) << std::endl;
    std::cout << "testIncrement(100) start=100 final=" << testIncrement(100) << std::endl;
    return 0;
}
"""
    obf_code, output, _ = build_and_run(src, "test_ref")
    assert "testIncrement(5) start=5 final=7" in output, f"Mismatch: {output}"
    assert "testIncrement(100) start=100 final=102" in output, f"Mismatch: {output}"
    assert "vm_rt::run" in obf_code, "Functions were not virtualized!"
    print(f"[PASS] test_reference_parameter output:\n{output}")


def test_pointer_parameter():
    src = """#include <iostream>

void incrementPtr(int* p) {
    *p = *p + 1;
}

int testIncrementPtr(int start) {
    int val = start;
    incrementPtr(&val);
    incrementPtr(&val);
    return val;
}

int main() {
    std::cout << "testIncrementPtr(10) start=10 final=" << testIncrementPtr(10) << std::endl;
    std::cout << "testIncrementPtr(0) start=0 final=" << testIncrementPtr(0) << std::endl;
    return 0;
}
"""
    obf_code, output, _ = build_and_run(src, "test_ptr")
    assert "testIncrementPtr(10) start=10 final=12" in output, f"Mismatch: {output}"
    assert "testIncrementPtr(0) start=0 final=2" in output, f"Mismatch: {output}"
    assert "vm_rt::run" in obf_code, "Functions were not virtualized!"
    print(f"[PASS] test_pointer_parameter output:\n{output}")


def test_swap_function():
    src = """#include <iostream>

void swap(int& a, int& b) {
    int temp = a;
    a = b;
    b = temp;
}

int testSwap(int x, int y) {
    int u = x;
    int v = y;
    swap(u, v);
    return u * 100 + v;
}

int main() {
    std::cout << "testSwap(3, 7) before=(3, 7) after=(" << (testSwap(3, 7)/100) << ", " << (testSwap(3, 7)%100) << ")" << std::endl;
    std::cout << "testSwap(42, 99) before=(42, 99) after=(" << (testSwap(42, 99)/100) << ", " << (testSwap(42, 99)%100) << ")" << std::endl;
    std::cout << "testSwap(15, 80) before=(15, 80) after=(" << (testSwap(15, 80)/100) << ", " << (testSwap(15, 80)%100) << ")" << std::endl;
    return 0;
}
"""
    obf_code, output, _ = build_and_run(src, "test_swap")
    assert "testSwap(3, 7) before=(3, 7) after=(7, 3)" in output, f"Swap output mismatch! Got:\n{output}"
    assert "testSwap(42, 99) before=(42, 99) after=(99, 42)" in output, f"Swap output mismatch! Got:\n{output}"
    assert "testSwap(15, 80) before=(15, 80) after=(80, 15)" in output, f"Swap output mismatch! Got:\n{output}"
    assert "vm_rt::run" in obf_code, "Functions were not virtualized!"
    print(f"[PASS] test_swap_function output:\n{output}")


def test_rejection_cases():
    src = """
struct Point { int x; int y; };

void badStructPtr(Point* p) {
    p->x = 10;
}

int& getRef(int& x) {
    return x;
}

int badPtrArith(int* p) {
    return *(p + 1) + p[0];
}
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.cpp', delete=False) as f:
        f.write(src)
        src_file = f.name

    try:
        ctx = PipelineContext(source_code=src, filename=src_file)
        stage_parse(ctx)
        stage_eligibility_check(ctx)

        treatments = {f.spelling: ctx.treatments[f] for f in ctx.funcs}
        ok_sp, reason_sp = treatments["badStructPtr"]
        assert not ok_sp, "badStructPtr should be rejected!"
        assert "non-int" in reason_sp or "pointer" in reason_sp.lower(), f"Unexpected reason: {reason_sp}"

        ok_gr, reason_gr = treatments["getRef"]
        assert not ok_gr, "getRef should be rejected!"
        assert "return type" in reason_gr.lower(), f"Unexpected reason: {reason_gr}"

        ok_pa, reason_pa = treatments["badPtrArith"]
        assert not ok_pa, "badPtrArith should be rejected!"
        assert "pointer arithmetic" in reason_pa.lower(), f"Unexpected reason: {reason_pa}"

        print("[PASS] test_rejection_cases: struct pointer, reference return, and pointer arithmetic correctly rejected")
    finally:
        os.remove(src_file)


def test_mixed_register_and_memory_locals():
    src = """#include <iostream>

void addFive(int& ref) {
    ref = ref + 5;
}

int testMixed(int input) {
    int regVar = input * 2;
    int memVar = input + 10;
    addFive(memVar);
    regVar = regVar + 1;
    return regVar + memVar;
}

int main() {
    std::cout << testMixed(3) << std::endl;
    return 0;
}
"""
    obf_code, output, _ = build_and_run(src, "test_mixed")
    # input = 3
    # regVar = 6, memVar = 13
    # addFive(memVar) -> memVar = 18
    # regVar = 7
    # return 7 + 18 = 25
    assert output == "25", f"Mixed locals output mismatch! Got: '{output}', Expected: '25'"
    assert "vm_rt::run" in obf_code, "testMixed was not virtualized!"
    print("[PASS] test_mixed_register_and_memory_locals: testMixed(3) = 25")


def test_opcode_shuffling_interaction():
    src = """#include <iostream>

void doubleVal(int* p) {
    *p = *p * 2;
}

int runShuffledPtr(int start) {
    int val = start;
    doubleVal(&val);
    doubleVal(&val);
    return val;
}

int main() {
    std::cout << runShuffledPtr(7) << std::endl;
    return 0;
}
"""
    obf_code, output, _ = build_and_run(src, "shuffled_ptr", opcode_shuffle_seed=777)
    assert output == "28", f"Shuffled pointer output mismatch! Got: '{output}', Expected: '28'"
    print("[PASS] test_opcode_shuffling_interaction: runShuffledPtr(7) = 28 with shuffle seed 777")


def test_frame_memory_budget():
    # 1. Confirm function over 16 slots budget is rejected
    over_budget_src = """
struct Point { int x; int y; };
int overBudget(int a) {
    int arr[10];
    Point p1;
    Point p2;
    Point p3;
    Point p4;
    return arr[0] + p1.x + p2.x + p3.x + p4.x;
}
"""
    tmp_path = "/tmp/test_over_budget.cpp"
    with open(tmp_path, "w") as f:
        f.write(over_budget_src)
    tu = ci.Index.create().parse(tmp_path, args=["-std=c++17"] + _macos_clang_args())
    fn_over = [c for c in tu.cursor.get_children() if c.spelling == "overBudget"][0]
    el_over, reason_over = eligibility_check(fn_over)
    assert not el_over, "Function using > 16 slots should be ineligible!"
    assert "exceeds max per-frame limit of 16 slots" in reason_over, f"Unexpected reason: {reason_over}"

    # 2. Confirm nested function call with 14 slots in callee and 4 slots in caller runs with no cross-frame memory corruption
    within_budget_src = """#include <iostream>

struct Point { int x; int y; };

int calleeLarge(int start) {
    int arr[10];
    for (int i = 0; i < 10; i = i + 1) {
        arr[i] = start + i;
    }
    Point p1 = { 100, 200 };
    Point p2 = { 300, 400 };
    int sum = 0;
    for (int i = 0; i < 10; i = i + 1) {
        sum = sum + arr[i];
    }
    return sum + p1.x + p1.y + p2.x + p2.y;
}

int callerNested(int val) {
    Point cp1 = { 11, 22 };
    Point cp2 = { 33, 44 };
    int callee_res = calleeLarge(val);
    return callee_res + cp1.x + cp1.y + cp2.x + cp2.y;
}

int main() {
    std::cout << "callerNested(5) = " << callerNested(5) << std::endl;
    return 0;
}
"""
    obf_code, output, _ = build_and_run(within_budget_src, "test_nested_budget")
    # callee: sum(5..14) = 95. p1(100+200)+p2(300+400) = 1000. callee_res = 1095.
    # caller: 1095 + cp1(11+22=33) + cp2(33+44=77) = 1095 + 110 = 1205.
    assert "callerNested(5) = 1205" in output, f"Nested budget test mismatch! Got: '{output}'"
    assert "vm_rt::run" in obf_code, "Functions were not virtualized!"
    print(f"[PASS] test_frame_memory_budget: overBudget rejected, callerNested(5) = 1205 verified with no frame corruption\n{output}")


if __name__ == "__main__":
    print("Running pointer and reference test suite...")
    test_reference_parameter()
    test_pointer_parameter()
    test_swap_function()
    test_rejection_cases()
    test_mixed_register_and_memory_locals()
    test_opcode_shuffling_interaction()
    test_frame_memory_budget()
    print("ALL POINTER AND REFERENCE TESTS PASSED!")
