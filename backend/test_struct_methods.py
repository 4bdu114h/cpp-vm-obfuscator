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
from bytecode_gen import FunctionCompiler, eligibility_check


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


def test_basic_method_correctness():
    src = """#include <iostream>

struct Counter {
    int value;
    int increment() {
        value = value + 1;
        return value;
    }
};

int runCounter(int start, int times) {
    Counter c;
    c.value = start;
    int last = 0;
    int i = 0;
    while (i < times) {
        last = c.increment();
        i = i + 1;
    }
    return last;
}

int main() {
    std::cout << runCounter(5, 3) << " " << runCounter(10, 0) << " " << runCounter(0, 5) << std::endl;
    return 0;
}
"""
    obf_code, output, _ = build_and_run(src, "basic_methods")
    assert output == "8 0 5", f"Basic method output mismatch! Got: '{output}', Expected: '8 0 5'"
    print("[PASS] test_basic_method_correctness: runCounter(5,3)=8, runCounter(10,0)=0, runCounter(0,5)=5")


def test_method_with_parameters():
    src = """#include <iostream>

struct Accumulator {
    int total;
    int addAndReturn(int amount) {
        total = total + amount;
        return total;
    }
};

int testAccumulator(int start) {
    Accumulator acc;
    acc.total = start;
    acc.addAndReturn(10);
    acc.addAndReturn(20);
    return acc.addAndReturn(5);
}

int main() {
    std::cout << testAccumulator(100) << std::endl;
    return 0;
}
"""
    obf_code, output, _ = build_and_run(src, "method_params")
    assert output == "135", f"Method with params output mismatch! Got: '{output}', Expected: '135'"
    print("[PASS] test_method_with_parameters: testAccumulator(100) = 135")


def test_rejection_method_on_struct_parameter():
    src = """
struct Counter {
    int value;
    int increment() {
        value = value + 1;
        return value;
    }
};

int callOnParam(Counter p) {
    return p.increment();
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
        ok, reason = treatments["callOnParam"]
        assert not ok, f"callOnParam should be rejected, but was accepted!"
        assert "struct parameter" in reason.lower(), f"Unexpected rejection reason: {reason}"
        print("[PASS] test_rejection_method_on_struct_parameter: callOnParam cleanly rejected")
    finally:
        os.remove(src_file)


def test_end_to_end_compile_and_run():
    src = """#include <iostream>

struct Vector2D {
    int x;
    int y;
    int manhattanLength() {
        int absX = x;
        if (absX < 0) { absX = 0 - absX; }
        int absY = y;
        if (absY < 0) { absY = 0 - absY; }
        return absX + absY;
    }
    int scaleAndAdd(int factor, int offset) {
        x = x * factor + offset;
        y = y * factor + offset;
        return manhattanLength();
    }
};

int computeVectorStats(int x, int y, int factor, int offset) {
    Vector2D v;
    v.x = x;
    v.y = y;
    return v.scaleAndAdd(factor, offset);
}

int main() {
    std::cout << computeVectorStats(-2, 3, 4, 1) << std::endl;
    return 0;
}
"""
    obf_code, output, _ = build_and_run(src, "e2e_methods")
    assert output == "20", f"End to end method output mismatch! Got: '{output}', Expected: '20'"
    assert "vm_rt::run" in obf_code, "Function computeVectorStats was not virtualized!"
    print("[PASS] test_end_to_end_compile_and_run: computeVectorStats(-2, 3, 4, 1) = 20")


def test_opcode_shuffling_interaction():
    src = """#include <iostream>

struct Multiplier {
    int factor;
    int multiply(int val) {
        factor = factor * val;
        return factor;
    }
};

int runMultiplier(int start, int m1, int m2) {
    Multiplier m;
    m.factor = start;
    m.multiply(m1);
    return m.multiply(m2);
}

int main() {
    std::cout << runMultiplier(2, 3, 4) << std::endl;
    return 0;
}
"""
    obf_code, output, _ = build_and_run(src, "shuffled_methods", opcode_shuffle_seed=9999)
    assert output == "24", f"Shuffled methods output mismatch! Got: '{output}', Expected: '24'"
    print("[PASS] test_opcode_shuffling_interaction: runMultiplier(2,3,4) = 24 with shuffle seed 9999")


def test_rejection_recursive_methods():
    src = """#include <iostream>

struct DirectRec {
    int val;
    int count(int n) {
        if (n <= 0) return val;
        return count(n - 1);
    }
};

struct MutualRec {
    int val;
    int ping(int n) {
        if (n <= 0) return val;
        return pong(n - 1);
    }
    int pong(int n) {
        if (n <= 0) return val;
        return ping(n - 1);
    }
};

int runDirect(int n) {
    DirectRec d;
    d.val = 10;
    return d.count(n);
}

int runMutual(int n) {
    MutualRec m;
    m.val = 20;
    return m.ping(n);
}

int main() {
    std::cout << runDirect(3) << " " << runMutual(4) << std::endl;
    return 0;
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
        ok_d, reason_d = treatments["runDirect"]
        assert not ok_d, "runDirect (direct recursive method) should be rejected, but was accepted!"
        assert "recursive" in reason_d.lower(), f"Unexpected rejection reason for runDirect: {reason_d}"

        ok_m, reason_m = treatments["runMutual"]
        assert not ok_m, "runMutual (mutual recursive method) should be rejected, but was accepted!"
        assert "recursive" in reason_m.lower(), f"Unexpected rejection reason for runMutual: {reason_m}"

        obf_code, output, _ = build_and_run(src, "rec_methods_fallback")
        assert output == "10 20", f"Recursive methods fallback output mismatch! Got: '{output}', Expected: '10 20'"
        print("[PASS] test_rejection_recursive_methods: direct and mutual method recursion cleanly rejected & fallback executed correctly")
    finally:
        os.remove(src_file)


if __name__ == "__main__":
    print("Running struct methods test suite...")
    test_basic_method_correctness()
    test_method_with_parameters()
    test_rejection_method_on_struct_parameter()
    test_end_to_end_compile_and_run()
    test_opcode_shuffling_interaction()
    test_rejection_recursive_methods()
    print("ALL STRUCT METHOD TESTS PASSED!")
