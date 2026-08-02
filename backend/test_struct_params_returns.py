#!/usr/bin/env python3
import os
import sys
import tempfile
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

sys.path.insert(0, os.path.dirname(__file__))
from codegen import obfuscate, _macos_clang_args
from pipeline import PipelineContext, stage_parse, stage_eligibility_check


def build_and_run(source_code, name, opcode_shuffle_seed=None):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.cpp', delete=False) as f:
        f.write(source_code)
        src_file = f.name

    try:
        obf_code, _, _ = obfuscate(source_code, filename=src_file, opcode_shuffle_seed=opcode_shuffle_seed)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.cpp', delete=False) as f:
            f.write(obf_code)
            obf_file = f.name

        bin_file = obf_file + '.out'
        compile_cmd = ['g++', '-std=c++17', obf_file, '-o', bin_file]
        res = subprocess.run(compile_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Compilation failed for {name}:\n{res.stderr}\nCode:\n{obf_code}")

        run_res = subprocess.run([bin_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        os.remove(obf_file)
        os.remove(bin_file)
        return obf_code, run_res.stdout.strip(), run_res.returncode
    finally:
        os.remove(src_file)


def test_struct_parameters():
    src = """#include <iostream>

struct Point {
    int x;
    int y;
};

int manhattanDistance(Point p, Point q) {
    int dx = p.x - q.x;
    int dy = p.y - q.y;
    if (dx < 0) { dx = 0 - dx; }
    if (dy < 0) { dy = 0 - dy; }
    return dx + dy;
}

int main() {
    Point p1 = {1, 2};
    Point p2 = {4, 6};
    std::cout << manhattanDistance(p1, p2) << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "struct_params")
    assert code == 0, f"Process exited with code {code}"
    assert output == "7", f"Manhattan distance output mismatch! Got: '{output}', Expected: '7'"
    print("[PASS] test_struct_parameters: manhattanDistance({1,2}, {4,6}) = 7")


def test_struct_returns():
    src = """#include <iostream>

struct Point {
    int x;
    int y;
};

Point makePoint(int x, int y) {
    Point p;
    p.x = x;
    p.y = y;
    return p;
}

int useMadePoint(int x, int y) {
    Point p = makePoint(x, y);
    return p.x * 10 + p.y;
}

int main() {
    std::cout << useMadePoint(3, 4) << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "struct_returns")
    assert code == 0, f"Process exited with code {code}"
    assert output == "34", f"Struct return output mismatch! Got: '{output}', Expected: '34'"
    print("[PASS] test_struct_returns: useMadePoint(3, 4) = 34")


def test_mixed_int_and_struct_parameters():
    src = """#include <iostream>

struct Point {
    int x;
    int y;
};

int computeOffset(Point p, int extra) {
    return p.x + p.y + extra;
}

int main() {
    Point p = {10, 20};
    std::cout << computeOffset(p, 5) << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "mixed_params")
    assert code == 0, f"Process exited with code {code}"
    assert output == "35", f"Mixed parameters output mismatch! Got: '{output}', Expected: '35'"
    print("[PASS] test_mixed_int_and_struct_parameters: computeOffset({10,20}, 5) = 35")


def test_slot_limit_rejection():
    src = """
struct Point {
    int x;
    int y;
};

int badSlots(Point p, Point q, int extra) {
    return p.x + q.x + extra;
}

int callerFunc(Point p, Point q, int extra) {
    return badSlots(p, q, extra);
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
        ok, reason = treatments["callerFunc"]
        assert not ok, f"callerFunc should be rejected, but was accepted!"
        assert "max 4 supported" in reason or "5" in reason, f"Unexpected rejection reason: {reason}"
        print("[PASS] test_slot_limit_rejection: callerFunc calling badSlots (5 slots) correctly rejected")
    finally:
        os.remove(src_file)


def test_chained_struct_returns_buffer_safety():
    src = """#include <iostream>

struct Point {
    int x;
    int y;
};

Point makePoint(int x, int y) {
    Point p;
    p.x = x;
    p.y = y;
    return p;
}

int testChainedReturns(int x1, int y1, int x2, int y2) {
    Point p1 = makePoint(x1, y1);
    Point p2 = makePoint(x2, y2);
    return p1.x * 1000 + p1.y * 100 + p2.x * 10 + p2.y;
}

int main() {
    std::cout << testChainedReturns(1, 2, 3, 4) << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "chained_returns", opcode_shuffle_seed=777)
    assert code == 0, f"Process exited with code {code}"
    assert output == "1234", f"Chained struct returns output mismatch! Got: '{output}', Expected: '1234'"
    print("[PASS] test_chained_struct_returns_buffer_safety: testChainedReturns(1,2,3,4) = 1234")


def test_opcode_shuffling_interaction():
    src = """#include <iostream>

struct Point {
    int x;
    int y;
};

Point addPoints(Point p, Point q) {
    Point res;
    res.x = p.x + q.x;
    res.y = p.y + q.y;
    return res;
}

int main() {
    Point p1 = {10, 20};
    Point p2 = {30, 40};
    Point sum = addPoints(p1, p2);
    std::cout << sum.x << " " << sum.y << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "shuffled_struct_func", opcode_shuffle_seed=999)
    assert code == 0, f"Process exited with code {code}"
    assert output == "40 60", f"Shuffled struct params/returns output mismatch! Got: '{output}', Expected: '40 60'"
    print("[PASS] test_opcode_shuffling_interaction: addPoints({10,20}, {30,40}) = '40 60'")


if __name__ == '__main__':
    test_struct_parameters()
    test_struct_returns()
    test_mixed_int_and_struct_parameters()
    test_slot_limit_rejection()
    test_chained_struct_returns_buffer_safety()
    test_opcode_shuffling_interaction()
