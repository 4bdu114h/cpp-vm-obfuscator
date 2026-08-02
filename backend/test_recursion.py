"""
test_recursion.py
Tests recursion and multi-level call chain support in cpp-vm-obfuscator across 5 primary categories:
1. Basic recursion (factorial)
2. Deeper recursion (fibonacci)
3. Mutual recursion (isEvenRec / isOddRec with forward declarations/references)
4. Stack overflow protection (returns safe sentinel 0 on exceeding MAX_CALL_DEPTH=32)
5. Preservation of top-level arguments across nested call return paths (c.args restoration)
"""

import os
import math
import subprocess
import sys
from typing import Tuple
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


def build_and_run(source_code: str, tmp_prefix: str) -> Tuple[str, str, int]:
    src_path = f"/tmp/{tmp_prefix}_input.cpp"
    cpp_path = f"/tmp/{tmp_prefix}_obf.cpp"
    bin_path = f"/tmp/{tmp_prefix}_bin"

    with open(src_path, "w") as f:
        f.write(source_code)

    obf_code, report, errs = obfuscate(source_code, src_path)
    assert not errs, f"Obfuscation failed with errors: {errs}"

    with open(cpp_path, "w") as f:
        f.write(obf_code)

    cmd = ["g++", "-std=c++17"] + _macos_clang_args() + [cpp_path, "-o", bin_path]
    comp = subprocess.run(cmd, capture_output=True, text=True)
    assert comp.returncode == 0, f"g++ compilation failed:\n{comp.stderr}"

    run_res = subprocess.run([bin_path], capture_output=True, text=True)
    return obf_code, run_res.stdout.strip(), run_res.returncode


def test_basic_recursion_factorial():
    src = """#include <iostream>

int factorialRec(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorialRec(n - 1);
}

int main() {
    for (int i = 0; i <= 8; i++) {
        std::cout << factorialRec(i) << " ";
    }
    std::cout << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "test_rec_fact")
    assert code == 0, f"Binary exited with code {code}"
    results = [int(x) for x in output.split()]
    expected = [math.factorial(i) for i in range(9)]
    assert results == expected, f"Factorial mismatch:\nGot: {results}\nExpected: {expected}"
    print(f"[PASS] test_basic_recursion_factorial: {results}")


def test_deeper_recursion_fibonacci():
    src = """#include <iostream>

int fibRec(int n) {
    if (n <= 1) {
        return n;
    }
    return fibRec(n - 1) + fibRec(n - 2);
}

int main() {
    for (int i = 0; i <= 10; i++) {
        std::cout << fibRec(i) << " ";
    }
    std::cout << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "test_rec_fib")
    assert code == 0, f"Binary exited with code {code}"
    results = [int(x) for x in output.split()]
    def fib_py(n):
        if n <= 1: return n
        return fib_py(n - 1) + fib_py(n - 2)
    expected = [fib_py(i) for i in range(11)]
    assert results == expected, f"Fibonacci mismatch:\nGot: {results}\nExpected: {expected}"
    print(f"[PASS] test_deeper_recursion_fibonacci: {results}")


def test_mutual_recursion():
    src = """#include <iostream>

int isOddRec(int n);

int isEvenRec(int n) {
    if (n == 0) { return 1; }
    return isOddRec(n - 1);
}

int isOddRec(int n) {
    if (n == 0) { return 0; }
    return isEvenRec(n - 1);
}

int main() {
    std::cout << isEvenRec(4) << " " << isEvenRec(5) << " "
              << isOddRec(4) << " " << isOddRec(5) << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "test_rec_mutual")
    assert code == 0, f"Binary exited with code {code}"
    results = output.split()
    assert results == ["1", "0", "0", "1"], f"Mutual recursion mismatch: {results}"
    print(f"[PASS] test_mutual_recursion: {results}")


def test_stack_overflow_protection():
    src = """#include <iostream>

int deepRec(int n) {
    if (n <= 0) { return 42; }
    return deepRec(n - 1) + 1;
}

int main() {
    // MAX_CALL_DEPTH is 32. n=50 should exceed call depth limit and safely return 0 sentinel without crashing.
    int res = deepRec(50);
    std::cout << "Result: " << res << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "test_rec_overflow")
    assert code == 0, f"Binary crashed with exit code {code} on stack overflow!"
    assert output == "Result: 0", f"Stack overflow protection did not return sentinel 0! Got: {output}"
    print("[PASS] test_stack_overflow_protection: safely returned sentinel 0")


def test_top_level_arguments_preservation():
    src = """#include <iostream>

int addOne(int x) {
    return x + 1;
}

int callerFunc(int a, int b) {
    int sub = addOne(a);
    // After addOne returns, verify 'b' is still correctly read from original_args
    return sub + b;
}

int main() {
    std::cout << callerFunc(10, 20) << std::endl;
    return 0;
}
"""
    obf_code, output, code = build_and_run(src, "test_rec_args_preservation")
    assert code == 0, f"Binary exited with code {code}"
    assert output == "31", f"Top-level arguments preservation failed! Got: {output}, Expected: 31"
    print("[PASS] test_top_level_arguments_preservation: callerFunc(10, 20) = 31")


if __name__ == "__main__":
    test_basic_recursion_factorial()
    test_deeper_recursion_fibonacci()
    test_mutual_recursion()
    test_stack_overflow_protection()
    test_top_level_arguments_preservation()
