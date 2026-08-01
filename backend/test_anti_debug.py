"""
test_anti_debug.py
Unit tests and end-to-end integration tests for anti-debugging protection.
"""
import os
import sys
import time
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

from codegen import obfuscate


def test_mac_clean_compilation():
    src = """#include <iostream>

int square(int x) {
    return x * x;
}

int main() {
    std::cout << square(7) << std::endl;
    return 0;
}
"""
    tmp_src = "/tmp/test_antidebug_comp_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    out_cpp = "/tmp/test_antidebug_comp.cpp"
    out_bin = "/tmp/test_antidebug_comp_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    print("[PASS] test_mac_clean_compilation: compiled with zero errors")


def test_normal_non_debugged_execution():
    src = """#include <iostream>

int square(int x) {
    return x * x;
}

int main() {
    std::cout << square(7) << std::endl;
    return 0;
}
"""
    tmp_src = "/tmp/test_antidebug_norm_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    out_cpp = "/tmp/test_antidebug_norm.cpp"
    out_bin = "/tmp/test_antidebug_norm_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    run_res = subprocess.run([out_bin], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    output = run_res.stdout.strip()
    assert output == "49", f"Expected '49', got '{output}'"

    print(f"[PASS] test_normal_non_debugged_execution: square(7) = {output}")


def test_lldb_attach_denial_mac():
    src = """#include <iostream>
#include <unistd.h>

int square(int x) {
    return x * x;
}

int main() {
    std::cout << square(7) << std::endl;
    sleep(5);
    return 0;
}
"""
    tmp_src = "/tmp/test_lldb_attach_input.cpp"
    obf_code, report, errs = obfuscate(src, tmp_src)
    assert not errs, f"Unexpected parse errors: {errs}"

    out_cpp = "/tmp/test_lldb_attach.cpp"
    out_bin = "/tmp/test_lldb_attach_bin"
    with open(out_cpp, "w") as f:
        f.write(obf_code)

    comp = subprocess.run(["g++", "-std=c++17", out_cpp, "-o", out_bin], capture_output=True, text=True)
    assert comp.returncode == 0, f"Compilation failed: {comp.stderr}"

    proc = subprocess.Popen([out_bin], stdout=subprocess.PIPE, text=True)
    pid = proc.pid
    time.sleep(0.5)

    try:
        lldb_res = subprocess.run(["lldb", "--batch", "-o", f"process attach --pid {pid}", "-o", "quit"], capture_output=True, text=True)
        combined_output = lldb_res.stdout + lldb_res.stderr
        assert "attach failed" in combined_output or "Not allowed to attach" in combined_output, f"Expected lldb attach failure message, got: {combined_output}"
        print("[PASS] test_lldb_attach_denial_mac: confirmed LLDB attach was denied by PT_DENY_ATTACH")
    finally:
        proc.terminate()


if __name__ == "__main__":
    test_mac_clean_compilation()
    test_normal_non_debugged_execution()
    test_lldb_attach_denial_mac()
