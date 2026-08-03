"""
test_interpreter_obfuscation.py
Tests for VM interpreter source code obfuscation (name randomization & multi-function dispatch splitting).
"""
import re
import tempfile
import subprocess
import unittest
from codegen import generate_vm_runtime, obfuscate


class TestInterpreterObfuscation(unittest.TestCase):

    def test_interpreter_name_randomization(self):
        """Verify internal helper names are randomized per build while public API names stay stable."""
        rt1 = generate_vm_runtime()
        rt2 = generate_vm_runtime()

        # Public API symbols MUST remain stable in both runs
        public_symbols = ["VMContext", "StringVMContext", "CallFrame", "run", "run_str", "run_struct"]
        for sym in public_symbols:
            self.assertIn(sym, rt1, f"Public API symbol {sym} missing from run 1")
            self.assertIn(sym, rt2, f"Public API symbol {sym} missing from run 2")

        # Original internal names MUST NOT be present as identifier tokens
        original_internal_names = [
            "fetch8", "fetch16", "fetch64", "str_fetch8",
            "anti_debug_check", "debugger_detected_flag", "fnv1a_32"
        ]
        for name in original_internal_names:
            self.assertFalse(re.search(r'\b' + re.escape(name) + r'\b', rt1), f"Un-obfuscated name {name} found in run 1")
            self.assertFalse(re.search(r'\b' + re.escape(name) + r'\b', rt2), f"Un-obfuscated name {name} found in run 2")

        # Internal helper names generated MUST differ between runs
        matches1 = set(re.findall(r'\bvm_[a-zA-Z0-9_]+\b', rt1))
        matches2 = set(re.findall(r'\bvm_[a-zA-Z0-9_]+\b', rt2))
        
        self.assertGreater(len(matches1), 1, "No randomized vm_ identifiers found in run 1")
        self.assertGreater(len(matches2), 1, "No randomized vm_ identifiers found in run 2")
        self.assertNotEqual(matches1, matches2, "Randomized identifier sets between two runs should differ")

    def test_multi_function_dispatch_splitting(self):
        """Verify dispatch switch is split into multiple sub-dispatch functions using threshold comparisons."""
        rt = generate_vm_runtime()

        # Confirm at least 4 dispatch functions (2 for int VM, 2 for string VM)
        dispatch_func_matches = re.findall(r'inline void vm_d[a-zA-Z0-9_]+\(', rt)
        self.assertGreaterEqual(len(dispatch_func_matches), 4, f"Expected >=4 dispatch helper functions, found {len(dispatch_func_matches)}")

        # Confirm numeric opcode split threshold comparison
        split_branches = re.findall(r'if \(op < 0x[0-9a-fA-F]{2}\)', rt)
        self.assertGreaterEqual(len(split_branches), 2, f"Expected opcode numeric comparison split branches, found {len(split_branches)}")

    def test_interpreter_obfuscate_pipeline_correctness(self):
        """Full pipeline test: obfuscate, compile with g++, execute, verify correct runtime behavior."""
        code = """#include <iostream>

int calculateScore(int a, int b) {
    int score = a * 5 + b * 2;
    if (score > 50) return score;
    return 0;
}

int sumArray(int x, int y) {
    int arr[2];
    arr[0] = x;
    arr[1] = y;
    return arr[0] + arr[1];
}

int main() {
    std::cout << calculateScore(10, 5) << " " << sumArray(20, 30) << std::endl;
    return 0;
}"""

        res = obfuscate(code, filename="/tmp/test_obf.cpp")
        obf_code = res[0]

        # Verify no un-obfuscated internal helper names exist in the output
        for name in ["fetch8", "fetch16", "fetch64", "str_fetch8", "anti_debug_check", "debugger_detected_flag", "fnv1a_32"]:
            self.assertFalse(re.search(r'\b' + re.escape(name) + r'\b', obf_code), f"Un-obfuscated name {name} present in pipeline output")

        # Compile and execute real binary
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cpp', delete=False) as f:
            f.write(obf_code)
            cpp_file = f.name

        bin_file = cpp_file + ".out"
        compile_proc = subprocess.run(["g++", "-std=c++17", cpp_file, "-o", bin_file], capture_output=True, text=True)
        self.assertEqual(compile_proc.returncode, 0, f"g++ compilation failed:\n{compile_proc.stderr}")

        run_proc = subprocess.run([bin_file], capture_output=True, text=True)
        self.assertEqual(run_proc.returncode, 0, f"Execution failed:\n{run_proc.stderr}")
        self.assertEqual(run_proc.stdout.strip(), "60 50", f"Unexpected output: '{run_proc.stdout.strip()}'")


if __name__ == "__main__":
    unittest.main()

