import clang.cindex as ci
import sys
sys.path.insert(0, '/home/claude/obfuscator/backend')
from bytecode_gen import eligibility_check, FunctionCompiler

source = """
int calculateRiskScore(int a, int b) {
    int score = a * 7 + b * 3;
    if (score > 100) {
        return 1;
    }
    return 0;
}

int addNumbers(int x, int y) {
    return x + y;
}
"""
with open('/tmp/test2.cpp', 'w') as f:
    f.write(source)

index = ci.Index.create()
tu = index.parse('/tmp/test2.cpp', args=['-std=c++17'])

for node in tu.cursor.get_children():
    if node.kind == ci.CursorKind.FUNCTION_DECL and node.location.file and str(node.location.file) == '/tmp/test2.cpp':
        ok, reason = eligibility_check(node)
        print(f"\n=== {node.spelling} ===")
        print("Eligible:", ok, "-", reason)
        if ok:
            compiler = FunctionCompiler()
            bc = compiler.compile_function(node)
            print("Bytecode length:", len(bc), "bytes")
            print("Bytecode hex:", bc.hex(' '))
