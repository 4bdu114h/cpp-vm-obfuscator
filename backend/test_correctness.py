import clang.cindex as ci
ci.Config.set_library_file('/usr/lib/x86_64-linux-gnu/libclang-18.so.1')
import sys
sys.path.insert(0, '/home/claude/obfuscator/backend')
from bytecode_gen import *

def run_bytecode(code, args):
    regs = [0] * 16
    pc = 0
    while pc < len(code):
        op = code[pc]; pc += 1
        if op == OP_LOAD_ARG:
            r, a = code[pc], code[pc+1]; pc += 2
            regs[r] = args[a]
        elif op == OP_LOAD_CONST:
            r = code[pc]; pc += 1
            val = int.from_bytes(code[pc:pc+8], "little", signed=True); pc += 8
            regs[r] = val
        elif op in (OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD,
                    OP_CMP_GT, OP_CMP_GE, OP_CMP_LT, OP_CMP_LE, OP_CMP_EQ, OP_CMP_NE):
            r, a, b = code[pc], code[pc+1], code[pc+2]; pc += 3
            av, bv = regs[a], regs[b]
            if op == OP_ADD: regs[r] = av + bv
            elif op == OP_SUB: regs[r] = av - bv
            elif op == OP_MUL: regs[r] = av * bv
            elif op == OP_DIV: regs[r] = int(av / bv)
            elif op == OP_MOD: regs[r] = av % bv
            elif op == OP_CMP_GT: regs[r] = 1 if av > bv else 0
            elif op == OP_CMP_GE: regs[r] = 1 if av >= bv else 0
            elif op == OP_CMP_LT: regs[r] = 1 if av < bv else 0
            elif op == OP_CMP_LE: regs[r] = 1 if av <= bv else 0
            elif op == OP_CMP_EQ: regs[r] = 1 if av == bv else 0
            elif op == OP_CMP_NE: regs[r] = 1 if av != bv else 0
        elif op == OP_JMP:
            target = int.from_bytes(code[pc:pc+2], "little"); pc = target
        elif op == OP_JMP_IF_TRUE:
            r = code[pc]; target = int.from_bytes(code[pc+1:pc+3], "little")
            pc += 3
            if regs[r] != 0: pc = target
        elif op == OP_JMP_IF_FALSE:
            r = code[pc]; target = int.from_bytes(code[pc+1:pc+3], "little")
            pc += 3
            if regs[r] == 0: pc = target
        elif op == OP_RET_CONST:
            val = int.from_bytes(code[pc:pc+8], "little", signed=True)
            return val
        elif op == OP_RET_REG:
            r = code[pc]
            return regs[r]
        else:
            raise RuntimeError(f"unknown opcode {op} at pc {pc-1}")
    raise RuntimeError("fell off end of bytecode without returning")


def native_calculateRiskScore(a, b):
    score = a * 7 + b * 3
    return 1 if score > 100 else 0

def native_addNumbers(x, y):
    return x + y


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

funcs = {}
for node in tu.cursor.get_children():
    if node.kind == ci.CursorKind.FUNCTION_DECL and node.location.file and str(node.location.file) == '/tmp/test2.cpp':
        ok, reason = eligibility_check(node)
        if ok:
            compiler = FunctionCompiler()
            funcs[node.spelling] = compiler.compile_function(node)

# Verify calculateRiskScore across many inputs, same style as the Android project's 676-case test
bc = funcs['calculateRiskScore']
failures = 0
total = 0
for a in range(-5, 21):
    for b in range(-5, 21):
        expected = native_calculateRiskScore(a, b)
        actual = run_bytecode(bc, [a, b])
        total += 1
        if expected != actual:
            failures += 1
            print(f"MISMATCH calculateRiskScore({a},{b}): expected {expected}, got {actual}")
print(f"calculateRiskScore: {total - failures}/{total} matched")

# Verify addNumbers
bc2 = funcs['addNumbers']
failures2 = 0
total2 = 0
for x in range(-10, 11):
    for y in range(-10, 11):
        expected = native_addNumbers(x, y)
        actual = run_bytecode(bc2, [x, y])
        total2 += 1
        if expected != actual:
            failures2 += 1
            print(f"MISMATCH addNumbers({x},{y}): expected {expected}, got {actual}")
print(f"addNumbers: {total2 - failures2}/{total2} matched")
