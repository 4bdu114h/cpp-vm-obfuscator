"""
bytecode_gen.py
Walks a Clang AST for a single function and, if it's eligible (uses only
integer arithmetic, comparisons, if/return - the same subset the Android
VM project supports), emits bytecode instructions in the exact same
opcode format as interpreter/vm_bytecode.h from the Android project.

If a function is NOT eligible (uses loops, pointers, floats, calls,
classes, etc.), eligibility_check() returns False and the caller should
fall back to simple identifier renaming instead.
"""
import clang.cindex as ci

# Same opcode numbering as interpreter/vm_bytecode.h in the Android project
OP_LOAD_ARG = 0x01
OP_LOAD_CONST = 0x02
OP_MOV = 0x03
OP_ADD = 0x04
OP_SUB = 0x05
OP_MUL = 0x06
OP_DIV = 0x07
OP_MOD = 0x08
OP_CMP_GT = 0x09
OP_CMP_GE = 0x0A
OP_CMP_LT = 0x0B
OP_CMP_LE = 0x0C
OP_CMP_EQ = 0x0D
OP_CMP_NE = 0x0E
OP_JMP = 0x0F
OP_JMP_IF_TRUE = 0x10
OP_JMP_IF_FALSE = 0x11
OP_RET_CONST = 0x12
OP_RET_REG = 0x13
OP_HALT = 0x14

BIN_OP_TO_OPCODE = {
    '+': OP_ADD, '-': OP_SUB, '*': OP_MUL, '/': OP_DIV, '%': OP_MOD,
    '>': OP_CMP_GT, '>=': OP_CMP_GE, '<': OP_CMP_LT, '<=': OP_CMP_LE,
    '==': OP_CMP_EQ, '!=': OP_CMP_NE,
}

OPCODE_OPERAND_WIDTHS = {
    OP_LOAD_ARG: 2,
    OP_LOAD_CONST: 9,
    OP_MOV: 2,
    OP_ADD: 3,
    OP_SUB: 3,
    OP_MUL: 3,
    OP_DIV: 3,
    OP_MOD: 3,
    OP_CMP_GT: 3,
    OP_CMP_GE: 3,
    OP_CMP_LT: 3,
    OP_CMP_LE: 3,
    OP_CMP_EQ: 3,
    OP_CMP_NE: 3,
    OP_JMP: 2,
    OP_JMP_IF_TRUE: 3,
    OP_JMP_IF_FALSE: 3,
    OP_RET_CONST: 8,
    OP_RET_REG: 1,
    OP_HALT: 0,
}

ALL_OPCODES = list(OPCODE_OPERAND_WIDTHS.keys())


ALLOWED_KINDS = {
    ci.CursorKind.FUNCTION_DECL, ci.CursorKind.PARM_DECL,
    ci.CursorKind.COMPOUND_STMT, ci.CursorKind.DECL_STMT,
    ci.CursorKind.VAR_DECL, ci.CursorKind.BINARY_OPERATOR,
    ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.DECL_REF_EXPR,
    ci.CursorKind.INTEGER_LITERAL, ci.CursorKind.IF_STMT,
    ci.CursorKind.RETURN_STMT, ci.CursorKind.PAREN_EXPR,
    ci.CursorKind.UNARY_OPERATOR,
}


def eligibility_check(func_cursor):
    """Returns (True, reason) if this function can be fully virtualized,
    (False, reason) otherwise. Only allows: int params, int locals,
    arithmetic, comparisons, if/return, integer literals."""
    # All parameters and the return type must be int
    if func_cursor.result_type.spelling not in ("int",):
        return False, f"unsupported return type '{func_cursor.result_type.spelling}'"
    for p in func_cursor.get_arguments():
        if p.type.spelling != "int":
            return False, f"unsupported parameter type '{p.type.spelling}'"

    bad = []

    def walk(node):
        if node.kind not in ALLOWED_KINDS:
            bad.append(str(node.kind))
            return
        for c in node.get_children():
            walk(c)

    walk(func_cursor)
    if bad:
        return False, f"unsupported construct(s): {', '.join(sorted(set(bad)))}"
    return True, "eligible"


class BytecodeBuilder:
    """Same role as interpreter/vm_assembler.h's Assembler class, but in
    Python, targeting the same byte format."""
    def __init__(self):
        self.code = bytearray()

    def here(self):
        return len(self.code)

    def load_arg(self, r_dst, arg_index):
        self.code += bytes([OP_LOAD_ARG, r_dst, arg_index])

    def load_const(self, r_dst, value):
        self.code += bytes([OP_LOAD_CONST, r_dst])
        self.code += int(value).to_bytes(8, "little", signed=True)

    def binop(self, opcode, r_dst, r_a, r_b):
        self.code += bytes([opcode, r_dst, r_a, r_b])

    def jmp_if_true(self, r_cond):
        self.code += bytes([OP_JMP_IF_TRUE, r_cond, 0xFF, 0xFF])
        return len(self.code) - 2

    def jmp(self):
        self.code += bytes([OP_JMP, 0xFF, 0xFF])
        return len(self.code) - 2

    def patch(self, patch_at, target):
        self.code[patch_at] = target & 0xFF
        self.code[patch_at + 1] = (target >> 8) & 0xFF

    def ret_const(self, value):
        self.code += bytes([OP_RET_CONST])
        self.code += int(value).to_bytes(8, "little", signed=True)

    def ret_reg(self, r_src):
        self.code += bytes([OP_RET_REG, r_src])


class FunctionCompiler:
    """Compiles one eligible function's AST into bytecode."""
    def __init__(self):
        self.b = BytecodeBuilder()
        self.next_reg = 0
        self.var_reg = {}   # variable name -> register index
        self.arg_index = {}  # param name -> arg index

    def alloc_reg(self):
        r = self.next_reg
        self.next_reg += 1
        if self.next_reg > 16:
            raise RuntimeError("ran out of registers (max 16 supported)")
        return r

    def compile_function(self, func_cursor):
        params = list(func_cursor.get_arguments())
        for i, p in enumerate(params):
            self.arg_index[p.spelling] = i

        body = None
        for c in func_cursor.get_children():
            if c.kind == ci.CursorKind.COMPOUND_STMT:
                body = c
        self.compile_stmt(body)
        return bytes(self.b.code)

    def compile_stmt(self, node):
        if node.kind == ci.CursorKind.COMPOUND_STMT:
            for c in node.get_children():
                self.compile_stmt(c)

        elif node.kind == ci.CursorKind.DECL_STMT:
            for c in node.get_children():
                self.compile_stmt(c)

        elif node.kind == ci.CursorKind.VAR_DECL:
            children = list(node.get_children())
            r = self.alloc_reg()
            self.var_reg[node.spelling] = r
            if children:
                init_reg = self.compile_expr(children[0])
                self.b.binop_mov = None  # not used; MOV via ADD-with-0 pattern avoided
                self.copy_reg(r, init_reg)

        elif node.kind == ci.CursorKind.IF_STMT:
            children = list(node.get_children())
            cond = children[0]
            then_branch = children[1]
            else_branch = children[2] if len(children) > 2 else None
            cond_reg = self.compile_expr(cond)
            patch_true = self.b.jmp_if_true(cond_reg)
            if else_branch:
                self.compile_stmt(else_branch)
            patch_skip_then = self.b.jmp()
            then_target = self.b.here()
            self.b.patch(patch_true, then_target)
            self.compile_stmt(then_branch)
            end_target = self.b.here()
            self.b.patch(patch_skip_then, end_target)

        elif node.kind == ci.CursorKind.RETURN_STMT:
            children = list(node.get_children())
            if not children:
                self.b.ret_const(0)
                return
            expr = children[0]
            if expr.kind == ci.CursorKind.INTEGER_LITERAL:
                tokens = list(expr.get_tokens())
                value = int(tokens[0].spelling) if tokens else 0
                self.b.ret_const(value)
            else:
                r = self.compile_expr(expr)
                self.b.ret_reg(r)
        else:
            raise RuntimeError(f"unhandled statement kind: {node.kind}")

    def copy_reg(self, r_dst, r_src):
        # MOV emulated as ADD with 0 to keep opcode set minimal in this MVP
        zero = self.alloc_reg()
        self.b.load_const(zero, 0)
        self.b.binop(OP_ADD, r_dst, r_src, zero)

    def compile_expr(self, node):
        if node.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
            children = list(node.get_children())
            if children:
                return self.compile_expr(children[0])
            r = self.alloc_reg()
            tokens = list(node.get_tokens())
            val = int(tokens[0].spelling) if tokens else 0
            self.b.load_const(r, val)
            return r

        if node.kind == ci.CursorKind.DECL_REF_EXPR:
            name = node.spelling
            if name in self.var_reg:
                return self.var_reg[name]
            if name in self.arg_index:
                r = self.alloc_reg()
                self.b.load_arg(r, self.arg_index[name])
                return r
            raise RuntimeError(f"unknown identifier: {name}")

        if node.kind == ci.CursorKind.INTEGER_LITERAL:
            tokens = list(node.get_tokens())
            val = int(tokens[0].spelling) if tokens else 0
            r = self.alloc_reg()
            self.b.load_const(r, val)
            return r

        if node.kind == ci.CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            lhs, rhs = children[0], children[1]
            op_token = self._binary_op_symbol(node)
            r_a = self.compile_expr(lhs)
            r_b = self.compile_expr(rhs)
            r_dst = self.alloc_reg()
            opcode = BIN_OP_TO_OPCODE[op_token]
            self.b.binop(opcode, r_dst, r_a, r_b)
            return r_dst

        raise RuntimeError(f"unhandled expression kind: {node.kind}")

    def _binary_op_symbol(self, node):
        # Clang doesn't expose the operator directly via cindex; recover it
        # from the token stream between the two child expressions.
        children = list(node.get_children())
        lhs_extent_end = children[0].extent.end
        rhs_extent_start = children[1].extent.start
        for tok in node.get_tokens():
            if (tok.extent.start.offset >= lhs_extent_end.offset and
                    tok.extent.end.offset <= rhs_extent_start.offset):
                if tok.spelling in BIN_OP_TO_OPCODE:
                    return tok.spelling
        # fallback: scan all tokens for a known operator symbol
        for tok in node.get_tokens():
            if tok.spelling in BIN_OP_TO_OPCODE:
                return tok.spelling
        raise RuntimeError("could not determine binary operator")
