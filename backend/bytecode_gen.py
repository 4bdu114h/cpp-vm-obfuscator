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
OP_ARR_LOAD = 0x15
OP_ARR_STORE = 0x16
OP_CALL = 0x17
OP_STR_LOAD_ARG = 0x18
OP_STR_LOAD_CONST = 0x19
OP_STR_CONCAT = 0x1A
OP_STR_EQ = 0x1B
OP_STR_NE = 0x1C
OP_RET_STR = 0x1D
OP_RET_STR_INT = 0x1E

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
    OP_ARR_LOAD: 3,
    OP_ARR_STORE: 3,
    OP_CALL: 7,
    OP_STR_LOAD_ARG: 2,
    OP_STR_LOAD_CONST: 2,
    OP_STR_CONCAT: 3,
    OP_STR_EQ: 3,
    OP_STR_NE: 3,
    OP_RET_STR: 1,
    OP_RET_STR_INT: 1,
}

ALL_OPCODES = list(OPCODE_OPERAND_WIDTHS.keys())


ALLOWED_KINDS = {
    ci.CursorKind.FUNCTION_DECL, ci.CursorKind.PARM_DECL,
    ci.CursorKind.COMPOUND_STMT, ci.CursorKind.DECL_STMT,
    ci.CursorKind.VAR_DECL, ci.CursorKind.BINARY_OPERATOR,
    ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.DECL_REF_EXPR,
    ci.CursorKind.INTEGER_LITERAL, ci.CursorKind.IF_STMT,
    ci.CursorKind.RETURN_STMT, ci.CursorKind.PAREN_EXPR,
    ci.CursorKind.UNARY_OPERATOR, ci.CursorKind.WHILE_STMT,
    ci.CursorKind.FOR_STMT, ci.CursorKind.ARRAY_SUBSCRIPT_EXPR,
    ci.CursorKind.INIT_LIST_EXPR, ci.CursorKind.CALL_EXPR,
    ci.CursorKind.MEMBER_REF_EXPR, ci.CursorKind.TYPE_REF,
    ci.CursorKind.STRUCT_DECL, ci.CursorKind.FIELD_DECL,
}


def eligibility_check(func_cursor, all_func_names=None, known_leaf_functions=None, struct_names=None):
    """Returns (True, reason) if this function can be fully virtualized,
    (False, reason) otherwise. Only allows: int params, int locals,
    fixed-size int arrays, int-fields-only struct locals, arithmetic, comparisons,
    loops, if/return, and calls (including recursive / multi-level) with <= 4 args."""
    if known_leaf_functions is not None and all_func_names is None:
        allowed_callees = known_leaf_functions
    else:
        allowed_callees = all_func_names

    if struct_names is None and hasattr(func_cursor, 'translation_unit') and func_cursor.translation_unit:
        struct_names = {c.spelling for c in func_cursor.translation_unit.cursor.get_children()
                        if c.kind in (ci.CursorKind.STRUCT_DECL, ci.CursorKind.CLASS_DECL)}
    else:
        struct_names = struct_names or set()

    # All parameters and the return type must be int
    if func_cursor.result_type.spelling not in ("int",):
        return False, f"unsupported return type '{func_cursor.result_type.spelling}'"
    for p in func_cursor.get_arguments():
        if p.type.spelling != "int":
            return False, f"unsupported parameter type '{p.type.spelling}'"

    bad = []

    def get_struct_fields(decl_cursor):
        if hasattr(decl_cursor.type, 'get_fields'):
            fields = list(decl_cursor.type.get_fields())
            if fields: return fields
        return [c for c in decl_cursor.get_children() if c.kind == ci.CursorKind.FIELD_DECL]

    def walk(node):
        if node.kind not in ALLOWED_KINDS:
            bad.append(str(node.kind))
            return
        if node.kind == ci.CursorKind.VAR_DECL:
            if node.type.kind == ci.TypeKind.CONSTANTARRAY:
                if node.type.element_type.spelling != "int":
                    bad.append(f"non-int array '{node.type.spelling}'")
                    return
            elif node.type.kind == ci.TypeKind.RECORD:
                decl = node.type.get_declaration()
                fields = get_struct_fields(decl)
                if not fields:
                    bad.append(f"struct '{node.type.spelling}' has no fields")
                    return
                for f in fields:
                    if f.type.kind != ci.TypeKind.INT:
                        bad.append(f"struct field '{f.spelling}' of type '{f.type.spelling}' is non-int")
                        return
            elif node.type.kind != ci.TypeKind.INT:
                bad.append(f"unsupported variable type '{node.type.spelling}'")
                return
        elif node.kind == ci.CursorKind.CALL_EXPR:
            callee_name = node.spelling
            if not callee_name:
                children = list(node.get_children())
                if children:
                    callee_name = children[0].spelling
            if callee_name in struct_names:
                return  # Default struct constructor call inside VAR_DECL
            if allowed_callees is not None and callee_name not in allowed_callees:
                bad.append(f"call to non-leaf/unknown function '{callee_name}'")
                return
            args = list(node.get_arguments())
            if not args:
                children = list(node.get_children())
                if len(children) > 1:
                    args = children[1:]
            if len(args) > 4:
                bad.append(f"call to '{callee_name}' with {len(args)} args (max 4 supported)")
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
    def __init__(self, start_offset=0):
        self.start_offset = start_offset
        self.code = bytearray()

    def here(self):
        return self.start_offset + len(self.code)

    def load_arg(self, r_dst, arg_index):
        self.code += bytes([OP_LOAD_ARG, r_dst, arg_index])

    def load_const(self, r_dst, value):
        self.code += bytes([OP_LOAD_CONST, r_dst])
        self.code += int(value).to_bytes(8, "little", signed=True)

    def binop(self, opcode, r_dst, r_a, r_b):
        self.code += bytes([opcode, r_dst, r_a, r_b])

    def jmp_if_true(self, r_cond):
        self.code += bytes([OP_JMP_IF_TRUE, r_cond, 0xFF, 0xFF])
        return self.start_offset + len(self.code) - 2

    def jmp_if_false(self, r_cond):
        self.code += bytes([OP_JMP_IF_FALSE, r_cond, 0xFF, 0xFF])
        return self.start_offset + len(self.code) - 2

    def jmp(self):
        self.code += bytes([OP_JMP, 0xFF, 0xFF])
        return self.start_offset + len(self.code) - 2

    def jmp_to(self, target):
        """Unconditional jump to an ALREADY KNOWN address (e.g. jumping
        backward to a loop's start) - unlike self.jmp(), which returns a
        patch location for a FORWARD target not yet known."""
        self.code += bytes([OP_JMP])
        self.code += int(target).to_bytes(2, "little")

    def patch(self, patch_at, target):
        rel_patch_at = patch_at - self.start_offset
        self.code[rel_patch_at] = target & 0xFF
        self.code[rel_patch_at + 1] = (target >> 8) & 0xFF

    def ret_const(self, value):
        self.code += bytes([OP_RET_CONST])
        self.code += int(value).to_bytes(8, "little", signed=True)

    def ret_reg(self, r_src):
        self.code += bytes([OP_RET_REG, r_src])

    def arr_load(self, r_dst, base_offset, r_idx):
        self.code += bytes([OP_ARR_LOAD, r_dst, base_offset, r_idx])

    def arr_store(self, base_offset, r_idx, r_src):
        self.code += bytes([OP_ARR_STORE, base_offset, r_idx, r_src])

    def call(self, callee_offset, arg_regs, r_dst):
        args_padded = list(arg_regs) + [0xFF] * (4 - len(arg_regs))
        self.code += bytes([OP_CALL])
        self.code += int(callee_offset).to_bytes(2, "little")
        self.code += bytes(args_padded[:4])
        self.code += bytes([r_dst])


class FunctionCompiler:
    """Compiles one eligible function's AST into bytecode."""
    def __init__(self, start_offset=0, func_entry_offsets=None):
        self.start_offset = start_offset
        self.b = BytecodeBuilder(start_offset=start_offset)
        self.next_reg = 0
        self.var_reg = {}   # variable name -> register index
        self.arg_index = {}  # param name -> arg index
        self.next_mem_offset = 0
        self.array_offsets = {}  # array name -> (base_offset, size)
        self.struct_offsets = {} # struct var name -> (base_offset, {field_name: field_index})
        self.func_entry_offsets = func_entry_offsets or {}  # callee name -> offset

    def alloc_reg(self):
        r = self.next_reg
        self.next_reg += 1
        if self.next_reg > 16:
            raise RuntimeError("ran out of registers (max 16 supported)")
        return r

    def free_scratch_regs(self):
        if self.var_reg:
            self.next_reg = max(self.var_reg.values()) + 1
        else:
            self.next_reg = 0

    def parse_array_subscript(self, node):
        children = list(node.get_children())
        base_node = children[0]
        idx_node = children[1]
        while base_node.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
            sub = list(base_node.get_children())
            if sub:
                base_node = sub[0]
            else:
                break
        return base_node.spelling, idx_node

    def parse_member_ref(self, node):
        field_name = node.spelling
        children = list(node.get_children())
        if not children:
            raise RuntimeError(f"invalid member ref expr: {node.spelling}")
        child = children[0]
        while child.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
            child_subs = list(child.get_children())
            if not child_subs:
                break
            child = child_subs[0]
        if child.kind == ci.CursorKind.DECL_REF_EXPR:
            struct_name = child.spelling
            if struct_name not in self.struct_offsets:
                raise RuntimeError(f"unknown struct identifier: '{struct_name}'")
            base_offset, field_map = self.struct_offsets[struct_name]
            if field_name not in field_map:
                raise RuntimeError(f"unknown field '{field_name}' in struct '{struct_name}'")
            return base_offset + field_map[field_name]
        raise RuntimeError(f"unsupported member ref target: {child.kind}")

    def compile_function(self, func_cursor):
        params = list(func_cursor.get_arguments())
        for i, p in enumerate(params):
            self.arg_index[p.spelling] = i
            r = self.alloc_reg()
            self.b.load_arg(r, i)
            self.var_reg[p.spelling] = r

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
                self.free_scratch_regs()

        elif node.kind == ci.CursorKind.DECL_STMT:
            for c in node.get_children():
                self.compile_stmt(c)
                self.free_scratch_regs()

        elif node.kind == ci.CursorKind.VAR_DECL:
            if node.type.kind == ci.TypeKind.CONSTANTARRAY:
                elem_type = node.type.element_type.spelling
                if elem_type != "int":
                    raise RuntimeError(f"unsupported array element type '{elem_type}'")
                size = node.type.element_count
                if self.next_mem_offset + size > 256:
                    raise RuntimeError(f"array memory overflow: allocated {self.next_mem_offset + size} > 256")
                base_offset = self.next_mem_offset
                self.array_offsets[node.spelling] = (base_offset, size)
                self.next_mem_offset += size

                children = list(node.get_children())
                init_list = None
                for c in children:
                    if c.kind == ci.CursorKind.INIT_LIST_EXPR:
                        init_list = c
                        break
                if init_list:
                    init_exprs = list(init_list.get_children())
                    for idx, elem_expr in enumerate(init_exprs):
                        val_reg = self.compile_expr(elem_expr)
                        idx_reg = self.alloc_reg()
                        self.b.load_const(idx_reg, idx)
                        self.b.arr_store(base_offset, idx_reg, val_reg)
                        self.free_scratch_regs()
            elif node.type.kind == ci.TypeKind.RECORD:
                decl = node.type.get_declaration()
                if hasattr(decl.type, 'get_fields'):
                    fields = list(decl.type.get_fields())
                    if not fields:
                        fields = [c for c in decl.get_children() if c.kind == ci.CursorKind.FIELD_DECL]
                else:
                    fields = [c for c in decl.get_children() if c.kind == ci.CursorKind.FIELD_DECL]
                size = len(fields)
                if self.next_mem_offset + size > 256:
                    raise RuntimeError(f"struct memory overflow: allocated {self.next_mem_offset + size} > 256")
                base_offset = self.next_mem_offset
                field_map = {f.spelling: idx for idx, f in enumerate(fields)}
                self.struct_offsets[node.spelling] = (base_offset, field_map)
                self.next_mem_offset += size

                children = list(node.get_children())
                init_list = None
                for c in children:
                    if c.kind == ci.CursorKind.INIT_LIST_EXPR:
                        init_list = c
                        break
                if init_list:
                    init_exprs = list(init_list.get_children())
                    for idx, elem_expr in enumerate(init_exprs):
                        val_reg = self.compile_expr(elem_expr)
                        r_zero = self.alloc_reg()
                        self.b.load_const(r_zero, 0)
                        field_mem_slot = base_offset + idx
                        self.b.arr_store(field_mem_slot, r_zero, val_reg)
                        self.free_scratch_regs()
            else:
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

        elif node.kind == ci.CursorKind.WHILE_STMT:
            children = list(node.get_children())
            cond = children[0]
            body = children[1]
            loop_start = self.b.here()
            cond_reg = self.compile_expr(cond)
            patch_exit = self.b.jmp_if_false(cond_reg)
            self.compile_stmt(body)
            self.b.jmp_to(loop_start)
            exit_target = self.b.here()
            self.b.patch(patch_exit, exit_target)

        elif node.kind == ci.CursorKind.FOR_STMT:
            tokens = list(node.get_tokens())
            semis = [t for t in tokens if t.spelling == ';'][:2]
            semi1_start = semis[0].extent.start.offset if len(semis) > 0 else 0
            semi2_start = semis[1].extent.start.offset if len(semis) > 1 else 0

            children = list(node.get_children())
            body_node = children[-1]
            init_node, cond_node, inc_node = None, None, None
            for c in children[:-1]:
                c_start = c.extent.start.offset
                if c_start < semi1_start:
                    init_node = c
                elif semi1_start <= c_start < semi2_start:
                    cond_node = c
                elif c_start > semi2_start:
                    inc_node = c

            if init_node:
                self.compile_stmt(init_node)

            loop_start = self.b.here()
            patch_exit = None
            if cond_node:
                cond_reg = self.compile_expr(cond_node)
                patch_exit = self.b.jmp_if_false(cond_reg)

            self.compile_stmt(body_node)

            if inc_node:
                self.compile_stmt(inc_node)

            self.b.jmp_to(loop_start)
            exit_target = self.b.here()
            if patch_exit is not None:
                self.b.patch(patch_exit, exit_target)

        elif node.kind == ci.CursorKind.BINARY_OPERATOR:
            op_tok = self._binary_op_symbol(node)
            if op_tok == '=':
                children = list(node.get_children())
                lhs, rhs = children[0], children[1]
                r_src = self.compile_expr(rhs)
                target = lhs
                if target.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                    target = list(target.get_children())[0]
                if target.kind == ci.CursorKind.DECL_REF_EXPR and target.spelling in self.var_reg:
                    r_dst = self.var_reg[target.spelling]
                    self.copy_reg(r_dst, r_src)
                elif target.kind == ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
                    arr_name, idx_node = self.parse_array_subscript(target)
                    if arr_name not in self.array_offsets:
                        raise RuntimeError(f"unknown array identifier: {arr_name}")
                    base_offset, arr_size = self.array_offsets[arr_name]
                    idx_reg = self.compile_expr(idx_node)
                    self.b.arr_store(base_offset, idx_reg, r_src)
                elif target.kind == ci.CursorKind.MEMBER_REF_EXPR:
                    field_mem_slot = self.parse_member_ref(target)
                    r_zero = self.alloc_reg()
                    self.b.load_const(r_zero, 0)
                    self.b.arr_store(field_mem_slot, r_zero, r_src)
                else:
                    raise RuntimeError(f"cannot assign to {getattr(target, 'spelling', '<unknown>')}")
            else:
                self.compile_expr(node)

        elif node.kind == ci.CursorKind.UNARY_OPERATOR:
            tokens = [t.spelling for t in node.get_tokens()]
            children = list(node.get_children())
            target = children[0]
            if target.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                target = list(target.get_children())[0]
            if target.kind == ci.CursorKind.DECL_REF_EXPR and target.spelling in self.var_reg:
                r_var = self.var_reg[target.spelling]
                one_reg = self.alloc_reg()
                self.b.load_const(one_reg, 1)
                if '++' in tokens:
                    self.b.binop(OP_ADD, r_var, r_var, one_reg)
                elif '--' in tokens:
                    self.b.binop(OP_SUB, r_var, r_var, one_reg)
                else:
                    raise RuntimeError(f"unsupported unary operator: {tokens}")
            elif target.kind == ci.CursorKind.MEMBER_REF_EXPR:
                field_mem_slot = self.parse_member_ref(target)
                r_zero = self.alloc_reg()
                self.b.load_const(r_zero, 0)
                cur_val_reg = self.alloc_reg()
                self.b.arr_load(cur_val_reg, field_mem_slot, r_zero)
                one_reg = self.alloc_reg()
                self.b.load_const(one_reg, 1)
                new_val_reg = self.alloc_reg()
                if '++' in tokens:
                    self.b.binop(OP_ADD, new_val_reg, cur_val_reg, one_reg)
                elif '--' in tokens:
                    self.b.binop(OP_SUB, new_val_reg, cur_val_reg, one_reg)
                else:
                    raise RuntimeError(f"unsupported unary operator: {tokens}")
                self.b.arr_store(field_mem_slot, r_zero, new_val_reg)
            else:
                raise RuntimeError(f"cannot increment/decrement {getattr(target, 'spelling', '<unknown>')}")

        elif node.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
            children = list(node.get_children())
            if children:
                self.compile_stmt(children[0])

        elif node.kind == ci.CursorKind.CALL_EXPR:
            callee_name = node.spelling
            if not callee_name:
                children = list(node.get_children())
                if children:
                    callee_name = children[0].spelling
            if callee_name in self.struct_offsets or node.type.kind == ci.TypeKind.RECORD:
                return  # Nop default constructor call for struct
            self.compile_expr(node)

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

        if node.kind == ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
            arr_name, idx_node = self.parse_array_subscript(node)
            if arr_name not in self.array_offsets:
                raise RuntimeError(f"unknown array identifier: {arr_name}")
            base_offset, arr_size = self.array_offsets[arr_name]
            idx_reg = self.compile_expr(idx_node)
            dst_reg = self.alloc_reg()
            self.b.arr_load(dst_reg, base_offset, idx_reg)
            return dst_reg

        if node.kind == ci.CursorKind.MEMBER_REF_EXPR:
            field_mem_slot = self.parse_member_ref(node)
            r_zero = self.alloc_reg()
            self.b.load_const(r_zero, 0)
            dst_reg = self.alloc_reg()
            self.b.arr_load(dst_reg, field_mem_slot, r_zero)
            return dst_reg

        if node.kind == ci.CursorKind.CALL_EXPR:
            callee_name = node.spelling
            if not callee_name:
                children = list(node.get_children())
                if children:
                    callee_name = children[0].spelling
            if callee_name not in self.func_entry_offsets:
                raise RuntimeError(f"unknown callee function: '{callee_name}'")
            callee_offset = self.func_entry_offsets[callee_name]

            args = list(node.get_arguments())
            if not args:
                children = list(node.get_children())
                if len(children) > 1:
                    args = children[1:]
            if len(args) > 4:
                raise RuntimeError(f"call to '{callee_name}' has {len(args)} args (max 4 supported)")

            arg_regs = [self.compile_expr(a) for a in args]
            r_dst = self.alloc_reg()
            self.b.call(callee_offset, arg_regs, r_dst)
            return r_dst

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
        if len(children) >= 2:
            lhs_extent_end = children[0].extent.end
            rhs_extent_start = children[1].extent.start
            for tok in node.get_tokens():
                if (tok.extent.start.offset >= lhs_extent_end.offset and
                        tok.extent.end.offset <= rhs_extent_start.offset):
                    if tok.spelling in BIN_OP_TO_OPCODE or tok.spelling == '=':
                        return tok.spelling
        # fallback: scan all tokens for a known operator symbol
        for tok in node.get_tokens():
            if tok.spelling in BIN_OP_TO_OPCODE or tok.spelling == '=':
                return tok.spelling
        raise RuntimeError("could not determine binary operator")


def is_string_type(type_spelling: str) -> bool:
    """Checks if a C++ type spelling is std::string."""
    return "string" in type_spelling or "basic_string" in type_spelling


def string_function_eligibility_check(func_cursor) -> bool:
    """Checks if a function qualifies for std::string VM virtualization:
    - All parameters are std::string.
    - Return type is std::string, bool, or int.
    - Body is a single RETURN_STMT containing string concatenation (+),
      equality comparison (==), or inequality comparison (!=)."""
    if func_cursor.kind != ci.CursorKind.FUNCTION_DECL:
        return False

    params = list(func_cursor.get_arguments())
    if not params:
        return False

    for p in params:
        if not is_string_type(p.type.spelling):
            return False

    ret_type = func_cursor.result_type.spelling
    if not (is_string_type(ret_type) or ret_type in ("bool", "_Bool", "int", "int64_t")):
        return False

    body = next((c for c in func_cursor.get_children() if c.kind == ci.CursorKind.COMPOUND_STMT), None)
    if body is None:
        return False

    stmts = list(body.get_children())
    if len(stmts) != 1 or stmts[0].kind != ci.CursorKind.RETURN_STMT:
        return False

    allowed_kinds = {
        ci.CursorKind.RETURN_STMT, ci.CursorKind.CALL_EXPR, ci.CursorKind.BINARY_OPERATOR,
        ci.CursorKind.DECL_REF_EXPR, ci.CursorKind.STRING_LITERAL, ci.CursorKind.UNEXPOSED_EXPR,
        ci.CursorKind.PAREN_EXPR
    }

    for n in stmts[0].walk_preorder():
        if n.kind not in allowed_kinds:
            return False
        if n.kind in (ci.CursorKind.CALL_EXPR, ci.CursorKind.BINARY_OPERATOR):
            sp = n.spelling
            if sp and not any(op in sp for op in ("operator+", "operator==", "operator!=", "+", "==", "!=")):
                return False

    return True


class StringFunctionCompiler:
    """Compiles eligible std::string functions into string VM bytecode and string constant pools."""

    def __init__(self, func_cursor):
        self.func = func_cursor
        self.params = {p.spelling: idx for idx, p in enumerate(func_cursor.get_arguments())}
        self.const_pool = []
        self.const_map = {}
        self.bytecode = bytearray()
        self.next_str_reg = 0
        self.next_int_reg = 0

    def alloc_str_reg(self) -> int:
        r = self.next_str_reg
        self.next_str_reg += 1
        if self.next_str_reg > 16:
            raise RuntimeError("Ran out of string registers (max 16)")
        return r

    def get_const_idx(self, s_val: str) -> int:
        if s_val not in self.const_map:
            idx = len(self.const_pool)
            self.const_pool.append(s_val)
            self.const_map[s_val] = idx
        return self.const_map[s_val]

    def compile(self):
        body = next(c for c in self.func.get_children() if c.kind == ci.CursorKind.COMPOUND_STMT)
        ret_stmt = next(c for c in body.get_children() if c.kind == ci.CursorKind.RETURN_STMT)
        expr = list(ret_stmt.get_children())[0]
        res_kind, res_reg = self._compile_expr(expr)

        if res_kind == "string":
            self.bytecode.append(OP_RET_STR)
            self.bytecode.append(res_reg)
        else:
            self.bytecode.append(OP_RET_STR_INT)
            self.bytecode.append(res_reg)

        return bytes(self.bytecode), self.const_pool

    def _compile_expr(self, node):
        while node.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
            children = list(node.get_children())
            if not children:
                break
            if len(children) == 1 and children[0].kind == ci.CursorKind.DECL_REF_EXPR and "operator" in children[0].spelling:
                break
            node = children[0]

        if node.kind == ci.CursorKind.DECL_REF_EXPR and node.spelling in self.params:
            arg_idx = self.params[node.spelling]
            reg = self.alloc_str_reg()
            self.bytecode.append(OP_STR_LOAD_ARG)
            self.bytecode.append(reg)
            self.bytecode.append(arg_idx)
            return "string", reg

        elif node.kind == ci.CursorKind.STRING_LITERAL:
            raw_spelling = node.spelling
            from pipeline import decode_cpp_string_literal
            unescaped_bytes = decode_cpp_string_literal(raw_spelling)
            unescaped_str = unescaped_bytes.decode("utf-8", errors="replace")
            const_idx = self.get_const_idx(unescaped_str)
            reg = self.alloc_str_reg()
            self.bytecode.append(OP_STR_LOAD_CONST)
            self.bytecode.append(reg)
            self.bytecode.append(const_idx)
            return "string", reg

        elif node.kind in (ci.CursorKind.CALL_EXPR, ci.CursorKind.BINARY_OPERATOR):
            sp = node.spelling
            children = list(node.get_children())

            is_concat = "operator+" in sp or sp == "+" or any(t.spelling == "+" for t in node.get_tokens())
            is_eq = "operator==" in sp or sp == "==" or any(t.spelling == "==" for t in node.get_tokens())
            is_ne = "operator!=" in sp or sp == "!=" or any(t.spelling == "!=" for t in node.get_tokens())

            operand_children = []
            for c in children:
                sub = c
                while sub.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                    subs = list(sub.get_children())
                    if not subs: break
                    sub = subs[0]
                if sub.kind == ci.CursorKind.DECL_REF_EXPR and "operator" in sub.spelling:
                    continue
                operand_children.append(c)

            saved_str_reg = self.next_str_reg

            if is_concat:
                _, reg1 = self._compile_expr(operand_children[0])
                _, reg2 = self._compile_expr(operand_children[1])
                self.next_str_reg = saved_str_reg
                dst_reg = self.alloc_str_reg()
                self.bytecode.append(OP_STR_CONCAT)
                self.bytecode.append(dst_reg)
                self.bytecode.append(reg1)
                self.bytecode.append(reg2)
                return "string", dst_reg

            elif is_eq or is_ne:
                _, reg1 = self._compile_expr(operand_children[0])
                _, reg2 = self._compile_expr(operand_children[1])
                self.next_str_reg = saved_str_reg
                dst_int_reg = self.next_int_reg
                self.next_int_reg += 1
                op_code = OP_STR_EQ if is_eq else OP_STR_NE
                self.bytecode.append(op_code)
                self.bytecode.append(dst_int_reg)
                self.bytecode.append(reg1)
                self.bytecode.append(reg2)
                return "int", dst_int_reg

        raise RuntimeError(f"Unsupported string expression node: {node.kind} {node.spelling}")

