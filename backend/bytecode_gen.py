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

OP_RET_STRUCT = 0x1F
OP_STRUCT_RET_LOAD = 0x20
OP_LOAD_FRAME_ADDR = 0x21

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
    OP_RET_STRUCT: 5,
    OP_STRUCT_RET_LOAD: 2,
    OP_LOAD_FRAME_ADDR: 2,
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
    ci.CursorKind.CXX_METHOD, ci.CursorKind.CXX_THIS_EXPR,
}


def eligibility_check(func_cursor, all_func_names=None, known_leaf_functions=None, struct_names=None):
    """Returns (True, reason) if this function can be fully virtualized,
    (False, reason) otherwise. Only allows: int/struct params (total slots <= 4), int/struct locals,
    fixed-size int arrays, arithmetic, comparisons, loops, if/return, calls, and struct methods."""
    if known_leaf_functions is not None and all_func_names is None:
        allowed_callees = known_leaf_functions
    else:
        allowed_callees = all_func_names

    if struct_names is None and hasattr(func_cursor, 'translation_unit') and func_cursor.translation_unit:
        struct_names = {c.spelling for c in func_cursor.translation_unit.cursor.get_children()
                        if c.kind in (ci.CursorKind.STRUCT_DECL, ci.CursorKind.CLASS_DECL)}
    else:
        struct_names = struct_names or set()

    def get_struct_fields(decl_cursor):
        if hasattr(decl_cursor.type, 'get_fields'):
            fields = list(decl_cursor.type.get_fields())
            if fields: return fields
        return [c for c in decl_cursor.get_children() if c.kind == ci.CursorKind.FIELD_DECL]

    # Return type check: int, void, or int-only fields struct (max 4 fields)
    ret_type = func_cursor.result_type
    if ret_type.kind in (ci.TypeKind.LVALUEREFERENCE, ci.TypeKind.POINTER):
        return False, f"unsupported return type '{ret_type.spelling}' (pointers/references not supported as return types)"
    if ret_type.spelling != "int" and ret_type.spelling != "void" and ret_type.kind != ci.TypeKind.VOID:
        if ret_type.kind == ci.TypeKind.RECORD:
            decl = ret_type.get_declaration()
            fields = get_struct_fields(decl)
            if not fields:
                return False, f"unsupported return struct type '{ret_type.spelling}' (no fields)"
            for f in fields:
                if f.type.kind != ci.TypeKind.INT:
                    return False, f"unsupported return struct field '{f.spelling}' of type '{f.type.spelling}' (non-int)"
            if len(fields) > 4:
                return False, f"unsupported return struct '{ret_type.spelling}' with {len(fields)} fields (max 4 supported)"
        else:
            return False, f"unsupported return type '{ret_type.spelling}'"

    # Parameter check
    for p in func_cursor.get_arguments():
        if p.type.spelling == "int":
            pass
        elif p.type.kind in (ci.TypeKind.LVALUEREFERENCE, ci.TypeKind.POINTER):
            pointee = p.type.get_pointee()
            if pointee.spelling != "int" and pointee.kind != ci.TypeKind.INT:
                return False, f"unsupported pointer/reference parameter '{p.spelling}' to non-int type '{pointee.spelling}'"
        elif p.type.kind == ci.TypeKind.RECORD:
            decl = p.type.get_declaration()
            fields = get_struct_fields(decl)
            if not fields:
                return False, f"unsupported struct parameter '{p.spelling}' (no fields)"
            for f in fields:
                if f.type.kind != ci.TypeKind.INT:
                    return False, f"unsupported struct parameter field '{f.spelling}' of type '{f.type.spelling}' (non-int)"
        else:
            return False, f"unsupported parameter type '{p.type.spelling}'"

    # Per-frame memory budget check: combined local memory slots (struct params, arrays, structs, address-taken variables) <= 16
    total_mem_slots = 0
    for p in func_cursor.get_arguments():
        if p.type.kind == ci.TypeKind.RECORD:
            decl = p.type.get_declaration()
            fields = get_struct_fields(decl)
            total_mem_slots += len(fields)

    body_cursor = None
    for c in func_cursor.get_children():
        if c.kind == ci.CursorKind.COMPOUND_STMT:
            body_cursor = c

    if body_cursor:
        address_taken_names = set()
        for n in body_cursor.walk_preorder():
            if n.kind == ci.CursorKind.VAR_DECL:
                if n.type.kind == ci.TypeKind.CONSTANTARRAY:
                    total_mem_slots += n.type.element_count
                elif n.type.kind == ci.TypeKind.RECORD:
                    decl = n.type.get_declaration()
                    fields = get_struct_fields(decl)
                    total_mem_slots += len(fields)
            elif n.kind == ci.CursorKind.UNARY_OPERATOR:
                toks = [t.spelling for t in n.get_tokens()]
                if toks and toks[0] == "&":
                    subs = list(n.get_children())
                    if subs:
                        target = subs[0]
                        while target.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                            c_subs = list(target.get_children())
                            if c_subs: target = c_subs[0]
                            else: break
                        if target.kind == ci.CursorKind.DECL_REF_EXPR:
                            address_taken_names.add(target.spelling)
            elif n.kind == ci.CursorKind.CALL_EXPR:
                callee_cursor = n.get_definition() if hasattr(n, 'get_definition') else None
                if callee_cursor and callee_cursor.kind == ci.CursorKind.FUNCTION_DECL:
                    c_params = list(callee_cursor.get_arguments())
                    args = list(n.get_arguments())
                    for p_node, arg_expr in zip(c_params, args):
                        if p_node.type.kind in (ci.TypeKind.LVALUEREFERENCE, ci.TypeKind.POINTER):
                            sub = arg_expr
                            while sub.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                                c_subs = list(sub.get_children())
                                if c_subs: sub = c_subs[0]
                                else: break
                            if sub.kind == ci.CursorKind.DECL_REF_EXPR:
                                address_taken_names.add(sub.spelling)
                            elif sub.kind == ci.CursorKind.UNARY_OPERATOR:
                                s_toks = [t.spelling for t in sub.get_tokens()]
                                if s_toks and s_toks[0] == "&":
                                    c_subs = list(sub.get_children())
                                    if c_subs:
                                        c_target = c_subs[0]
                                        while c_target.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                                            subs2 = list(c_target.get_children())
                                            if subs2: c_target = subs2[0]
                                            else: break
                                        if c_target.kind == ci.CursorKind.DECL_REF_EXPR:
                                            address_taken_names.add(c_target.spelling)

        for var_name in address_taken_names:
            is_scalar = True
            for n in body_cursor.walk_preorder():
                if n.kind == ci.CursorKind.VAR_DECL and n.spelling == var_name:
                    if n.type.kind in (ci.TypeKind.CONSTANTARRAY, ci.TypeKind.RECORD):
                        is_scalar = False
                    break
            if is_scalar:
                total_mem_slots += 1

    if total_mem_slots > 16:
        return False, f"function local memory allocation ({total_mem_slots} slots) exceeds max per-frame limit of 16 slots"

    bad = []

    rec_methods = set()
    tu = func_cursor.translation_unit if hasattr(func_cursor, 'translation_unit') else None
    if tu:
        for s_node in tu.cursor.get_children():
            if s_node.kind in (ci.CursorKind.STRUCT_DECL, ci.CursorKind.CLASS_DECL):
                s_name = s_node.spelling
                methods = {c.spelling: c for c in s_node.get_children() if c.kind == ci.CursorKind.CXX_METHOD}
                if not methods:
                    continue
                graph = {m_name: set() for m_name in methods}
                for m_name, m_cursor in methods.items():
                    for n in m_cursor.walk_preorder():
                        if n.kind == ci.CursorKind.CALL_EXPR:
                            n_children = list(n.get_children())
                            if n_children and n_children[0].kind == ci.CursorKind.MEMBER_REF_EXPR:
                                target_m = n_children[0].spelling
                                if target_m in methods:
                                    graph[m_name].add(target_m)

                cycles = set()
                def dfs(n_m, path, visited):
                    visited.add(n_m)
                    path.append(n_m)
                    for neighbor in graph.get(n_m, []):
                        if neighbor in path:
                            cycles.update(path[path.index(neighbor):])
                        elif neighbor not in visited:
                            dfs(neighbor, path, visited)
                    path.pop()

                for m_name in methods:
                    dfs(m_name, [], set())
                for m_name in cycles:
                    rec_methods.add((s_name, m_name))

    def get_struct_fields(decl_cursor):
        if hasattr(decl_cursor.type, 'get_fields'):
            fields = list(decl_cursor.type.get_fields())
            if fields: return fields
        return [c for c in decl_cursor.get_children() if c.kind == ci.CursorKind.FIELD_DECL]

    def walk(node):
        if node.kind not in ALLOWED_KINDS:
            bad.append(str(node.kind))
            return
        if node.kind == ci.CursorKind.STRUCT_DECL:
            s_name = node.spelling
            for child in node.get_children():
                if child.kind == ci.CursorKind.CXX_METHOD:
                    m_name = child.spelling
                    if (s_name, m_name) in rec_methods:
                        bad.append(f"struct method '{m_name}' is recursive (recursion not supported for inlined methods)")
                        return
                    if child.result_type.spelling != "int":
                        bad.append(f"method '{child.spelling}' with non-int return type '{child.result_type.spelling}'")
                        return
                    for mp in child.get_arguments():
                        if mp.type.spelling != "int":
                            bad.append(f"method '{child.spelling}' parameter '{mp.spelling}' of non-int type '{mp.type.spelling}'")
                            return
        elif node.kind == ci.CursorKind.VAR_DECL:
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
        elif node.kind == ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
            children = list(node.get_children())
            if children:
                base = children[0]
                while base.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                    subs = list(base.get_children())
                    if subs: base = subs[0]
                    else: break
                def_cursor = base.get_definition() if hasattr(base, 'get_definition') and base.get_definition() else None
                if def_cursor and def_cursor.type.kind in (ci.TypeKind.POINTER, ci.TypeKind.LVALUEREFERENCE):
                    bad.append("pointer arithmetic/subscript 'p[i]' not supported")
                    return
                elif base.kind == ci.CursorKind.DECL_REF_EXPR and base.type.kind in (ci.TypeKind.POINTER, ci.TypeKind.LVALUEREFERENCE) and (not def_cursor or def_cursor.type.kind not in (ci.TypeKind.CONSTANTARRAY, ci.TypeKind.INCOMPLETEARRAY)):
                    bad.append("pointer arithmetic/subscript 'p[i]' not supported")
                    return
        elif node.kind == ci.CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            if any(c.type.kind in (ci.TypeKind.POINTER, ci.TypeKind.LVALUEREFERENCE) for c in children):
                bad.append("pointer arithmetic not supported")
                return
        elif node.kind == ci.CursorKind.UNARY_OPERATOR:
            toks = list(node.get_tokens())
            op_str = toks[0].spelling if toks else ""
            if op_str in ("++", "--"):
                children = list(node.get_children())
                if children and children[0].type.kind in (ci.TypeKind.POINTER, ci.TypeKind.LVALUEREFERENCE):
                    bad.append("pointer arithmetic 'p++'/'p--' not supported")
                    return
        elif node.kind == ci.CursorKind.CALL_EXPR:
            children = list(node.get_children())
            if children and children[0].kind == ci.CursorKind.MEMBER_REF_EXPR:
                mem_ref = children[0]
                m_name = mem_ref.spelling
                for (s_n, rec_m) in rec_methods:
                    if m_name == rec_m:
                        bad.append(f"struct method '{m_name}' is recursive (recursion not supported for inlined methods)")
                        return
                mem_children = list(mem_ref.get_children())
                if mem_children:
                    inst = mem_children[0]
                    while inst.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                        sub_inst = list(inst.get_children())
                        if sub_inst: inst = sub_inst[0]
                        else: break
                    if inst.kind != ci.CursorKind.DECL_REF_EXPR:
                        bad.append(f"method call '{node.spelling}' on non-variable instance")
                        return
                    defn = inst.get_definition()
                    if defn and defn.kind == ci.CursorKind.PARM_DECL:
                        bad.append(f"method call '{node.spelling}' on struct parameter '{inst.spelling}'")
                        return
                    if defn and defn.kind != ci.CursorKind.VAR_DECL:
                        bad.append(f"method call '{node.spelling}' on non-local struct variable '{inst.spelling}'")
                        return
                return
            callee_name = node.spelling
            if not callee_name:
                if children:
                    callee_name = children[0].spelling
            if callee_name in struct_names:
                return  # Default struct constructor call inside VAR_DECL
            if allowed_callees is not None and callee_name not in allowed_callees:
                bad.append(f"call to non-leaf/unknown function '{callee_name}'")
                return
            args = list(node.get_arguments())
            if not args:
                if len(children) > 1:
                    args = children[1:]
            total_slots = 0
            for a in args:
                if a.type.kind == ci.TypeKind.RECORD:
                    fields = get_struct_fields(a.type.get_declaration())
                    total_slots += len(fields) if fields else 1
                else:
                    total_slots += 1
            if total_slots > 4:
                bad.append(f"call to '{callee_name}' with {total_slots} argument slots (max 4 supported)")
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
        self.last_op = None

    def here(self):
        return self.start_offset + len(self.code)

    def load_arg(self, r_dst, arg_index):
        self.last_op = OP_LOAD_ARG
        self.code += bytes([OP_LOAD_ARG, r_dst, arg_index])

    def load_const(self, r_dst, value):
        self.last_op = OP_LOAD_CONST
        self.code += bytes([OP_LOAD_CONST, r_dst])
        self.code += int(value).to_bytes(8, "little", signed=True)

    def binop(self, opcode, r_dst, r_a, r_b):
        self.last_op = opcode
        self.code += bytes([opcode, r_dst, r_a, r_b])

    def jmp_if_true(self, r_cond):
        self.last_op = OP_JMP_IF_TRUE
        self.code += bytes([OP_JMP_IF_TRUE, r_cond, 0xFF, 0xFF])
        return self.start_offset + len(self.code) - 2

    def jmp_if_false(self, r_cond):
        self.last_op = OP_JMP_IF_FALSE
        self.code += bytes([OP_JMP_IF_FALSE, r_cond, 0xFF, 0xFF])
        return self.start_offset + len(self.code) - 2

    def jmp(self):
        self.last_op = OP_JMP
        self.code += bytes([OP_JMP, 0xFF, 0xFF])
        return self.start_offset + len(self.code) - 2

    def jmp_to(self, target):
        """Unconditional jump to an ALREADY KNOWN address (e.g. jumping
        backward to a loop's start) - unlike self.jmp(), which returns a
        patch location for a FORWARD target not yet known."""
        self.last_op = OP_JMP
        self.code += bytes([OP_JMP])
        self.code += int(target).to_bytes(2, "little")

    def patch(self, patch_at, target):
        rel_patch_at = patch_at - self.start_offset
        self.code[rel_patch_at] = target & 0xFF
        self.code[rel_patch_at + 1] = (target >> 8) & 0xFF

    def ret_const(self, value):
        self.last_op = OP_RET_CONST
        self.code += bytes([OP_RET_CONST])
        self.code += int(value).to_bytes(8, "little", signed=True)

    def ret_reg(self, r_src):
        self.last_op = OP_RET_REG
        self.code += bytes([OP_RET_REG, r_src])

    def arr_load(self, r_dst, base_offset, r_idx):
        self.last_op = OP_ARR_LOAD
        self.code += bytes([OP_ARR_LOAD, r_dst, base_offset, r_idx])

    def arr_store(self, base_offset, r_idx, r_src):
        self.last_op = OP_ARR_STORE
        self.code += bytes([OP_ARR_STORE, base_offset, r_idx, r_src])

    def call(self, callee_offset, arg_regs, r_dst):
        self.last_op = OP_CALL
        args_padded = list(arg_regs) + [0xFF] * (4 - len(arg_regs))
        self.code += bytes([OP_CALL])
        self.code += int(callee_offset).to_bytes(2, "little")
        self.code += bytes(args_padded[:4])
        self.code += bytes([r_dst])

    def ret_struct(self, n_fields, field_regs):
        self.last_op = OP_RET_STRUCT
        r0 = field_regs[0] if len(field_regs) > 0 else 0xFF
        r1 = field_regs[1] if len(field_regs) > 1 else 0xFF
        r2 = field_regs[2] if len(field_regs) > 2 else 0xFF
        r3 = field_regs[3] if len(field_regs) > 3 else 0xFF
        self.code += bytes([OP_RET_STRUCT, n_fields, r0, r1, r2, r3])

    def struct_ret_load(self, r_dst, field_idx):
        self.last_op = OP_STRUCT_RET_LOAD
        self.code += bytes([OP_STRUCT_RET_LOAD, r_dst, field_idx])

    def load_frame_addr(self, r_dst, slot_offset):
        self.last_op = OP_LOAD_FRAME_ADDR
        self.code += bytes([OP_LOAD_FRAME_ADDR, r_dst, slot_offset])


class FunctionCompiler:
    """Compiles one eligible function's AST into bytecode."""
    def __init__(self, start_offset=0, func_entry_offsets=None, struct_names=None):
        self.start_offset = start_offset
        self.b = BytecodeBuilder(start_offset=start_offset)
        self.next_reg = 0
        self.var_reg = {}   # variable name -> register index
        self.arg_index = {}  # param name -> arg index
        self.next_mem_offset = 0
        self.array_offsets = {}  # array name -> (base_offset, size)
        self.struct_offsets = {} # struct var name -> (base_offset, {field_name: field_index})
        self.func_entry_offsets = func_entry_offsets or {}  # callee name -> offset
        self.struct_names = struct_names or set()
        self.struct_methods = {}
        self.current_this_offset = None
        self.current_this_fields = None
        self.in_method_return = False
        self.method_ret_reg = None
        self.method_ret_jmps = []
        self.ref_params = set()
        self.ptr_params = set()
        self.mem_vars = {}

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

    def copy_reg(self, r_dst, r_src):
        if r_dst == r_src:
            return
        r_zero = self.alloc_reg()
        if r_zero == r_src:
            r_zero = self.alloc_reg()
        self.b.load_const(r_zero, 0)
        self.b.binop(OP_ADD, r_dst, r_src, r_zero)

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
        if not children or (children[0].kind in (ci.CursorKind.CXX_THIS_EXPR, ci.CursorKind.UNEXPOSED_EXPR) and not list(children[0].get_children())):
            if self.current_this_offset is None or self.current_this_fields is None:
                raise RuntimeError(f"implicit member reference '{field_name}' outside of method scope")
            if field_name not in self.current_this_fields:
                raise RuntimeError(f"unknown field '{field_name}' in struct method scope")
            return self.current_this_offset + self.current_this_fields[field_name]

        child = children[0]
        while child.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
            child_subs = list(child.get_children())
            if not child_subs:
                break
            child = child_subs[0]

        if child.kind == ci.CursorKind.CXX_THIS_EXPR:
            if self.current_this_offset is None or self.current_this_fields is None:
                raise RuntimeError(f"explicit 'this->{field_name}' reference outside of method scope")
            if field_name not in self.current_this_fields:
                raise RuntimeError(f"unknown field '{field_name}' in struct method scope")
            return self.current_this_offset + self.current_this_fields[field_name]

        if child.kind == ci.CursorKind.DECL_REF_EXPR:
            struct_name = child.spelling
            if struct_name not in self.struct_offsets:
                raise RuntimeError(f"unknown struct identifier: '{struct_name}'")
            base_offset, field_map = self.struct_offsets[struct_name]
            if field_name not in field_map:
                raise RuntimeError(f"unknown field '{field_name}' in struct '{struct_name}'")
            return base_offset + field_map[field_name]
        raise RuntimeError(f"unsupported member ref target: {child.kind}")

    def unwrap_expr(self, node):
        while True:
            if node.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                children = list(node.get_children())
                if children:
                    node = children[0]
                    continue
            elif node.kind == ci.CursorKind.CALL_EXPR:
                if node.spelling in self.func_entry_offsets:
                    break  # Real function call - keep intact
                if node.spelling in self.struct_names:
                    children = list(node.get_children())
                    if children:
                        node = children[0]
                        continue
            break
        return node

    def _get_struct_fields(self, decl_cursor):
        if hasattr(decl_cursor.type, 'get_fields'):
            fields = list(decl_cursor.type.get_fields())
            if fields: return fields
        return [c for c in decl_cursor.get_children() if c.kind == ci.CursorKind.FIELD_DECL]

    def compile_function(self, func_cursor):
        if hasattr(func_cursor, 'translation_unit') and func_cursor.translation_unit:
            if not self.struct_names:
                self.struct_names = {c.spelling for c in func_cursor.translation_unit.cursor.get_children()
                                     if c.kind in (ci.CursorKind.STRUCT_DECL, ci.CursorKind.CLASS_DECL)}
            for c in func_cursor.translation_unit.cursor.get_children():
                if c.kind in (ci.CursorKind.STRUCT_DECL, ci.CursorKind.CLASS_DECL):
                    m_map = {m.spelling: m for m in c.get_children() if m.kind == ci.CursorKind.CXX_METHOD}
                    if m_map:
                        self.struct_methods[c.spelling] = m_map

        self.result_type = func_cursor.result_type
        params = list(func_cursor.get_arguments())
        slot_idx = 0
        for p in params:
            if p.type.spelling == "int":
                self.arg_index[p.spelling] = slot_idx
                r = self.alloc_reg()
                self.b.load_arg(r, slot_idx)
                self.var_reg[p.spelling] = r
                slot_idx += 1
            elif p.type.kind in (ci.TypeKind.LVALUEREFERENCE, ci.TypeKind.POINTER):
                if p.type.kind == ci.TypeKind.LVALUEREFERENCE:
                    self.ref_params.add(p.spelling)
                else:
                    self.ptr_params.add(p.spelling)
                self.arg_index[p.spelling] = slot_idx
                r = self.alloc_reg()
                self.b.load_arg(r, slot_idx)
                self.var_reg[p.spelling] = r
                slot_idx += 1
            elif p.type.kind == ci.TypeKind.RECORD:
                decl = p.type.get_declaration()
                fields = self._get_struct_fields(decl)
                if self.next_mem_offset + len(fields) > 16:
                    raise RuntimeError(f"struct parameter memory overflow: allocated {self.next_mem_offset + len(fields)} > 16 slots per frame")
                base_offset = self.next_mem_offset
                field_map = {f.spelling: idx for idx, f in enumerate(fields)}
                self.struct_offsets[p.spelling] = (base_offset, field_map)
                self.next_mem_offset += len(fields)
                for idx in range(len(fields)):
                    r_arg = self.alloc_reg()
                    self.b.load_arg(r_arg, slot_idx)
                    r_zero = self.alloc_reg()
                    self.b.load_const(r_zero, 0)
                    field_mem_slot = base_offset + idx
                    self.b.arr_store(field_mem_slot, r_zero, r_arg)
                    self.free_scratch_regs()
                    slot_idx += 1

        body = None
        for c in func_cursor.get_children():
            if c.kind == ci.CursorKind.COMPOUND_STMT:
                body = c

        if body:
            address_taken = set()
            for n in body.walk_preorder():
                if n.kind == ci.CursorKind.UNARY_OPERATOR:
                    toks = [t.spelling for t in n.get_tokens()]
                    if toks and toks[0] == "&":
                        subs = list(n.get_children())
                        if subs:
                            target = subs[0]
                            while target.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                                c_subs = list(target.get_children())
                                if c_subs: target = c_subs[0]
                                else: break
                            if target.kind == ci.CursorKind.DECL_REF_EXPR:
                                address_taken.add(target.spelling)
                elif n.kind == ci.CursorKind.CALL_EXPR:
                    callee_cursor = n.get_definition()
                    if callee_cursor and callee_cursor.kind == ci.CursorKind.FUNCTION_DECL:
                        c_params = list(callee_cursor.get_arguments())
                        args = list(n.get_arguments())
                        for p_node, arg_expr in zip(c_params, args):
                            if p_node.type.kind in (ci.TypeKind.LVALUEREFERENCE, ci.TypeKind.POINTER):
                                sub = arg_expr
                                while sub.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                                    c_subs = list(sub.get_children())
                                    if c_subs: sub = c_subs[0]
                                    else: break
                                if sub.kind == ci.CursorKind.DECL_REF_EXPR:
                                    address_taken.add(sub.spelling)
                                elif sub.kind == ci.CursorKind.UNARY_OPERATOR:
                                    s_toks = [t.spelling for t in sub.get_tokens()]
                                    if s_toks and s_toks[0] == "&":
                                        c_subs = list(sub.get_children())
                                        if c_subs:
                                            c_target = c_subs[0]
                                            while c_target.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                                                subs2 = list(c_target.get_children())
                                                if subs2: c_target = subs2[0]
                                                else: break
                                            if c_target.kind == ci.CursorKind.DECL_REF_EXPR:
                                                address_taken.add(c_target.spelling)

            for var_name in address_taken:
                if var_name not in self.var_reg and var_name not in self.ref_params and var_name not in self.ptr_params:
                    if self.next_mem_offset + 1 > 16:
                        raise RuntimeError(f"address-taken variable memory overflow: allocated {self.next_mem_offset + 1} > 16 slots per frame")
                    slot = self.next_mem_offset
                    self.mem_vars[var_name] = slot
                    self.next_mem_offset += 1

        self.compile_stmt(body)
        if getattr(self.b, 'last_op', None) not in (OP_RET_CONST, OP_RET_REG, OP_RET_STRUCT):
            self.b.ret_const(0)
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
                if self.next_mem_offset + size > 16:
                    raise RuntimeError(f"array memory overflow: allocated {self.next_mem_offset + size} > 16 slots per frame")
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
                fields = self._get_struct_fields(decl)
                size = len(fields)
                if self.next_mem_offset + size > 16:
                    raise RuntimeError(f"struct memory overflow: allocated {self.next_mem_offset + size} > 16 slots per frame")
                base_offset = self.next_mem_offset
                field_map = {f.spelling: idx for idx, f in enumerate(fields)}
                self.struct_offsets[node.spelling] = (base_offset, field_map)
                self.next_mem_offset += size

                children = list(node.get_children())
                init_list = None
                other_init = None
                for c in children:
                    if c.kind == ci.CursorKind.INIT_LIST_EXPR:
                        init_list = c
                        break
                    elif c.kind not in (ci.CursorKind.TYPE_REF, ci.CursorKind.STRUCT_DECL):
                        if c.kind == ci.CursorKind.CALL_EXPR and c.spelling in self.struct_names and len(list(c.get_children())) == 0:
                            continue
                        other_init = c
                if init_list:
                    init_exprs = list(init_list.get_children())
                    for idx, elem_expr in enumerate(init_exprs):
                        val_reg = self.compile_expr(elem_expr)
                        r_zero = self.alloc_reg()
                        self.b.load_const(r_zero, 0)
                        field_mem_slot = base_offset + idx
                        self.b.arr_store(field_mem_slot, r_zero, val_reg)
                        self.free_scratch_regs()
                elif other_init:
                    unwrapped_init = self.unwrap_expr(other_init)
                    if unwrapped_init.kind == ci.CursorKind.CALL_EXPR:
                        self.compile_expr(unwrapped_init)
                        for idx in range(size):
                            r_val = self.alloc_reg()
                            self.b.struct_ret_load(r_val, idx)
                            r_zero = self.alloc_reg()
                            self.b.load_const(r_zero, 0)
                            self.b.arr_store(base_offset + idx, r_zero, r_val)
                            self.free_scratch_regs()
                    elif unwrapped_init.kind == ci.CursorKind.DECL_REF_EXPR and unwrapped_init.spelling in self.struct_offsets:
                        src_base, _ = self.struct_offsets[unwrapped_init.spelling]
                        for idx in range(size):
                            r_val = self.alloc_reg()
                            r_zero = self.alloc_reg()
                            self.b.load_const(r_zero, 0)
                            self.b.arr_load(r_val, src_base + idx, r_zero)
                            r_zero2 = self.alloc_reg()
                            self.b.load_const(r_zero2, 0)
                            self.b.arr_store(base_offset + idx, r_zero2, r_val)
                            self.free_scratch_regs()
            else:
                children = list(node.get_children())
                if node.spelling in self.mem_vars:
                    slot_offset = self.mem_vars[node.spelling]
                    if children:
                        val_reg = self.compile_expr(children[0])
                        r_zero = self.alloc_reg()
                        self.b.load_const(r_zero, 0)
                        self.b.arr_store(slot_offset, r_zero, val_reg)
                        self.free_scratch_regs()
                else:
                    r = self.alloc_reg()
                    self.var_reg[node.spelling] = r
                    if children:
                        init_reg = self.compile_expr(children[0])
                        self.b.binop_mov = None  # not used; MOV via ADD-with-0 pattern avoided
                        self.copy_reg(r, init_reg)

        elif node.kind == ci.CursorKind.IF_STMT:
            children = list(node.get_children())
            cond = children[0]
            then_body = children[1]
            else_body = children[2] if len(children) > 2 else None

            r_cond = self.compile_expr(cond)
            patch_else = self.b.jmp_if_false(r_cond)
            self.free_scratch_regs()

            self.compile_stmt(then_body)
            if else_body:
                patch_exit = self.b.jmp()
                else_target = self.b.here()
                self.b.patch(patch_else, else_target)
                self.compile_stmt(else_body)
                exit_target = self.b.here()
                self.b.patch(patch_exit, exit_target)
            else:
                exit_target = self.b.here()
                self.b.patch(patch_else, exit_target)

        elif node.kind == ci.CursorKind.WHILE_STMT:
            children = list(node.get_children())
            cond = children[0]
            body = children[1]

            loop_start = self.b.here()
            r_cond = self.compile_expr(cond)
            patch_exit = self.b.jmp_if_false(r_cond)
            self.free_scratch_regs()

            self.compile_stmt(body)
            self.b.jmp_to(loop_start)

            loop_exit = self.b.here()
            self.b.patch(patch_exit, loop_exit)

        elif node.kind == ci.CursorKind.FOR_STMT:
            children = list(node.get_children())
            init_node = children[0] if len(children) > 0 else None
            cond_node = children[1] if len(children) > 1 else None
            inc_node = children[2] if len(children) > 2 else None
            body_node = children[3] if len(children) > 3 else None

            if init_node:
                self.compile_stmt(init_node)

            loop_start = self.b.here()
            patch_exit = None
            if cond_node:
                r_cond = self.compile_expr(cond_node)
                patch_exit = self.b.jmp_if_false(r_cond)
                self.free_scratch_regs()

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
                target = lhs
                if target.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                    target = list(target.get_children())[0]
                if target.kind == ci.CursorKind.DECL_REF_EXPR and target.spelling in self.struct_offsets:
                    base_offset, field_map = self.struct_offsets[target.spelling]
                    unwrapped_rhs = self.unwrap_expr(rhs)
                    if unwrapped_rhs.kind == ci.CursorKind.CALL_EXPR:
                        self.compile_expr(unwrapped_rhs)
                        for idx in range(len(field_map)):
                            r_val = self.alloc_reg()
                            self.b.struct_ret_load(r_val, idx)
                            r_zero = self.alloc_reg()
                            self.b.load_const(r_zero, 0)
                            self.b.arr_store(base_offset + idx, r_zero, r_val)
                            self.free_scratch_regs()
                    elif unwrapped_rhs.kind == ci.CursorKind.DECL_REF_EXPR and unwrapped_rhs.spelling in self.struct_offsets:
                        src_base, _ = self.struct_offsets[unwrapped_rhs.spelling]
                        for idx in range(len(field_map)):
                            r_val = self.alloc_reg()
                            r_zero = self.alloc_reg()
                            self.b.load_const(r_zero, 0)
                            self.b.arr_load(r_val, src_base + idx, r_zero)
                            r_zero2 = self.alloc_reg()
                            self.b.load_const(r_zero2, 0)
                            self.b.arr_store(base_offset + idx, r_zero2, r_val)
                            self.free_scratch_regs()
                elif target.kind == ci.CursorKind.DECL_REF_EXPR and target.spelling in self.ref_params:
                    r_src = self.compile_expr(rhs)
                    r_ptr = self.var_reg[target.spelling]
                    self.b.arr_store(0xFF, r_ptr, r_src)
                elif target.kind == ci.CursorKind.DECL_REF_EXPR and target.spelling in self.mem_vars:
                    r_src = self.compile_expr(rhs)
                    slot_offset = self.mem_vars[target.spelling]
                    r_zero = self.alloc_reg()
                    self.b.load_const(r_zero, 0)
                    self.b.arr_store(slot_offset, r_zero, r_src)
                elif target.kind == ci.CursorKind.DECL_REF_EXPR and target.spelling in self.var_reg:
                    r_src = self.compile_expr(rhs)
                    r_dst = self.var_reg[target.spelling]
                    self.copy_reg(r_dst, r_src)
                elif target.kind == ci.CursorKind.UNARY_OPERATOR:
                    toks = [t.spelling for t in target.get_tokens()]
                    if toks and toks[0] == "*":
                        r_src = self.compile_expr(rhs)
                        ptr_children = list(target.get_children())
                        r_ptr = self.compile_expr(ptr_children[0])
                        self.b.arr_store(0xFF, r_ptr, r_src)
                elif target.kind == ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
                    r_src = self.compile_expr(rhs)
                    arr_name, idx_node = self.parse_array_subscript(target)
                    if arr_name not in self.array_offsets:
                        raise RuntimeError(f"unknown array identifier: {arr_name}")
                    base_offset, arr_size = self.array_offsets[arr_name]
                    idx_reg = self.compile_expr(idx_node)
                    self.b.arr_store(base_offset, idx_reg, r_src)
                elif target.kind == ci.CursorKind.MEMBER_REF_EXPR:
                    r_src = self.compile_expr(rhs)
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
            if target.kind == ci.CursorKind.DECL_REF_EXPR and (target.spelling in self.mem_vars or target.spelling in self.ref_params):
                r_zero = self.alloc_reg()
                self.b.load_const(r_zero, 0)
                cur_val_reg = self.alloc_reg()
                if target.spelling in self.ref_params:
                    r_ptr = self.var_reg[target.spelling]
                    self.b.arr_load(cur_val_reg, 0xFF, r_ptr)
                else:
                    slot_offset = self.mem_vars[target.spelling]
                    self.b.arr_load(cur_val_reg, slot_offset, r_zero)
                one_reg = self.alloc_reg()
                self.b.load_const(one_reg, 1)
                new_val_reg = self.alloc_reg()
                if '++' in tokens:
                    self.b.binop(OP_ADD, new_val_reg, cur_val_reg, one_reg)
                elif '--' in tokens:
                    self.b.binop(OP_SUB, new_val_reg, cur_val_reg, one_reg)
                else:
                    raise RuntimeError(f"unsupported unary operator: {tokens}")
                if target.spelling in self.ref_params:
                    r_ptr = self.var_reg[target.spelling]
                    self.b.arr_store(0xFF, r_ptr, new_val_reg)
                else:
                    slot_offset = self.mem_vars[target.spelling]
                    self.b.arr_store(slot_offset, r_zero, new_val_reg)
            elif target.kind == ci.CursorKind.DECL_REF_EXPR and target.spelling in self.var_reg:
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
            if self.in_method_return:
                if not children:
                    r_zero = self.alloc_reg()
                    self.b.load_const(r_zero, 0)
                    self.copy_reg(self.method_ret_reg, r_zero)
                else:
                    r_val = self.compile_expr(children[0])
                    self.copy_reg(self.method_ret_reg, r_val)
                patch_loc = self.b.jmp()
                self.method_ret_jmps.append(patch_loc)
                return

            if not children:
                self.b.ret_const(0)
                return
            expr = children[0]
            if hasattr(self, 'result_type') and self.result_type and self.result_type.kind == ci.TypeKind.RECORD:
                decl = self.result_type.get_declaration()
                fields = self._get_struct_fields(decl)
                n_fields = len(fields)
                unwrapped = self.unwrap_expr(expr)
                field_regs = []
                if unwrapped.kind == ci.CursorKind.DECL_REF_EXPR and unwrapped.spelling in self.struct_offsets:
                    base_offset, field_map = self.struct_offsets[unwrapped.spelling]
                    for idx in range(n_fields):
                        r_f = self.alloc_reg()
                        r_zero = self.alloc_reg()
                        self.b.load_const(r_zero, 0)
                        self.b.arr_load(r_f, base_offset + idx, r_zero)
                        field_regs.append(r_f)
                elif unwrapped.kind == ci.CursorKind.INIT_LIST_EXPR:
                    for elem in unwrapped.get_children():
                        field_regs.append(self.compile_expr(elem))
                elif unwrapped.kind == ci.CursorKind.CALL_EXPR:
                    self.compile_expr(unwrapped)
                    for idx in range(n_fields):
                        r_f = self.alloc_reg()
                        self.b.struct_ret_load(r_f, idx)
                        field_regs.append(r_f)
                else:
                    raise RuntimeError(f"unsupported return struct expression kind: {unwrapped.kind}")
                self.b.ret_struct(n_fields, field_regs)
            else:
                if expr.kind == ci.CursorKind.INTEGER_LITERAL:
                    tokens = list(expr.get_tokens())
                    value = int(tokens[0].spelling) if tokens else 0
                    self.b.ret_const(value)
                else:
                    r = self.compile_expr(expr)
                    self.b.ret_reg(r)
        else:
            raise RuntimeError(f"unhandled statement kind: {node.kind}")

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
            if name in self.ref_params:
                r_ptr = self.var_reg[name]
                r_dst = self.alloc_reg()
                self.b.arr_load(r_dst, 0xFF, r_ptr)
                return r_dst
            if name in self.mem_vars:
                slot_offset = self.mem_vars[name]
                r_dst = self.alloc_reg()
                r_zero = self.alloc_reg()
                self.b.load_const(r_zero, 0)
                self.b.arr_load(r_dst, slot_offset, r_zero)
                return r_dst
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

        if node.kind == ci.CursorKind.UNARY_OPERATOR:
            tokens = [t.spelling for t in node.get_tokens()]
            children = list(node.get_children())
            if tokens and tokens[0] == "&":
                target = children[0]
                while target.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                    c = list(target.get_children())
                    if c: target = c[0]
                    else: break
                if target.kind == ci.CursorKind.DECL_REF_EXPR:
                    if target.spelling in self.mem_vars:
                        slot_offset = self.mem_vars[target.spelling]
                        r_dst = self.alloc_reg()
                        self.b.load_frame_addr(r_dst, slot_offset)
                        return r_dst
                    elif target.spelling in self.ref_params or target.spelling in self.ptr_params:
                        return self.var_reg[target.spelling]
                raise RuntimeError(f"cannot take address of non-memory-backed variable '{getattr(target, 'spelling', '')}'")
            elif tokens and tokens[0] == "*":
                r_ptr = self.compile_expr(children[0])
                r_dst = self.alloc_reg()
                self.b.arr_load(r_dst, 0xFF, r_ptr)
                return r_dst

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
            r = self.alloc_reg()
            self.b.load_const(r, 0)
            self.b.arr_load(r, field_mem_slot, r)
            return r

        if node.kind == ci.CursorKind.CALL_EXPR:
            children = list(node.get_children())
            if children and children[0].kind == ci.CursorKind.MEMBER_REF_EXPR:
                mem_ref = children[0]
                mem_children = list(mem_ref.get_children())
                inst = None
                base_offset = None
                field_map = None
                if mem_children:
                    inst = mem_children[0]
                    while inst.kind in (ci.CursorKind.UNEXPOSED_EXPR, ci.CursorKind.PAREN_EXPR):
                        subs = list(inst.get_children())
                        if subs: inst = subs[0]
                        else: break

                if inst and inst.kind == ci.CursorKind.CXX_THIS_EXPR:
                    base_offset = self.current_this_offset
                    field_map = self.current_this_fields
                elif not mem_children or not inst:
                    base_offset = self.current_this_offset
                    field_map = self.current_this_fields
                elif inst and inst.kind == ci.CursorKind.DECL_REF_EXPR and inst.spelling in self.struct_offsets:
                    base_offset, field_map = self.struct_offsets[inst.spelling]

                if base_offset is not None and field_map is not None:
                    method_cursor = mem_ref.get_definition()
                    if not method_cursor or method_cursor.kind != ci.CursorKind.CXX_METHOD:
                        decl_name = None
                        if inst and hasattr(inst.type, 'get_declaration'):
                            decl_name = inst.type.get_declaration().spelling
                        if not decl_name and hasattr(mem_ref.type, 'get_declaration'):
                            decl_name = mem_ref.type.get_declaration().spelling
                        if decl_name and decl_name in self.struct_methods and mem_ref.spelling in self.struct_methods[decl_name]:
                            method_cursor = self.struct_methods[decl_name][mem_ref.spelling]
                        else:
                            for s_n, m_m in self.struct_methods.items():
                                if mem_ref.spelling in m_m:
                                    method_cursor = m_m[mem_ref.spelling]
                                    break
                    if method_cursor and method_cursor.kind == ci.CursorKind.CXX_METHOD:
                        raw_args = list(node.get_arguments())
                        if not raw_args and len(children) > 1:
                            raw_args = children[1:]

                        m_params = list(method_cursor.get_arguments())
                        for p_node, arg_expr in zip(m_params, raw_args):
                            r_arg = self.compile_expr(arg_expr)
                            self.var_reg[p_node.spelling] = r_arg

                        r_dst = self.alloc_reg()

                        old_this_off, old_this_f = self.current_this_offset, self.current_this_fields
                        old_in_ret, old_ret_r, old_jmps = self.in_method_return, self.method_ret_reg, self.method_ret_jmps

                        self.current_this_offset = base_offset
                        self.current_this_fields = field_map
                        self.in_method_return = True
                        self.method_ret_reg = r_dst
                        self.method_ret_jmps = []

                        method_body = [c for c in method_cursor.get_children() if c.kind == ci.CursorKind.COMPOUND_STMT][0]
                        self.compile_stmt(method_body)

                        end_target = self.b.here()
                        for patch_loc in self.method_ret_jmps:
                            self.b.patch(patch_loc, end_target)

                        self.current_this_offset, self.current_this_fields = old_this_off, old_this_f
                        self.in_method_return, self.method_ret_reg, self.method_ret_jmps = old_in_ret, old_ret_r, old_jmps

                        return r_dst

            callee_name = node.spelling
            if not callee_name:
                if children:
                    callee_name = children[0].spelling
            if callee_name not in self.func_entry_offsets:
                raise RuntimeError(f"unknown callee function: '{callee_name}'")
            callee_offset = self.func_entry_offsets[callee_name]

            raw_args = list(node.get_arguments())
            if not raw_args:
                children = list(node.get_children())
                if len(children) > 1:
                    raw_args = children[1:]

            callee_cursor = None
            if hasattr(node, 'get_definition'):
                callee_cursor = node.get_definition()
            c_params = list(callee_cursor.get_arguments()) if (callee_cursor and callee_cursor.kind == ci.CursorKind.FUNCTION_DECL) else []

            arg_regs = []
            for idx, a in enumerate(raw_args):
                unwrapped = self.unwrap_expr(a)
                p_param = c_params[idx] if idx < len(c_params) else None
                if p_param and p_param.type.kind in (ci.TypeKind.LVALUEREFERENCE, ci.TypeKind.POINTER):
                    sub = unwrapped
                    if sub.kind == ci.CursorKind.DECL_REF_EXPR and sub.spelling in self.mem_vars:
                        slot_offset = self.mem_vars[sub.spelling]
                        r = self.alloc_reg()
                        self.b.load_frame_addr(r, slot_offset)
                        arg_regs.append(r)
                    else:
                        arg_regs.append(self.compile_expr(a))
                elif unwrapped.kind == ci.CursorKind.DECL_REF_EXPR and unwrapped.spelling in self.struct_offsets:
                    base_offset, field_map = self.struct_offsets[unwrapped.spelling]
                    for f_idx in range(len(field_map)):
                        r = self.alloc_reg()
                        self.b.load_const(r, 0)
                        self.b.arr_load(r, base_offset + f_idx, r)
                        arg_regs.append(r)
                elif unwrapped.type.kind == ci.TypeKind.RECORD:
                    if unwrapped.kind == ci.CursorKind.INIT_LIST_EXPR:
                        for elem in unwrapped.get_children():
                            arg_regs.append(self.compile_expr(elem))
                    elif unwrapped.kind == ci.CursorKind.CALL_EXPR:
                        self.compile_expr(unwrapped)
                        decl = unwrapped.type.get_declaration()
                        fields = self._get_struct_fields(decl)
                        for f_idx in range(len(fields)):
                            r_f = self.alloc_reg()
                            self.b.struct_ret_load(r_f, f_idx)
                            arg_regs.append(r_f)
                    else:
                        raise RuntimeError(f"unsupported struct argument kind: {unwrapped.kind}")
                else:
                    arg_regs.append(self.compile_expr(a))

            if len(arg_regs) > 4:
                raise RuntimeError(f"call to '{callee_name}' has {len(arg_regs)} total arg slots (max 4 supported)")

            r_dst = self.alloc_reg()
            self.b.call(callee_offset, arg_regs, r_dst)
            return r_dst

        if node.kind == ci.CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            lhs, rhs = children[0], children[1]
            op_token = self._binary_op_symbol(node)
            r_a = self.compile_expr(lhs)
            r_b = self.compile_expr(rhs)
            opcode = BIN_OP_TO_OPCODE[op_token]
            if r_a not in self.var_reg.values():
                r_dst = r_a
            else:
                r_dst = self.alloc_reg()
            self.b.binop(opcode, r_dst, r_a, r_b)
            if r_b > r_dst and r_b not in self.var_reg.values():
                self.next_reg = r_b
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

