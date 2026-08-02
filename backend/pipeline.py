"""
pipeline.py
Multi-stage transformer pipeline for C++ VM obfuscation.
Executes ordered stages over a shared PipelineContext.
"""
from dataclasses import dataclass, field
from typing import Any, List, Dict, Tuple
import random
import re
import clang.cindex as ci
from bytecode_gen import eligibility_check, FunctionCompiler


@dataclass
class PipelineContext:
    source_code: str
    filename: str
    tu: Any = None
    funcs: List[Any] = field(default_factory=list)
    include_lines: List[str] = field(default_factory=list)
    treatments: Dict[Any, Tuple[bool, str]] = field(default_factory=dict)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    eligible_funcs: List[Tuple[Any, bytes]] = field(default_factory=list)
    eligible_str_funcs: List[Tuple[Any, bytes, List[str]]] = field(default_factory=list)
    fallback_funcs: List[Any] = field(default_factory=list)
    rename_map: Dict[str, str] = field(default_factory=dict)
    opcode_shuffle_map: Dict[int, int] = field(default_factory=dict)
    string_decode_helpers: List[str] = field(default_factory=list)
    func_replacements: Dict[Any, List[Tuple[int, int, str]]] = field(default_factory=dict)
    report: List[str] = field(default_factory=list)
    diag_errors: List[str] = field(default_factory=list)
    final_code: str = ""


def obfuscate_number_literal(value: int) -> str:
    """Given an integer literal's value, returns a C++ expression string
    that evaluates to exactly that value, disguised as arithmetic.
    Must be wrapped in parentheses so it's safe to substitute anywhere
    the original literal appeared."""
    if value < 0:
        pos_str = obfuscate_number_literal(abs(value))
        return f"(-{pos_str})"

    if value >= 0x7FFFFFFF - 1000:
        return f"(0x{value:x} ^ 0x0)"

    if value == 0:
        r = random.randint(1, 100)
        strats = [
            f"(0x{r:x} - 0x{r:x})",
            f"(0x{r:x} ^ 0x{r:x})",
            f"(0x0 * 0x{r:x})",
            "(0x0 ^ 0x0)",
        ]
        return random.choice(strats)

    strategies = []

    # Strategy 1: Addition split (value = a + b)
    if value > 1:
        a = random.randint(1, value - 1)
        b = value - a
        strategies.append(f"(0x{a:x} + 0x{b:x})")
    else:
        strategies.append(f"(0x0 + 0x{value:x})")

    # Strategy 2: Subtraction split (value = a - b)
    b = random.randint(1, 100)
    a = value + b
    strategies.append(f"(0x{a:x} - 0x{b:x})")

    # Strategy 3: Multiplication-then-add (value = quot * m + rem)
    m = random.choice([2, 3, 4, 5])
    quot = value // m
    rem = value % m
    strategies.append(f"(0x{quot:x} * 0x{m:x} + 0x{rem:x})")

    # Strategy 4: Bitwise XOR (value = a ^ k)
    k = random.randint(1, 255)
    a = value ^ k
    strategies.append(f"(0x{a:x} ^ 0x{k:x})")

    return random.choice(strategies)


def generate_opcode_shuffle(seed: int | None = None) -> dict[int, int]:
    """Returns a random bijective mapping {original_opcode: shuffled_opcode}
    covering every value in bytecode_gen.ALL_OPCODES. Uses `seed` if given
    (for reproducible/testable output), otherwise a fresh random shuffle."""
    from bytecode_gen import ALL_OPCODES
    rng = random.Random(seed)
    shuffled = ALL_OPCODES.copy()
    rng.shuffle(shuffled)
    return dict(zip(ALL_OPCODES, shuffled))


def apply_opcode_shuffle(bytecode: bytes, mapping: dict[int, int]) -> bytes:
    """Forward direction: `bytecode` uses ORIGINAL opcode values, `mapping`
    is {original: shuffled}. Widths are looked up directly from the
    original opcode byte (correct, since input bytes are original)."""
    from bytecode_gen import OPCODE_OPERAND_WIDTHS
    out = bytearray()
    i = 0
    while i < len(bytecode):
        op = bytecode[i]
        if op not in OPCODE_OPERAND_WIDTHS:
            raise ValueError(f"unknown opcode 0x{op:02x} at offset {i}")
        width = OPCODE_OPERAND_WIDTHS[op]
        out.append(mapping[op])
        out.extend(bytecode[i + 1 : i + 1 + width])
        i += 1 + width
    return bytes(out)


def apply_inverse_opcode_shuffle(shuffled_bytecode: bytes, mapping: dict[int, int]) -> bytes:
    """Reverse direction: `shuffled_bytecode` uses SHUFFLED opcode values,
    `mapping` is still {original: shuffled} (the same forward mapping -
    this function builds and uses its own inverse internally). Widths must
    be looked up via the ORIGINAL opcode (found through the inverse map),
    never from the shuffled byte directly, since a shuffled byte value
    does not correspond to its own true instruction width."""
    from bytecode_gen import OPCODE_OPERAND_WIDTHS
    inverse = {v: k for k, v in mapping.items()}
    out = bytearray()
    i = 0
    while i < len(shuffled_bytecode):
        shuffled_op = shuffled_bytecode[i]
        if shuffled_op not in inverse:
            raise ValueError(f"unknown shuffled opcode 0x{shuffled_op:02x} at offset {i}")
        orig_op = inverse[shuffled_op]
        width = OPCODE_OPERAND_WIDTHS[orig_op]
        out.append(orig_op)
        out.extend(shuffled_bytecode[i + 1 : i + 1 + width])
        i += 1 + width
    return bytes(out)


def stage_parse(ctx: PipelineContext) -> None:
    from codegen import _macos_clang_args, collect_top_level_functions

    with open(ctx.filename, "w") as f:
        f.write(ctx.source_code)

    index = ci.Index.create()
    parse_args = ["-std=c++17"] + _macos_clang_args()
    ctx.tu = index.parse(ctx.filename, args=parse_args)
    ctx.diag_errors = [str(d) for d in ctx.tu.diagnostics if d.severity >= ci.Diagnostic.Error]

    ctx.funcs = collect_top_level_functions(ctx.tu, ctx.filename)

    ctx.include_lines = [
        line for line in ctx.source_code.splitlines()
        if line.strip().startswith("#include") or line.strip().startswith("using ")
    ]

    if ctx.diag_errors:
        ctx.report = [
            "PARSE ERRORS DETECTED - no functions were virtualized, "
            "output below is your original code unchanged. Fix the "
            "errors listed below and try again."
        ]
        ctx.final_code = ctx.source_code


def stage_eligibility_check(ctx: PipelineContext) -> None:
    from bytecode_gen import string_function_eligibility_check

    # Pass 1: Identify all leaf eligible functions (no CALL_EXPR nodes)
    known_leaf_names = set()
    for f in ctx.funcs:
        ok, reason = eligibility_check(f, known_leaf_functions=set())
        if ok:
            body = next((c for c in f.get_children()
                         if c.kind == ci.CursorKind.COMPOUND_STMT), None)
            if body is not None and len(list(body.get_children())) == 0:
                ok, reason = False, "function body parsed as empty (likely a parse issue, not real code)"
            else:
                known_leaf_names.add(f.spelling)
        elif string_function_eligibility_check(f):
            ok, reason = True, "eligible (string VM)"
        ctx.treatments[f] = (ok, reason)

    # Pass 2: Identify caller functions that call only known leaf functions
    for f in ctx.funcs:
        if not ctx.treatments[f][0]:
            ok, reason = eligibility_check(f, known_leaf_functions=known_leaf_names)
            if ok:
                body = next((c for c in f.get_children()
                             if c.kind == ci.CursorKind.COMPOUND_STMT), None)
                if body is not None and len(list(body.get_children())) == 0:
                    ok, reason = False, "function body parsed as empty (likely a parse issue, not real code)"
                else:
                    ctx.treatments[f] = (True, "eligible (caller)")


def stage_virtualize(ctx: PipelineContext) -> None:
    from bytecode_gen import StringFunctionCompiler

    leaf_funcs = []
    caller_funcs = []
    str_funcs = []
    for f in ctx.funcs:
        ok, reason = ctx.treatments.get(f, (False, "unknown"))
        if ok:
            if "string VM" in reason:
                str_funcs.append(f)
            elif "caller" in reason:
                caller_funcs.append(f)
            else:
                leaf_funcs.append(f)
        else:
            ctx.fallback_funcs.append(f)
            ctx.report.append(f"{f.spelling}: NOT virtualized ({reason}) - identifiers renamed instead")

    shared_bytecode = bytearray()
    func_entry_offsets = {}

    # Compile leaf functions first to establish their entry offsets
    for f in leaf_funcs:
        try:
            offset = len(shared_bytecode)
            func_entry_offsets[f.spelling] = offset
            compiler = FunctionCompiler(start_offset=offset, func_entry_offsets=func_entry_offsets)
            bc = compiler.compile_function(f)
            shared_bytecode.extend(bc)
            ctx.eligible_funcs.append((f, offset))
            ctx.artifacts[f.spelling] = bc
            ctx.report.append(f"{f.spelling}: VIRTUALIZED ({len(bc)} bytes of bytecode)")
        except Exception as e:
            reason = f"codegen failed: {e}"
            ctx.fallback_funcs.append(f)
            ctx.report.append(f"{f.spelling}: NOT virtualized ({reason}) - identifiers renamed instead")

    # Compile caller functions next using the established leaf offsets
    for f in caller_funcs:
        try:
            offset = len(shared_bytecode)
            func_entry_offsets[f.spelling] = offset
            compiler = FunctionCompiler(start_offset=offset, func_entry_offsets=func_entry_offsets)
            bc = compiler.compile_function(f)
            shared_bytecode.extend(bc)
            ctx.eligible_funcs.append((f, offset))
            ctx.artifacts[f.spelling] = bc
            ctx.report.append(f"{f.spelling}: VIRTUALIZED ({len(bc)} bytes of bytecode)")
        except Exception as e:
            reason = f"codegen failed: {e}"
            ctx.fallback_funcs.append(f)
            ctx.report.append(f"{f.spelling}: NOT virtualized ({reason}) - identifiers renamed instead")

    # Compile string functions
    for f in str_funcs:
        try:
            compiler = StringFunctionCompiler(f)
            bc, const_pool = compiler.compile()
            ctx.eligible_str_funcs.append((f, bc, const_pool))
            ctx.artifacts[f.spelling] = bc
            ctx.report.append(f"{f.spelling}: VIRTUALIZED STRING VM ({len(bc)} bytes of bytecode)")
        except Exception as e:
            reason = f"codegen failed: {e}"
            ctx.fallback_funcs.append(f)
            ctx.report.append(f"{f.spelling}: NOT virtualized ({reason}) - identifiers renamed instead")

    ctx.artifacts["shared_bytecode"] = bytes(shared_bytecode)
    ctx.func_entry_offsets = func_entry_offsets



def stage_shuffle_opcodes(ctx: PipelineContext) -> None:
    if not ctx.eligible_funcs and not ctx.eligible_str_funcs:
        return
    ctx.opcode_shuffle_map = generate_opcode_shuffle()
    if ctx.eligible_funcs:
        shared_bc = ctx.artifacts["shared_bytecode"]
        shuffled_shared_bc = apply_opcode_shuffle(shared_bc, ctx.opcode_shuffle_map)
        ctx.artifacts["shared_bytecode"] = shuffled_shared_bc

    if ctx.eligible_str_funcs:
        new_str_funcs = []
        for f, bc, pool in ctx.eligible_str_funcs:
            shuffled_bc = apply_opcode_shuffle(bc, ctx.opcode_shuffle_map)
            new_str_funcs.append((f, shuffled_bc, pool))
            ctx.artifacts[f.spelling] = shuffled_bc
        ctx.eligible_str_funcs = new_str_funcs


def fnv1a_32(data: bytes) -> int:
    h = 0x811c9dc5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def stage_compute_bytecode_checksum(ctx: PipelineContext) -> None:
    if not ctx.eligible_funcs and not ctx.eligible_str_funcs:
        return
    if ctx.eligible_funcs:
        shared_bc = ctx.artifacts.get("shared_bytecode", b"")
        ctx.artifacts["bytecode_checksum"] = fnv1a_32(shared_bc)

    for f, bc, _ in ctx.eligible_str_funcs:
        ctx.artifacts[f"checksum_{f.spelling}"] = fnv1a_32(bc)


def stage_rename_fallback(ctx: PipelineContext) -> None:
    from codegen import random_name

    rename_map = {}
    for f in ctx.fallback_funcs:
        for node in f.walk_preorder():
            if node.kind in (ci.CursorKind.VAR_DECL, ci.CursorKind.PARM_DECL):
                if node.spelling and node.spelling not in rename_map:
                    rename_map[node.spelling] = random_name("var_")
    ctx.rename_map = rename_map
    ctx.artifacts["rename_map"] = rename_map


def decode_cpp_string_literal(tok_spelling: str) -> bytes:
    s = tok_spelling
    quote_idx = s.find('"')
    if quote_idx != -1 and s.endswith('"'):
        s = s[quote_idx + 1:-1]
    return s.encode("utf-8").decode("unicode_escape").encode("latin1")


def is_safe_string_literal(node, parent_chain) -> bool:
    if node.kind != ci.CursorKind.STRING_LITERAL:
        return False
    # Reject if any ancestor up to compound statement is VAR_DECL
    for p in reversed(parent_chain):
        if p.kind == ci.CursorKind.COMPOUND_STMT:
            break
        if p.kind == ci.CursorKind.VAR_DECL:
            return False
    # Must have a CALL_EXPR ancestor before compound stmt
    for p in reversed(parent_chain):
        if p.kind == ci.CursorKind.COMPOUND_STMT:
            break
        if p.kind == ci.CursorKind.CALL_EXPR:
            return True
    return False


def generate_string_decode_function(func_name: str, raw_bytes: bytes, key: int) -> str:
    enc_bytes = [b ^ key for b in raw_bytes]
    enc_str = ", ".join(f"0x{b:02x}" for b in enc_bytes)
    length = len(raw_bytes)
    return f"""inline const char* {func_name}() {{
    static char buf[{length + 1}] = {{0}};
    static bool decoded = false;
    if (!decoded) {{
        static const unsigned char enc[] = {{ {enc_str} }};
        const unsigned char key = 0x{key:02x};
        for (int i = 0; i < {length}; i++) buf[i] = (char)(enc[i] ^ key);
        buf[{length}] = '\\0';
        decoded = true;
    }}
    return buf;
}}"""


def stage_obfuscate_literals(ctx: PipelineContext) -> None:
    """Finds all INTEGER_LITERAL AST nodes in fallback functions using exact token byte offsets
    and collects replacement tuples into ctx.func_replacements.

    Note: This stage does NOT perform any text modification or slicing itself. The actual merged
    text slicing and identifier renaming for both integer and string literal replacements occurs
    in stage_encrypt_strings(), which MUST run after this stage in PIPELINE_STAGES for either
    transform to take effect."""
    if not ctx.fallback_funcs:
        return

    for func in ctx.fallback_funcs:
        func_start = func.extent.start.offset
        func_end = func.extent.end.offset

        replacements = ctx.func_replacements.setdefault(func, [])
        seen_spans = set()
        for node in func.walk_preorder():
            if node.kind == ci.CursorKind.INTEGER_LITERAL:
                tokens = list(node.get_tokens())
                if tokens:
                    tok = tokens[0]
                    tok_start = tok.extent.start.offset
                    tok_end = tok.extent.end.offset
                    if func_start <= tok_start < tok_end <= func_end:
                        span = (tok_start - func_start, tok_end - func_start)
                        if span not in seen_spans:
                            seen_spans.add(span)
                            try:
                                val = int(tok.spelling, 0)
                            except ValueError:
                                continue
                            obf_expr = obfuscate_number_literal(val)
                            replacements.append((span[0], span[1], obf_expr))


def stage_encrypt_strings(ctx: PipelineContext) -> None:
    """Finds all safe STRING_LITERAL AST nodes in fallback functions using exact token byte offsets.
    Replaces safe string literals with call to unique inline decode helper functions.
    Merges replacements with integer literal replacements, slices text once, and applies identifier renaming."""
    from codegen import random_name

    if not ctx.fallback_funcs:
        return

    with open(ctx.filename) as f:
        original_text = f.read()

    for func in ctx.fallback_funcs:
        func_start = func.extent.start.offset
        func_end = func.extent.end.offset
        func_text = original_text[func_start:func_end]

        replacements = ctx.func_replacements.setdefault(func, [])
        seen_spans = {(r[0], r[1]) for r in replacements}

        used_keys = set()

        def get_unique_key():
            for _ in range(1000):
                k = random.randint(1, 255)
                if k not in used_keys:
                    used_keys.add(k)
                    return k
            return random.randint(1, 255)

        def traverse(node, parents):
            if node.kind == ci.CursorKind.STRING_LITERAL:
                if is_safe_string_literal(node, parents):
                    tokens = list(node.get_tokens())
                    if tokens:
                        tok = tokens[0]
                        tok_start = tok.extent.start.offset
                        tok_end = tok.extent.end.offset
                        if func_start <= tok_start < tok_end <= func_end:
                            span = (tok_start - func_start, tok_end - func_start)
                            if span not in seen_spans:
                                seen_spans.add(span)
                                raw_b = decode_cpp_string_literal(tok.spelling)
                                k = get_unique_key()
                                h_name = random_name("str_dec_")
                                h_code = generate_string_decode_function(h_name, raw_b, k)
                                ctx.string_decode_helpers.append(h_code)
                                replacements.append((span[0], span[1], f"{h_name}()"))
            for c in node.get_children():
                traverse(c, parents + [node])

        traverse(func, [])

        # Merge replacements (numbers + strings), sort by start_offset, slice text
        replacements.sort(key=lambda x: x[0])
        pieces = []
        last_pos = 0
        for rel_start, rel_end, obf_expr in replacements:
            pieces.append(func_text[last_pos:rel_start])
            pieces.append(obf_expr)
            last_pos = rel_end
        pieces.append(func_text[last_pos:])
        obfuscated_text = "".join(pieces)

        # Identifier renaming regex substitution on the obfuscated text
        for old, new in ctx.rename_map.items():
            obfuscated_text = re.sub(rf"\b{re.escape(old)}\b", new, obfuscated_text)

        ctx.artifacts[f"{func.spelling}_obfuscated_text"] = obfuscated_text


def stage_flatten_control_flow(ctx: PipelineContext) -> None:
    """Restructures qualifying fallback functions (>= 4 top-level statements, no early return)
    into a randomized switch-inside-while(true) state machine dispatcher. Lifts variable
    declarations to the outer block scope so switch case state transitions compile cleanly."""
    from codegen import random_name

    if not ctx.fallback_funcs:
        return

    with open(ctx.filename) as f:
        original_text = f.read()

    for func in ctx.fallback_funcs:
        obf_key = f"{func.spelling}_obfuscated_text"
        body = next((c for c in func.get_children() if c.kind == ci.CursorKind.COMPOUND_STMT), None)
        if body is None:
            continue

        stmts = list(body.get_children())

        # Threshold check: >= 4 top-level statements required
        if len(stmts) < 4:
            continue

        # Early return check: no return statement in stmts[:-1]
        has_early_return = False
        for s in stmts[:-1]:
            for n in s.walk_preorder():
                if n.kind == ci.CursorKind.RETURN_STMT:
                    has_early_return = True
                    break
            if has_early_return:
                break
        if has_early_return:
            continue

        func_start = func.extent.start.offset
        body_start = body.extent.start.offset
        header_text = original_text[func_start:body_start]
        for old, new in ctx.rename_map.items():
            header_text = re.sub(rf"\b{re.escape(old)}\b", new, header_text)

        func_replacements = ctx.func_replacements.get(func, [])
        lifted_decls = []
        stmt_texts = []
        unsupported = False

        for s in stmts:
            s_rel_start = s.extent.start.offset - func_start
            s_rel_end = s.extent.end.offset - func_start
            s_text_raw = original_text[s.extent.start.offset:s.extent.end.offset]

            # Collect replacements for s (which were recorded relative to func_start)
            s_repls = [(r[0] - s_rel_start, r[1] - s_rel_start, r[2]) for r in func_replacements if s_rel_start <= r[0] < r[1] <= s_rel_end]
            s_repls.sort(key=lambda x: x[0])

            pieces = []
            last_pos = 0
            for r_start_rel, r_end_rel, obf_expr in s_repls:
                pieces.append(s_text_raw[last_pos:r_start_rel])
                pieces.append(obf_expr)
                last_pos = r_end_rel
            pieces.append(s_text_raw[last_pos:])
            s_text = "".join(pieces).strip()

            if s.kind == ci.CursorKind.DECL_STMT:
                var_decls = [c for c in s.get_children() if c.kind == ci.CursorKind.VAR_DECL]
                if len(var_decls) > 1:
                    unsupported = True
                    break
                for child in var_decls:
                    type_spelling = child.type.spelling
                    if "[" in type_spelling or child.type.kind in (ci.TypeKind.CONSTANTARRAY, ci.TypeKind.INCOMPLETEARRAY, ci.TypeKind.VARIABLEARRAY):
                        unsupported = True
                        break
                    if any(t in type_spelling for t in ("int", "long", "short", "char", "float", "double", "bool", "*", "size_t")):
                        var_name = ctx.rename_map.get(child.spelling, child.spelling)
                        lifted_decls.append(f"{type_spelling} {var_name};")
                        s_text = re.sub(rf"^.*?\b{re.escape(child.spelling)}\b", var_name, s_text)
                    else:
                        unsupported = True
                        break
                if unsupported:
                    break

            # Apply identifier renaming to statement text
            for old, new in ctx.rename_map.items():
                s_text = re.sub(rf"\b{re.escape(old)}\b", new, s_text)

            stmt_texts.append(s_text)

        if unsupported:
            continue

        num_stmts = len(stmt_texts)
        label_pool = [x for x in range(10, 99) if x not in (50, 100)]
        case_labels = random.sample(label_pool, num_stmts)
        start_label = case_labels[0]
        state_var = random_name("cf_state_")

        case_blocks = []
        for i in range(num_stmts):
            label = case_labels[i]
            next_label = case_labels[i + 1] if i < num_stmts - 1 else -1
            stmt_t = stmt_texts[i]
            if not stmt_t.endswith(";"):
                stmt_t += ";"
            block = f"            case {label}:\n                {stmt_t}\n                {state_var} = {next_label};\n                continue;"
            case_blocks.append(block)

        random.shuffle(case_blocks)
        cases_str = "\n".join(case_blocks)

        lifted_str = "\n    ".join(lifted_decls)
        if lifted_str:
            lifted_str = "\n    " + lifted_str

        flattened_body = f""" {{
{lifted_str}
    int {state_var} = {start_label};
    while (true) {{
        switch ({state_var}) {{
{cases_str}
        }}
        break;
    }}
}}"""

        new_func_text = header_text + flattened_body
        ctx.artifacts[obf_key] = new_func_text
        ctx.artifacts[f"{func.spelling}_flattened"] = True


def generate_always_true_condition() -> str:
    """Generates a randomly chosen C++ boolean expression that evaluates to true by construction."""
    pattern_choice = random.randint(0, 3)
    if pattern_choice == 0:
        a = random.randint(-50, 50)
        b = random.randint(-50, 50)
        return f"(({a} + {b}) == ({b} + {a}))"
    elif pattern_choice == 1:
        a = random.randint(1, 50) * random.choice([-1, 1])
        b = random.randint(-50, 50)
        mod_val = abs(a)
        return f"((({a} * {b}) + {a}) % {mod_val} == 0)"
    elif pattern_choice == 2:
        a = random.randint(-50, 50)
        return f"(({a} * {a}) >= 0)"
    else:
        a = random.randint(-50, 50)
        return f"((({a} * 2) % 2) == 0)"


def generate_junk_code() -> str:
    """Generates a semantically inert, 100% side-effect-free C++ dead code block."""
    from codegen import random_name

    var_name = random_name("dead_")
    val1 = random.randint(1, 100)
    val2 = random.randint(1, 100)
    op = random.choice(["+", "-", "*"])
    return f"{{ int {var_name} = {val1} {op} {val2}; (void){var_name}; }}"


def stage_inject_dead_code(ctx: PipelineContext) -> None:
    """Injects fake, never-executed decoy branches (always-true condition guarding real statement,
    decoy else branch with inert junk code) into fallback functions that are NOT already flattened
    and contain >= 2 top-level statements."""
    if not ctx.fallback_funcs:
        return

    with open(ctx.filename) as f:
        original_text = f.read()

    for func in ctx.fallback_funcs:
        # Check if already flattened by stage_flatten_control_flow
        if ctx.artifacts.get(f"{func.spelling}_flattened"):
            continue

        obf_key = f"{func.spelling}_obfuscated_text"
        body = next((c for c in func.get_children() if c.kind == ci.CursorKind.COMPOUND_STMT), None)
        if body is None:
            continue

        stmts = list(body.get_children())
        if len(stmts) < 2:
            continue

        # Filter candidate statements (must not be DECL_STMT and must not contain RETURN_STMT)
        candidate_stmts = []
        for s in stmts:
            if s.kind == ci.CursorKind.DECL_STMT:
                continue
            has_return = False
            for n in s.walk_preorder():
                if n.kind == ci.CursorKind.RETURN_STMT:
                    has_return = True
                    break
            if not has_return:
                candidate_stmts.append(s)

        if not candidate_stmts:
            continue

        # Pick 1 to 3 statements to wrap
        count_to_wrap = min(len(candidate_stmts), random.randint(1, 3))
        stmts_to_wrap = set(random.sample(candidate_stmts, count_to_wrap))

        func_start = func.extent.start.offset
        body_start = body.extent.start.offset
        header_text = original_text[func_start:body_start]
        for old, new in ctx.rename_map.items():
            header_text = re.sub(rf"\b{re.escape(old)}\b", new, header_text)

        func_replacements = ctx.func_replacements.get(func, [])
        stmt_texts = []

        for s in stmts:
            s_rel_start = s.extent.start.offset - func_start
            s_rel_end = s.extent.end.offset - func_start
            s_text_raw = original_text[s.extent.start.offset:s.extent.end.offset]

            s_repls = [(r[0] - s_rel_start, r[1] - s_rel_start, r[2]) for r in func_replacements if s_rel_start <= r[0] < r[1] <= s_rel_end]
            s_repls.sort(key=lambda x: x[0])

            pieces = []
            last_pos = 0
            for r_start_rel, r_end_rel, obf_expr in s_repls:
                pieces.append(s_text_raw[last_pos:r_start_rel])
                pieces.append(obf_expr)
                last_pos = r_end_rel
            pieces.append(s_text_raw[last_pos:])
            s_text = "".join(pieces).strip()

            # Apply identifier renaming
            for old, new in ctx.rename_map.items():
                s_text = re.sub(rf"\b{re.escape(old)}\b", new, s_text)

            if not s_text.endswith(";"):
                s_text += ";"

            if s in stmts_to_wrap:
                cond = generate_always_true_condition()
                junk = generate_junk_code()
                wrapped = f"if ({cond}) {{\n        {s_text}\n    }} else {junk}"
                stmt_texts.append(wrapped)
            else:
                stmt_texts.append(s_text)

        body_inner = "\n    ".join(stmt_texts)
        new_func_text = f"{header_text} {{\n    {body_inner}\n}}"
        ctx.artifacts[obf_key] = new_func_text


def stage_assemble_output(ctx: PipelineContext) -> None:
    from codegen import random_name, bytes_to_c_array, generate_vm_runtime

    checksum = ctx.artifacts.get("bytecode_checksum", 0)
    checksum_str = f"0x{checksum:08x}u"

    str_vm_parts = []
    if ctx.eligible_str_funcs:
        used_keys = set()
        for f, bc, const_pool in ctx.eligible_str_funcs:
            bc_arr_name = random_name(f"bc_str_{f.spelling}_")
            pool_arr_name = random_name(f"pool_str_{f.spelling}_")
            str_vm_parts.append(bytes_to_c_array(bc_arr_name, bc))

            pool_elems = []
            for s in const_pool:
                raw_b = s.encode("utf-8")
                while True:
                    k = random.randint(1, 255)
                    if k not in used_keys or len(used_keys) >= 254:
                        used_keys.add(k)
                        break
                h_name = random_name("str_dec_")
                h_code = generate_string_decode_function(h_name, raw_b, k)
                ctx.string_decode_helpers.append(h_code)
                pool_elems.append(f"{h_name}()")

            pool_lits = ", ".join(pool_elems)
            str_vm_parts.append(
                f"static const std::string {pool_arr_name}[] = {{ {pool_lits} }};\n"
                f"static const size_t {pool_arr_name}_len = {len(const_pool)};\n\n"
            )

            params = list(f.get_arguments())
            param_list = ", ".join(f"{p.type.spelling} {p.spelling}" for p in params)
            args_init = ", ".join(p.spelling for p in params)

            str_checksum = ctx.artifacts.get(f"checksum_{f.spelling}", 0)
            str_checksum_str = f"0x{str_checksum:08x}u"

            ret_spelling = f.result_type.spelling
            if "string" in ret_spelling or "basic_string" in ret_spelling:
                str_vm_parts.append(
                    f"{ret_spelling} {f.spelling}({param_list}) {{\n"
                    f"    std::string __args[] = {{ {args_init} }};\n"
                    f"    return vm_rt::run_str({bc_arr_name}, {bc_arr_name}_len, __args, {len(params)}, {pool_arr_name}, {pool_arr_name}_len, nullptr, {str_checksum_str});\n"
                    f"}}\n\n"
                )
            else:
                str_vm_parts.append(
                    f"{ret_spelling} {f.spelling}({param_list}) {{\n"
                    f"    std::string __args[] = {{ {args_init} }};\n"
                    f"    int64_t __res = 0;\n"
                    f"    vm_rt::run_str({bc_arr_name}, {bc_arr_name}_len, __args, {len(params)}, {pool_arr_name}, {pool_arr_name}_len, &__res, {str_checksum_str});\n"
                    f"    return ({ret_spelling})__res;\n"
                    f"}}\n\n"
                )

    output_parts = [
        "// ================================================================\n"
        "// Auto-generated obfuscated output.\n"
        "// Functions using only int arithmetic/comparisons/if/return were\n"
        "// converted to VM bytecode. Everything else was passed through\n"
        "// with local identifiers renamed.\n"
        "// ================================================================\n",
        "\n".join(ctx.include_lines) + "\n\n" if ctx.include_lines else "",
        generate_vm_runtime(ctx.opcode_shuffle_map),
    ]

    if ctx.string_decode_helpers:
        output_parts.append("\n// ---- String decode helpers ----\n" + "\n\n".join(ctx.string_decode_helpers) + "\n")

    output_parts.append("\n// ---- Bytecode-backed functions ----\n")

    if ctx.eligible_funcs:
        shared_bc = ctx.artifacts["shared_bytecode"]
        arr_name = random_name("shared_bc_")
        output_parts.append(bytes_to_c_array(arr_name, shared_bc))
        for f, offset in ctx.eligible_funcs:
            params = list(f.get_arguments())
            param_list = ", ".join(f"int {p.spelling}" for p in params)
            args_init = ", ".join(f"(int64_t){p.spelling}" for p in params)
            output_parts.append(
                f"int {f.spelling}({param_list}) {{\n"
                f"    int64_t __args[] = {{ {args_init} }};\n"
                f"    return (int)vm_rt::run({arr_name}, {arr_name}_len, __args, {len(params)}, {offset}, {checksum_str});\n"
                f"}}\n\n"
            )

    if str_vm_parts:
        output_parts.append("\n// ---- String VM functions ----\n")
        output_parts.extend(str_vm_parts)

    if ctx.fallback_funcs:
        output_parts.append("\n// ---- Renamed (non-virtualized) functions ----\n")
        for f in ctx.fallback_funcs:
            obf_key = f"{f.spelling}_obfuscated_text"
            if obf_key in ctx.artifacts:
                func_text = ctx.artifacts[obf_key]
            else:
                with open(ctx.filename) as file_obj:
                    original_text = file_obj.read()
                start, end = f.extent.start.offset, f.extent.end.offset
                func_text = original_text[start:end]
                for old, new in ctx.rename_map.items():
                    func_text = re.sub(rf"\b{re.escape(old)}\b", new, func_text)
            output_parts.append(func_text + "\n\n")

    ctx.final_code = "".join(output_parts)


PIPELINE_STAGES = [
    stage_parse,
    stage_eligibility_check,
    stage_virtualize,
    stage_shuffle_opcodes,
    stage_compute_bytecode_checksum,
    stage_rename_fallback,
    stage_obfuscate_literals,
    stage_encrypt_strings,
    stage_flatten_control_flow,
    stage_inject_dead_code,
    stage_assemble_output,
]


def run_pipeline(source_code: str, filename: str) -> Tuple[str, List[str], List[str]]:
    ctx = PipelineContext(source_code=source_code, filename=filename)
    for stage in PIPELINE_STAGES:
        stage(ctx)
        if ctx.diag_errors and stage is stage_parse:
            break  # preserve existing early-exit behavior on parse errors
    return ctx.final_code, ctx.report, ctx.diag_errors
