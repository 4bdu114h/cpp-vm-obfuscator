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
    fallback_funcs: List[Any] = field(default_factory=list)
    rename_map: Dict[str, str] = field(default_factory=dict)
    opcode_shuffle_map: Dict[int, int] = field(default_factory=dict)
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
    for f in ctx.funcs:
        ok, reason = eligibility_check(f)
        if ok:
            body = next((c for c in f.get_children()
                         if c.kind == ci.CursorKind.COMPOUND_STMT), None)
            if body is not None and len(list(body.get_children())) == 0:
                ok, reason = False, "function body parsed as empty (likely a parse issue, not real code)"
        ctx.treatments[f] = (ok, reason)


def stage_virtualize(ctx: PipelineContext) -> None:
    for f in ctx.funcs:
        ok, reason = ctx.treatments.get(f, (False, "unknown"))
        if ok:
            try:
                compiler = FunctionCompiler()
                bc = compiler.compile_function(f)
                ctx.eligible_funcs.append((f, bc))
                ctx.artifacts[f.spelling] = bc
                ctx.report.append(f"{f.spelling}: VIRTUALIZED ({len(bc)} bytes of bytecode)")
                continue
            except Exception as e:
                reason = f"codegen failed: {e}"
        ctx.fallback_funcs.append(f)
        ctx.report.append(f"{f.spelling}: NOT virtualized ({reason}) - identifiers renamed instead")


def stage_shuffle_opcodes(ctx: PipelineContext) -> None:
    if not ctx.eligible_funcs:
        return
    ctx.opcode_shuffle_map = generate_opcode_shuffle()
    new_eligible = []
    for f, bc in ctx.eligible_funcs:
        shuffled_bc = apply_opcode_shuffle(bc, ctx.opcode_shuffle_map)
        new_eligible.append((f, shuffled_bc))
        ctx.artifacts[f.spelling] = shuffled_bc
    ctx.eligible_funcs = new_eligible


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


def stage_obfuscate_literals(ctx: PipelineContext) -> None:
    """Finds all INTEGER_LITERAL AST nodes in fallback functions using exact token byte offsets.
    Replaces each integer literal with an obfuscated arithmetic expression, then applies
    identifier renaming to the resulting text to guarantee offset safety."""
    if not ctx.fallback_funcs:
        return

    with open(ctx.filename) as f:
        original_text = f.read()

    for func in ctx.fallback_funcs:
        func_start = func.extent.start.offset
        func_end = func.extent.end.offset
        func_text = original_text[func_start:func_end]

        replacements = []
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

        # Pass 1: Offset-based slicing for integer literal replacements
        replacements.sort(key=lambda x: x[0])
        pieces = []
        last_pos = 0
        for rel_start, rel_end, obf_expr in replacements:
            pieces.append(func_text[last_pos:rel_start])
            pieces.append(obf_expr)
            last_pos = rel_end
        pieces.append(func_text[last_pos:])
        obfuscated_text = "".join(pieces)

        # Pass 2: Identifier renaming regex substitution on the obfuscated text
        for old, new in ctx.rename_map.items():
            obfuscated_text = re.sub(rf"\b{re.escape(old)}\b", new, obfuscated_text)

        ctx.artifacts[f"{func.spelling}_obfuscated_text"] = obfuscated_text


def stage_assemble_output(ctx: PipelineContext) -> None:
    from codegen import random_name, bytes_to_c_array, generate_vm_runtime

    output_parts = [
        "// ================================================================\n"
        "// Auto-generated obfuscated output.\n"
        "// Functions using only int arithmetic/comparisons/if/return were\n"
        "// converted to VM bytecode. Everything else was passed through\n"
        "// with local identifiers renamed.\n"
        "// ================================================================\n",
        "\n".join(ctx.include_lines) + "\n\n" if ctx.include_lines else "",
        generate_vm_runtime(ctx.opcode_shuffle_map),
        "\n// ---- Bytecode-backed functions ----\n",
    ]

    for f, bc in ctx.eligible_funcs:
        arr_name = random_name("bc_")
        params = list(f.get_arguments())
        param_list = ", ".join(f"int {p.spelling}" for p in params)
        args_init = ", ".join(f"(int64_t){p.spelling}" for p in params)
        output_parts.append(bytes_to_c_array(arr_name, bc))
        output_parts.append(
            f"int {f.spelling}({param_list}) {{\n"
            f"    int64_t __args[] = {{ {args_init} }};\n"
            f"    return (int)vm_rt::run({arr_name}, {arr_name}_len, __args, {len(params)});\n"
            f"}}\n\n"
        )

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
    stage_rename_fallback,
    stage_obfuscate_literals,
    stage_assemble_output,
]


def run_pipeline(source_code: str, filename: str) -> Tuple[str, List[str], List[str]]:
    ctx = PipelineContext(source_code=source_code, filename=filename)
    for stage in PIPELINE_STAGES:
        stage(ctx)
        if ctx.diag_errors and stage is stage_parse:
            break  # preserve existing early-exit behavior on parse errors
    return ctx.final_code, ctx.report, ctx.diag_errors
