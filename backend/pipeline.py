"""
pipeline.py
Multi-stage transformer pipeline for C++ VM obfuscation.
Executes ordered stages over a shared PipelineContext.
"""
from dataclasses import dataclass, field
from typing import Any, List, Dict, Tuple
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
    report: List[str] = field(default_factory=list)
    diag_errors: List[str] = field(default_factory=list)
    final_code: str = ""


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


def stage_assemble_output(ctx: PipelineContext) -> None:
    from codegen import random_name, bytes_to_c_array, VM_RUNTIME

    output_parts = [
        "// ================================================================\n"
        "// Auto-generated obfuscated output.\n"
        "// Functions using only int arithmetic/comparisons/if/return were\n"
        "// converted to VM bytecode. Everything else was passed through\n"
        "// with local identifiers renamed.\n"
        "// ================================================================\n",
        "\n".join(ctx.include_lines) + "\n\n" if ctx.include_lines else "",
        VM_RUNTIME,
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
        with open(ctx.filename) as f:
            original_text = f.read()
        for f in ctx.fallback_funcs:
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
    stage_rename_fallback,
    stage_assemble_output,
]


def run_pipeline(source_code: str, filename: str) -> Tuple[str, List[str], List[str]]:
    ctx = PipelineContext(source_code=source_code, filename=filename)
    for stage in PIPELINE_STAGES:
        stage(ctx)
        if ctx.diag_errors and stage is stage_parse:
            break  # preserve existing early-exit behavior on parse errors
    return ctx.final_code, ctx.report, ctx.diag_errors
