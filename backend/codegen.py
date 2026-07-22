"""
codegen.py
Takes parsed C++ source, virtualizes eligible functions (via bytecode_gen),
and falls back to simple identifier renaming for everything Clang parses
but that isn't eligible for full VM protection (loops, pointers, floats,
function calls, classes, etc.). Produces one final, compilable .cpp file.
"""
import re
import random
import string
import subprocess
import platform
import clang.cindex as ci
from bytecode_gen import eligibility_check, FunctionCompiler


def _macos_clang_args():
    """On macOS, the pip 'libclang' package ships its own prebuilt libclang
    binary, built on some other machine, with its own baked-in default
    search paths - NOT the paths of the real `clang` installed on this
    Mac. That's why 'iostream file not found' happens even for completely
    valid code: libclang doesn't know where Apple's SDK headers are.

    Fixing that alone isn't enough, though: 'stdarg.h file not found' (or
    similar - stddef.h, etc.) then shows up next, because those are
    Clang's OWN builtin headers, shipped in Clang's "resource directory"
    (a completely different location from the SDK), which the bundled
    libclang also doesn't know how to find on its own.

    So this needs two separate fixes:
      1. -isysroot <sdk path>       (from `xcrun --show-sdk-path`)
      2. -resource-dir <clang dir>  (from `clang -print-resource-dir`)
    Both commands shell out to the REAL clang installed on the Mac (via
    Xcode Command Line Tools), which does know its own paths, and we hand
    those answers to libclang explicitly."""
    if platform.system() != "Darwin":
        return []

    args = []

    try:
        sdk_path = subprocess.check_output(
            ["xcrun", "--show-sdk-path"], stderr=subprocess.DEVNULL
        ).decode().strip()
        if sdk_path:
            args += ["-isysroot", sdk_path]
    except Exception as e:
        print(f"[_macos_clang_args] WARNING: xcrun --show-sdk-path failed: {e}")

    try:
        resource_dir = subprocess.check_output(
            ["clang", "-print-resource-dir"], stderr=subprocess.DEVNULL
        ).decode().strip()
        if resource_dir:
            args += ["-resource-dir", resource_dir]
    except Exception as e:
        print(f"[_macos_clang_args] WARNING: clang -print-resource-dir failed: {e}")

    print(f"[_macos_clang_args] resolved args: {args}")
    return args

VM_RUNTIME = r'''
// ============================================================
// Embedded VM runtime (auto-generated, do not edit by hand)
// Same opcode format as the Android custom-VM research project.
// ============================================================
#include <cstdint>
#include <cstddef>

namespace vm_rt {

struct VMContext {
    int64_t regs[16] = {0};
    const uint8_t* bytecode = nullptr;
    size_t bytecode_len = 0;
    size_t pc = 0;
    const int64_t* args = nullptr;
    int arg_count = 0;
};

inline uint8_t fetch8(VMContext& c) { return c.bytecode[c.pc++]; }
inline uint16_t fetch16(VMContext& c) {
    uint16_t lo = fetch8(c), hi = fetch8(c);
    return static_cast<uint16_t>(lo | (hi << 8));
}
inline int64_t fetch64(VMContext& c) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)c.bytecode[c.pc + i] << (8 * i);
    c.pc += 8;
    int64_t r; __builtin_memcpy(&r, &v, 8);
    return r;
}

inline int64_t run(const uint8_t* bytecode, size_t len, const int64_t* args, int argc) {
    VMContext c;
    c.bytecode = bytecode; c.bytecode_len = len; c.args = args; c.arg_count = argc;
    while (true) {
        uint8_t op = fetch8(c);
        switch (op) {
            case 0x01: { uint8_t r = fetch8(c), a = fetch8(c); c.regs[r] = c.args[a]; break; }
            case 0x02: { uint8_t r = fetch8(c); c.regs[r] = fetch64(c); break; }
            case 0x03: { uint8_t r = fetch8(c), s = fetch8(c); c.regs[r] = c.regs[s]; break; }
            case 0x04: { uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]+c.regs[b]; break; }
            case 0x05: { uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]-c.regs[b]; break; }
            case 0x06: { uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]*c.regs[b]; break; }
            case 0x07: { uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]/c.regs[b]; break; }
            case 0x08: { uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]%c.regs[b]; break; }
            case 0x09: { uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]>c.regs[b]; break; }
            case 0x0A: { uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]>=c.regs[b]; break; }
            case 0x0B: { uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]<c.regs[b]; break; }
            case 0x0C: { uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]<=c.regs[b]; break; }
            case 0x0D: { uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]==c.regs[b]; break; }
            case 0x0E: { uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]!=c.regs[b]; break; }
            case 0x0F: { c.pc = fetch16(c); break; }
            case 0x10: { uint8_t r=fetch8(c); uint16_t t=fetch16(c); if (c.regs[r]!=0) c.pc=t; break; }
            case 0x11: { uint8_t r=fetch8(c); uint16_t t=fetch16(c); if (c.regs[r]==0) c.pc=t; break; }
            case 0x12: { return fetch64(c); }
            case 0x13: { uint8_t r=fetch8(c); return c.regs[r]; }
            default: return 0;
        }
    }
}

} // namespace vm_rt
'''


def random_name(prefix="v"):
    return prefix + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def collect_top_level_functions(tu, filename):
    return [n for n in tu.cursor.get_children()
            if n.kind == ci.CursorKind.FUNCTION_DECL
            and n.location.file and str(n.location.file) == filename
            and n.is_definition()]


def bytes_to_c_array(name, data):
    hex_bytes = ", ".join(f"0x{b:02x}" for b in data)
    return f"static const unsigned char {name}[] = {{ {hex_bytes} }};\nstatic const size_t {name}_len = {len(data)};\n"


def obfuscate(source_code, filename="/tmp/input.cpp"):
    with open(filename, "w") as f:
        f.write(source_code)

    index = ci.Index.create()
    parse_args = ["-std=c++17"] + _macos_clang_args()
    tu = index.parse(filename, args=parse_args)
    diag_errors = [str(d) for d in tu.diagnostics if d.severity >= ci.Diagnostic.Error]

    funcs = collect_top_level_functions(tu, filename)

    include_lines = [line for line in source_code.splitlines()
                      if line.strip().startswith("#include")
                      or line.strip().startswith("using ")]

    if diag_errors:
        report = ["PARSE ERRORS DETECTED - no functions were virtualized, "
                   "output below is your original code unchanged. Fix the "
                   "errors listed below and try again."]
        return source_code, report, diag_errors

    eligible_funcs = []
    fallback_funcs = []
    report = []

    for f in funcs:
        ok, reason = eligibility_check(f)
        if ok:
            body = next((c for c in f.get_children()
                         if c.kind == ci.CursorKind.COMPOUND_STMT), None)
            if body is not None and len(list(body.get_children())) == 0:
                ok, reason = False, "function body parsed as empty (likely a parse issue, not real code)"
        if ok:
            try:
                compiler = FunctionCompiler()
                bc = compiler.compile_function(f)
                eligible_funcs.append((f, bc))
                report.append(f"{f.spelling}: VIRTUALIZED ({len(bc)} bytes of bytecode)")
                continue
            except Exception as e:
                reason = f"codegen failed: {e}"
        fallback_funcs.append(f)
        report.append(f"{f.spelling}: NOT virtualized ({reason}) - identifiers renamed instead")

    rename_map = {}
    for f in fallback_funcs:
        for node in f.walk_preorder():
            if node.kind in (ci.CursorKind.VAR_DECL, ci.CursorKind.PARM_DECL):
                if node.spelling and node.spelling not in rename_map:
                    rename_map[node.spelling] = random_name("var_")

    output_parts = [
        "// ================================================================\n"
        "// Auto-generated obfuscated output.\n"
        "// Functions using only int arithmetic/comparisons/if/return were\n"
        "// converted to VM bytecode. Everything else was passed through\n"
        "// with local identifiers renamed.\n"
        "// ================================================================\n",
        "\n".join(include_lines) + "\n\n" if include_lines else "",
        VM_RUNTIME,
        "\n// ---- Bytecode-backed functions ----\n",
    ]

    for f, bc in eligible_funcs:
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

    if fallback_funcs:
        output_parts.append("\n// ---- Renamed (non-virtualized) functions ----\n")
        with open(filename) as f:
            original_text = f.read()
        for f in fallback_funcs:
            start, end = f.extent.start.offset, f.extent.end.offset
            func_text = original_text[start:end]
            for old, new in rename_map.items():
                func_text = re.sub(rf"\b{re.escape(old)}\b", new, func_text)
            output_parts.append(func_text + "\n\n")

    final_code = "".join(output_parts)
    return final_code, report, diag_errors