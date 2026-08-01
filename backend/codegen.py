"""
codegen.py
Takes parsed C++ source, virtualizes eligible functions (via bytecode_gen),
and falls back to simple identifier renaming for everything Clang parses
but that isn't eligible for full VM protection (loops, pointers, floats,
function calls, classes, etc.). Produces one final, compilable .cpp file.
"""
import re
import os
import random
import string
import subprocess
import platform
import clang.cindex as ci
from bytecode_gen import eligibility_check, FunctionCompiler


def _macos_clang_args():
    """On macOS, pip's libclang (18.1.1) is version-mismatched with the
    LATEST Apple SDK - its C++ headers now assume newer compiler builtins
    that 18.1.1 doesn't have. Instead of mixing toolchains, we pin to an
    older, already-installed Apple SDK (MacOSX15.sdk) whose headers
    predate that requirement, while still getting Apple's real resource
    directory for builtin headers like stdarg.h."""
    if platform.system() != "Darwin":
        return []

    args = []

    older_sdk = "/Library/Developer/CommandLineTools/SDKs/MacOSX15.sdk"
    if os.path.isdir(older_sdk):
        args += ["-isysroot", older_sdk]
    else:
        print(f"[_macos_clang_args] WARNING: {older_sdk} not found, falling back to xcrun --show-sdk-path")
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
            ["xcrun", "clang", "-print-resource-dir"], stderr=subprocess.DEVNULL
        ).decode().strip()
        if resource_dir:
            args += ["-resource-dir", resource_dir]
    except Exception as e:
        print(f"[_macos_clang_args] WARNING: xcrun clang -print-resource-dir failed: {e}")

    print(f"[_macos_clang_args] resolved args: {args}")
    return args

def generate_vm_runtime(opcode_shuffle_map=None):
    mapping = opcode_shuffle_map or {}

    op_bodies = [
        (0x01, "{ uint8_t r = fetch8(c), a = fetch8(c); c.regs[r] = c.args[a]; break; }"),
        (0x02, "{ uint8_t r = fetch8(c); c.regs[r] = fetch64(c); break; }"),
        (0x03, "{ uint8_t r = fetch8(c), s = fetch8(c); c.regs[r] = c.regs[s]; break; }"),
        (0x04, "{ uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]+c.regs[b]; break; }"),
        (0x05, "{ uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]-c.regs[b]; break; }"),
        (0x06, "{ uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]*c.regs[b]; break; }"),
        (0x07, "{ uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]/c.regs[b]; break; }"),
        (0x08, "{ uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]%c.regs[b]; break; }"),
        (0x09, "{ uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]>c.regs[b]; break; }"),
        (0x0A, "{ uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]>=c.regs[b]; break; }"),
        (0x0B, "{ uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]<c.regs[b]; break; }"),
        (0x0C, "{ uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]<=c.regs[b]; break; }"),
        (0x0D, "{ uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]==c.regs[b]; break; }"),
        (0x0E, "{ uint8_t r=fetch8(c),a=fetch8(c),b=fetch8(c); c.regs[r]=c.regs[a]!=c.regs[b]; break; }"),
        (0x0F, "{ c.pc = fetch16(c); break; }"),
        (0x10, "{ uint8_t r=fetch8(c); uint16_t t=fetch16(c); if (c.regs[r]!=0) c.pc=t; break; }"),
        (0x11, "{ uint8_t r=fetch8(c); uint16_t t=fetch16(c); if (c.regs[r]==0) c.pc=t; break; }"),
        (0x12, "{ int64_t v = fetch64(c); if (c.in_call) { __builtin_memcpy(c.regs, c.saved_regs, sizeof(c.regs)); c.regs[c.call_dst_reg] = v; c.args = c.saved_args; c.pc = c.saved_pc; c.in_call = false; break; } return v; }"),
        (0x13, "{ uint8_t r = fetch8(c); int64_t v = c.regs[r]; if (c.in_call) { __builtin_memcpy(c.regs, c.saved_regs, sizeof(c.regs)); c.regs[c.call_dst_reg] = v; c.args = c.saved_args; c.pc = c.saved_pc; c.in_call = false; break; } return v; }"),
        (0x14, "{ break; }"),
        (0x15, "{ uint8_t r = fetch8(c), base = fetch8(c), idx_r = fetch8(c); c.regs[r] = c.mem[base + c.regs[idx_r]]; break; }"),
        (0x16, "{ uint8_t base = fetch8(c), idx_r = fetch8(c), src_r = fetch8(c); c.mem[base + c.regs[idx_r]] = c.regs[src_r]; break; }"),
        (0x17, "{ uint16_t target = fetch16(c); uint8_t a0 = fetch8(c), a1 = fetch8(c), a2 = fetch8(c), a3 = fetch8(c); uint8_t r_dst = fetch8(c); __builtin_memcpy(c.saved_regs, c.regs, sizeof(c.regs)); c.saved_pc = c.pc; c.saved_args = c.args; c.in_call = true; c.call_dst_reg = r_dst; c.call_args[0] = (a0 != 0xFF) ? c.regs[a0] : 0; c.call_args[1] = (a1 != 0xFF) ? c.regs[a1] : 0; c.call_args[2] = (a2 != 0xFF) ? c.regs[a2] : 0; c.call_args[3] = (a3 != 0xFF) ? c.regs[a3] : 0; __builtin_memset(c.regs, 0, sizeof(c.regs)); c.args = c.call_args; c.pc = target; break; }"),
    ]

    cases = []
    for orig_op, body in op_bodies:
        target_op = mapping.get(orig_op, orig_op)
        cases.append(f"            case 0x{target_op:02x}: {body}")

    cases_str = "\n".join(cases)

    return f"""\
// ============================================================
// Embedded VM runtime (auto-generated, do not edit by hand)
// Same opcode format as the Android custom-VM research project.
// ============================================================
#include <cstdint>
#include <cstddef>

namespace vm_rt {{

struct VMContext {{
    int64_t regs[16] = {{0}};
    int64_t mem[256] = {{0}};
    int64_t saved_regs[16] = {{0}};
    size_t saved_pc = 0;
    bool in_call = false;
    uint8_t call_dst_reg = 0;
    int64_t call_args[4] = {{0}};
    const int64_t* saved_args = nullptr;
    const uint8_t* bytecode = nullptr;
    size_t bytecode_len = 0;
    size_t pc = 0;
    const int64_t* args = nullptr;
    int arg_count = 0;
}};

inline uint8_t fetch8(VMContext& c) {{ return c.bytecode[c.pc++]; }}
inline uint16_t fetch16(VMContext& c) {{
    uint16_t lo = fetch8(c), hi = fetch8(c);
    return static_cast<uint16_t>(lo | (hi << 8));
}}
inline int64_t fetch64(VMContext& c) {{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)c.bytecode[c.pc + i] << (8 * i);
    c.pc += 8;
    int64_t r; __builtin_memcpy(&r, &v, 8);
    return r;
}}

inline uint32_t fnv1a_32(const uint8_t* data, size_t len) {{
    uint32_t hash = 0x811c9dc5u;
    for (size_t i = 0; i < len; i++) {{
        hash ^= data[i];
        hash *= 0x01000193u;
    }}
    return hash;
}}

inline int64_t run(const uint8_t* bytecode, size_t len, const int64_t* args, int argc, size_t entry_pc = 0, uint32_t expected_checksum = 0) {{
    if (expected_checksum != 0 && fnv1a_32(bytecode, len) != expected_checksum) {{
        return 0;
    }}
    VMContext c;
    c.bytecode = bytecode; c.bytecode_len = len; c.args = args; c.arg_count = argc; c.pc = entry_pc;
    while (true) {{
        uint8_t op = fetch8(c);
        switch (op) {{
{cases_str}
            default: return 0;
        }}
    }}
}}

}} // namespace vm_rt
"""


VM_RUNTIME = generate_vm_runtime()



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


from pipeline import run_pipeline


def obfuscate(source_code, filename="/tmp/input.cpp"):
    return run_pipeline(source_code, filename)