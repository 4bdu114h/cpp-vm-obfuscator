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
        (0x12, "{ int64_t v = fetch64(c); if (c.call_depth > 0) { c.call_depth--; CallFrame& frame = c.call_stack[c.call_depth]; __builtin_memcpy(c.regs, frame.regs, sizeof(c.regs)); __builtin_memcpy(c.mem, frame.mem, sizeof(c.mem)); c.regs[frame.dst_reg] = v; c.args = (c.call_depth > 0) ? c.call_stack[c.call_depth - 1].saved_args_buf : c.original_args; c.pc = frame.return_pc; break; } return v; }"),
        (0x13, "{ uint8_t r = fetch8(c); int64_t v = c.regs[r]; if (c.call_depth > 0) { c.call_depth--; CallFrame& frame = c.call_stack[c.call_depth]; __builtin_memcpy(c.regs, frame.regs, sizeof(c.regs)); __builtin_memcpy(c.mem, frame.mem, sizeof(c.mem)); c.regs[frame.dst_reg] = v; c.args = (c.call_depth > 0) ? c.call_stack[c.call_depth - 1].saved_args_buf : c.original_args; c.pc = frame.return_pc; break; } return v; }"),
        (0x14, "{ break; }"),
        (0x15, "{ uint8_t r = fetch8(c), base = fetch8(c), idx_r = fetch8(c); c.regs[r] = c.mem[base + c.regs[idx_r]]; break; }"),
        (0x16, "{ uint8_t base = fetch8(c), idx_r = fetch8(c), src_r = fetch8(c); c.mem[base + c.regs[idx_r]] = c.regs[src_r]; break; }"),
        (0x17, "{ uint16_t target = fetch16(c); uint8_t a0 = fetch8(c), a1 = fetch8(c), a2 = fetch8(c), a3 = fetch8(c); uint8_t r_dst = fetch8(c); if (c.call_depth >= MAX_CALL_DEPTH) return 0; CallFrame& frame = c.call_stack[c.call_depth]; __builtin_memcpy(frame.regs, c.regs, sizeof(c.regs)); __builtin_memcpy(frame.mem, c.mem, sizeof(c.mem)); frame.return_pc = c.pc; frame.dst_reg = r_dst; frame.saved_args_buf[0] = (a0 != 0xFF) ? c.regs[a0] : 0; frame.saved_args_buf[1] = (a1 != 0xFF) ? c.regs[a1] : 0; frame.saved_args_buf[2] = (a2 != 0xFF) ? c.regs[a2] : 0; frame.saved_args_buf[3] = (a3 != 0xFF) ? c.regs[a3] : 0; c.call_depth++; __builtin_memset(c.regs, 0, sizeof(c.regs)); __builtin_memset(c.mem, 0, sizeof(c.mem)); c.args = frame.saved_args_buf; c.pc = target; break; }"),
        (0x1F, "{ uint8_t n = fetch8(c), r0 = fetch8(c), r1 = fetch8(c), r2 = fetch8(c), r3 = fetch8(c); c.struct_ret_buf[0] = (r0 != 0xFF) ? c.regs[r0] : 0; c.struct_ret_buf[1] = (r1 != 0xFF) ? c.regs[r1] : 0; c.struct_ret_buf[2] = (r2 != 0xFF) ? c.regs[r2] : 0; c.struct_ret_buf[3] = (r3 != 0xFF) ? c.regs[r3] : 0; if (c.out_struct_buf) { __builtin_memcpy(c.out_struct_buf, c.struct_ret_buf, sizeof(c.struct_ret_buf)); } if (c.call_depth > 0) { c.call_depth--; CallFrame& frame = c.call_stack[c.call_depth]; __builtin_memcpy(c.regs, frame.regs, sizeof(c.regs)); __builtin_memcpy(c.mem, frame.mem, sizeof(c.mem)); c.args = (c.call_depth > 0) ? c.call_stack[c.call_depth - 1].saved_args_buf : c.original_args; c.pc = frame.return_pc; break; } return 0; }"),
        (0x20, "{ uint8_t r = fetch8(c), idx = fetch8(c); c.regs[r] = c.struct_ret_buf[idx]; break; }"),
    ]

    cases = []
    for orig_op, body in op_bodies:
        target_op = mapping.get(orig_op, orig_op)
        cases.append(f"            case 0x{target_op:02x}: {body}")

    cases_str = "\n".join(cases)

    str_op_18 = mapping.get(0x18, 0x18)
    str_op_19 = mapping.get(0x19, 0x19)
    str_op_1a = mapping.get(0x1A, 0x1A)
    str_op_1b = mapping.get(0x1B, 0x1B)
    str_op_1c = mapping.get(0x1C, 0x1C)
    str_op_1d = mapping.get(0x1D, 0x1D)
    str_op_1e = mapping.get(0x1E, 0x1E)

    return f"""\
// ============================================================
// Embedded VM runtime (auto-generated, do not edit by hand)
// Same opcode format as the Android custom-VM research project.
// ============================================================
#include <cstdint>
#include <cstddef>
#include <string>

#if defined(__APPLE__)
#include <sys/ptrace.h>
#elif defined(__linux__)
#include <sys/ptrace.h>
#endif

namespace vm_rt {{

inline bool anti_debug_check() {{
#if defined(__APPLE__)
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
    return false;
#elif defined(__linux__)
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {{
        return true;
    }}
    return false;
#else
    return false;
#endif
}}

inline bool& debugger_detected_flag() {{
    static bool detected = anti_debug_check();
    return detected;
}}

static const int MAX_CALL_DEPTH = 32;
struct CallFrame {{
    int64_t regs[16];
    int64_t mem[256];
    size_t return_pc;
    uint8_t dst_reg;
    int64_t saved_args_buf[4];
}};

struct VMContext {{
    int64_t regs[16] = {{0}};
    int64_t mem[256] = {{0}};
    int64_t struct_ret_buf[4] = {{0}};
    int64_t* out_struct_buf = nullptr;
    CallFrame call_stack[MAX_CALL_DEPTH];
    int call_depth = 0;
    const uint8_t* bytecode = nullptr;
    size_t bytecode_len = 0;
    size_t pc = 0;
    const int64_t* args = nullptr;
    const int64_t* original_args = nullptr;
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
    if (debugger_detected_flag()) {{
        return 0;
    }}
    if (expected_checksum != 0 && fnv1a_32(bytecode, len) != expected_checksum) {{
        return 0;
    }}
    VMContext c;
    c.bytecode = bytecode; c.bytecode_len = len; c.args = args; c.original_args = args; c.arg_count = argc; c.pc = entry_pc;
    while (true) {{
        uint8_t op = fetch8(c);
        switch (op) {{
{cases_str}
            default: return 0;
        }}
    }}
}}

inline int64_t run_struct(const uint8_t* bytecode, size_t len, const int64_t* args, int argc, size_t entry_pc, uint32_t expected_checksum, int64_t* out_struct_buf, int out_count) {{
    if (debugger_detected_flag()) {{
        for (int i = 0; i < out_count; i++) out_struct_buf[i] = 0;
        return 0;
    }}
    if (expected_checksum != 0 && fnv1a_32(bytecode, len) != expected_checksum) {{
        for (int i = 0; i < out_count; i++) out_struct_buf[i] = 0;
        return 0;
    }}
    VMContext c;
    c.bytecode = bytecode; c.bytecode_len = len; c.args = args; c.original_args = args; c.arg_count = argc; c.pc = entry_pc; c.out_struct_buf = out_struct_buf;
    while (true) {{
        uint8_t op = fetch8(c);
        switch (op) {{
{cases_str}
            default: return 0;
        }}
    }}
}}

struct StringVMContext {{
    std::string str_regs[16];
    int64_t int_regs[8] = {{0}};
    const uint8_t* bytecode = nullptr;
    size_t bytecode_len = 0;
    size_t pc = 0;
    const std::string* str_args = nullptr;
    int str_arg_count = 0;
    const std::string* const_pool = nullptr;
    int const_pool_count = 0;
}};

inline uint8_t str_fetch8(StringVMContext& c) {{ return c.bytecode[c.pc++]; }}

inline std::string run_str(const uint8_t* bytecode, size_t len,
                           const std::string* str_args, int argc,
                           const std::string* const_pool, int pool_count,
                           int64_t* out_int_result = nullptr,
                           uint32_t expected_checksum = 0) {{
    if (debugger_detected_flag()) {{
        if (out_int_result) *out_int_result = 0;
        return "";
    }}
    if (expected_checksum != 0 && fnv1a_32(bytecode, len) != expected_checksum) {{
        if (out_int_result) *out_int_result = 0;
        return "";
    }}
    StringVMContext c;
    c.bytecode = bytecode; c.bytecode_len = len;
    c.str_args = str_args; c.str_arg_count = argc;
    c.const_pool = const_pool; c.const_pool_count = pool_count;

    while (true) {{
        uint8_t op = str_fetch8(c);
        switch (op) {{
            case 0x{str_op_18:02x}: {{
                uint8_t r = str_fetch8(c), a = str_fetch8(c);
                c.str_regs[r] = c.str_args[a];
                break;
            }}
            case 0x{str_op_19:02x}: {{
                uint8_t r = str_fetch8(c), idx = str_fetch8(c);
                c.str_regs[r] = c.const_pool[idx];
                break;
            }}
            case 0x{str_op_1a:02x}: {{
                uint8_t r = str_fetch8(c), s1 = str_fetch8(c), s2 = str_fetch8(c);
                c.str_regs[r] = c.str_regs[s1] + c.str_regs[s2];
                break;
            }}
            case 0x{str_op_1b:02x}: {{
                uint8_t r = str_fetch8(c), s1 = str_fetch8(c), s2 = str_fetch8(c);
                c.int_regs[r] = (c.str_regs[s1] == c.str_regs[s2]) ? 1 : 0;
                break;
            }}
            case 0x{str_op_1c:02x}: {{
                uint8_t r = str_fetch8(c), s1 = str_fetch8(c), s2 = str_fetch8(c);
                c.int_regs[r] = (c.str_regs[s1] != c.str_regs[s2]) ? 1 : 0;
                break;
            }}
            case 0x{str_op_1d:02x}: {{
                uint8_t r = str_fetch8(c);
                return c.str_regs[r];
            }}
            case 0x{str_op_1e:02x}: {{
                uint8_t r = str_fetch8(c);
                if (out_int_result) *out_int_result = c.int_regs[r];
                return "";
            }}
            default:
                if (out_int_result) *out_int_result = 0;
                return "";
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


def collect_top_level_type_decls(tu, filename):
    return [n for n in tu.cursor.get_children()
            if n.kind in (ci.CursorKind.STRUCT_DECL, ci.CursorKind.CLASS_DECL,
                         ci.CursorKind.ENUM_DECL, ci.CursorKind.TYPEDEF_DECL,
                         ci.CursorKind.TYPE_ALIAS_DECL)
            and n.location.file and str(n.location.file) == filename]


def bytes_to_c_array(name, data):
    hex_bytes = ", ".join(f"0x{b:02x}" for b in data)
    return f"static const unsigned char {name}[] = {{ {hex_bytes} }};\nstatic const size_t {name}_len = {len(data)};\n"


from pipeline import run_pipeline


def obfuscate(source_code, filename="/tmp/input.cpp", opcode_shuffle_seed=None):
    return run_pipeline(source_code, filename, opcode_shuffle_seed=opcode_shuffle_seed)