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

    # Per-build random identifier generator for internal interpreter names
    def rand_id(prefix="vm_"):
        return prefix + "".join(random.choices(string.ascii_lowercase + string.digits, k=7))

    # Helper function random names
    fn_fetch8 = rand_id("vm_f8_")
    fn_fetch16 = rand_id("vm_f16_")
    fn_fetch64 = rand_id("vm_f64_")
    fn_str_fetch8 = rand_id("vm_sf8_")
    fn_anti_debug = rand_id("vm_adc_")
    fn_debugger_flag = rand_id("vm_ddf_")
    fn_fnv = rand_id("vm_fnv_")
    fn_dispatch_lo = rand_id("vm_dlo_")
    fn_dispatch_hi = rand_id("vm_dhi_")
    fn_str_dispatch_lo = rand_id("vm_dstr_lo_")
    fn_str_dispatch_hi = rand_id("vm_dstr_hi_")

    # Internal variable random names
    v_ctx = rand_id("vm_c_")
    v_ret_val = rand_id("vm_rv_")
    v_has_returned = rand_id("vm_hr_")
    v_ret_str = rand_id("vm_rs_")
    v_detected = rand_id("vm_det_")

    op_bodies = [
        (0x01, f"{{ uint8_t r = {fn_fetch8}({v_ctx}), a = {fn_fetch8}({v_ctx}); {v_ctx}.regs[r] = {v_ctx}.args[a]; break; }}"),
        (0x02, f"{{ uint8_t r = {fn_fetch8}({v_ctx}); {v_ctx}.regs[r] = {fn_fetch64}({v_ctx}); break; }}"),
        (0x03, f"{{ uint8_t r = {fn_fetch8}({v_ctx}), s = {fn_fetch8}({v_ctx}); {v_ctx}.regs[r] = {v_ctx}.regs[s]; break; }}"),
        (0x04, f"{{ uint8_t r={fn_fetch8}({v_ctx}),a={fn_fetch8}({v_ctx}),b={fn_fetch8}({v_ctx}); {v_ctx}.regs[r]={v_ctx}.regs[a]+{v_ctx}.regs[b]; break; }}"),
        (0x05, f"{{ uint8_t r={fn_fetch8}({v_ctx}),a={fn_fetch8}({v_ctx}),b={fn_fetch8}({v_ctx}); {v_ctx}.regs[r]={v_ctx}.regs[a]-{v_ctx}.regs[b]; break; }}"),
        (0x06, f"{{ uint8_t r={fn_fetch8}({v_ctx}),a={fn_fetch8}({v_ctx}),b={fn_fetch8}({v_ctx}); {v_ctx}.regs[r]={v_ctx}.regs[a]*{v_ctx}.regs[b]; break; }}"),
        (0x07, f"{{ uint8_t r={fn_fetch8}({v_ctx}),a={fn_fetch8}({v_ctx}),b={fn_fetch8}({v_ctx}); {v_ctx}.regs[r]={v_ctx}.regs[a]/{v_ctx}.regs[b]; break; }}"),
        (0x08, f"{{ uint8_t r={fn_fetch8}({v_ctx}),a={fn_fetch8}({v_ctx}),b={fn_fetch8}({v_ctx}); {v_ctx}.regs[r]={v_ctx}.regs[a]%{v_ctx}.regs[b]; break; }}"),
        (0x09, f"{{ uint8_t r={fn_fetch8}({v_ctx}),a={fn_fetch8}({v_ctx}),b={fn_fetch8}({v_ctx}); {v_ctx}.regs[r]={v_ctx}.regs[a]>{v_ctx}.regs[b]; break; }}"),
        (0x0A, f"{{ uint8_t r={fn_fetch8}({v_ctx}),a={fn_fetch8}({v_ctx}),b={fn_fetch8}({v_ctx}); {v_ctx}.regs[r]={v_ctx}.regs[a]>={v_ctx}.regs[b]; break; }}"),
        (0x0B, f"{{ uint8_t r={fn_fetch8}({v_ctx}),a={fn_fetch8}({v_ctx}),b={fn_fetch8}({v_ctx}); {v_ctx}.regs[r]={v_ctx}.regs[a]<{v_ctx}.regs[b]; break; }}"),
        (0x0C, f"{{ uint8_t r={fn_fetch8}({v_ctx}),a={fn_fetch8}({v_ctx}),b={fn_fetch8}({v_ctx}); {v_ctx}.regs[r]={v_ctx}.regs[a]<={v_ctx}.regs[b]; break; }}"),
        (0x0D, f"{{ uint8_t r={fn_fetch8}({v_ctx}),a={fn_fetch8}({v_ctx}),b={fn_fetch8}({v_ctx}); {v_ctx}.regs[r]={v_ctx}.regs[a]=={v_ctx}.regs[b]; break; }}"),
        (0x0E, f"{{ uint8_t r={fn_fetch8}({v_ctx}),a={fn_fetch8}({v_ctx}),b={fn_fetch8}({v_ctx}); {v_ctx}.regs[r]={v_ctx}.regs[a]!={v_ctx}.regs[b]; break; }}"),
        (0x0F, f"{{ {v_ctx}.pc = {fn_fetch16}({v_ctx}); break; }}"),
        (0x10, f"{{ uint8_t r={fn_fetch8}({v_ctx}); uint16_t t={fn_fetch16}({v_ctx}); if ({v_ctx}.regs[r]!=0) {v_ctx}.pc=t; break; }}"),
        (0x11, f"{{ uint8_t r={fn_fetch8}({v_ctx}); uint16_t t={fn_fetch16}({v_ctx}); if ({v_ctx}.regs[r]==0) {v_ctx}.pc=t; break; }}"),
        (0x12, f"{{ int64_t v = {fn_fetch64}({v_ctx}); if ({v_ctx}.call_depth > 0) {{ {v_ctx}.call_depth--; CallFrame& frame = {v_ctx}.call_stack[{v_ctx}.call_depth]; __builtin_memcpy({v_ctx}.regs, frame.regs, sizeof({v_ctx}.regs)); {v_ctx}.frame_base = frame.saved_frame_base; {v_ctx}.regs[frame.dst_reg] = v; {v_ctx}.args = ({v_ctx}.call_depth > 0) ? {v_ctx}.call_stack[{v_ctx}.call_depth - 1].saved_args_buf : {v_ctx}.original_args; {v_ctx}.pc = frame.return_pc; break; }} *{v_ret_val} = v; *{v_has_returned} = true; return; }}"),
        (0x13, f"{{ uint8_t r = {fn_fetch8}({v_ctx}); int64_t v = {v_ctx}.regs[r]; if ({v_ctx}.call_depth > 0) {{ {v_ctx}.call_depth--; CallFrame& frame = {v_ctx}.call_stack[{v_ctx}.call_depth]; __builtin_memcpy({v_ctx}.regs, frame.regs, sizeof({v_ctx}.regs)); {v_ctx}.frame_base = frame.saved_frame_base; {v_ctx}.regs[frame.dst_reg] = v; {v_ctx}.args = ({v_ctx}.call_depth > 0) ? {v_ctx}.call_stack[{v_ctx}.call_depth - 1].saved_args_buf : {v_ctx}.original_args; {v_ctx}.pc = frame.return_pc; break; }} *{v_ret_val} = v; *{v_has_returned} = true; return; }}"),
        (0x14, f"{{ break; }}"),
        (0x15, f"{{ uint8_t r = {fn_fetch8}({v_ctx}), base = {fn_fetch8}({v_ctx}), idx_r = {fn_fetch8}({v_ctx}); {v_ctx}.regs[r] = (base == 0xFF) ? {v_ctx}.mem[{v_ctx}.regs[idx_r]] : {v_ctx}.mem[{v_ctx}.frame_base + base + {v_ctx}.regs[idx_r]]; break; }}"),
        (0x16, f"{{ uint8_t base = {fn_fetch8}({v_ctx}), idx_r = {fn_fetch8}({v_ctx}), src_r = {fn_fetch8}({v_ctx}); if (base == 0xFF) {{ {v_ctx}.mem[{v_ctx}.regs[idx_r]] = {v_ctx}.regs[src_r]; }} else {{ {v_ctx}.mem[{v_ctx}.frame_base + base + {v_ctx}.regs[idx_r]] = {v_ctx}.regs[src_r]; }} break; }}"),
        (0x17, f"{{ uint16_t target = {fn_fetch16}({v_ctx}); uint8_t a0 = {fn_fetch8}({v_ctx}), a1 = {fn_fetch8}({v_ctx}), a2 = {fn_fetch8}({v_ctx}), a3 = {fn_fetch8}({v_ctx}); uint8_t r_dst = {fn_fetch8}({v_ctx}); if ({v_ctx}.call_depth >= MAX_CALL_DEPTH) {{ *{v_ret_val} = 0; *{v_has_returned} = true; return; }} CallFrame& frame = {v_ctx}.call_stack[{v_ctx}.call_depth]; __builtin_memcpy(frame.regs, {v_ctx}.regs, sizeof({v_ctx}.regs)); frame.saved_frame_base = {v_ctx}.frame_base; frame.return_pc = {v_ctx}.pc; frame.dst_reg = r_dst; frame.saved_args_buf[0] = (a0 != 0xFF) ? {v_ctx}.regs[a0] : 0; frame.saved_args_buf[1] = (a1 != 0xFF) ? {v_ctx}.regs[a1] : 0; frame.saved_args_buf[2] = (a2 != 0xFF) ? {v_ctx}.regs[a2] : 0; frame.saved_args_buf[3] = (a3 != 0xFF) ? {v_ctx}.regs[a3] : 0; {v_ctx}.call_depth++; {v_ctx}.frame_base += 16; __builtin_memset({v_ctx}.regs, 0, sizeof({v_ctx}.regs)); {v_ctx}.args = frame.saved_args_buf; {v_ctx}.pc = target; break; }}"),
        (0x1F, f"{{ uint8_t n = {fn_fetch8}({v_ctx}), r0 = {fn_fetch8}({v_ctx}), r1 = {fn_fetch8}({v_ctx}), r2 = {fn_fetch8}({v_ctx}), r3 = {fn_fetch8}({v_ctx}); {v_ctx}.struct_ret_buf[0] = (r0 != 0xFF) ? {v_ctx}.regs[r0] : 0; {v_ctx}.struct_ret_buf[1] = (r1 != 0xFF) ? {v_ctx}.regs[r1] : 0; {v_ctx}.struct_ret_buf[2] = (r2 != 0xFF) ? {v_ctx}.regs[r2] : 0; {v_ctx}.struct_ret_buf[3] = (r3 != 0xFF) ? {v_ctx}.regs[r3] : 0; if ({v_ctx}.out_struct_buf) {{ __builtin_memcpy({v_ctx}.out_struct_buf, {v_ctx}.struct_ret_buf, sizeof({v_ctx}.struct_ret_buf)); }} if ({v_ctx}.call_depth > 0) {{ {v_ctx}.call_depth--; CallFrame& frame = {v_ctx}.call_stack[{v_ctx}.call_depth]; __builtin_memcpy({v_ctx}.regs, frame.regs, sizeof({v_ctx}.regs)); {v_ctx}.frame_base = frame.saved_frame_base; {v_ctx}.args = ({v_ctx}.call_depth > 0) ? {v_ctx}.call_stack[{v_ctx}.call_depth - 1].saved_args_buf : {v_ctx}.original_args; {v_ctx}.pc = frame.return_pc; break; }} *{v_ret_val} = 0; *{v_has_returned} = true; return; }}"),
        (0x20, f"{{ uint8_t r = {fn_fetch8}({v_ctx}), idx = {fn_fetch8}({v_ctx}); {v_ctx}.regs[r] = {v_ctx}.struct_ret_buf[idx]; break; }}"),
        (0x21, f"{{ uint8_t r = {fn_fetch8}({v_ctx}), slot = {fn_fetch8}({v_ctx}); {v_ctx}.regs[r] = {v_ctx}.frame_base + slot; break; }}"),
    ]

    target_mapped = [(mapping.get(op, op), body) for op, body in op_bodies]
    target_ops = sorted([t[0] for t in target_mapped])
    mid_idx = len(target_ops) // 2
    split_threshold = target_ops[mid_idx]

    lo_cases = []
    hi_cases = []
    for target_op, body in target_mapped:
        case_line = f"            case 0x{target_op:02x}: {body}"
        if target_op < split_threshold:
            lo_cases.append(case_line)
        else:
            hi_cases.append(case_line)

    lo_cases_str = "\n".join(lo_cases)
    hi_cases_str = "\n".join(hi_cases)

    str_op_18 = mapping.get(0x18, 0x18)
    str_op_19 = mapping.get(0x19, 0x19)
    str_op_1a = mapping.get(0x1A, 0x1A)
    str_op_1b = mapping.get(0x1B, 0x1B)
    str_op_1c = mapping.get(0x1C, 0x1C)
    str_op_1d = mapping.get(0x1D, 0x1D)
    str_op_1e = mapping.get(0x1E, 0x1E)

    str_target_ops = sorted([str_op_18, str_op_19, str_op_1a, str_op_1b, str_op_1c, str_op_1d, str_op_1e])
    str_mid_idx = len(str_target_ops) // 2
    str_split_threshold = str_target_ops[str_mid_idx]

    str_op_bodies = [
        (str_op_18, f"{{ uint8_t r = {fn_str_fetch8}({v_ctx}), a = {fn_str_fetch8}({v_ctx}); {v_ctx}.str_regs[r] = {v_ctx}.str_args[a]; break; }}"),
        (str_op_19, f"{{ uint8_t r = {fn_str_fetch8}({v_ctx}), idx = {fn_str_fetch8}({v_ctx}); {v_ctx}.str_regs[r] = {v_ctx}.const_pool[idx]; break; }}"),
        (str_op_1a, f"{{ uint8_t r = {fn_str_fetch8}({v_ctx}), s1 = {fn_str_fetch8}({v_ctx}), s2 = {fn_str_fetch8}({v_ctx}); {v_ctx}.str_regs[r] = {v_ctx}.str_regs[s1] + {v_ctx}.str_regs[s2]; break; }}"),
        (str_op_1b, f"{{ uint8_t r = {fn_str_fetch8}({v_ctx}), s1 = {fn_str_fetch8}({v_ctx}), s2 = {fn_str_fetch8}({v_ctx}); {v_ctx}.int_regs[r] = ({v_ctx}.str_regs[s1] == {v_ctx}.str_regs[s2]) ? 1 : 0; break; }}"),
        (str_op_1c, f"{{ uint8_t r = {fn_str_fetch8}({v_ctx}), s1 = {fn_str_fetch8}({v_ctx}), s2 = {fn_str_fetch8}({v_ctx}); {v_ctx}.int_regs[r] = ({v_ctx}.str_regs[s1] != {v_ctx}.str_regs[s2]) ? 1 : 0; break; }}"),
        (str_op_1d, f"{{ uint8_t r = {fn_str_fetch8}({v_ctx}); *{v_ret_str} = {v_ctx}.str_regs[r]; *{v_has_returned} = true; return; }}"),
        (str_op_1e, f"{{ uint8_t r = {fn_str_fetch8}({v_ctx}); if (out_int_result) *out_int_result = {v_ctx}.int_regs[r]; *{v_ret_str} = \"\"; *{v_has_returned} = true; return; }}"),
    ]

    str_lo_cases = []
    str_hi_cases = []
    for target_op, body in str_op_bodies:
        case_line = f"            case 0x{target_op:02x}: {body}"
        if target_op < str_split_threshold:
            str_lo_cases.append(case_line)
        else:
            str_hi_cases.append(case_line)

    str_lo_cases_str = "\n".join(str_lo_cases)
    str_hi_cases_str = "\n".join(str_hi_cases)

    return f"""\
// ============================================================
// Embedded VM runtime (auto-generated, obfuscated)
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

inline bool {fn_anti_debug}() {{
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

inline bool& {fn_debugger_flag}() {{
    static bool {v_detected} = {fn_anti_debug}();
    return {v_detected};
}}

static const int MAX_CALL_DEPTH = 32;
struct CallFrame {{
    int64_t regs[16];
    int saved_frame_base;
    size_t return_pc;
    uint8_t dst_reg;
    int64_t saved_args_buf[4];
}};

struct VMContext {{
    int64_t regs[16] = {{0}};
    int64_t mem[256] = {{0}};
    int frame_base = 0;
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

inline uint8_t {fn_fetch8}(VMContext& {v_ctx}) {{ return {v_ctx}.bytecode[{v_ctx}.pc++]; }}
inline uint16_t {fn_fetch16}(VMContext& {v_ctx}) {{
    uint16_t lo = {fn_fetch8}({v_ctx}), hi = {fn_fetch8}({v_ctx});
    return static_cast<uint16_t>(lo | (hi << 8));
}}
inline int64_t {fn_fetch64}(VMContext& {v_ctx}) {{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t){v_ctx}.bytecode[{v_ctx}.pc + i] << (8 * i);
    {v_ctx}.pc += 8;
    int64_t r; __builtin_memcpy(&r, &v, 8);
    return r;
}}

inline uint32_t {fn_fnv}(const uint8_t* data, size_t len) {{
    uint32_t hash = 0x811c9dc5u;
    for (size_t i = 0; i < len; i++) {{
        hash ^= data[i];
        hash *= 0x01000193u;
    }}
    return hash;
}}

inline void {fn_dispatch_lo}(VMContext& {v_ctx}, uint8_t op, int64_t* {v_ret_val}, bool* {v_has_returned}) {{
    switch (op) {{
{lo_cases_str}
        default:
            *{v_ret_val} = 0;
            *{v_has_returned} = true;
            return;
    }}
}}

inline void {fn_dispatch_hi}(VMContext& {v_ctx}, uint8_t op, int64_t* {v_ret_val}, bool* {v_has_returned}) {{
    switch (op) {{
{hi_cases_str}
        default:
            *{v_ret_val} = 0;
            *{v_has_returned} = true;
            return;
    }}
}}

inline int64_t run(const uint8_t* bytecode, size_t len, const int64_t* args, int argc, size_t entry_pc = 0, uint32_t expected_checksum = 0) {{
    if ({fn_debugger_flag}()) {{
        return 0;
    }}
    if (expected_checksum != 0 && {fn_fnv}(bytecode, len) != expected_checksum) {{
        return 0;
    }}
    VMContext {v_ctx};
    {v_ctx}.bytecode = bytecode; {v_ctx}.bytecode_len = len; {v_ctx}.args = args; {v_ctx}.original_args = args; {v_ctx}.arg_count = argc; {v_ctx}.pc = entry_pc;
    while (true) {{
        uint8_t op = {fn_fetch8}({v_ctx});
        int64_t {v_ret_val} = 0;
        bool {v_has_returned} = false;
        if (op < 0x{split_threshold:02x}) {{
            {fn_dispatch_lo}({v_ctx}, op, &{v_ret_val}, &{v_has_returned});
        }} else {{
            {fn_dispatch_hi}({v_ctx}, op, &{v_ret_val}, &{v_has_returned});
        }}
        if ({v_has_returned}) return {v_ret_val};
    }}
}}

inline int64_t run_struct(const uint8_t* bytecode, size_t len, const int64_t* args, int argc, size_t entry_pc, uint32_t expected_checksum, int64_t* out_struct_buf, int out_count) {{
    if ({fn_debugger_flag}()) {{
        for (int i = 0; i < out_count; i++) out_struct_buf[i] = 0;
        return 0;
    }}
    if (expected_checksum != 0 && {fn_fnv}(bytecode, len) != expected_checksum) {{
        for (int i = 0; i < out_count; i++) out_struct_buf[i] = 0;
        return 0;
    }}
    VMContext {v_ctx};
    {v_ctx}.bytecode = bytecode; {v_ctx}.bytecode_len = len; {v_ctx}.args = args; {v_ctx}.original_args = args; {v_ctx}.arg_count = argc; {v_ctx}.pc = entry_pc; {v_ctx}.out_struct_buf = out_struct_buf;
    while (true) {{
        uint8_t op = {fn_fetch8}({v_ctx});
        int64_t {v_ret_val} = 0;
        bool {v_has_returned} = false;
        if (op < 0x{split_threshold:02x}) {{
            {fn_dispatch_lo}({v_ctx}, op, &{v_ret_val}, &{v_has_returned});
        }} else {{
            {fn_dispatch_hi}({v_ctx}, op, &{v_ret_val}, &{v_has_returned});
        }}
        if ({v_has_returned}) return {v_ret_val};
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

inline uint8_t {fn_str_fetch8}(StringVMContext& {v_ctx}) {{ return {v_ctx}.bytecode[{v_ctx}.pc++]; }}

inline void {fn_str_dispatch_lo}(StringVMContext& {v_ctx}, uint8_t op, std::string* {v_ret_str}, int64_t* out_int_result, bool* {v_has_returned}) {{
    switch (op) {{
{str_lo_cases_str}
        default:
            if (out_int_result) *out_int_result = 0;
            *{v_ret_str} = "";
            *{v_has_returned} = true;
            return;
    }}
}}

inline void {fn_str_dispatch_hi}(StringVMContext& {v_ctx}, uint8_t op, std::string* {v_ret_str}, int64_t* out_int_result, bool* {v_has_returned}) {{
    switch (op) {{
{str_hi_cases_str}
        default:
            if (out_int_result) *out_int_result = 0;
            *{v_ret_str} = "";
            *{v_has_returned} = true;
            return;
    }}
}}

inline std::string run_str(const uint8_t* bytecode, size_t len,
                           const std::string* str_args, int argc,
                           const std::string* const_pool, int pool_count,
                           int64_t* out_int_result = nullptr,
                           uint32_t expected_checksum = 0) {{
    if ({fn_debugger_flag}()) {{
        if (out_int_result) *out_int_result = 0;
        return "";
    }}
    if (expected_checksum != 0 && {fn_fnv}(bytecode, len) != expected_checksum) {{
        if (out_int_result) *out_int_result = 0;
        return "";
    }}
    StringVMContext {v_ctx};
    {v_ctx}.bytecode = bytecode; {v_ctx}.bytecode_len = len;
    {v_ctx}.str_args = str_args; {v_ctx}.str_arg_count = argc;
    {v_ctx}.const_pool = const_pool; {v_ctx}.const_pool_count = pool_count;

    while (true) {{
        uint8_t op = {fn_str_fetch8}({v_ctx});
        std::string {v_ret_str} = "";
        bool {v_has_returned} = false;
        if (op < 0x{str_split_threshold:02x}) {{
            {fn_str_dispatch_lo}({v_ctx}, op, &{v_ret_str}, out_int_result, &{v_has_returned});
        }} else {{
            {fn_str_dispatch_hi}({v_ctx}, op, &{v_ret_str}, out_int_result, &{v_has_returned});
        }}
        if ({v_has_returned}) return {v_ret_str};
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