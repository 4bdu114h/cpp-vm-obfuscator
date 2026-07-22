"""
app.py
Flask backend for the C++ obfuscator website. Wraps codegen.obfuscate()
(tested and working, see test_correctness.py) behind a simple HTTP API.
"""
import os
import clang.cindex as ci

# The exact path differs by OS/install method; this list covers the
# common Linux and macOS (Homebrew) locations. install.sh / the setup
# instructions print the right one to hardcode here if autodetect fails.
_CANDIDATE_LIBCLANG_PATHS = [
    "/usr/lib/x86_64-linux-gnu/libclang-18.so.1",
    "/usr/lib/llvm-18/lib/libclang.so",
    "/opt/homebrew/opt/llvm/lib/libclang.dylib",
    "/usr/local/opt/llvm/lib/libclang.dylib",
    "/Library/Developer/CommandLineTools/usr/lib/libclang.dylib",
]

_lib_set = False
for _p in _CANDIDATE_LIBCLANG_PATHS:
    if os.path.exists(_p):
        ci.Config.set_library_file(_p)
        _lib_set = True
        break
if not _lib_set:
    print("WARNING: could not auto-locate libclang. Set LIBCLANG_PATH env var.")
    env_path = os.environ.get("LIBCLANG_PATH")
    if env_path:
        ci.Config.set_library_file(env_path)

from flask import Flask, request, jsonify
from codegen import obfuscate

app = Flask(__name__)


@app.route("/")
def index():
    with open(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")) as f:
        return f.read()


@app.route("/obfuscate", methods=["POST"])
def obfuscate_endpoint():
    data = request.get_json(force=True)
    source = data.get("code", "")
    if not source.strip():
        return jsonify({"error": "No code provided"}), 400

    try:
        final_code, report, diag_errors = obfuscate(source, "/tmp/web_input.cpp")
    except Exception as e:
        return jsonify({"error": f"Internal error: {e}"}), 500

    return jsonify({
        "obfuscated_code": final_code,
        "report": report,
        "parse_warnings": diag_errors,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)
