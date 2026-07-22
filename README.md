# cpp-vm-obfuscator

A web tool that takes pasted C++ code and produces a VM-obfuscated version,
similar to how obfuscator.io works for JavaScript.

Status: in progress — core pipeline built (Flask + Clang-based parsing +
custom VM bytecode generation), currently debugging a macOS-specific
libclang header resolution issue.

## Structure
- `backend/` - Flask server, Clang-based codegen pipeline, bytecode generation
- `frontend/` - paste-code UI

## Setup
```bash
cd backend
pip install -r requirements.txt
python3 app.py
```
EOF