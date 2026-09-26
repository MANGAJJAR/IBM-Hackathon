"""
BobPulse Entrypoint Runner.
Starts the FastAPI application server on http://localhost:8000.
"""

import sys
import os

# Set UTF-8 encoding for Windows standard output
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import uvicorn

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("=" * 60)
    print("  [*] Starting BobPulse Studio (Powered by IBM Bob 2.0)")
    print("  [*] Access Dashboard: http://localhost:8000")
    print("  [*] API Docs:         http://localhost:8000/docs")
    print("=" * 60)
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=False)
