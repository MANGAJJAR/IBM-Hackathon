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

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import uvicorn

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    apikey = os.getenv("IBM_WATSONX_APIKEY") or os.getenv("WATSONX_APIKEY")
    granite_mode = "ONLINE (Live Granite 20B API)" if apikey else "STANDBY (Rule engine fallback - set IBM_WATSONX_APIKEY in .env)"
    print("=" * 60)
    print("  [*] Starting BobPulse Studio (Powered by IBM Bob 2.0)")
    print("  [*] Access Dashboard: http://localhost:8000")
    print("  [*] API Docs:         http://localhost:8000/docs")
    print(f"  [*] watsonx Granite:  {granite_mode}")
    print("=" * 60)
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=False)
