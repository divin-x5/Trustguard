"""Make the trustguard root importable for tests (uvicorn-style flat layout)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
