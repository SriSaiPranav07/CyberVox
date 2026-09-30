"""
Backend Server Launcher for SIH 2026.
Starts Uvicorn server on configured host and port.
"""

import sys
import os
import uvicorn

# Ensure backend root is in python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.config import settings

if __name__ == "__main__":
    print(f"[*] Starting {settings.APP_NAME} v{settings.VERSION}")
    print(f"[*] Enclave Mode: READ-ONLY INGEST | ZERO RETURN PATH")
    print(f"[*] Server listening on http://{settings.HOST}:{settings.PORT}")
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=False, log_level="info")
