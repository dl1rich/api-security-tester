#!/usr/bin/env python3
"""
Entry point for the FastAPI backend server.
This file provides a simpler import path for uvicorn.
"""

import sys
import os

# Add src directory to Python path
backend_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(backend_dir, 'src')
sys.path.insert(0, src_dir)

from api.main import create_app

# Create FastAPI application instance
app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )