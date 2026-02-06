#!/usr/bin/env python3
"""
API Security Tester - Automated Setup and Launch Script
Handles complete setup and startup of both backend and frontend services
"""

import os
import sys
import subprocess
import time
import webbrowser
import threading
from pathlib import Path

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                    API Security Tester                       ║
║           Comprehensive API Vulnerability Scanner            ║
║                                                               ║
║  🔒 OWASP API Top 10 Testing                                ║
║  🚀 Real-time WebSocket Monitoring                          ║
║  📊 Executive & Technical Reports                           ║
║  🛡️ Multi-format Export (JSON/CSV/XML/PDF)                 ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}
    """)

def log(message, level="INFO"):
    colors = {
        "INFO": Colors.BLUE,
        "SUCCESS": Colors.GREEN, 
        "WARNING": Colors.YELLOW,
        "ERROR": Colors.RED
    }
    print(f"{colors.get(level, '')}{Colors.BOLD}[{level}]{Colors.END} {message}")

def run_command(command, cwd=None, shell=True, capture_output=False):
    """Run a command and return the result"""
    try:
        if capture_output:
            result = subprocess.run(command, cwd=cwd, shell=shell, capture_output=True, text=True)
            return result.returncode == 0, result.stdout, result.stderr
        else:
            result = subprocess.run(command, cwd=cwd, shell=shell)
            return result.returncode == 0, "", ""
    except Exception as e:
        return False, "", str(e)

def check_python():
    """Check if Python 3.9+ is available"""
    log("Checking Python version...")
    try:
        result = subprocess.run([sys.executable, "--version"], capture_output=True, text=True)
        version = result.stdout.strip().split()[1]
        major, minor = map(int, version.split(".")[:2])
        
        if major >= 3 and minor >= 9:
            log(f"Python {version} detected ✓", "SUCCESS")
            return True
        else:
            log(f"Python {version} found, but 3.9+ is required", "ERROR")
            return False
    except Exception as e:
        log(f"Failed to check Python version: {e}", "ERROR")
        return False

def check_node():
    """Check if Node.js is available"""
    log("Checking Node.js availability...")
    success, stdout, _ = run_command("node --version", capture_output=True)
    
    if success:
        version = stdout.strip()
        log(f"Node.js {version} detected ✓", "SUCCESS")
        return True
    else:
        log("Node.js not found. Please install Node.js 16+ from https://nodejs.org/", "WARNING")
        return False

def setup_backend():
    """Setup Python backend environment and dependencies"""
    backend_dir = Path(__file__).parent / "backend"
    venv_dir = backend_dir / "venv"
    
    log("Setting up Python backend environment...")
    
    # Create virtual environment if it doesn't exist
    if not venv_dir.exists():
        log("Creating Python virtual environment...")
        success, _, error = run_command([sys.executable, "-m", "venv", "venv"], cwd=backend_dir)
        if not success:
            log(f"Failed to create virtual environment: {error}", "ERROR")
            return False
        log("Virtual environment created ✓", "SUCCESS")
    else:
        log("Virtual environment already exists ✓", "SUCCESS")
    
    # Determine activation script path
    if os.name == 'nt':  # Windows
        activate_script = venv_dir / "Scripts" / "activate.bat"
        pip_path = venv_dir / "Scripts" / "pip.exe"
        python_path = venv_dir / "Scripts" / "python.exe"
    else:  # Unix-like
        activate_script = venv_dir / "bin" / "activate"
        pip_path = venv_dir / "bin" / "pip"
        python_path = venv_dir / "bin" / "python"
    
    # Install Python dependencies
    log("Installing Python dependencies...")
    requirements_file = backend_dir / "requirements.txt"
    
    if requirements_file.exists():
        success, _, error = run_command([str(pip_path), "install", "-r", "requirements.txt"], cwd=backend_dir)
        if not success:
            log(f"Failed to install Python dependencies: {error}", "ERROR")
            # Try installing core dependencies individually
            log("Attempting to install core dependencies individually...")
            core_deps = [
                "fastapi[standard]==0.115.6",
                "uvicorn[standard]==0.32.1", 
                "pydantic==2.10.4",
                "sqlalchemy==2.0.36",
                "requests==2.32.3",
                "pyyaml==6.0.2"
            ]
            
            for dep in core_deps:
                log(f"Installing {dep.split('==')[0]}...")
                success, _, _ = run_command([str(pip_path), "install", dep], cwd=backend_dir)
                if not success:
                    log(f"Failed to install {dep}", "WARNING")
        else:
            log("Python dependencies installed ✓", "SUCCESS")
    else:
        log("requirements.txt not found, installing core dependencies...", "WARNING")
        # Install minimal dependencies to get started
        core_deps = [
            "fastapi[standard]",
            "uvicorn[standard]", 
            "pydantic",
            "sqlalchemy",
            "requests",
            "pyyaml"
        ]
        
        for dep in core_deps:
            log(f"Installing {dep}...")
            run_command([str(pip_path), "install", dep], cwd=backend_dir)
    
    return True

def setup_frontend():
    """Setup React frontend environment and dependencies"""
    frontend_dir = Path(__file__).parent / "frontend"
    
    if not check_node():
        log("Skipping frontend setup due to missing Node.js", "WARNING")
        return False
    
    log("Setting up React frontend environment...")
    
    # Install npm dependencies
    package_json = frontend_dir / "package.json"
    
    if package_json.exists():
        log("Installing npm dependencies...")
        success, _, error = run_command("npm install", cwd=frontend_dir)
        if not success:
            log(f"npm install failed: {error}", "ERROR")
            # Try with yarn as fallback
            log("Trying with yarn as fallback...")
            success, _, error = run_command("yarn install", cwd=frontend_dir)
            if not success:
                log(f"yarn install also failed: {error}", "ERROR")
                return False
        
        log("Frontend dependencies installed ✓", "SUCCESS")
        return True
    else:
        log("package.json not found in frontend directory", "ERROR")
        return False

def start_backend():
    """Start the FastAPI backend server"""
    backend_dir = Path(__file__).parent / "backend"
    venv_dir = backend_dir / "venv"
    
    if os.name == 'nt':  # Windows
        python_path = venv_dir / "Scripts" / "python.exe"
    else:  # Unix-like
        python_path = venv_dir / "bin" / "python"
    
    log("Starting FastAPI backend server on http://127.0.0.1:8000...")
    
    # Start uvicorn server using simplified app.py entry point
    backend_cmd = [
        str(python_path), "-m", "uvicorn", 
        "app:app",  # Use simplified app.py entry point
        "--host", "127.0.0.1",
        "--port", "8000", 
        "--reload"
    ]
    
    process = subprocess.Popen(
        backend_cmd,
        cwd=backend_dir  # Run from backend directory to find app.py
    )
    
    return process

def start_frontend():
    """Start the React frontend development server"""
    frontend_dir = Path(__file__).parent / "frontend"
    
    if not check_node():
        log("Cannot start frontend without Node.js", "ERROR")
        return None
    
    log("Starting React frontend development server on http://localhost:3000...")
    
    # Start React development server with explicit shell=True on Windows
    import platform
    shell_flag = platform.system() == "Windows"
    
    process = subprocess.Popen(
        ["npm", "start"],
        cwd=frontend_dir,
        shell=shell_flag
    )
    
    return process

def wait_for_server(url, timeout=30):
    """Wait for a server to become available"""
    import urllib.request
    import urllib.error
    
    for i in range(timeout):
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(1)
    
    return False

def open_browser():
    """Open the application in the default web browser"""
    log("Waiting for servers to start...")
    time.sleep(3)
    
    # Check if frontend is running
    if wait_for_server("http://localhost:3000", timeout=15):
        log("Frontend server is running ✓", "SUCCESS")
        log("Opening application in web browser...", "INFO")
        webbrowser.open("http://localhost:3000")
    else:
        log("Frontend server may not be ready", "WARNING")
        log("You can manually open http://localhost:3000 in your browser", "INFO")

def main():
    """Main setup and launch function"""
    print_banner()
    
    # Clear Python bytecode cache to avoid import issues
    backend_src = Path(__file__).parent / "backend" / "src"
    if backend_src.exists():
        log("Clearing Python bytecode cache...", "INFO")
        import shutil
        for pycache in backend_src.rglob("__pycache__"):
            shutil.rmtree(pycache, ignore_errors=True)
        for pyc in backend_src.rglob("*.pyc"):
            pyc.unlink(missing_ok=True)
    
    # Check prerequisites
    if not check_python():
        log("Python 3.9+ is required. Please install Python and try again.", "ERROR")
        return False
    
    # Setup backend
    if not setup_backend():
        log("Backend setup failed", "ERROR")
        return False
    
    # Setup frontend
    frontend_available = setup_frontend()
    
    # Start services
    log("Starting application services...", "INFO")
    
    try:
        # Start backend
        backend_process = start_backend()
        time.sleep(2)  # Give backend time to start
        
        # Start frontend if available
        frontend_process = None
        if frontend_available:
            frontend_process = start_frontend()
        
        # Open browser after a delay
        browser_thread = threading.Thread(target=open_browser)
        browser_thread.daemon = True
        browser_thread.start()
        
        # Print running information
        print(f"""
{Colors.GREEN}{Colors.BOLD}
🚀 API Security Tester is now running!

📊 Backend API: http://127.0.0.1:8000
📚 API Docs: http://127.0.0.1:8000/docs
🖥️  Frontend: http://localhost:3000

Press Ctrl+C to stop all services
{Colors.END}
        """)
        
        # Wait for processes
        try:
            if frontend_process:
                frontend_process.wait()
            else:
                backend_process.wait()
        except KeyboardInterrupt:
            log("Shutting down services...", "INFO")
            
            # Terminate processes
            if backend_process:
                backend_process.terminate()
            if frontend_process:
                frontend_process.terminate()
            
            log("Services stopped ✓", "SUCCESS")
            
    except Exception as e:
        log(f"Error starting services: {e}", "ERROR")
        return False
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        log("Setup interrupted by user", "WARNING")
        sys.exit(1)
    except Exception as e:
        log(f"Unexpected error: {e}", "ERROR")
        sys.exit(1)