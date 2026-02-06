#!/bin/bash
# API Security Tester - Unix/Linux/macOS Startup Script
# This script automatically sets up and starts the entire application

set -e  # Exit on any error

echo ""
echo "========================================"
echo "   API Security Tester - Auto Setup   "
echo "========================================"
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed or not in PATH"
    echo "Please install Python 3.9+ and try again"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.9"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "ERROR: Python $PYTHON_VERSION found, but $REQUIRED_VERSION+ is required"
    exit 1
fi

# Make the script executable
chmod +x start.py

# Run the Python setup script
echo "Starting automated setup and launch..."
echo ""
python3 start.py
