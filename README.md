# API Security Tester 🔒

A comprehensive, professional-grade API security testing tool designed for penetration testers and security professionals. Supports all OpenAPI/Swagger versions with real-time vulnerability detection and executive reporting.

## 🚀 Quick Start (Fully Automated)

### Windows
```bash
# Simply double-click or run:
start.bat
```

### Linux/macOS
```bash
# Make executable and run:
chmod +x start.sh
./start.sh
```

### Cross-Platform Python
```bash
# Direct Python execution:
python start.py
```

**That's it!** The automated setup will:
- ✅ Check system prerequisites (Python 3.9+, Node.js)
- ✅ Create Python virtual environment
- ✅ Install all backend dependencies
- ✅ Setup React frontend environment  
- ✅ Start backend API server (http://127.0.0.1:8000)
- ✅ Start frontend development server (http://localhost:3000)
- ✅ Open your browser automatically
- ✅ Display all service URLs and documentation links

## 🛡️ Features Overview

### Core Capabilities
- **Multi-Version OpenAPI Support**: OpenAPI 3.0.x, 3.1.x, Swagger 2.0, 1.2
- **OWASP API Top 10 (2023)**: Complete coverage of all 10 categories
- **Real-time Testing**: WebSocket-powered live vulnerability discovery
- **Smart Authentication**: Preserves user roles during security testing
- **Executive Reporting**: Business-focused risk assessments and technical details
- ⚡ **Real-time Progress** - WebSocket-based live testing updates
- 📊 **Professional Reporting** - Multiple export formats for client delivery
- 🔒 **Role-Based Testing** - Test endpoints with different privilege levels
- 🚀 **Async Testing** - Efficient concurrent vulnerability scanning

## Quick Start

### Backend Setup

```bash
# Install Poetry (if not already installed)
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
cd backend
poetry install

# Run development server
poetry run uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup

```bash
cd frontend
npm install
npm start
```

## Architecture

```
api-security-tester/
├── backend/                 # Python FastAPI backend
│   ├── src/
│   │   ├── api/            # FastAPI routes and WebSocket handlers
│   │   ├── auth/           # Authentication handling and role management
│   │   ├── parser/         # OpenAPI/Swagger specification parsing
│   │   ├── testing/        # Vulnerability testing modules
│   │   ├── data/           # Test data generation
│   │   ├── reporting/      # Report generation and export
│   │   └── utils/          # Utility functions
│   └── tests/              # Backend unit and integration tests
├── frontend/               # React TypeScript frontend
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── pages/          # Main application pages
│   │   ├── services/       # API communication
│   │   └── types/          # TypeScript type definitions
│   └── public/             # Static assets
└── docs/                   # Documentation
```

## Security Testing Coverage

### OWASP API Security Top 10 (2023)
- ✅ API1: Broken Object Level Authorization (BOLA/IDOR)
- ✅ API2: Broken Authentication
- ✅ API3: Broken Object Property Level Authorization
- ✅ API4: Unrestricted Resource Consumption
- ✅ API5: Broken Function Level Authorization
- ✅ API6: Unrestricted Access to Sensitive Business Flows
- ✅ API7: Server Side Request Forgery (SSRF)
- ✅ API8: Security Misconfiguration
- ✅ API9: Improper Inventory Management
- ✅ API10: Unsafe Consumption of APIs

### Additional Security Tests
- SQL/NoSQL Injection
- Cross-Site Scripting (XSS)
- Command Injection (OS Command Execution)
- Path Traversal / Local File Inclusion
- LDAP Injection
- XML External Entity (XXE)
- Remote Code Execution (RCE)
- Insecure Deserialization
- CORS Misconfiguration
- Open Redirect
- Business Logic Flaws
- Rate Limiting Bypass

## 🆕 Enhanced Features

### Comprehensive Vulnerability Detection
This tool now includes **25+ vulnerability detectors** covering:
- All OWASP API Top 10 (2023) categories
- Common injection vulnerabilities (SQL, NoSQL, Command, LDAP, XXE)
- Advanced attack vectors (RCE, Deserialization, CORS)
- File system vulnerabilities (Path Traversal, LFI)

### Detailed Statistics for Pentesters
- ⏱️ **Timing Metrics**: Average time per endpoint and test type
- 📊 **Vulnerability Density**: Vulnerabilities per endpoint ratio
- 🎯 **Risk Scoring**: Risk scores for each endpoint
- 📈 **Testing Efficiency**: Endpoints/minute, tests/second

### Pentester Guidance
For each vulnerability type, get:
- **What to look for**: Specific indicators and patterns
- **Exploitation steps**: Step-by-step manual testing guide
- **Tool recommendations**: Best tools for each vulnerability
- **Severity assessment**: How to determine impact level

See [ENHANCEMENTS.md](ENHANCEMENTS.md) for complete documentation.

## Usage

1. **Upload API Specification**: Drag and drop your OpenAPI/Swagger file or enter a URL
2. **Configure Testing**: Select test modules and authentication handling
3. **Start Testing**: Watch real-time progress as vulnerabilities are discovered
4. **Review Results**: Interactive reports with detailed findings and recommendations
5. **Export Reports**: Generate professional reports for clients

## Legal and Ethical Use

⚠️ **IMPORTANT**: This tool is designed for authorized security testing only. Users must:
- Obtain proper authorization before testing any API
- Comply with applicable laws and regulations
- Use responsibly and ethically
- Not use against systems without explicit permission

## Contributing

This is a professional security testing tool. Please ensure all contributions maintain the highest security and code quality standards.

## License

[Insert appropriate license here - consider MIT or Apache 2.0 for open source]