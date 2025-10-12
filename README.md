<div align="center">
  <img src="assets/logo-aresprobe.png" alt="AresProbe Logo" width="400"/>
  
  # AresProbe
  ### Advanced Web Security Testing Framework
  
  [![GitHub](https://img.shields.io/badge/GitHub-g0dux%2FAresProbe-blue?logo=github)](https://github.com/g0dux/AresProbe)
  [![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
  [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
  
  **More powerful than Burp Suite + SQLMap combined**
  
  ---
</div>

## 📋 About The Project

AresProbe is an advanced web security testing tool that combines the functionalities of Burp Suite and SQLMap, but with greater efficiency and a powerful terminal interface. Developed for security professionals who need a complete and modular tool.

## 🚀 Key Features

### 🔍 Advanced Security Testing
- **SQL Injection**: Multiple techniques (Boolean-based, Time-based, Union-based, Error-based, Stacked queries)
- **XSS (Cross-Site Scripting)**: XSS vulnerability detection with advanced payloads
- **Directory Traversal**: Directory traversal vulnerability testing
- **Command Injection**: System command injection detection
- **XXE (XML External Entity)**: XXE vulnerability testing
- **SSRF (Server-Side Request Forgery)**: SSRF vulnerability detection

### 🌐 HTTP/HTTPS Proxy
- Real-time traffic interception
- Full HTTPS support with tunneling
- Request and response analysis
- Real-time traffic modification

### 📊 Detailed Reports
- Reports in multiple formats (JSON, HTML, TXT)
- Detailed vulnerability analysis
- Performance metrics and response time
- Data export for further analysis

### 🔧 Modular Interface
- Interactive and intuitive CLI
- Extensible plugin system
- Advanced session management
- Detailed logging with configurable levels

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Quick Installation

#### Windows (Recommended)
```bash
# Clone the repository
git clone https://github.com/g0dux/AresProbe.git
cd AresProbe

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
venv\Scripts\activate

# Automatic installation for Windows
python install_windows.py

# Or manual installation
pip install -r requirements-windows.txt

# Run AresProbe
python main.py
```

#### Linux/Mac
```bash
# Clone the repository
git clone https://github.com/g0dux/AresProbe.git
cd AresProbe

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run AresProbe
python main.py
```

### Windows Troubleshooting

If you encounter issues with `uvloop` on Windows:
- Use `requirements-windows.txt` instead of `requirements.txt`
- Run `python install_windows.py` for automatic installation
- `uvloop` is not compatible with Windows, but AresProbe works perfectly without it

## 🎯 Quick Usage

### Interactive Mode
```bash
python main.py
```

### Quick Scan
```bash
python main.py --scan http://example.com
```

### Proxy Server
```bash
python main.py --proxy 8080
```

## 📖 Main Commands

### Security Scan
```bash
# Comprehensive scan
scan http://example.com --type comprehensive

# SQL Injection specific scan
scan http://example.com --type sql

# Scan with proxy enabled
scan http://example.com --proxy --threads 20
```

### Proxy Management
```bash
# Start proxy
proxy start 8080

# Check status
proxy status

# View intercepted requests
proxy requests

# Clear intercepted data
proxy clear
```

### Reports
```bash
# Generate report
report generate

# Show latest results
report show

# Export in different formats
report export json
report export html
```

## 🔧 Advanced Configuration

### Environment Variables
```bash
# Configure log level
export ARESPROBE_LOG_LEVEL=DEBUG

# Configure default timeout
export ARESPROBE_TIMEOUT=60

# Configure number of threads
export ARESPROBE_THREADS=20
```

### Configuration File
Create a `config.json` file in the project root:
```json
{
    "default_timeout": 30,
    "default_threads": 10,
    "proxy_port": 8080,
    "log_level": "INFO",
    "user_agent": "AresProbe/1.0",
    "verify_ssl": false
}
```

## 🛡️ Security Features

### Implemented Protections
- Strict input validation
- Malicious payload sanitization
- Rate limiting to prevent overload
- Logging of all operations
- Permission verification

### Best Practices
- Use only in authorized environments
- Keep logs of all operations
- Regularly update dependencies
- Monitor resource usage

## 📚 Documentation

### Project Structure
```
aresprobe/
├── core/           # Core modules
│   ├── engine.py   # Main engine
│   ├── proxy.py    # Proxy server
│   ├── scanner.py  # Vulnerability scanner
│   ├── sql_injector.py  # SQL injection engine
│   ├── session.py  # Session manager
│   └── logger.py   # Logging system
├── cli/            # Command line interface
│   ├── interface.py # Main CLI
│   └── commands.py  # Command implementation
└── plugins/        # Plugin system
```

### Development API
```python
from aresprobe import AresEngine, ScanConfig, ScanType

# Initialize engine
engine = AresEngine()
engine.initialize()

# Configure scan
config = ScanConfig(
    target_url="http://example.com",
    scan_types=[ScanType.SQL_INJECTION, ScanType.XSS],
    threads=10,
    timeout=30
)

# Execute scan
results = engine.run_scan(config)

# Generate report
report = engine.generate_report("report.html")
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the project
2. Create a branch for your feature (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal Disclaimer

This tool is intended for authorized security testing only. Unauthorized use is strictly prohibited and may violate local and international laws. The developers are not responsible for misuse of this tool.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/g0dux/AresProbe/issues)
- **Documentation**: [Wiki](https://github.com/g0dux/AresProbe/wiki)
- **Discord**: [Community Server](https://discord.gg/aresprobe)

## 🏆 Acknowledgments

- Inspired by Burp Suite and SQLMap
- Open source security community
- Contributors and testers

---

**AresProbe** - More powerful than Burp Suite + SQLMap, with the efficiency you need.
