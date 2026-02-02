# SSRF-Detection-Tool

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)

![License](https://img.shields.io/badge/license-MIT-green.svg)

![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg)

![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen.svg)

**A Professional Server-Side Request Forgery (SSRF) Detection Tool for Bug Bounty Hunters and Security Researchers**

</div>

---

## 🎯 Overview

SSRF Detection Tool is a comprehensive, GUI-based security testing application designed specifically for identifying Server-Side Request Forgery vulnerabilities in web applications. Built with bug bounty hunters and penetration testers in mind, it combines multiple detection techniques, bypass methods, and a built-in callback server infrastructure.

### Why This Tool?

- **All-in-One Solution**: Combines payload generation, testing, and callback server in a single application
- **Real-World Tested**: Payloads based on actual bug bounty findings and OWASP guidelines
- **User-Friendly**: Intuitive GUI with hacker-themed interface
- **Comprehensive**: Covers basic SSRF, blind SSRF, protocol smuggling, and cloud metadata exploitation
- **Extensible**: Easy to add custom payloads and detection methods

---

## ✨ Features

### 🔍 Detection Capabilities

- **Basic SSRF Detection**: Standard callback-based detection with DNS/HTTP monitoring
- **Blind SSRF Detection**: Time-based analysis and out-of-band detection
- **Partial Response Reading**: Analysis of response headers and timing
- **Protocol Smuggling**: Testing for `file://`, `gopher://`, `dict://`, `ftp://`, `ldap://`, and more
- **Cloud Metadata Exploitation**: Automated testing against AWS, GCP, Azure, and other cloud providers

### 🎯 Bypass Techniques

- **IP Encoding Variations**:
    - Decimal notation (2130706433)
    - Octal notation (0177.0.0.1)
    - Hexadecimal notation (0x7f000001)
    - IPv6 variations (::1, ::ffff:127.0.0.1)
    - Mixed encoding formats
- **URL Parser Exploits**:
    - URL encoding bypass
    - Double encoding
    - CRLF injection
    - Null byte injection
    - Backslash confusion
    - @ symbol tricks
- **Redirect-Based Bypass**: Testing for open redirect + SSRF chains

### ☁️ Cloud Metadata Endpoints

Pre-configured payloads for:

- **AWS**: EC2 metadata (169.254.169.254)
- **Google Cloud**: Metadata server
- **Azure**: Instance metadata service
- **DigitalOcean**: Metadata API
- **Alibaba Cloud**: Metadata endpoints
- **Oracle Cloud**: Instance metadata

### 🌐 Internal Network Discovery

- Port scanning via SSRF
- Common internal IP range testing (192.168.x.x, 10.x.x.x, 172.16.x.x)
- Service fingerprinting
- Response time analysis
- Common internal service detection

### 🖥️ Callback Infrastructure

- **HTTP/HTTPS Callback Server**: Built-in threaded server
- **DNS Callback Support**: Detect DNS-only SSRF
- **Unique Token Tracking**: Per-payload tracking system
- **Comprehensive Logging**: Timestamp, IP, headers, and body capture
- **Real-Time Monitoring**: Live callback detection in GUI

### 🎨 User Interface

- **Hacker-Themed GUI**: Professional dark theme with neon accents
- **Real-Time Progress**: Live scan progress and status updates
- **Multi-Tab Results**: Separate views for results, callbacks, and payloads
- **Export Functionality**: Save results in TXT or JSON format
- **Detailed Logging**: Color-coded log levels for easy analysis

---

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)
- Internet connection (for external callback testing)

### Quick Install

```bash
# Clone the repository
git clone <https://github.com/yourusername/ssrf-detection-tool.git>

# Navigate to the directory
cd ssrf-detection-tool

# Install required dependencies
pip install -r requirements.txt

# Run the tool
python ssrf_detector.py

```

### Manual Installation

```bash
# Install individual packages
pip install requests urllib3 tkinter

```

---

## 📖 Usage

### Basic Usage

1. **Launch the Application**
    
    ```bash
    python ssrf_detector.py
    
    ```
    
2. **Configure Callback Server**
    - Enter your public IP or domain in the "Callback Server" section
    - Set the port (default: 8888)
    - Click "Start Server"
3. **Set Target URL**
    - Enter the target web application URL
    - Example: `https://example.com/api/fetch`
4. **Select Attack Vectors**
    - Choose payload types (Basic SSRF, Cloud Metadata, etc.)
    - Select HTTP methods (GET, POST)
5. **Start Scanning**
    - Click "START SCAN"
    - Monitor results in real-time
    - Check the "Callbacks" tab for out-of-band hits
6. **Export Results**
    - Click "Export Results" to save findings
    - Choose format (TXT or JSON)

### Advanced Usage

### Custom Payload Testing

```python
# Modify the payload generator in the code
payloads = [
    "<http://internal-api.company.local/admin>",
    "<http://192.168.1.100:8080/config>",
    "file:///var/www/html/config.php"
]

```

### Callback Server on External VPS

1. Set up a VPS with public IP
2. Open firewall port (e.g., 8888)
3. Enter VPS IP in the callback configuration
4. Start server and begin testing

### Blind SSRF Detection

- Enable all payload types
- Monitor response times (>5 seconds may indicate interaction)
- Check callback server logs for DNS/HTTP requests

---

## 🔬 Detection Capabilities

### 1. Basic SSRF Detection

**Method**: Direct HTTP callback

```
Target: <https://example.com/fetch?url=http://attacker.com/callback>
Result: HTTP request received on callback server

```

### 2. Blind SSRF Detection

**Method**: Timing analysis + out-of-band detection

```
- Response time > 5 seconds
- DNS query to callback domain
- No direct HTTP response

```

### 3. Protocol Smuggling

**Protocols Tested**:

- `file://` - Local file access
- `gopher://` - Protocol smuggling
- `dict://` - Dictionary protocol
- `ftp://` - File transfer
- `ldap://` - Directory access
- `tftp://` - Trivial FTP
- `smb://` - Server Message Block

### 4. Cloud Metadata Exploitation

**Detection Indicators**:

- Response contains: `ami-id`, `instance-id`, `access_token`
- Cloud-specific headers
- JSON metadata structures

### 5. Internal Network Scanning

**Techniques**:

- Port scanning (80, 443, 8080, 22, 3306)
- Service fingerprinting
- Response analysis
- Timing correlation

---

## 💉 Payload Types

### IP Encoding Variations

```
127.0.0.1           # Standard
2130706433          # Decimal
0x7f000001          # Hexadecimal
0177.0.0.1          # Octal
::1                 # IPv6 localhost
::ffff:127.0.0.1    # IPv6-mapped IPv4

```

### URL Parser Bypass

```
<http://evil.com@internal.local>
<http://internal.local#@evil.com>
<http://internal.local%00@evil.com>
<http://internal.local%0d%0a@evil.com>

```

### Cloud Metadata

```
<http://169.254.169.254/latest/meta-data/>
<http://metadata.google.internal/computeMetadata/v1/>
<http://169.254.169.254/metadata/instance?api-version=2021-02-01>

```

### Protocol Smuggling

```
file:///etc/passwd
gopher://internal:25/_MAIL%20FROM:attacker
dict://internal:11211/stat

```

---

## 📸 Screenshots

### Main Interface

```
┌─────────────────────────────────────────────────────────────┐
│              ⚡ SSRF DETECTION TOOL ⚡                       │
│     Server-Side Request Forgery Vulnerability Scanner       │
├─────────────────────┬───────────────────────────────────────┤
│  ⚙ CONFIGURATION    │     📊 RESULTS & LOGS                 │
│                     │                                       │
│  Target URL:        │  [Scan Results] [Callbacks] [Payloads]│
│  [_______________]  │                                       │
│                     │  [🚨 VULNERABILITY FOUND!]            │
│  Callback Server:   │  Target: <https://example.com>          │
│  IP: [__________]   │  Payload: <http://169.254.169.254>      │
│  Port: [8888]       │  Evidence: Cloud metadata detected    │
│                     │                                       │
│  [▶ Start Server]   │                                       │
│                     │                                       │
│  Attack Vectors:    │                                       │
│  ☑ Basic SSRF       │                                       │
│  ☑ Cloud Metadata   │                                       │
│  ☑ Protocol Smug.   │                                       │
│                     │                                       │
│  [🚀 START SCAN]    │  [📄 Export] [🗑 Clear]              │
│  [████████░░] 80%   │                                       │
└─────────────────────┴───────────────────────────────────────┘
 Ready | Vulnerabilities: 3

```

---

### Detection Logic Flow

```
1. Payload Generation
   ↓
2. HTTP Request Injection
   ↓
3. Response Analysis
   ├── Status Code Check
   ├── Content Analysis
   ├── Timing Analysis
   └── Header Inspection
   ↓
4. Callback Monitoring
   ↓
5. Vulnerability Reporting

```

---

## ⚙️ Configuration

### Environment Variables

```bash
# Optional: Set default callback server
export SSRF_CALLBACK_HOST="your-vps-ip.com"
export SSRF_CALLBACK_PORT="8888"

# Optional: Set request timeout
export SSRF_TIMEOUT="10"

```

### Custom Configuration File

Create `config.json`:

```json
{
  "callback_host": "your-server.com",
  "callback_port": 8888,
  "timeout": 10,
  "max_threads": 5,
  "custom_payloads": [
    "<http://internal-service.local/admin>",
    "file:///etc/shadow"
  ],
  "exclude_protocols": ["ftp", "smb"]
}

```

## ⚖️ Legal Disclaimer

```
╔══════════════════════════════════════════════════════════════╗
║                    ⚠️  LEGAL NOTICE ⚠️                       ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  This tool is provided for AUTHORIZED SECURITY TESTING ONLY  ║
║                                                              ║
║  • Only use on systems you own or have explicit written     ║
║    permission to test                                        ║
║                                                              ║
║  • Unauthorized access to computer systems is ILLEGAL        ║
║    under laws including CFAA (US), Computer Misuse Act (UK)  ║
║                                                              ║
║  • The authors assume NO LIABILITY for misuse or damage      ║
║                                                              ║
║  • You are RESPONSIBLE for compliance with all applicable    ║
║    laws and regulations                                      ║
║                                                              ║
║  By using this tool, you acknowledge that you understand     ║
║  and agree to use it legally and responsibly.                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

```

### Responsible Disclosure

If you discover vulnerabilities using this tool:

1. **Report to Program Owners**: Use bug bounty platforms or security contact
2. **Allow Time to Fix**: Give vendors reasonable time (typically 90 days)
3. **Don't Exploit**: Never use findings for malicious purposes
4. **Protect Data**: Don't access more data than necessary to prove vulnerability
5. **Follow Guidelines**: Adhere to responsible disclosure policies

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Reporting Bugs

```markdown
**Bug Report Template**

**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior.

**Expected behavior**
What you expected to happen.

**Screenshots**
If applicable, add screenshots.

**Environment:**
 - OS: [e.g. Ubuntu 22.04]
 - Python Version: [e.g. 3.9]
 - Tool Version: [e.g. 1.0]

```

### Suggesting Features

- Open an issue with tag `enhancement`
- Describe the feature and use case
- Provide examples if possible

### Pull Requests

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style

- Follow PEP 8 guidelines
- Add docstrings to functions
- Include comments for complex logic
- Update README if adding features

---

## 📊 Performance

### Benchmark Results

```
Test Environment: Ubuntu 22.04, Python 3.9, 4GB RAM

Payload Generation: ~0.5s for 100 payloads
Single Request: ~1-2s (depending on target)
Full Scan (500 payloads): ~8-10 minutes
Memory Usage: ~50-80MB
CPU Usage: ~10-15% (single thread)

```

---

## 🔧 Troubleshooting

### Common Issues

**Issue**: Callback server won't start

```bash
Solution:
- Check if port is already in use: netstat -an | grep 8888
- Use a different port
- Run with sudo if using port < 1024

```

**Issue**: No callbacks received

```bash
Solution:
- Verify firewall allows incoming connections
- Check if using public IP (not localhost)
- Test callback URL in browser first
- Ensure target can reach your server

```

**Issue**: GUI doesn't launch

```bash
Solution:
- Install tkinter: sudo apt-get install python3-tk
- Check DISPLAY variable: echo $DISPLAY
- Try: export DISPLAY=:0

```

**Issue**: SSL warnings

```bash
Solution: These are expected when testing HTTPS endpoints
The tool disables verification for testing purposes

```

---

## 📚 Resources

### Learning Materials

- [OWASP SSRF Guide](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PortSwigger SSRF Labs](https://portswigger.net/web-security/ssrf)
- [HackerOne SSRF Reports](https://hackerone.com/hacktivity?querystring=ssrf)

### Similar Tools

- [SSRFmap](https://github.com/swisskyrepo/SSRFmap)
- [Gopherus](https://github.com/tarunkant/Gopherus)
- [Ground Control](https://github.com/jobertabma/ground-control)

### Bug Bounty Platforms

- [HackerOne](https://hackerone.com/)
- [Bugcrowd](https://bugcrowd.com/)
- [Intigriti](https://intigriti.com/)
- [YesWeHack](https://yeswehack.com/)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://www.notion.so/LICENSE) file for details.

```
MIT License

Copyright (c) 2024 SSRF Detection Tool Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

[Full MIT License Text]

```

---

## 👥 Credits

### Author

**Your Name** - *Initial work* - [@yourusername](https://github.com/yourusername)

### Contributors

See the list of [contributors](https://github.com/yourusername/ssrf-detection-tool/contributors) who participated in this project.

### Acknowledgments

- OWASP for security research and documentation
- Bug bounty community for real-world payload examples
- Orange Tsai for SSRF research and techniques
- PortSwigger for excellent security training materials

---

## 📈 Statistics

[GitHub stars](https://img.shields.io/github/stars/yourusername/ssrf-detection-tool?style=social)

[GitHub forks](https://img.shields.io/github/forks/yourusername/ssrf-detection-tool?style=social)

[GitHub watchers](https://img.shields.io/github/watchers/yourusername/ssrf-detection-tool?style=social)

---

## 🌟 Star History

[Star History Chart](https://api.star-history.com/svg?repos=yourusername/ssrf-detection-tool&type=Date)

---

<div align="center">

**Made with ❤️ for the Security Community**

If this tool helped you find bugs, consider:

- ⭐ Starring the repository
- 🐛 Reporting bugs
- 💡 Suggesting features
- 🤝 Contributing code

</div>

---

## 📝 Changelog

### [1.0.0] - 2024-01-XX

### Added

- Initial release
- Basic SSRF detection with callback server
- Cloud metadata payload generation
- Protocol smuggling support
- IP encoding bypass techniques
- GUI with hacker theme
- Export functionality (TXT/JSON)
- Real-time callback monitoring

### Security

- Added legal disclaimer
- Implemented request rate limiting
- Added timeout protections

---

**⚡ Happy Hunting! Stay Legal, Stay Ethical! ⚡**
