# Required libraries for kadlyzer
import os
import subprocess

def install_packages():
    packages = [
        "requests",           # Untuk melakukan HTTP requests
        "beautifulsoup4",     # Untuk parsing HTML
        "lxml",              # Parser yang cepat untuk BeautifulSoup
        "colorama",          # Untuk output berwarna di terminal
        "pyfiglet",         # Untuk membuat ASCII art text
        "pyyaml",           # Untuk membaca file YAML
        "fake-useragent",   # Untuk menghasilkan User-Agent acak
        "urllib3",          # Dependency untuk requests
        "certifi",          # Untuk SSL/TLS certificate verification
        "charset-normalizer" # Untuk menangani encoding
    ]
    
    print("Menginstal package yang dibutuhkan...")
    for package in packages:
        try:
            print(f"Menginstal {package}...")
            subprocess.check_call([os.sys.executable, "-m", "pip", "install", package])
            print(f"✓ {package} berhasil diinstal")
        except subprocess.CalledProcessError:
            print(f"❌ Gagal menginstal {package}")
        except Exception as e:
            print(f"❌ Error saat menginstal {package}: {str(e)}")

if __name__ == "__main__":
    install_packages()
    print("\nProses instalasi selesai!")
