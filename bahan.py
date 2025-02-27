# Required libraries for kadlyzer
import os
import subprocess
import platform

def install_packages():
    # Daftar package yang dibutuhkan untuk semua sistem operasi
    packages = [
        "requests",           # Untuk HTTP requests
        "beautifulsoup4",     # Untuk parsing HTML
        "lxml",              # Parser yang cepat untuk BeautifulSoup
        "colorama",          # Untuk output berwarna di terminal
        "pyfiglet",          # Untuk ASCII art text
        "pyyaml",            # Untuk membaca file YAML
        "fake-useragent",    # Untuk User-Agent acak
        "urllib3",           # Dependency untuk requests
        "certifi",           # Untuk SSL/TLS certificate verification
        "charset-normalizer", # Untuk menangani encoding
        "aiohttp",           # Untuk async HTTP requests
        "asyncio",           # Untuk async/await functionality
        "argparse",          # Untuk parsing command line arguments
        "concurrent.futures", # Untuk parallel processing
        "psutil",            # Untuk sistem resource management (cross-platform)
        "tqdm"              # Untuk progress bar
    ]

    # Hapus package yang tidak kompatibel dengan Windows
    if platform.system() == "Windows":
        print("\n⚠️ Terdeteksi sistem operasi Windows")
        print("Beberapa fitur mungkin tidak tersedia di Windows\n")
    
    print("\n🚀 Memulai instalasi package untuk KADLYZER...\n")
    
    success_count = 0
    failed_packages = []
    
    for package in packages:
        try:
            print(f"📦 Menginstal {package}...")
            subprocess.check_call([os.sys.executable, "-m", "pip", "install", package, "--upgrade"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            success_count += 1
            print(f"✅ {package} berhasil diinstal")
        except subprocess.CalledProcessError:
            failed_packages.append(package)
            print(f"❌ Gagal menginstal {package}")
        except Exception as e:
            failed_packages.append(package)
            print(f"❌ Error saat menginstal {package}: {str(e)}")
        
        # Tambahkan garis pemisah untuk memudahkan pembacaan
        print("-" * 50)

    # Tampilkan ringkasan instalasi
    print("\n📊 Ringkasan Instalasi:")
    print(f"✅ Berhasil menginstal: {success_count} package")
    print(f"❌ Gagal menginstal: {len(failed_packages)} package")
    
    if failed_packages:
        print("\n⚠️ Package yang gagal diinstal:")
        for pkg in failed_packages:
            print(f"   - {pkg}")
        print("\nSilakan coba install package yang gagal secara manual dengan:")
        print("pip install nama_package")

if __name__ == "__main__":
    try:
        print("🔍 KADLYZER Package Installer")
        print("=" * 50)
        install_packages()
        print("\n✨ Proses instalasi selesai!")
    except KeyboardInterrupt:
        print("\n\n⚠️ Instalasi dibatalkan oleh pengguna")
    except Exception as e:
        print(f"\n❌ Terjadi kesalahan: {str(e)}")
