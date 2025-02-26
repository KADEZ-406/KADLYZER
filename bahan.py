import os

def install_bahan():
    print("\n[🔧] Memulai instalasi bahan yang dibutuhkan...\n")
    
    # List package yang dibutuhkan
    packages = [
        "requests",
        "socket",
        "json",
        "threading",
        "random",
        "base64",
        "time"
    ]
    
    # Install tiap package
    for package in packages:
        try:
            print(f"[⏳] Menginstall {package}...")
            os.system(f"pip install {package}")
            print(f"[✔] {package} berhasil diinstall!\n")
        except Exception as e:
            print(f"[✖] Gagal menginstall {package}: {e}\n")

    print("[✅] Semua bahan sudah diinstall! Jalankan `python kadlyzer.py` untuk mulai scanning.")

if __name__ == "__main__":
    install_bahan()
