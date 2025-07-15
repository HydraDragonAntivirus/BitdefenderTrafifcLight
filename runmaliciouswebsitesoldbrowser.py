import requests
import random
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Config
DOMAIN_LIST_PATH = r"C:\Users\hydradragonav\Desktop\recentmalware.txt"
MYPAL_PATH = r"C:\Users\hydradragonav\Downloads\mypal-74.1.0.en-US.win32\mypal\mypal.exe"
MAX_THREADS = 100  # Increase or decrease depending on your CPU
TIMEOUT = 5  # seconds

def check_and_open(domain):
    domain = domain.strip()
    if not domain:
        return

    url = f"http://{domain}"
    print(f"Checking: {url}")
    try:
        response = requests.get(url, timeout=TIMEOUT)
        if response.status_code < 400:
            print(f"[✓] Online, opening in Mypal: {domain}")
            subprocess.Popen([MYPAL_PATH, url], shell=False)
        else:
            print(f"[X] Server responded with code {response.status_code}: {domain}")
    except requests.RequestException as e:
        print(f"[X] Failed to connect: {domain} → {e}")

def main():
    if not Path(DOMAIN_LIST_PATH).exists():
        print(f"[!] File not found: {DOMAIN_LIST_PATH}")
        return

    with open(DOMAIN_LIST_PATH, "r", encoding="utf-8") as f:
        domains = [line.strip() for line in f if line.strip()]

    random.shuffle(domains)

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        executor.map(check_and_open, domains)

if __name__ == "__main__":
    main()
