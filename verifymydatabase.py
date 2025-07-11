import os
import time
import requests
import urllib3
import threading
from requests.exceptions import ConnectionError, Timeout
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress SSL warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Configuration ===
CLOUD_HOST       = "nimbus.bitdefender.net"
URL_STATUS_PATH  = "/url/status"
CLIENT_ID_HEADER = "X-Nimbus-ClientId"
CLIENT_ID        = "a4c35c82-b0b5-46c3-b641-41ed04075269"
NIMBUS_IPS       = ["34.117.254.173", "34.120.243.77", "34.98.122.109"]

INPUT_DIR   = "website"
MAX_WORKERS = 10000  # Too high = throttling or bans

write_lock = threading.Lock()  # Lock for writing to file safely

def request_with_retries(method, url, **kwargs):
    backoff = 1
    for attempt in range(4):
        try:
            return requests.request(method, url, timeout=10, **kwargs)
        except (ConnectionError, Timeout):
            if attempt < 3:
                time.sleep(backoff)
                backoff *= 2
            else:
                return None

def scan_domain(domain: str) -> tuple[str, dict]:
    """Scan using Bitdefender Nimbus and return result dict."""
    params = {"url": f"http://{domain}"}
    headers = {CLIENT_ID_HEADER: CLIENT_ID, "Host": CLOUD_HOST}
    for ip in NIMBUS_IPS:
        try:
            resp = request_with_retries(
                "GET",
                f"https://{ip}{URL_STATUS_PATH}",
                params=params,
                headers=headers,
                verify=False
            )
            if resp is None:
                continue
            resp.raise_for_status()
            return domain, resp.json()
        except Exception:
            continue
    return domain, {"error": "scan_failed"}

def process_file(fname: str):
    in_path  = os.path.join(INPUT_DIR, fname)
    out_path = os.path.join(INPUT_DIR, f"{os.path.splitext(fname)[0]}_results.txt")

    print(f"Processing {fname} → {os.path.basename(out_path)}")

    with open(in_path, 'r', encoding='utf-8', errors='ignore') as infile:
        domains = [line.strip() for line in infile if line.strip() and not line.startswith("#")]

    total = len(domains)
    progress = 0

    with open(out_path, 'w', encoding='utf-8') as outfile:
        def task(domain):
            nonlocal progress
            domain, result = scan_domain(domain)
            with write_lock:
                outfile.write(f"{domain}\t{result}\n")
                outfile.flush()  # Force immediate write
                progress += 1
                print(f"  [{progress}/{total}] {domain} → {result}")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            executor.map(task, domains)

    print(f"✅ Finished {fname}\n")

if __name__ == "__main__":
    for fname in sorted(os.listdir(INPUT_DIR)):
        if fname.lower().endswith(".txt"):
            process_file(fname)
    print("✅ All done.")
