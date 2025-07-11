import os
import time
import requests
import urllib3
from tqdm import tqdm
from multiprocessing import cpu_count
from concurrent.futures import ProcessPoolExecutor, as_completed
from requests.exceptions import ConnectionError, Timeout

# Suppress SSL warnings for verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Configuration ===
CLOUD_HOST       = "nimbus.bitdefender.net"
URL_STATUS_PATH  = "/url/status"
CLIENT_ID_HEADER = "X-Nimbus-ClientId"
CLIENT_ID        = "a4c35c82-b0b5-46c3-b641-41ed04075269"
NIMBUS_IPS       = ["34.117.254.173", "34.120.243.77", "34.98.122.109"]

INPUT_DIR   = "website"
MAX_WORKERS = min(60, cpu_count() * 4)  # Avoid ValueError

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
    """Scan a domain or IP and return (domain, result)."""
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

    # ✅ Skip if results file already exists
    if os.path.exists(out_path):
        print(f"⏩ Skipping {fname}, results already exist.")
        return

    print(f"📁 Processing {fname} → {os.path.basename(out_path)}")

    with open(in_path, 'r', encoding='utf-8', errors='ignore') as infile:
        domains = [line.strip() for line in infile if line.strip() and not line.startswith("#")]

    total = len(domains)
    if total == 0:
        print(f"⚠️ No valid domains found in {fname}. Skipping.\n")
        return

    with open(out_path, 'w', encoding='utf-8') as outfile:
        with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_domain = {executor.submit(scan_domain, d): d for d in domains}
            for future in tqdm(as_completed(future_to_domain), total=total, desc="🔍 Scanning", ncols=80):
                try:
                    domain, result = future.result()
                    outfile.write(f"{domain}\t{result}\n")
                    outfile.flush()  # Write immediately
                except Exception as e:
                    failed = future_to_domain[future]
                    outfile.write(f"{failed}\t{{'error': 'exception'}}\n")
                    outfile.flush()

    print(f"✅ Finished {fname}\n")

if __name__ == "__main__":
    for fname in sorted(os.listdir(INPUT_DIR)):
        if fname.lower().endswith(".txt") and not fname.endswith("_results.txt"):
            process_file(fname)
    print("✅ All done.")
