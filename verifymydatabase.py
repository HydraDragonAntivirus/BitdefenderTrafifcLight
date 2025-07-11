import os
import time
import requests
import urllib3
from requests.exceptions import ConnectionError, Timeout
from concurrent.futures import ProcessPoolExecutor, as_completed, Manager

# Suppress SSL warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Configuration ===
CLOUD_HOST       = "nimbus.bitdefender.net"
URL_STATUS_PATH  = "/url/status"
CLIENT_ID_HEADER = "X-Nimbus-ClientId"
CLIENT_ID        = "a4c35c82-b0b5-46c3-b641-41ed04075269"
NIMBUS_IPS       = ["34.117.254.173", "34.120.243.77", "34.98.122.109"]

INPUT_DIR   = "website"
MAX_WORKERS = 8  # Processes, not threads

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
    done = 0

    with open(out_path, 'w', encoding='utf-8') as outfile:
        with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_domain = {executor.submit(scan_domain, domain): domain for domain in domains}
            for future in as_completed(future_to_domain):
                domain, result = future.result()
                outfile.write(f"{domain}\t{result}\n")
                outfile.flush()  # Ensure immediate write
                done += 1
                print(f"  [{done}/{total}] {domain} → {result}")

    print(f"✅ Finished {fname}\n")

if __name__ == "__main__":
    for fname in sorted(os.listdir(INPUT_DIR)):
        if fname.lower().endswith(".txt"):
            process_file(fname)
    print("✅ All done.")
