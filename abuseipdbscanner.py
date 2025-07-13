import requests
import time
import json
import os
import re
import html
import sys
from typing import Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import ConnectionError, Timeout, HTTPError
import urllib3
from tqdm import tqdm
from multiprocessing import cpu_count
import threading

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Calculate optimal max workers
MAX_WORKERS = min(60, cpu_count() * 4)  # Avoid ValueError

class IPSpamScanner:
    def __init__(self):
        # GridinSoft Configuration
        self.gridinsoft_url = "https://gridinsoft.com/online-virus-scanner/ip/"
        
        # Bitdefender Configuration
        self.cloud_host = "nimbus.bitdefender.net"
        self.url_status_path = "/url/status"
        self.client_id_header = "X-Nimbus-ClientId"
        self.client_id = "a4c35c82-b0b5-46c3-b641-41ed04075269"
        self.nimbus_ips = ["34.117.254.173", "34.120.243.77", "34.98.122.109"]
        
        # Spam IP list
        self.spam_ips = set()
        
        # Thread-safe statistics
        self.stats_lock = threading.Lock()
        
        # Regex patterns for GridinSoft
        self.review_re = re.compile(
            r'<h1[^>]*class="[^"]*bCheckId__title[^"]*"[^>]*>'
            r'.*?<span[^>]*class="[^"]*small[^"]*"[^>]*>\s*(.*?)\s*</span>',
            re.IGNORECASE | re.DOTALL
        )
        self.points_re = re.compile(
            r'<div[^>]*id="bScalePoints"[^>]*data-points\s*=\s*"(\d+)"',
            re.IGNORECASE
        )
        self.item_re = re.compile(
            r'<div[^>]*class="[^"]*bScalePoints__item[^"]*"[^>]*>\s*(.*?)\s*</div>',
            re.IGNORECASE | re.DOTALL
        )
        
        # Load spam IP list
        self.load_spam_ips()
        
    def load_spam_ips(self):
        """Load spam IPs from website//IPv4Spam.txt"""
        if os.path.exists('website//IPv4Spam.txt'):
            try:
                with open('website//IPv4Spam.txt', 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith('#') and self.is_valid_ipv4(ip):
                            self.spam_ips.add(ip)
                print(f"Loaded {len(self.spam_ips)} spam IPs from website//IPv4Spam.txt")
            except Exception as e:
                print(f"Error loading website//IPv4Spam.txt: {e}")
        else:
            print("website//IPv4Spam.txt not found")
    
    def is_valid_ipv4(self, ip: str) -> bool:
        """Validate IPv4 address"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False
    
    def check_spam_list(self, ip: str) -> bool:
        """Check if IP is in local spam list"""
        return ip in self.spam_ips
    
    def extract_review_and_risk(self, html_text: str) -> Tuple[str, str]:
        """Extract review and risk from GridinSoft response"""
        m = self.review_re.search(html_text)
        review = html.unescape(m.group(1).strip()) if m else ""

        risk = "Unknown"
        pm = self.points_re.search(html_text)
        items = self.item_re.findall(html_text)
        if pm and items:
            dp = int(pm.group(1))
            idx = round(dp * (len(items) - 1) / 100)
            risk = html.unescape(items[idx].strip())

        return review, risk
    
    def check_gridinsoft(self, ip: str) -> Dict:
        """Check IP against GridinSoft - SPAM ONLY"""
        url = f"{self.gridinsoft_url}{ip}"
        
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 404 or "gridinsoft.com/410" in resp.url:
                return {"ip": ip, "review": "", "risk": "Unknown", "is_spam": False}
            else:
                review, risk = self.extract_review_and_risk(resp.text)
                
                # ONLY check for specific AbuseIPDB categories: Web Spam, Email Spam, Blog Spam
                spam_indicators = [
                    # Web Spam (Category 10) - Comment/forum spam, HTTP referer spam, CMS spam
                    'web spam', 'comment spam', 'forum spam', 'cms spam',
                    'http referer spam', 'referer spam', 'referrer spam',
                    'comment spamming', 'forum spamming',
                    
                    # Email Spam (Category 11) - Spam email content
                    'email spam', 'spam email', 'spam mail',
                    'bulk email', 'unsolicited email', 'junk mail',
                    'email spamming', 'mail spam',
                    
                    # Blog Spam (Category 12) - CMS blog comment spam
                    'blog spam', 'blog comment spam', 'cms blog spam',
                    'blog spamming', 'wordpress spam', 'cms comment spam'
                ]
                
                # Check both review and risk text for SPAM indicators only
                combined_text = f"{review} {risk}".lower()
                is_spam = any(indicator in combined_text for indicator in spam_indicators)
                
                return {
                    "ip": ip, 
                    "review": review, 
                    "risk": risk,
                    "is_spam": is_spam,
                    "detection_reason": "Spam indicators found" if is_spam else "No spam indicators"
                }
        except requests.RequestException as e:
            return {"ip": ip, "review": "", "risk": "Error", "error": str(e), "is_spam": False}
    
    def _make_request_with_retries(self, method, url, **kwargs):
        """Make HTTP request with retries"""
        backoff = 1
        for attempt in range(4):
            try:
                return requests.request(method, url, timeout=10, **kwargs)
            except (ConnectionError, Timeout):
                if attempt < 3:
                    time.sleep(backoff)
                    backoff *= 2
                else:
                    raise
    
    def check_bitdefender(self, ip: str) -> Dict:
        """Check IP against Bitdefender - SPAM ONLY"""
        url = f"http://{ip}"  # Create URL from IP
        params = {"url": url}
        headers = {
            self.client_id_header: self.client_id,
            "Host": self.cloud_host,
        }
        
        for nimbus_ip in self.nimbus_ips:
            endpoint = f"https://{nimbus_ip}{self.url_status_path}"
            try:
                resp = self._make_request_with_retries(
                    "GET", endpoint,
                    params=params,
                    headers=headers,
                    verify=False
                )
                resp.raise_for_status()
                data = resp.json()
                
                # Check for SPAM indicators only in status and categories
                status = data.get('status', '').lower()
                categories = data.get('categories', [])
                
                # ONLY check for specific AbuseIPDB categories: Web Spam, Email Spam, Blog Spam
                spam_status_indicators = [
                    # Web Spam (Category 10) - Comment/forum spam, HTTP referer spam, CMS spam
                    'web spam', 'comment spam', 'forum spam', 'cms spam',
                    'http referer spam', 'referer spam', 'referrer spam',
                    'comment spamming', 'forum spamming',
                    
                    # Email Spam (Category 11) - Spam email content
                    'email spam', 'spam email', 'spam mail',
                    'bulk email', 'unsolicited email', 'junk mail',
                    'email spamming', 'mail spam',
                    
                    # Blog Spam (Category 12) - CMS blog comment spam
                    'blog spam', 'blog comment spam', 'cms blog spam',
                    'blog spamming', 'wordpress spam', 'cms comment spam'
                ]
                
                # Check status for spam indicators only
                is_spam_status = any(indicator in status for indicator in spam_status_indicators)
                
                # Check categories for spam indicators only
                is_spam_categories = False
                spam_categories = []
                if categories:
                    for category in categories:
                        cat_str = str(category).lower()
                        if any(indicator in cat_str for indicator in spam_status_indicators):
                            is_spam_categories = True
                            spam_categories.append(category)
                
                is_spam = is_spam_status or is_spam_categories
                
                detection_reason = []
                if is_spam_status:
                    detection_reason.append(f"Spam status: {status}")
                if is_spam_categories:
                    detection_reason.append(f"Spam categories: {spam_categories}")
                
                return {
                    'status': data.get('status', 'Unknown'),
                    'categories': categories,
                    'is_spam': is_spam,
                    'detection_reason': " | ".join(detection_reason) if detection_reason else "No spam indicators",
                    'full_response': data
                }
            except HTTPError:
                continue
            except Exception:
                continue
        
        return {'error': 'All Nimbus IPs failed', 'is_spam': False, 'detection_reason': 'API Error'}
    
    def comprehensive_scan(self, ip: str) -> Dict:
        """Perform comprehensive scan of IP - SPAM ONLY"""
        results = {
            'ip': ip,
            'spam_list': self.check_spam_list(ip),
            'gridinsoft': self.check_gridinsoft(ip),
            'bitdefender': self.check_bitdefender(ip),
            'verification_count': 0,
            'confidence': 0,
            'should_report': False
        }
        
        # Count verifications with detailed reasoning - SPAM ONLY
        verification_sources = []
        verification_details = []
        
        # Check local spam list
        if results['spam_list']:
            verification_sources.append('Local Spam List')
            verification_details.append('IP found in website//IPv4Spam.txt')
        
        # Check GridinSoft with spam text verification
        if (not results['gridinsoft'].get('error') and 
            results['gridinsoft'].get('is_spam') and
            results['gridinsoft'].get('detection_reason') != 'No spam indicators'):
            verification_sources.append('GridinSoft')
            verification_details.append(f"GridinSoft: {results['gridinsoft'].get('detection_reason')}")
        
        # Check Bitdefender with spam text verification
        if (not results['bitdefender'].get('error') and 
            results['bitdefender'].get('is_spam') and
            results['bitdefender'].get('detection_reason') != 'No spam indicators'):
            verification_sources.append('Bitdefender')
            verification_details.append(f"Bitdefender: {results['bitdefender'].get('detection_reason')}")
        
        results['verification_sources'] = verification_sources
        results['verification_details'] = verification_details
        results['verification_count'] = len(verification_sources)
        
        # Calculate confidence - only high confidence for 2+ sources
        if results['verification_count'] >= 3:
            results['confidence'] = 100
        elif results['verification_count'] >= 2:
            results['confidence'] = 85
        elif results['verification_count'] >= 1:
            results['confidence'] = 40  # Low confidence for single source
        else:
            results['confidence'] = 0
        
        # STRICT: Only report if verified by 2+ sources
        results['should_report'] = results['verification_count'] >= 2
        
        return results

    def scan_all_ips(self, max_workers: int = MAX_WORKERS):
        """Scan all IPs from the spam list with tqdm progress bar"""
        if not self.spam_ips:
            print("No spam IPs loaded")
            return

        print(f"Starting spam scan of {len(self.spam_ips)} IPs with {max_workers} workers...")
        sys.stdout.flush()

        results = []
        ips_to_report = []

        stats = {
            'total': len(self.spam_ips),
            'verified': 0,
            'unverified': 0,
            'errors': 0,
            'high_confidence': 0,
            'medium_confidence': 0,
            'low_confidence': 0
        }

        # ────── PROGRESS BAR SETUP ──────
        pbar = tqdm(
            total=len(self.spam_ips),
            desc="Scanning IPs",
            unit="IP",
            ncols=100,
            bar_format=(
                '{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} '
                '[{elapsed}<{remaining}, {rate_fmt}] {postfix}'
            ),
            dynamic_ncols=False,
            file=sys.stdout,
            miniters=1,
            mininterval=0.1,
            maxinterval=1.0,
            smoothing=0.1,
            ascii=False,
            leave=True,
            position=0
        )
        # initialize postfix
        pbar.set_postfix(
            verified=stats['verified'],
            errors=stats['errors'],
            reportable=len(ips_to_report)
        )
        # draw the bar once without advancing
        pbar.update(0)

        # ────── SCAN LOOP ──────
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(self.comprehensive_scan, ip): ip
                for ip in self.spam_ips
            }

            for future in as_completed(future_to_ip):
                try:
                    result = future.result()
                    results.append(result)

                    # update stats under lock
                    with self.stats_lock:
                        vc = result['verification_count']
                        conf = result['confidence']

                        if vc >= 2:
                            stats['verified'] += 1
                            if conf >= 85:
                                stats['high_confidence'] += 1
                            else:
                                stats['medium_confidence'] += 1
                        elif vc == 1:
                            stats['unverified'] += 1
                            stats['low_confidence'] += 1
                        else:
                            stats['unverified'] += 1

                        if result['should_report']:
                            ips_to_report.append(result)

                        # update the bar display
                        pbar.set_postfix(
                            verified=stats['verified'],
                            errors=stats['errors'],
                            reportable=len(ips_to_report)
                        )

                except Exception:
                    # count the error and update display
                    with self.stats_lock:
                        stats['errors'] += 1
                        pbar.set_postfix(
                            verified=stats['verified'],
                            errors=stats['errors'],
                            reportable=len(ips_to_report)
                        )

                # advance bar by one IP
                pbar.update(1)

        pbar.close()

        # ────── FINAL OUTPUT ──────
        print("\n📊 SPAM SCAN COMPLETED:")
        print(f"Total IPs scanned: {stats['total']}")
        print(f"✅ Verified spam IPs (2+ sources): {stats['verified']}")
        print(f"❓ Unverified spam IPs: {stats['unverified']}")
        print(f"❌ Errors: {stats['errors']}")
        print(f"🔴 High confidence (100%): {stats['high_confidence']}")
        print(f"🟡 Medium confidence (85%): {stats['medium_confidence']}")
        print(f"🟢 Low confidence (40%): {stats['low_confidence']}")
        print(f"📋 Ready for manual reporting: {len(ips_to_report)}")

        # Save JSON results
        with open('spam_scan_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        print("Detailed spam scan results saved to spam_scan_results.json")

        # Optionally generate reports here…
        return results

    # ... rest of the methods remain the same ...
    def _determine_spam_category(self, ip_data: Dict) -> str:
        """Determine the most appropriate AbuseIPDB category for spam type"""
        # Check detection details to determine spam type
        details = ' '.join(ip_data.get('verification_details', [])).lower()
        
        # Blog spam indicators (Category 12)
        if any(term in details for term in ['blog spam', 'cms blog', 'wordpress spam', 'cms comment spam']):
            return "12"
        
        # Email spam indicators (Category 11)
        elif any(term in details for term in ['email spam', 'spam email', 'spam mail', 'bulk email', 'mail spam']):
            return "11"
        
        # Web spam indicators (Category 10) - default for comment/forum/referer spam
        elif any(term in details for term in ['web spam', 'comment spam', 'forum spam', 'referer spam', 'cms spam']):
            return "10"
        
        # Default to Web Spam (Category 10) if no specific type detected
        return "10"
    
    def create_bulk_report_files(self, ips_to_report: List[Dict]):
        """Create bulk report CSV files for manual submission to AbuseIPDB"""
        if not ips_to_report:
            print("No spam IPs to report")
            return []
        
        print(f"Creating bulk report files for {len(ips_to_report)} spam IPs...")
        
        # AbuseIPDB limits: 10,000 lines (including header), 8MB file size
        max_lines_per_file = 9999  # 10,000 - 1 for header
        max_file_size = 8 * 1024 * 1024  # 8MB in bytes
        
        files_created = []
        file_counter = 1
        current_batch = []
        current_size = 0
        
        # CSV header
        header = "IP,Categories,ReportDate,Comment\n"
        header_size = len(header.encode('utf-8'))
        
        for ip_data in ips_to_report:
            ip = ip_data['ip']
            categories = self._determine_spam_category(ip_data)
            
            # Use ISO 8601 format with timezone
            report_date = time.strftime("%Y-%m-%dT%H:%M:%S+00:00")
            
            # Create comment based on verification sources (max 1024 chars)
            sources = ip_data.get('verification_sources', [])
            details = ip_data.get('verification_details', [])
            
            comment = f"Spam IP verified by {len(sources)} sources: {', '.join(sources)}. "
            comment += f"Confidence: {ip_data.get('confidence', 0)}%. "
            
            # Add detection details
            if details:
                comment += f"Detection details: {' | '.join(details)}. "
            
            # Specific comment based on category
            if categories == "10":
                comment += "Web spam detected: Comment/forum spam, HTTP referer spam, or other CMS spam."
            elif categories == "11":
                comment += "Email spam detected: Spam email content, infected attachments, and phishing emails."
            elif categories == "12":
                comment += "Blog spam detected: CMS blog comment spam."
            else:
                comment += "Spam detected: Web spam, email spam, or blog spam activities."
            
            # Truncate comment to 1024 characters
            if len(comment) > 1024:
                comment = comment[:1021] + "..."
            
            # Escape quotes in comment
            comment = comment.replace('"', '""')
            
            # Create CSV line
            csv_line = f'"{ip}","{categories}","{report_date}","{comment}"\n'
            line_size = len(csv_line.encode('utf-8'))
            
            # Check if we need to create a new file
            if (len(current_batch) >= max_lines_per_file or 
                current_size + line_size + header_size > max_file_size):
                
                # Save current batch
                if current_batch:
                    filename = f"spam_bulk_report_{file_counter}.csv"
                    self._save_bulk_report_file(filename, current_batch)
                    files_created.append(filename)
                    file_counter += 1
                    current_batch = []
                    current_size = 0
            
            current_batch.append({
                'ip': ip,
                'categories': categories,
                'report_date': report_date,
                'comment': comment,
                'csv_line': csv_line
            })
            current_size += line_size
        
        # Save remaining batch
        if current_batch:
            filename = f"spam_bulk_report_{file_counter}.csv"
            self._save_bulk_report_file(filename, current_batch)
            files_created.append(filename)
        
        print(f"Created {len(files_created)} spam bulk report files:")
        for filename in files_created:
            print(f"  - {filename}")
        
        return files_created
    
    def _save_bulk_report_file(self, filename: str, batch: List[Dict]):
        """Save a batch of reports to CSV file"""
        with open(filename, 'w', encoding='utf-8', newline='') as f:
            f.write("IP,Categories,ReportDate,Comment\n")
            for item in batch:
                f.write(item['csv_line'])
        
        file_size = os.path.getsize(filename)
        print(f"Created {filename}: {len(batch)} spam IPs, {file_size:,} bytes")
    
    def create_manual_report_files(self, ips_to_report: List[Dict]):
        """Create CSV files for manual submission"""
        csv_files = self.create_bulk_report_files(ips_to_report)
        
        if csv_files:
            print(f"\n📋 Manual submission instructions:")
            print(f"1. Go to https://www.abuseipdb.com/bulk-report")
            print(f"2. Upload each CSV file manually:")
            for csv_file in csv_files:
                print(f"   - {csv_file}")
            print(f"3. No API key required - just drag and drop the files!")
        
        return csv_files
    
    def create_readable_report(self, results: List[Dict]):
        """Create a human-readable report file"""
        verified_ips = [r for r in results if r['should_report']]
        
        if not verified_ips:
            print("No verified spam IPs to create readable report")
            return
        
        filename = f"spam_report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("SPAM IP VERIFICATION REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total verified spam IPs: {len(verified_ips)}\n\n")
            
            for ip_data in verified_ips:
                f.write(f"IP: {ip_data['ip']}\n")
                f.write(f"Confidence: {ip_data['confidence']}%\n")
                f.write(f"Verification sources: {', '.join(ip_data['verification_sources'])}\n")
                f.write(f"Detection details: {'; '.join(ip_data['verification_details'])}\n")
                
                # GridinSoft details
                if ip_data['gridinsoft'].get('is_spam'):
                    f.write(f"GridinSoft Review: {ip_data['gridinsoft'].get('review', 'N/A')}\n")
                    f.write(f"GridinSoft Risk: {ip_data['gridinsoft'].get('risk', 'N/A')}\n")
                
                # Bitdefender details
                if ip_data['bitdefender'].get('is_spam'):
                    f.write(f"Bitdefender Status: {ip_data['bitdefender'].get('status', 'N/A')}\n")
                    f.write(f"Bitdefender Categories: {ip_data['bitdefender'].get('categories', 'N/A')}\n")
                
                f.write("-" * 30 + "\n")
        
        print(f"Human-readable spam report saved to: {filename}")
        return filename

def main():
    # Force unbuffered output
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 1)  # Unbuffered
    
    # Initialize scanner for manual reporting
    scanner = IPSpamScanner()
    
    print(f"Using {MAX_WORKERS} workers for optimal performance (CPU cores: {cpu_count()})")
    
    # Start scanning
    results = scanner.scan_all_ips(max_workers=MAX_WORKERS)
    
    print("\n🏁 Spam scan completed!")
    print("\n📝 Files created for MANUAL submission:")
    print("- spam_scan_results.json (detailed JSON results)")
    print("- spam_bulk_report_*.csv (upload these to AbuseIPDB manually)")
    print("- spam_report_*.txt (human-readable report)")

if __name__ == "__main__":
    main()