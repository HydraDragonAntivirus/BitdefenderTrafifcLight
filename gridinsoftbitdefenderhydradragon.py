import discord
from discord.ext import commands
import asyncio
import time
import requests
import urllib3
import re
import html
import threading
import os
import json
from datetime import datetime
from requests.exceptions import ConnectionError, Timeout, HTTPError
from typing import Dict, List, Tuple
import ipaddress
import socket
from urllib.parse import urlparse, urljoin

# Suppress only the InsecureRequestWarning from requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Configuration ===
BOT_TOKEN = "YOUR_DISCORD_BOT_TOKEN_HERE"

IP_REGEX = re.compile(
    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|'
    r'\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|'
    r'\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|'
    r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b',
    re.IGNORECASE
)

# Comprehensive URL patterns for different formats
URL_PATTERNS = [
    # Enhanced URL regex with protocol - comprehensive pattern
    re.compile(
        r'(?:https?://|ftp://|ftps://|www\.)'
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'(?::[0-9]{1,5})?'
        r'(?:/[^\s\)]*)?',
        re.IGNORECASE
    ),
    
    # Standard URLs with broader character support
    re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
    
    # URLs with www (without protocol)
    re.compile(r'www\.[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:/[^\s]*)?', re.IGNORECASE),
    
    # Domain-like patterns with word boundaries
    re.compile(r'\b[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:/[^\s]*)?(?=\s|$|[,.!?;)])', re.IGNORECASE),
    
    # Obfuscated URLs (dot replacement patterns)
    re.compile(r'\b[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\[?\.\]?[a-zA-Z]{2,}(?:/[^\s]*)?', re.IGNORECASE),
    
    # Email addresses
    re.compile(r'mailto:[\w._%+-]+@[\w.-]+\.[A-Za-z]{2,}', re.IGNORECASE),
    
    # FTP URLs
    re.compile(r'ftps?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?', re.IGNORECASE),
]

LEARNING_MODE_ENABLED = True  # Set to False to disable learning mode
LEARNING_DATA_FILE = "learning_data.json"
PENDING_FEEDBACK_FILE = "pending_feedback.json"
FEEDBACK_TIMEOUT = 300  # 5 minutes timeout for feedback

# Add new global variables after threat_cache
learning_data = {
    'user_feedback': {},
    'auto_whitelist': set(),
    'auto_blacklist': {
        'abuse': set(),
        'malware': set(),
        'phishing': set(),
        'spam': set(),
        'mining': set()
    },
    'feedback_stats': {
        'total_feedback': 0,
        'correct_predictions': 0,
        'false_positives': 0,
        'false_negatives': 0
    }
}

pending_feedback = {}  # Store pending feedback requests

AUTO_SCAN_ENABLED = True  # Set to False to disable auto-scanning
AUTO_SCAN_CHANNELS = []   # Leave empty to scan all channels, or add specific channel IDs

# GridinSoft Configuration
GRIDINSOFT_URL = "https://gridinsoft.com/online-virus-scanner/url/"
CSV_FILE = "DomainScanResults.csv"
MAX_THREADS = 100

# Bitdefender Configuration
CLOUD_HOST = "nimbus.bitdefender.net"
URL_STATUS_PATH = "/url/status"
CLIENT_ID_HEADER = "X-Nimbus-ClientId"
CLIENT_ID = "a4c35c82-b0b5-46c3-b641-41ed04075269"
NIMBUS_IPS = ["34.117.254.173", "34.120.243.77", "34.98.122.109"]

# Threat Intelligence Lists Directory
THREAT_LISTS_DIR = "website"

# Enable the message content intent so prefix commands work everywhere
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)

# Global threat intelligence cache
threat_cache = {
    'abuse_domains': set(),
    'malware_domains': set(),
    'phishing_domains': set(),
    'spam_domains': set(),
    'whitelist_domains': set(),
    'mining_domains': set(),
    'abuse_subdomains': set(),
    'malware_subdomains': set(),
    'phishing_subdomains': set(),
    'spam_subdomains': set(),
    'whitelist_subdomains': set(),
    'mining_subdomains': set(),
    'malware_ips': set(),
    'phishing_ips': set(),
    'spam_ips': set(),
    'ddos_ips': set(),
    'bruteforce_ips': set(),
    'whitelist_ips': set()
}

# Regex patterns for GridinSoft
REVIEW_RE = re.compile(
    r'<h1[^>]*class="[^"]*bCheckId__title[^"]*"[^>]*>'
    r'.*?<span[^>]*class="[^"]*small[^"]*"[^>]*>\s*(.*?)\s*</span>',
    re.IGNORECASE | re.DOTALL
)
POINTS_RE = re.compile(
    r'<div[^>]*id="bScalePoints"[^>]*data-points\s*=\s*"(\d+)"',
    re.IGNORECASE
)
ITEM_RE = re.compile(
    r'<div[^>]*class="[^"]*bScalePoints__item[^"]*"[^>]*>\s*(.*?)\s*</div>',
    re.IGNORECASE | re.DOTALL
)

csv_lock = threading.Lock()

def is_valid_ip(ip_string):
    """
    Validate if the string is a valid public IP address (IPv4/IPv6) or CIDR notation.
    Returns "ipv4", "ipv6" or None if invalid.
    """
    def is_bad_network(net):
        """Check if network is in excluded categories"""
        if net.version == 4:
            return (net.is_private or net.is_loopback
                    or net.is_link_local or net.is_multicast
                    or net.is_reserved)
        else:
            return (net.is_loopback or net.is_link_local
                    or net.is_multicast or net.is_reserved)
    
    try:
        # Try as network first (CIDR notation)
        net = ipaddress.ip_network(ip_string, strict=False)
        if is_bad_network(net):
            return None
        return "ipv4" if net.version == 4 else "ipv6"
    except ValueError:
        try:
            # Try as single IP address
            ip = ipaddress.ip_address(ip_string)
            if is_bad_network(ip):
                return None
            return "ipv4" if ip.version == 4 else "ipv6"
        except ValueError:
            return None

def is_valid_url(url_string):
    """
    Validate if the string is a valid HTTP/HTTPS URL.
    Returns True if valid, False otherwise.
    """
    try:
        result = urlparse(url_string)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except Exception:
        return False

def extract_content_from_website(url: str, timeout: int = 10) -> Dict:
    """
    Extract IPs, domains and URLs from a website's HTML content.
    Returns dictionary with extracted data and metadata.
    """
    extracted_data = {
        'url': url,
        'status': 'success',
        'ips': set(),
        'urls': set(),
        'domains': set(),
        'error': None,
        'response_time': 0,
        'content_length': 0,
        'server_ip': None
    }
    
    start_time = time.time()
    
    try:
        # Get server IP
        try:
            parsed = urlparse(url)
            server_ip = socket.gethostbyname(parsed.netloc)
            if is_valid_ip(server_ip):
                extracted_data['server_ip'] = server_ip
                extracted_data['ips'].add(server_ip)
        except Exception:
            pass
        
        # Fetch website content
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }
        resp = requests.get(url, timeout=timeout, headers=headers, verify=False)
        resp.raise_for_status()
        
        extracted_data['response_time'] = time.time() - start_time
        extracted_data['content_length'] = len(resp.content)
        html = resp.text
        
        # 1) IPs
        for ip in IP_REGEX.findall(html):
            if is_valid_ip(ip):
                extracted_data['ips'].add(ip)
        
        # 2) URLs & domains via all URL_PATTERNS
        for pattern in URL_PATTERNS:
            for match in pattern.findall(html):
                if is_valid_url(match):
                    extracted_data['urls'].add(match)
                    dom = urlparse(match).netloc.lower()
                    if dom:
                        extracted_data['domains'].add(dom)
        
        # 3) Relative links → absolute
        for attr in ('href', 'src', 'action'):
            for rel in re.findall(fr'{attr}=["\']([^"\']+)["\']', html, re.IGNORECASE):
                try:
                    abs_url = urljoin(url, rel)
                    if is_valid_url(abs_url):
                        extracted_data['urls'].add(abs_url)
                        dom = urlparse(abs_url).netloc.lower()
                        if dom:
                            extracted_data['domains'].add(dom)
                except Exception:
                    continue
        
        # finalize
        extracted_data['ips'] = list(extracted_data['ips'])
        extracted_data['urls'] = list(extracted_data['urls'])
        extracted_data['domains'] = list(extracted_data['domains'])
        
    except requests.exceptions.RequestException as e:
        extracted_data.update({
            'status': 'error',
            'error': f"Request error: {e}",
            'response_time': time.time() - start_time
        })
    except Exception as e:
        extracted_data.update({
            'status': 'error',
            'error': f"Unexpected error: {e}",
            'response_time': time.time() - start_time
        })
    
    return extracted_data

def format_extraction_results(extraction_data: Dict) -> str:
    """Format website extraction results for Discord"""
    url = extraction_data['url']
    status = extraction_data['status']
    
    if status == 'error':
        return f"❌ **Error extracting from** `{url}`\n**Error:** {extraction_data['error']}"
    
    result = f"🔍 **Website Content Extraction for:** `{url}`\n\n"
    
    # Response info
    result += f"📊 **Response Info:**\n"
    result += f"• Response Time: {extraction_data['response_time']:.2f}s\n"
    result += f"• Content Length: {extraction_data['content_length']} bytes\n"
    if extraction_data['server_ip']:
        result += f"• Server IP: {extraction_data['server_ip']}\n"
    result += "\n"
    
    # Extracted IPs
    ips = extraction_data['ips']
    if ips:
        result += f"🌐 **Extracted IPs ({len(ips)}):**\n"
        for ip in ips[:10]:  # Show first 10 IPs
            ip_type = is_valid_ip(ip)
            result += f"• `{ip}` ({ip_type})\n"
        if len(ips) > 10:
            result += f"*... and {len(ips) - 10} more IPs*\n"
        result += "\n"
    
    # Extracted URLs
    urls = extraction_data['urls']
    if urls:
        result += f"🔗 **Extracted URLs ({len(urls)}):**\n"
        for url_item in urls[:5]:  # Show first 5 URLs
            result += f"• `{url_item}`\n"
        if len(urls) > 5:
            result += f"*... and {len(urls) - 5} more URLs*\n"
        result += "\n"
    
    # Extracted domains
    domains = extraction_data['domains']
    if domains:
        result += f"🏷️ **Extracted Domains ({len(domains)}):**\n"
        for domain in domains[:10]:  # Show first 10 domains
            result += f"• `{domain}`\n"
        if len(domains) > 10:
            result += f"*... and {len(domains) - 10} more domains*\n"
    
    if not ips and not urls and not domains:
        result += "❓ **No IPs, URLs, or domains extracted from website content**"
    
    return result

def load_threat_lists():
    """Load all threat intelligence lists into memory"""
    print("Loading threat intelligence lists (load threat lists)...")
    
    # Domain lists
    load_list_to_cache('AbuseDomains.txt', 'abuse_domains')
    load_list_to_cache('MalwareDomains.txt', 'malware_domains')
    load_list_to_cache('PhishingDomains.txt', 'phishing_domains')
    load_list_to_cache('SpamDomains.txt', 'spam_domains')
    load_list_to_cache('WhiteListDomains.txt', 'whitelist_domains')
    load_list_to_cache('MiningDomains.txt', 'mining_domains')
    
    # Subdomain lists
    load_list_to_cache('AbuseSubDomains.txt', 'abuse_subdomains')
    load_list_to_cache('MalwareSubDomains.txt', 'malware_subdomains')
    load_list_to_cache('PhishingSubDomains.txt', 'phishing_subdomains')
    load_list_to_cache('SpamSubDomains.txt', 'spam_subdomains')
    load_list_to_cache('WhiteListSubDomains.txt', 'whitelist_subdomains')
    load_list_to_cache('MiningSubDomains.txt', 'mining_subdomains')
    
    # IP lists
    load_list_to_cache('IPv4Malware.txt', 'malware_ips')
    load_list_to_cache('IPv4PhishingActive.txt', 'phishing_ips')
    load_list_to_cache('IPv4Spam.txt', 'spam_ips')
    load_list_to_cache('IPv4DDoS.txt', 'ddos_ips')
    load_list_to_cache('IPv4BruteForce.txt', 'bruteforce_ips')
    load_list_to_cache('IPv4Whitelist.txt', 'whitelist_ips')
    
    print("Threat intelligence lists loaded successfully!")

def load_list_to_cache(filename: str, cache_key: str):
    """Load a text file into the specified cache set"""
    filepath = os.path.join(THREAT_LISTS_DIR, filename)
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        threat_cache[cache_key].add(line.lower())
            print(f"Loaded {len(threat_cache[cache_key])} entries from {filename}")
        except Exception as e:
            print(f"Error loading {filename}: {e}")

def load_compressed_list_to_cache(filename: str, cache_key: str):
    """Load a compressed file into the specified cache set - fallback to .txt version"""
    # Since .txt versions are available, use them directly
    txt_filename = filename.replace('.7z', '.txt')
    load_list_to_cache(txt_filename, cache_key)

def load_learning_data():
    """Load learning data from file"""
    global learning_data
    try:
        if os.path.exists(LEARNING_DATA_FILE):
            with open(LEARNING_DATA_FILE, 'r') as f:
                data = json.load(f)
                # Convert sets back from lists
                learning_data['auto_whitelist'] = set(data.get('auto_whitelist', []))
                for category in learning_data['auto_blacklist']:
                    learning_data['auto_blacklist'][category] = set(data.get('auto_blacklist', {}).get(category, []))
                learning_data['user_feedback'] = data.get('user_feedback', {})
                learning_data['feedback_stats'] = data.get('feedback_stats', learning_data['feedback_stats'])
                print(f"Loaded learning data with {len(learning_data['user_feedback'])} feedback entries")
    except Exception as e:
        print(f"Error loading learning data: {e}")

def save_learning_data():
    """Save learning data to file"""
    try:
        # Convert sets to lists for JSON serialization
        data_to_save = {
            'auto_whitelist': list(learning_data['auto_whitelist']),
            'auto_blacklist': {
                category: list(domains) for category, domains in learning_data['auto_blacklist'].items()
            },
            'user_feedback': learning_data['user_feedback'],
            'feedback_stats': learning_data['feedback_stats']
        }
        with open(LEARNING_DATA_FILE, 'w') as f:
            json.dump(data_to_save, f, indent=2)
        print("Learning data saved successfully")
    except Exception as e:
        print(f"Error saving learning data: {e}")

def load_pending_feedback():
    """Load pending feedback from file"""
    global pending_feedback
    try:
        if os.path.exists(PENDING_FEEDBACK_FILE):
            with open(PENDING_FEEDBACK_FILE, 'r') as f:
                pending_feedback = json.load(f)
                print(f"Loaded {len(pending_feedback)} pending feedback entries")
    except Exception as e:
        print(f"Error loading pending feedback: {e}")

def save_pending_feedback():
    """Save pending feedback to file"""
    try:
        with open(PENDING_FEEDBACK_FILE, 'w') as f:
            json.dump(pending_feedback, f, indent=2)
    except Exception as e:
        print(f"Error saving pending feedback: {e}")

def apply_user_learning(domain_or_ip: str) -> Dict[str, List[str]]:
    """Apply user learning data to threat intelligence check"""
    domain_or_ip = domain_or_ip.lower()
    results = {
        'threats': [],
        'whitelist': [],
        'categories': []
    }
    
    # Check user whitelist
    if domain_or_ip in learning_data['auto_whitelist']:
        results['whitelist'].append('User Whitelisted')
    
    # Check user blacklists
    for category, domains in learning_data['auto_blacklist'].items():
        if domain_or_ip in domains:
            results['threats'].append(f'User Blacklisted ({category.title()})')
            results['categories'].append(category)
    
    return results

def process_user_feedback(domain_or_ip: str, feedback_type: str, category: str = None, user_id: str = None):
    """Process user feedback and update learning data"""
    domain_or_ip = domain_or_ip.lower()
    timestamp = datetime.now().isoformat()
    
    # Store feedback
    if domain_or_ip not in learning_data['user_feedback']:
        learning_data['user_feedback'][domain_or_ip] = []
    
    feedback_entry = {
        'type': feedback_type,
        'category': category,
        'user_id': user_id,
        'timestamp': timestamp
    }
    learning_data['user_feedback'][domain_or_ip].append(feedback_entry)
    
    # Update counters
    learning_data['feedback_stats']['total_feedback'] += 1
    
    # Apply learning
    if feedback_type == 'whitelist':
        learning_data['auto_whitelist'].add(domain_or_ip)
        # Remove from blacklists if present
        for cat_domains in learning_data['auto_blacklist'].values():
            cat_domains.discard(domain_or_ip)
    elif feedback_type == 'blacklist' and category:
        learning_data['auto_blacklist'][category].add(domain_or_ip)
        # Remove from whitelist if present
        learning_data['auto_whitelist'].discard(domain_or_ip)
    elif feedback_type == 'false_positive':
        learning_data['feedback_stats']['false_positives'] += 1
        # Add to whitelist to prevent future false positives
        learning_data['auto_whitelist'].add(domain_or_ip)
    elif feedback_type == 'false_negative':
        learning_data['feedback_stats']['false_negatives'] += 1
        # Add to appropriate blacklist category
        if category:
            learning_data['auto_blacklist'][category].add(domain_or_ip)
    
    # Save learning data
    save_learning_data()
    
    return feedback_entry

def check_threat_intel(domain_or_ip: str) -> Dict[str, List[str]]:
    """Check domain/IP against threat intelligence lists including user learning"""
    domain_or_ip = domain_or_ip.lower().strip()

    # Strip leading 'www.' if it's a domain
    if domain_or_ip.startswith('www.') and '.' in domain_or_ip[4:]:
        domain_or_ip = domain_or_ip[4:]

    results = {
        'threats': [],
        'whitelist': [],
        'categories': []
    }

    # First check user learning data
    user_results = apply_user_learning(domain_or_ip)
    results['threats'].extend(user_results['threats'])
    results['whitelist'].extend(user_results['whitelist'])
    results['categories'].extend(user_results['categories'])

    # If user whitelisted, skip other checks
    if user_results['whitelist']:
        return results

    # Check domain lists
    if domain_or_ip in threat_cache['abuse_domains']:
        results['threats'].append('Abuse Domain')
        results['categories'].append('abuse')
    if domain_or_ip in threat_cache['malware_domains']:
        results['threats'].append('Malware Domain')
        results['categories'].append('malware')
    if domain_or_ip in threat_cache['phishing_domains']:
        results['threats'].append('Phishing Domain')
        results['categories'].append('phishing')
    if domain_or_ip in threat_cache['spam_domains']:
        results['threats'].append('Spam Domain')
        results['categories'].append('spam')
    if domain_or_ip in threat_cache['mining_domains']:
        results['threats'].append('Mining Domain')
        results['categories'].append('mining')

    # Check subdomain lists
    if domain_or_ip in threat_cache['abuse_subdomains']:
        results['threats'].append('Abuse Subdomain')
        results['categories'].append('abuse')
    if domain_or_ip in threat_cache['malware_subdomains']:
        results['threats'].append('Malware Subdomain')
        results['categories'].append('malware')
    if domain_or_ip in threat_cache['phishing_subdomains']:
        results['threats'].append('Phishing Subdomain')
        results['categories'].append('phishing')
    if domain_or_ip in threat_cache['spam_subdomains']:
        results['threats'].append('Spam Subdomain')
        results['categories'].append('spam')
    if domain_or_ip in threat_cache['mining_subdomains']:
        results['threats'].append('Mining Subdomain')
        results['categories'].append('mining')

    # Check IP lists
    if domain_or_ip in threat_cache['malware_ips']:
        results['threats'].append('Malware IP')
        results['categories'].append('malware')
    if domain_or_ip in threat_cache['phishing_ips']:
        results['threats'].append('Phishing IP')
        results['categories'].append('phishing')
    if domain_or_ip in threat_cache['spam_ips']:
        results['threats'].append('Spam IP')
        results['categories'].append('spam')
    if domain_or_ip in threat_cache['ddos_ips']:
        results['threats'].append('DDoS IP')
        results['categories'].append('ddos')
    if domain_or_ip in threat_cache['bruteforce_ips']:
        results['threats'].append('Brute Force IP')
        results['categories'].append('bruteforce')

    # Check whitelist
    if (domain_or_ip in threat_cache['whitelist_domains'] or 
        domain_or_ip in threat_cache['whitelist_subdomains'] or
        domain_or_ip in threat_cache['whitelist_ips']):
        results['whitelist'].append('Whitelisted')

    return results

def extract_review_and_risk(html_text: str) -> Tuple[str, str]:
    """Extract review and risk from GridinSoft response"""
    m = REVIEW_RE.search(html_text)
    review = html.unescape(m.group(1).strip()) if m else ""

    risk = "Unknown"
    pm = POINTS_RE.search(html_text)
    items = ITEM_RE.findall(html_text)
    if pm and items:
        dp = int(pm.group(1))
        idx = round(dp * (len(items) - 1) / 100)
        risk = html.unescape(items[idx].strip())

    return review, risk

def scan_gridinsoft(domain: str) -> Dict[str, str]:
    """Scan domain using GridinSoft with detailed logging"""
    slug = domain.replace(".", "-")
    url = f"{GRIDINSOFT_URL}{slug}"
    
    print(f"[i] Scanning {domain} via GridinSoft...")
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404 or "gridinsoft.com/410" in resp.url:
            print(f"[i] GridinSoft: {domain} not found in database")
            return {"domain": domain, "review": "", "risk": "Unknown"}
        else:
            review, risk = extract_review_and_risk(resp.text)
            print(f"[✓] GridinSoft scan successful for {domain}: {risk}")
            return {"domain": domain, "review": review, "risk": risk}
    except requests.RequestException as e:
        print(f"[!] GridinSoft error for {domain}: {e}")
        return {"domain": domain, "review": "", "risk": "Error", "error": str(e)}

def _make_request_with_retries(method, url, **kwargs):
    """Make HTTP request with retries and detailed logging"""
    backoff = 1
    for attempt in range(4):
        try:
            return requests.request(method, url, timeout=10, **kwargs)
        except (ConnectionError, Timeout) as e:
            if attempt < 3:
                print(f"[!] Network error ({e}), retrying in {backoff}s…")
                time.sleep(backoff)
                backoff *= 2
            else:
                raise

def scan_bitdefender(url: str) -> Dict:
    """
    Scan URL using Bitdefender TrafficLight API with detailed logging.
    Try each known Nimbus IP in turn, sending Host: header so we
    reach nimbus.bitdefender.net without needing DNS, and
    disable hostname checking on the cert.
    """
    params = {"url": url}
    headers = {
        CLIENT_ID_HEADER: CLIENT_ID,
        "Host": CLOUD_HOST,
    }
    
    for ip in NIMBUS_IPS:
        endpoint = f"https://{ip}{URL_STATUS_PATH}"
        print(f"[i] Trying Bitdefender IP {ip}…")
        try:
            # verify=False skips hostname check and cert validity
            resp = _make_request_with_retries(
                "GET",
                endpoint,
                params=params,
                headers=headers,
                verify=False
            )
            resp.raise_for_status()
            result = resp.json()
            print(f"[✓] Bitdefender scan successful via {ip}")
            return result
        except HTTPError as he:
            print(f"[!] HTTP error from {ip}: {he} - {he.response.text}")
            continue
        except Exception as e:
            print(f"[!] Failed at {ip}: {e}")
            continue
    
    # If we get here, none of the IPs worked
    raise ConnectionError(f"All Nimbus IPs failed: {NIMBUS_IPS}")

def format_bitdefender_status(bitdefender_result: dict) -> str:
    """Format Bitdefender status with proper classification based on domain_grey and categories"""
    if not isinstance(bitdefender_result, dict):
        return "❌ Error"
    
    # Check for domain_grey field first
    domain_grey = bitdefender_result.get('domain_grey', False)
    if domain_grey:
        return "⚠️ Harmful website"
    
    # Check categories
    categories = bitdefender_result.get('categories', [])
    status = bitdefender_result.get('status', 'Unknown')
    
    # If no categories and no grey, classify based on status or unknown
    if not categories or len(categories) == 0:
        if status == 'clean':
            return "✅ Clean"
        elif status == 'suspicious':
            return "🔶 Suspicious"
        else:
            return "❓ Unknown"
    
    # If there are categories but no grey, then it's clean
    return "✅ Clean"

def extract_urls_from_text(text: str) -> List[str]:
    """Enhanced URL extraction from message text with unified patterns"""
    if not text:
        return []
    
    urls = set()  # Use set to avoid duplicates
    
    # Apply all URL patterns
    for pattern in URL_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            # Handle tuple matches (from group captures)
            if isinstance(match, tuple):
                match = match[0] if match[0] else (match[1] if len(match) > 1 else '')
            
            if match:
                urls.add(match.strip())
    
    # Clean up and normalize URLs
    clean_urls = []
    for url in urls:
        url = url.strip()
        
        # Skip empty or very short URLs
        if not url or len(url) < 4:
            continue
        
        # Remove trailing punctuation
        url = url.rstrip('.,!?;)')
        
        # Handle obfuscated URLs (replace [.] with .)
        url = url.replace('[.]', '.').replace('[dot]', '.')
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://', 'ftp://', 'ftps://', 'mailto:')):
            if url.startswith('www.'):
                url = 'https://' + url
            elif '.' in url and not url.startswith(('tel:')):
                # Check if it looks like a domain
                if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}', url):
                    url = 'https://' + url
        
        # Validate URL format and add to results
        if is_valid_url(url) and url not in clean_urls:
            clean_urls.append(url)
    
    return clean_urls

async def perform_auto_scan(url: str) -> Dict:
    """Perform automatic scan of URL"""
    loop = asyncio.get_event_loop()
    
    # Extract domain from URL for threat intel check
    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
    
    try:
        # Run all scans concurrently
        gridinsoft_task = loop.run_in_executor(None, scan_gridinsoft, domain)
        bitdefender_task = loop.run_in_executor(None, scan_bitdefender, url)
        threat_intel_task = loop.run_in_executor(None, check_threat_intel, domain)
        
        gridinsoft_result = await gridinsoft_task
        bitdefender_result = await bitdefender_task
        threat_intel_result = await threat_intel_task
        
        return {
            'gridinsoft': gridinsoft_result,
            'bitdefender': bitdefender_result,
            'threat_intel': threat_intel_result
        }
    except Exception as e:
        return {'error': str(e)}

def format_auto_scan_results(url: str, scan_results: Dict) -> str:
    if 'error' in scan_results:
        return f"⚠️ **Auto-scan failed for** `{url}`: {scan_results['error']}"

    grid = scan_results.get('gridinsoft', {}) or {}
    bd = scan_results.get('bitdefender', {}) or {}
    intel = scan_results.get('threat_intel', {}) or {}

    gs_risk = grid.get('risk', 'Unknown')
    gs_risk_lower = gs_risk.lower()
    gd_clean_labels = {'gd_clean', 'trusted but verify'}
    gs_clean_labels = {'clean', 'safe', 'low', 'trusted but verify'}
    gd_clean = gs_risk_lower in gd_clean_labels
    gs_clean = gs_risk_lower in gs_clean_labels

    bd_status = bd.get('status', 'Unknown')
    bd_cats = bd.get('categories') or []
    bd_grey = bd.get('domain_grey', False)
    bd_clean = bool(bd_cats) and not bd_grey

    intel_threats = intel.get('threats', []) or []
    intel_clean = not intel_threats

    if gs_risk_lower == 'trusted but verify':
        gs_label = "GridinSoft: Trusted but verify"
    elif gd_clean:
        gs_label = "GridinSoft: Clean"
    else:
        gs_label = f"GridinSoft: {gs_risk}"

    if bd_clean:
        bd_label = "Bitdefender: Clean"
    elif bd_status.lower() == 'suspicious':
        bd_label = "Bitdefender: Harmful"
    else:
        bd_label = f"Bitdefender: {bd_status}"

    verdicts = [gs_label, bd_label]

    # Define if engines are definitely bad (not unknown)
    gs_bad = gs_risk_lower not in gs_clean_labels and gs_risk_lower != 'unknown'
    bd_status_lower = bd_status.lower()
    bd_bad = bd_status_lower == 'suspicious'

    # FULLY CLEAN CASE: no false positive, just TRUSTED
    if gd_clean and bd_clean and intel_clean:
        msg = (
            f"✅ **TRUSTED** ✅\n"
            f"**URL:** `{url}`\n"
            f"**Verdicts:** {', '.join(verdicts)}\n"
            f"**Note:** All engines clean, no intel threats.\n"
        )
        if LEARNING_MODE_ENABLED:
            msg += "*Feedback: `!feedback verify`*\n"
        return msg

    # POSSIBLE FALSE POSITIVE only if intel clean and one engine clean and other definitely bad (not unknown)
    if intel_clean and (
        (gs_clean and bd_bad) or
        (bd_clean and gs_bad)
    ):
        msg = (
            f"⚠️ **Possible false positive** ⚠️\n"
            f"**URL:** `{url}`\n"
            f"**Verdicts:** {', '.join(verdicts)}\n"
            f"**Note:** One engine clean, one suspicious, and no intel threats.\n"
        )
        if LEARNING_MODE_ENABLED:
            msg += "*Feedback: `!feedback falsepositive`*\n"
        return msg

    # Otherwise, threat summary
    threats = []
    if intel_threats:
        threats.append(f"Intel: {', '.join(intel_threats[:2])}")
    threats += verdicts

    msg = (
        f"🚨 **THREAT SUMMARY** 🚨\n"
        f"**URL:** `{url}`\n"
        f"**Threats:** {', '.join(threats)}\n"
        f"**Action:** ⚠️ **REVIEW or AVOID**\n"
    )
    if LEARNING_MODE_ENABLED:
        msg += "*Feedback: `!feedback block <category>`*\n"

    msg += (
        f"\n🛡️ **GridinSoft:**\n"
        f"• Risk: {gs_risk}\n"
        + (f"• Review: {grid.get('review')}\n" if grid.get('review') else "")
        + f"\n🛡️ **Bitdefender:**\n"
        f"• Status: {bd_status}\n"
        f"• Categories: {', '.join(bd_cats) or 'None'}\n"
        f"• Greylisted: {bd_grey}\n"
        + (f"• Risk Score: {bd.get('risk_score')}\n" if 'risk_score' in bd else "")
        + f"• Raw: `{json.dumps(bd)}`"
    )
    return msg

def format_scan_results(url: str,
                        gridinsoft_result: Dict,
                        bitdefender_result: Dict,
                        threat_intel: Dict) -> str:
    domain = url.split('//')[-1].split('/')[0]

    gs_risk = gridinsoft_result.get('risk', 'Unknown')
    gs_risk_lower = gs_risk.lower()

    gd_clean_labels = {'gd_clean', 'trusted but verify'}
    gs_clean_labels = {'clean', 'safe', 'low', 'trusted but verify'}
    gd_clean = gs_risk_lower in gd_clean_labels
    gs_clean = gs_risk_lower in gs_clean_labels

    bd_status = bitdefender_result.get('status', 'Unknown')
    bd_cats = bitdefender_result.get('categories') or []
    bd_grey = bitdefender_result.get('domain_grey', False)
    bd_clean = bool(bd_cats) and not bd_grey

    intel_threats = threat_intel.get('threats', []) or []
    intel_clean = not intel_threats

    if gs_risk_lower == 'trusted but verify':
        gs_label = "GridinSoft: Trusted but verify"
    elif gd_clean:
        gs_label = "GridinSoft: Clean"
    else:
        gs_label = f"GridinSoft: {gs_risk}"

    if bd_clean:
        bd_label = "Bitdefender: Clean"
    elif bd_status.lower() == 'suspicious':
        bd_label = "Bitdefender: Harmful"
    else:
        bd_label = f"Bitdefender: {bd_status}"

    verdicts = [gs_label, bd_label]

    gs_bad = gs_risk_lower not in gs_clean_labels and gs_risk_lower != 'unknown'
    bd_status_lower = bd_status.lower()
    bd_bad = bd_status_lower == 'suspicious'

    if gd_clean and bd_clean and intel_clean:
        result = (
            f"✅ **TRUSTED** ✅\n"
            f"**URL:** `{url}`\n"
            f"**Domain:** `{domain}`\n"
            f"**Verdicts:** {', '.join(verdicts)}\n"
            f"**Note:** All engines clean, no intel threats.\n"
        )
        if LEARNING_MODE_ENABLED:
            result += "*Feedback: `!feedback verify`*\n"
        return result

    if intel_clean and (
        (gs_clean and bd_bad) or
        (bd_clean and gs_bad)
    ):
        result = (
            f"⚠️ **Possible false positive** ⚠️\n"
            f"**URL:** `{url}`\n"
            f"**Domain:** `{domain}`\n"
            f"**Verdicts:** {', '.join(verdicts)}\n"
            f"**Note:** One engine clean, one suspicious, and no intel threats.\n"
        )
        if LEARNING_MODE_ENABLED:
            result += "*Feedback: `!feedback falsepositive`*\n"
        return result

    threats = []
    if intel_threats:
        threats.append(f"Intel: {', '.join(intel_threats)}")
    threats += verdicts

    result = (
        f"🚨 **THREAT SUMMARY** 🚨\n"
        f"**URL:** `{url}`\n"
        f"**Domain:** `{domain}`\n"
        f"**Threats:** {', '.join(threats)}\n"
        f"**Action:** ⚠️ **REVIEW or AVOID**\n"
    )
    if LEARNING_MODE_ENABLED:
        result += "*Feedback: `!feedback block <category>`*\n"

    result += (
        f"\n📊 **Threat Intelligence:**\n"
        + (f"✅ Whitelisted: {', '.join(threat_intel['whitelist'])}\n" if threat_intel.get('whitelist') else "")
        + (f"⚠️ Found in: {', '.join(intel_threats)}\n" if intel_threats else "❓ Not found\n")
        + f"\n🛡️ **GridinSoft Scan:**\n"
        + f"• Risk: {gs_risk}\n"
        + (f"📝 Review: {gridinsoft_result.get('review')}\n" if gridinsoft_result.get('review') else "")
        + f"\n🛡️ **Bitdefender Scan:**\n"
        + f"• Status: {bd_status}\n"
        + f"• Categories: {', '.join(bd_cats) or 'None'}\n"
        + f"• Greylisted: {bd_grey}\n"
        + (f"• Risk Score: {bitdefender_result['risk_score']}\n" if 'risk_score' in bitdefender_result else "")
        + f"• Raw: `{json.dumps(bitdefender_result)}`"
    )
    return result

@bot.event
async def on_message(message):
    """Enhanced message handler with improved URL scanning"""
    # Don't scan bot's own messages
    if message.author == bot.user:
        return
    
    # Check if auto-scanning is enabled
    if not AUTO_SCAN_ENABLED:
        await bot.process_commands(message)
        return
    
    # Check if channel is allowed (if specific channels are configured)
    if AUTO_SCAN_CHANNELS and message.channel.id not in AUTO_SCAN_CHANNELS:
        await bot.process_commands(message)
        return
    
    # Enhanced URL extraction
    urls = extract_urls_from_text(message.content)
    
    if urls:
        # Send initial scanning message
        scan_message = await message.channel.send(f"🔍 Scanning {len(urls)} URL(s) detected in message...")
        
        try:
            # Process each URL
            all_results = []
            for i, url in enumerate(urls):
                try:
                    # Update progress
                    await scan_message.edit(content=f"🔍 Scanning URL {i+1}/{len(urls)}: `{url[:50]}...`")
                    
                    # Perform scan
                    scan_results = await perform_auto_scan(url)
                    
                    # Format results
                    formatted_result = format_auto_scan_results(url, scan_results)
                    all_results.append(formatted_result)
                    
                except Exception as e:
                    error_result = f"❌ Error scanning `{url}`: {str(e)}"
                    all_results.append(error_result)
            
            # Combine all results
            final_message = "\n\n".join(all_results)
            
            # Split message if too long
            if len(final_message) > 2000:
                chunks = [final_message[i:i+1900] for i in range(0, len(final_message), 1900)]
                await scan_message.edit(content=chunks[0])
                for chunk in chunks[1:]:
                    await message.channel.send(chunk)
            else:
                await scan_message.edit(content=final_message)
                
        except Exception as e:
            await scan_message.edit(content=f"❌ Auto-scan error: {str(e)}")
    
    # Process commands normally
    await bot.process_commands(message)

@bot.command(name="feedback_help", help="Show detailed help for feedback command")
async def feedback_help(ctx):
    """Show detailed help for the feedback command"""
    help_text = """
🧠 **Feedback Command Help**

**Usage:** `!feedback <domain/ip> <action> [category]`

**Actions:**
• `wrong` - Mark scan result as false positive (will whitelist)
• `correct` - Mark scan result as correct
• `block` / `blacklist` - Add to blacklist (requires category)
• `allow` / `whitelist` - Add to whitelist

**Categories** (required for blocking):
• `abuse` - Abuse/malicious content
• `malware` - Malware hosting
• `phishing` - Phishing attempts
• `spam` - Spam/unwanted content
• `mining` - Cryptocurrency mining

**Examples:**
• `!feedback example.com wrong` - Mark as false positive
• `!feedback badsite.com block malware` - Add to malware blacklist
• `!feedback goodsite.com allow` - Add to whitelist
• `!feedback suspicious.com block phishing` - Block as phishing

**Learning Mode Status:** {'✅ Enabled' if LEARNING_MODE_ENABLED else '❌ Disabled'}
"""
    await ctx.send(help_text)

@bot.command(name="feedback", help="Provide feedback on scan results")
async def feedback(ctx, domain_or_ip: str = None, action: str = None, category: str = None):
    """Discord command: !feedback <domain/ip> <action> [category]"""
    
    if not LEARNING_MODE_ENABLED:
        await ctx.send("❌ Learning mode is currently disabled.")
        return
    
    # Check if required parameters are provided
    if not domain_or_ip:
        await ctx.send("❌ **Missing domain/IP!** Usage: `!feedback <domain/ip> <action> [category]`\n\n"
                      "**Examples:**\n"
                      "• `!feedback example.com wrong` - Mark as false positive\n"
                      "• `!feedback badsite.com block malware` - Add to malware blacklist\n"
                      "• `!feedback goodsite.com allow` - Add to whitelist")
        return
    
    if not action:
        await ctx.send("❌ **Missing action!** Usage: `!feedback <domain/ip> <action> [category]`\n\n"
                      "**Valid actions:** wrong, correct, block, allow, whitelist, blacklist\n\n"
                      "**Examples:**\n"
                      "• `!feedback example.com wrong` - Mark as false positive\n"
                      "• `!feedback badsite.com block malware` - Add to malware blacklist\n"
                      "• `!feedback goodsite.com allow` - Add to whitelist")
        return
    
    domain_or_ip = domain_or_ip.lower()
    action = action.lower()
    
    valid_actions = ['wrong', 'correct', 'block', 'allow', 'whitelist', 'blacklist']
    valid_categories = ['abuse', 'malware', 'phishing', 'spam', 'mining']
    
    if action not in valid_actions:
        await ctx.send(f"❌ Invalid action. Use: {', '.join(valid_actions)}")
        return
    
    if action in ['block', 'blacklist'] and not category:
        await ctx.send(f"❌ Category required for blocking. Use: {', '.join(valid_categories)}")
        return
    
    if category and category not in valid_categories:
        await ctx.send(f"❌ Invalid category. Use: {', '.join(valid_categories)}")
        return
    
    # Process feedback (rest of your existing code remains the same)
    try:
        feedback_type = None
        if action in ['wrong']:
            feedback_type = 'false_positive'
        elif action in ['correct']:
            feedback_type = 'correct'
        elif action in ['block', 'blacklist']:
            feedback_type = 'blacklist'
        elif action in ['allow', 'whitelist']:
            feedback_type = 'whitelist'
        
        feedback_entry = process_user_feedback(
            domain_or_ip, 
            feedback_type, 
            category, 
            str(ctx.author.id)
        )
        
        # Format response
        response = f"✅ **Feedback recorded for** `{domain_or_ip}`\n"
        response += f"**Action:** {action.title()}\n"
        if category:
            response += f"**Category:** {category.title()}\n"
        response += f"**User:** {ctx.author.mention}\n"
        response += f"**Timestamp:** {feedback_entry['timestamp']}\n\n"
        
        if feedback_type == 'whitelist':
            response += "🔓 Domain added to user whitelist"
        elif feedback_type == 'blacklist':
            response += f"🔒 Domain added to user blacklist ({category})"
        elif feedback_type == 'false_positive':
            response += "🔓 Domain whitelisted to prevent future false positives"
        
        await ctx.send(response)
        
    except Exception as e:
        await ctx.send(f"❌ Error processing feedback: {str(e)}")

@feedback.error
async def feedback_error(ctx, error):
    """Handle feedback command errors"""
    if isinstance(error, commands.MissingRequiredArgument):
        if error.param.name == 'domain_or_ip':
            await ctx.send("❌ **Missing domain/IP!** Usage: `!feedback <domain/ip> <action> [category]`\n\n"
                          "**Examples:**\n"
                          "• `!feedback example.com wrong` - Mark as false positive\n"
                          "• `!feedback badsite.com block malware` - Add to malware blacklist\n"
                          "• `!feedback goodsite.com allow` - Add to whitelist")
        elif error.param.name == 'action':
            await ctx.send("❌ **Missing action!** Usage: `!feedback <domain/ip> <action> [category]`\n\n"
                          "**Valid actions:** wrong, correct, block, allow, whitelist, blacklist\n\n"
                          "**Examples:**\n"
                          "• `!feedback example.com wrong` - Mark as false positive\n"
                          "• `!feedback badsite.com block malware` - Add to malware blacklist\n"
                          "• `!feedback goodsite.com allow` - Add to whitelist")
    else:
        await ctx.send(f"❌ **Error with feedback command:** {str(error)}")

@bot.event
async def on_command_error(ctx, error):
    """Global error handler for all commands"""
    if isinstance(error, commands.MissingRequiredArgument):
        command_name = ctx.command.name
        param_name = error.param.name
        
        if command_name == "feedback":
            if param_name == "domain_or_ip":
                await ctx.send("❌ **Missing domain/IP!** Usage: `!feedback <domain/ip> <action> [category]`\n\n"
                              "**Examples:**\n"
                              "• `!feedback example.com wrong` - Mark as false positive\n"
                              "• `!feedback badsite.com block malware` - Add to malware blacklist\n"
                              "• `!feedback goodsite.com allow` - Add to whitelist")
            elif param_name == "action":
                await ctx.send("❌ **Missing action!** Usage: `!feedback <domain/ip> <action> [category]`\n\n"
                              "**Valid actions:** wrong, correct, block, allow, whitelist, blacklist\n\n"
                              "**Examples:**\n"
                              "• `!feedback example.com wrong` - Mark as false positive\n"
                              "• `!feedback badsite.com block malware` - Add to malware blacklist\n"
                              "• `!feedback goodsite.com allow` - Add to whitelist")
        else:
            await ctx.send(f"❌ **Missing required parameter `{param_name}`** for command `{command_name}`")
    
    elif isinstance(error, commands.CommandNotFound):
        # Silently ignore command not found errors
        pass
    
    elif isinstance(error, commands.MissingPermissions):
        await ctx.send("❌ You don't have permission to use this command.")
    
    else:
        # Log other errors for debugging
        print(f"Command error: {error}")
        await ctx.send(f"❌ An error occurred while processing the command: {str(error)}")

@bot.command(name="learning", help="Show learning mode statistics and controls")
async def learning_stats(ctx, action: str = "stats"):
    """Discord command: !learning [stats/enable/disable/reset]"""
    
    if action.lower() == "enable":
        if not ctx.author.guild_permissions.manage_messages:
            await ctx.send("❌ You need 'Manage Messages' permission to control learning mode.")
            return
        
        global LEARNING_MODE_ENABLED
        LEARNING_MODE_ENABLED = True
        await ctx.send("✅ **Learning mode enabled** - Users can now provide feedback on scan results")
        
    elif action.lower() == "disable":
        if not ctx.author.guild_permissions.manage_messages:
            await ctx.send("❌ You need 'Manage Messages' permission to control learning mode.")
            return
        
        LEARNING_MODE_ENABLED = False
        await ctx.send("❌ **Learning mode disabled** - Feedback commands will be ignored")
        
    elif action.lower() == "reset":
        if not ctx.author.guild_permissions.administrator:
            await ctx.send("❌ You need 'Administrator' permission to reset learning data.")
            return
        
        # Reset learning data
        learning_data['user_feedback'] = {}
        learning_data['auto_whitelist'] = set()
        learning_data['auto_blacklist'] = {cat: set() for cat in learning_data['auto_blacklist']}
        learning_data['feedback_stats'] = {
            'total_feedback': 0,
            'correct_predictions': 0,
            'false_positives': 0,
            'false_negatives': 0
        }
        save_learning_data()
        await ctx.send("🔄 **Learning data reset successfully**")
        
    elif action.lower() == "stats":
        status = "✅ Enabled" if LEARNING_MODE_ENABLED else "❌ Disabled"
        stats = learning_data['feedback_stats']
        
        response = f"🧠 **Learning Mode Status:** {status}\n\n"
        response += f"📊 **Feedback Statistics:**\n"
        response += f"• Total Feedback: {stats['total_feedback']}\n"
        response += f"• False Positives: {stats['false_positives']}\n"
        response += f"• False Negatives: {stats['false_negatives']}\n"
        response += f"• Correct Predictions: {stats['correct_predictions']}\n\n"
        
        response += f"🔓 **User Whitelist:** {len(learning_data['auto_whitelist'])} domains\n"
        response += f"🔒 **User Blacklists:**\n"
        for category, domains in learning_data['auto_blacklist'].items():
            response += f"• {category.title()}: {len(domains)} domains\n"
        
        total_learned = len(learning_data['auto_whitelist']) + sum(len(d) for d in learning_data['auto_blacklist'].values())
        response += f"\n🎯 **Total Learned Domains:** {total_learned}"
        
        await ctx.send(response)
        
    else:
        await ctx.send("❓ **Usage:** `!learning [stats/enable/disable/reset]`")

@bot.command(name="learned", help="Show learned domains for a specific category")
async def learned_domains(ctx, category: str = "all"):
    """Discord command: !learned [category/all]"""
    
    if not LEARNING_MODE_ENABLED:
        await ctx.send("❌ Learning mode is currently disabled.")
        return
    
    category = category.lower()
    
    if category == "all":
        response = "🧠 **All Learned Domains:**\n\n"
        
        if learning_data['auto_whitelist']:
            response += f"🔓 **Whitelist ({len(learning_data['auto_whitelist'])}):**\n"
            whitelist_sample = list(learning_data['auto_whitelist'])[:10]
            response += "```\n" + "\n".join(whitelist_sample) + "\n```"
            if len(learning_data['auto_whitelist']) > 10:
                response += f"*... and {len(learning_data['auto_whitelist']) - 10} more*\n"
        
        for cat, domains in learning_data['auto_blacklist'].items():
            if domains:
                response += f"\n🔒 **{cat.title()} Blacklist ({len(domains)}):**\n"
                domain_sample = list(domains)[:5]
                response += "```\n" + "\n".join(domain_sample) + "\n```"
                if len(domains) > 5:
                    response += f"*... and {len(domains) - 5} more*\n"
        
        if len(response) > 2000:
            await ctx.send(response[:2000])
            await ctx.send(response[2000:])
        else:
            await ctx.send(response)
            
    elif category == "whitelist":
        if not learning_data['auto_whitelist']:
            await ctx.send("📝 No domains in user whitelist")
            return
        
        domains = list(learning_data['auto_whitelist'])
        response = f"🔓 **User Whitelist ({len(domains)} domains):**\n"
        response += "```\n" + "\n".join(domains[:50]) + "\n```"
        if len(domains) > 50:
            response += f"*... and {len(domains) - 50} more*"
        
        await ctx.send(response)
        
    elif category in learning_data['auto_blacklist']:
        domains = learning_data['auto_blacklist'][category]
        if not domains:
            await ctx.send(f"📝 No domains in {category} blacklist")
            return
        
        domain_list = list(domains)
        response = f"🔒 **{category.title()} Blacklist ({len(domain_list)} domains):**\n"
        response += "```\n" + "\n".join(domain_list[:50]) + "\n```"
        if len(domain_list) > 50:
            response += f"*... and {len(domain_list) - 50} more*"
        
        await ctx.send(response)
        
    else:
        valid_categories = ['all', 'whitelist'] + list(learning_data['auto_blacklist'].keys())
        await ctx.send(f"❓ **Valid categories:** {', '.join(valid_categories)}")

@bot.command(name="autoscan", help="Toggle auto-scanning on/off")
@commands.has_permissions(manage_messages=True)
async def toggle_autoscan(ctx, action: str = "status"):
    """Discord command: !autoscan [on/off/status]"""
    global AUTO_SCAN_ENABLED
    
    if action.lower() == "on":
        AUTO_SCAN_ENABLED = True
        await ctx.send("✅ **Auto-scanning enabled** - URLs posted in chat will be automatically scanned")
    elif action.lower() == "off":
        AUTO_SCAN_ENABLED = False
        await ctx.send("❌ **Auto-scanning disabled** - URLs will not be automatically scanned")
    elif action.lower() == "status":
        status = "✅ Enabled" if AUTO_SCAN_ENABLED else "❌ Disabled"
        await ctx.send(f"📊 **Auto-scan Status:** {status}")
    else:
        await ctx.send("❓ **Usage:** `!autoscan [on/off/status]`")

@bot.command(name="bulk_scan", help="Scan multiple URLs at once")
async def bulk_scan(ctx, *urls):
    """Discord command: !bulk_scan <url1> <url2> ... - Scan multiple URLs"""
    if not urls:
        await ctx.send("❌ Please provide at least one URL to scan.\n**Usage:** `!bulk_scan <url1> <url2> <url3>`")
        return
    
    if len(urls) > 10:
        await ctx.send("❌ Maximum 10 URLs per bulk scan to avoid spam.")
        return
    
    message = await ctx.send(f"🔍 Bulk scanning {len(urls)} URLs...")
    
    try:
        results = []
        for i, url in enumerate(urls):
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Update progress
            await message.edit(content=f"🔍 Scanning URL {i+1}/{len(urls)}: `{url[:50]}...`")
            
            # Perform scan
            scan_results = await perform_auto_scan(url)
            formatted_result = format_auto_scan_results(url, scan_results)
            results.append(formatted_result)
        
        # Combine results
        final_message = f"📊 **Bulk Scan Complete ({len(urls)} URLs)**\n\n"
        final_message += "\n\n".join(results)
        
        # Split message if too long
        if len(final_message) > 2000:
            chunks = [final_message[i:i+1900] for i in range(0, len(final_message), 1900)]
            await message.edit(content=chunks[0])
            for chunk in chunks[1:]:
                await ctx.send(chunk)
        else:
            await message.edit(content=final_message)
            
    except Exception as e:
        await message.edit(content=f"❌ Bulk scan error: {str(e)}")

@bot.command(name="scan", help="Comprehensive scan using GridinSoft, Bitdefender, and threat intelligence")
async def scan_url(ctx, url: str):
    """Enhanced scan command with better error handling"""
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    message = await ctx.send(f"🔍 Scanning `{url}`...")
    
    try:
        # Set a timeout for the entire scan process
        scan_results = await asyncio.wait_for(perform_auto_scan(url), timeout=60)
        
        # Use the enhanced format for detailed results
        if 'error' in scan_results:
            await message.edit(content=f"❌ Scan failed: {scan_results['error']}")
            return
        
        # Format comprehensive results
        domain = url.replace('http://', '').replace('https://', '').split('/')[0]
        formatted_result = format_scan_results(
            url, 
            scan_results.get('gridinsoft', {}), 
            scan_results.get('bitdefender', {}), 
            scan_results.get('threat_intel', {})
        )
        
        # Add learning mode feedback option
        if LEARNING_MODE_ENABLED:
            formatted_result += f"\n\n🧠 **Feedback Options:**\n"
            formatted_result += f"• `!feedback {domain} wrong` - Report false positive\n"
            formatted_result += f"• `!feedback {domain} block <category>` - Report missed threat\n"
            formatted_result += f"• `!feedback {domain} allow` - Mark as safe"
        
        await message.edit(content=formatted_result)
        
    except asyncio.TimeoutError:
        await message.edit(content=f"⏱️ Scan timeout for `{url}` - taking too long to complete")
    except Exception as e:
        await message.edit(content=f"❌ Scan error: {str(e)}")

@bot.command(name="gridinsoft", help="Scan URL using GridinSoft only")
async def gridinsoft_scan(ctx, url: str):
    """Discord command: !gridinsoft <url>"""
    message = await ctx.send(f"🔍 GridinSoft scanning `{url}`...")
    
    try:
        loop = asyncio.get_event_loop()
        domain = url.replace('http://', '').replace('https://', '').split('/')[0]
        result = await loop.run_in_executor(None, scan_gridinsoft, domain)
        
        response = f"🛡️ **GridinSoft Scan Result for:** `{url}`\n\n"
        if result.get('error'):
            response += f"❌ Error: {result['error']}"
        else:
            risk = result.get('risk', 'Unknown')
            review = result.get('review', '')
            response += f"Risk Level: {risk}\n"
            if review:
                response += f"Review: {review}"
        
        await message.edit(content=response)
        
    except Exception as e:
        await message.edit(content=f"❌ Error scanning with GridinSoft: {str(e)}")

@bot.command(name="bitdefender", help="Scan URL using Bitdefender only")
async def bitdefender_scan(ctx, url: str):
    """Discord command: !bitdefender <url>"""
    message = await ctx.send(f"🔍 Bitdefender scanning `{url}`...")
    
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, scan_bitdefender, url)
        
        response = f"🛡️ **Bitdefender Scan Result for:** `{url}`\n\n"
        if isinstance(result, dict):
            formatted_status = format_bitdefender_status(result)
            response += f"**Status:** {formatted_status}\n"
            
            if 'categories' in result and result['categories']:
                response += f"**Categories:** {', '.join(result['categories'])}\n"
            
            if 'risk_score' in result:
                response += f"**Risk Score:** {result['risk_score']}\n"
            
            if 'scan_time' in result:
                response += f"**Scan Time:** {result['scan_time']}\n"
            
            # Show full result for detailed analysis
            response += f"**Full Result:** ```json\n{result}\n```"
        else:
            response += f"**Result:** {result}"
        
        # Split message if too long
        if len(response) > 2000:
            chunks = [response[i:i+2000] for i in range(0, len(response), 2000)]
            await message.edit(content=chunks[0])
            for chunk in chunks[1:]:
                await ctx.send(chunk)
        else:
            await message.edit(content=response)
        
    except Exception as e:
        await message.edit(content=f"❌ Error scanning with Bitdefender: {str(e)}")

@bot.command(name="intel", help="Check domain/IP against threat intelligence lists")
async def threat_intel_check(ctx, domain_or_ip: str):
    """Discord command: !intel <domain_or_ip>"""
    message = await ctx.send(f"🔍 Checking threat intelligence for `{domain_or_ip}`...")
    
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, check_threat_intel, domain_or_ip)
        
        response = f"📊 **Threat Intelligence for:** `{domain_or_ip}`\n\n"
        
        if result['whitelist']:
            response += f"✅ **Whitelist Status:** {', '.join(result['whitelist'])}\n\n"
        
        if result['threats']:
            response += f"⚠️ **Threats Found:** {', '.join(result['threats'])}\n"
            response += f"🏷️ **Categories:** {', '.join(set(result['categories']))}\n"
        else:
            response += "✅ **No threats found in our intelligence lists**"
        
        await message.edit(content=response)
        
    except Exception as e:
        await message.edit(content=f"❌ Error checking threat intelligence: {str(e)}")

@bot.command(name="stats", help="Show threat intelligence statistics")
async def stats(ctx):
    """Discord command: !stats"""
    response = "📊 **Threat Intelligence Statistics:**\n\n"
    
    response += f"🚨 **Domains:**\n"
    response += f"• Abuse: {len(threat_cache['abuse_domains']):,}\n"
    response += f"• Malware: {len(threat_cache['malware_domains']):,}\n"
    response += f"• Phishing: {len(threat_cache['phishing_domains']):,}\n"
    response += f"• Spam: {len(threat_cache['spam_domains']):,}\n"
    response += f"• Mining: {len(threat_cache['mining_domains']):,}\n"
    response += f"• Whitelist: {len(threat_cache['whitelist_domains']):,}\n\n"
    
    response += f"🌐 **Subdomains:**\n"
    response += f"• Abuse: {len(threat_cache['abuse_subdomains']):,}\n"
    response += f"• Malware: {len(threat_cache['malware_subdomains']):,}\n"
    response += f"• Phishing: {len(threat_cache['phishing_subdomains']):,}\n"
    response += f"• Spam: {len(threat_cache['spam_subdomains']):,}\n"
    response += f"• Mining: {len(threat_cache['mining_subdomains']):,}\n"
    response += f"• Whitelist: {len(threat_cache['whitelist_subdomains']):,}\n\n"
    
    response += f"🌍 **IP Addresses:**\n"
    response += f"• Malware: {len(threat_cache['malware_ips']):,}\n"
    response += f"• Phishing: {len(threat_cache['phishing_ips']):,}\n"
    response += f"• Spam: {len(threat_cache['spam_ips']):,}\n"
    response += f"• DDoS: {len(threat_cache['ddos_ips']):,}\n"
    response += f"• Brute Force: {len(threat_cache['bruteforce_ips']):,}\n"
    response += f"• Whitelist: {len(threat_cache['whitelist_ips']):,}\n"
    
    total_threats = sum(len(cache) for key, cache in threat_cache.items() if 'whitelist' not in key)
    response += f"\n🔢 **Total Threat Indicators:** {total_threats:,}"
    
    await ctx.send(response)

@bot.command(name="extract", help="Extract IPs and URLs from a website")
async def extract_website_content(ctx, url: str):
    """Discord command: !extract <url>"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    message = await ctx.send(f"🔍 Extracting content from `{url}`...")
    
    try:
        loop = asyncio.get_event_loop()
        extraction_data = await loop.run_in_executor(None, extract_content_from_website, url)
        
        formatted_result = format_extraction_results(extraction_data)
        
        # Split message if too long
        if len(formatted_result) > 2000:
            chunks = [formatted_result[i:i+2000] for i in range(0, len(formatted_result), 2000)]
            await message.edit(content=chunks[0])
            for chunk in chunks[1:]:
                await ctx.send(chunk)
        else:
            await message.edit(content=formatted_result)
            
    except Exception as e:
        await message.edit(content=f"❌ Error extracting content: {str(e)}")

@bot.command(name="deep_scan", help="Extract content from URL and scan all found IPs/URLs")
async def deep_scan_website(ctx, url: str):
    """Discord command: !deep_scan <url> - Extract and scan all content"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    message = await ctx.send(f"🔍 Performing deep scan of `{url}`...")

    scanners = [
        ('Threat‑Intel', check_threat_intel),
        ('GridinSoft', scan_gridinsoft),
        ('Bitdefender', scan_bitdefender),
    ]

    try:
        loop = asyncio.get_event_loop()
        extraction_data = await loop.run_in_executor(None, extract_content_from_website, url)

        # If extraction errored, still scan any IPs/domains we got before the failure
        if extraction_data.get('status') == 'error':
            partial_ips = list(extraction_data.get('ips', []))
            partial_domains = list(extraction_data.get('domains', []))
            partial = partial_ips + partial_domains

            await message.edit(content=(
                f"⚠️ Deep scan extraction failed part‑way: {extraction_data['error']}\n"
                "🔄 Scanning whatever targets we did extract…"
            ))

            for tgt in partial[:20]:
                entry = f"**{tgt}**\n"
                for name, fn in scanners:
                    try:
                        if asyncio.iscoroutinefunction(fn):
                            score, info = await fn(tgt)
                        else:
                            result = await loop.run_in_executor(None, fn, tgt)
                            score, info = result if isinstance(result, tuple) else (None, result)
                        entry += f"- {name}: {score} ({info})\n"
                    except Exception as e:
                        entry += f"- {name}: Error ({e})\n"
                await ctx.send(entry)

            # Then fall back to the regular URL scan
            return await ctx.invoke(bot.get_command('scan'), url=url)

        # Normal deep-scan flow
        all_targets = extraction_data['ips'] + extraction_data['domains'] + extraction_data['urls']
        total = len(all_targets)
        capped = all_targets[:20]
        skipped = total - len(capped)

        results = []
        for tgt in capped:
            entry = f"**{tgt}**\n"
            for name, fn in scanners:
                try:
                    if asyncio.iscoroutinefunction(fn):
                        score, info = await fn(tgt)
                    else:
                        result = await loop.run_in_executor(None, fn, tgt)
                        score, info = result if isinstance(result, tuple) else (None, result)
                    entry += f"- {name}: {score} ({info})\n"
                except Exception as e:
                    entry += f"- {name}: Error ({e})\n"
            results.append(entry)

        if skipped:
            results.append(f"_…and {skipped} more targets not checked._")

        # split on item boundaries
        chunks, buf = [], ""
        for item in results:
            if len(buf) + len(item) > 1900:
                chunks.append(buf)
                buf = ""
            buf += item + "\n"
        if buf:
            chunks.append(buf)

        footer = "\n🧠 Feedback: Use `!feedback <domain> wrong` for false positives, or `!feedback <domain> block <category>` for missed threats."
        await message.edit(content=f"🔍 **Deep Scan Results for:** `{url}`\n\n{chunks.pop(0)}{footer}")
        for part in chunks:
            await ctx.send(part + footer)

    except Exception as e:
        await message.edit(content=f"❌ Deep scan encountered an error: {e}\n🔄 Falling back to regular scan...")
        await ctx.invoke(bot.get_command('scan'), url=url)

# Update the commands list to include the new command
@bot.event
async def on_ready():
    """Bot startup event - Updated to include learning data"""
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")
    print("Loading threat intelligence lists (on ready)...")
    
    # Load threat intelligence lists in background
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, load_threat_lists)
    
    # Load learning data
    await loop.run_in_executor(None, load_learning_data)
    await loop.run_in_executor(None, load_pending_feedback)
    
    print("Ready to scan URLs, check threat intelligence, and learn from feedback!")

def update_commands_help():
    """Updated help text with enhanced scanning features"""
    help_text = """
🤖 **HydraDragon AV Discord Bot Commands:**

**🔍 Enhanced Scanning Commands:**
• `!scan <url>` - Comprehensive scan using all engines
• `!bulk_scan <url1> <url2> ...` - Scan multiple URLs (max 10)
• `!gridinsoft <url>` - GridinSoft scan only
• `!bitdefender <url>` - Bitdefender scan only
• `!intel <domain/ip>` - Check threat intelligence lists
• `!extract <url>` - Extract IPs and URLs from website content
• `!deep_scan <url>` - Extract content and scan all found targets

**📊 Information Commands:**
• `!stats` - Show threat intelligence statistics
• `!commands` - Show this help message

**🤖 Auto-Scanning Commands:**
• `!autoscan [on/off/status]` - Control automatic URL scanning

**🧠 Learning Mode Commands:**
• `!feedback <domain> <action> [category]` - Provide feedback on results
• `!learning [stats/enable/disable/reset]` - Control learning mode
• `!learned [category/all]` - Show learned domains
• `!feedback_help` - Detailed feedback command help

**🛡️ Enhanced Features:**
• **No cooldown** - Scan duplicate URLs
• **Enhanced URL detection** - Better pattern matching
• **Bulk scanning** - Multiple URLs at once
• **Obfuscated URL support** - Detects [.] and [dot] patterns
• **Real-time progress** - Live scanning updates
• **Detailed threat analysis** - Comprehensive reports
• **Machine learning** - Learns from user feedback
• **Automatic scanning** - Scans URLs in chat messages

**💾 Threat Intelligence:**
• 22+ million threat indicators
• Real-time threat correlation
• User-trained whitelist/blacklist
• Multiple threat categories
• Continuous learning system

**🔍 Enhanced Detection:**
• Standard URLs (http/https)
• Obfuscated URLs ([.] notation)
• Domain-only patterns
• www. prefixed domains
• Mixed case variations
• URLs in any message context
"""
    return help_text

# Replace the existing commands_list function content with:
@bot.command(name="commands", help="Show available commands")
async def commands_list(ctx):
    """Discord command: !commands - Updated with extraction commands"""
    help_text = update_commands_help()
    await ctx.send(help_text)

if __name__ == "__main__":
    bot.run(BOT_TOKEN)
