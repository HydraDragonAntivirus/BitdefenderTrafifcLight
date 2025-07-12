import discord
from discord.ext import commands
import asyncio
import time
import requests
import urllib.parse
import urllib3
import csv
import re
import html
import threading
import os
import gzip
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import ConnectionError, Timeout, HTTPError
from typing import Dict, List, Set, Optional, Tuple

# Suppress only the InsecureRequestWarning from requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Configuration ===
BOT_TOKEN = "YOUR_DISCORD_BOT_TOKEN_HERE"

URL_REGEX = re.compile(
    r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
    re.IGNORECASE
)

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
SCAN_COOLDOWN = {}        # Track scan cooldowns per URL
COOLDOWN_SECONDS = 300    # 5 minutes cooldown per URL

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

def load_threat_lists():
    """Load all threat intelligence lists into memory"""
    print("Loading threat intelligence lists...")
    
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

# Add these new imports at the top with other imports
import json
from datetime import datetime

# Add these new configuration variables after existing config
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

# Add these new functions after existing threat intelligence functions

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
    domain_or_ip = domain_or_ip.lower()
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
    
    # Check domain lists (existing code)
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
    
    # Check subdomain lists (existing code)
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
    
    # Check IP lists (existing code)
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
    
    # Check whitelist (existing code)
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
        elif status == 'malicious':
            return "🚨 Malicious"
        elif status == 'suspicious':
            return "🔶 Suspicious"
        else:
            return "❓ Unknown"
    
    # If there are categories but no grey, then it's clean
    return "✅ Clean"

def format_scan_results(url: str, gridinsoft_result: Dict, bitdefender_result: Dict, threat_intel: Dict) -> str:
    """Format comprehensive scan results with detailed information"""
    result = f"🔍 **Comprehensive Scan Results for:** `{url}`\n\n"
    
    # Threat Intelligence Results
    if threat_intel['threats'] or threat_intel['whitelist']:
        result += "📊 **Threat Intelligence:**\n"
        if threat_intel['whitelist']:
            result += f"✅ {', '.join(threat_intel['whitelist'])}\n"
        if threat_intel['threats']:
            result += f"⚠️ Found in: {', '.join(threat_intel['threats'])}\n"
        result += "\n"
    else:
        result += "📊 **Threat Intelligence:** ❓ Not found in threat lists\n\n"
    
    # GridinSoft Results
    result += "🛡️ **GridinSoft Scan:**\n"
    if gridinsoft_result.get('error'):
        result += f"❌ Error: {gridinsoft_result['error']}\n"
    else:
        risk = gridinsoft_result.get('risk', 'Unknown')
        review = gridinsoft_result.get('review', '')
        
        if risk == "Unknown":
            result += "❓ Risk Level: Unknown\n"
        elif "safe" in risk.lower() or "clean" in risk.lower():
            result += f"✅ Risk Level: {risk}\n"
        else:
            result += f"⚠️ Risk Level: {risk}\n"
        
        if review:
            result += f"📝 Review: {review}\n"
    result += "\n"
    
    # Bitdefender Results
    result += "🛡️ **Bitdefender TrafficLight:**\n"
    if isinstance(bitdefender_result, dict):
        formatted_status = format_bitdefender_status(bitdefender_result)
        result += f"Status: {formatted_status}\n"
        
        # Show more detailed information if available
        if 'categories' in bitdefender_result and bitdefender_result['categories']:
            result += f"🏷️ Categories: {', '.join(bitdefender_result['categories'])}\n"
        
        if 'risk_score' in bitdefender_result:
            result += f"📊 Risk Score: {bitdefender_result['risk_score']}\n"
        
        if 'scan_time' in bitdefender_result:
            result += f"⏱️ Scan Time: {bitdefender_result['scan_time']}\n"
            
        # Show full result for debugging if needed
        if len(str(bitdefender_result)) < 500:  # Only show if reasonably short
            result += f"📋 Full Result: `{bitdefender_result}`\n"
    else:
        result += f"❌ Error: {bitdefender_result}\n"
    
    return result

def extract_urls_from_text(text: str) -> List[str]:
    """Extract URLs from message text"""
    urls = URL_REGEX.findall(text)
    # Clean up URLs and remove duplicates
    clean_urls = []
    for url in urls:
        url = url.strip()
        if url and url not in clean_urls:
            clean_urls.append(url)
    return clean_urls

def is_url_on_cooldown(url: str) -> bool:
    """Check if URL is on cooldown"""
    if url in SCAN_COOLDOWN:
        time_diff = time.time() - SCAN_COOLDOWN[url]
        return time_diff < COOLDOWN_SECONDS
    return False

def add_url_to_cooldown(url: str):
    """Add URL to cooldown tracker"""
    SCAN_COOLDOWN[url] = time.time()

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
    """Format auto-scan results in compact format with feedback option"""
    if 'error' in scan_results:
        return f"⚠️ **Auto-scan failed for** `{url}`: {scan_results['error']}"
    
    # Extract domain from URL
    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
    
    # Check if any threats were found
    threat_intel = scan_results.get('threat_intel', {})
    gridinsoft = scan_results.get('gridinsoft', {})
    bitdefender = scan_results.get('bitdefender', {})
    
    threats_found = []
    
    # Check threat intelligence
    if threat_intel.get('threats'):
        threats_found.extend(threat_intel['threats'])
    
    # Check GridinSoft risk
    risk = gridinsoft.get('risk', 'Unknown')
    if risk != 'Unknown' and not any(safe_word in risk.lower() for safe_word in ['safe', 'clean', 'low']):
        threats_found.append(f"GridinSoft: {risk}")
    
    # Check Bitdefender
    if isinstance(bitdefender, dict):
        if bitdefender.get('domain_grey', False):
            threats_found.append("Bitdefender: Harmful website")
        elif bitdefender.get('status') == 'malicious':
            threats_found.append("Bitdefender: Malicious")
        elif bitdefender.get('status') == 'suspicious':
            threats_found.append("Bitdefender: Suspicious")
    
    # Format response based on findings
    if threats_found:
        result = f"🚨 **THREAT DETECTED** in URL: `{url}`\n"
        result += f"**Threats:** {', '.join(threats_found[:3])}"  # Limit to 3 threats
        if len(threats_found) > 3:
            result += f" (+{len(threats_found) - 3} more)"
        result += f"\n*Use `!scan {url}` for detailed analysis*"
        
        # Add feedback option if learning mode is enabled
        if LEARNING_MODE_ENABLED:
            result += f"\n*Think this is wrong? Use `!feedback {domain} wrong` to report false positive*"
        
        return result
    elif threat_intel.get('whitelist'):
        result = f"✅ **Safe URL detected:** `{url}` (Whitelisted)"
        
        # Add feedback option if learning mode is enabled
        if LEARNING_MODE_ENABLED:
            result += f"\n*Think this should be blocked? Use `!feedback {domain} block <category>` to report*"
        
        return result
    else:
        result = f"✅ **URL scanned:** `{url}` - No threats detected"
        
        # Add feedback option if learning mode is enabled
        if LEARNING_MODE_ENABLED:
            result += f"\n*Know this is malicious? Use `!feedback {domain} block <category>` to report*"
        
        return result

@bot.event
async def on_message(message):
    """Handle incoming messages and auto-scan URLs"""
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
    
    # Extract URLs from message
    urls = extract_urls_from_text(message.content)
    
    if urls:
        for url in urls:
            # Check cooldown
            if is_url_on_cooldown(url):
                continue
            
            # Add to cooldown
            add_url_to_cooldown(url)
            
            # Send scanning message
            scan_message = await message.channel.send(f"🔍 Auto-scanning detected URL...")
            
            try:
                # Perform scan
                scan_results = await perform_auto_scan(url)
                
                # Format and send results
                formatted_result = format_auto_scan_results(url, scan_results)
                await scan_message.edit(content=formatted_result)
                
            except Exception as e:
                await scan_message.edit(content=f"❌ Auto-scan error for `{url}`: {str(e)}")
    
    # Process commands normally
    await bot.process_commands(message)

@bot.command(name="feedback", help="Provide feedback on scan results")
async def feedback(ctx, domain_or_ip: str, action: str, category: str = None):
    """Discord command: !feedback <domain/ip> <action> [category]"""
    
    if not LEARNING_MODE_ENABLED:
        await ctx.send("❌ Learning mode is currently disabled.")
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
    
    # Process feedback
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
        cooldown_count = len(SCAN_COOLDOWN)
        await ctx.send(f"📊 **Auto-scan Status:** {status}\n🕒 **URLs on cooldown:** {cooldown_count}")
    else:
        await ctx.send("❓ **Usage:** `!autoscan [on/off/status]`")

@bot.event
async def on_ready():
    """Bot startup event"""
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")
    print("Loading threat intelligence lists...")
    
    # Load threat intelligence lists in background
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, load_threat_lists)
    
    print("Ready to scan URLs and check threat intelligence!")

@bot.command(name="scan", help="Comprehensive scan using GridinSoft, Bitdefender, and threat intelligence")
async def scan(ctx, url: str):
    """Discord command: !scan <url>"""
    message = await ctx.send(f"🔍 Performing comprehensive scan of `{url}`...")
    
    try:
        loop = asyncio.get_event_loop()
        
        # Extract domain from URL for threat intel check
        domain = url.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Run all scans concurrently
        gridinsoft_task = loop.run_in_executor(None, scan_gridinsoft, domain)
        bitdefender_task = loop.run_in_executor(None, scan_bitdefender, url)
        threat_intel_task = loop.run_in_executor(None, check_threat_intel, domain)
        
        gridinsoft_result = await gridinsoft_task
        bitdefender_result = await bitdefender_task
        threat_intel_result = await threat_intel_task
        
        # Format and send results
        formatted_result = format_scan_results(url, gridinsoft_result, bitdefender_result, threat_intel_result)
        
        # Split message if too long
        if len(formatted_result) > 2000:
            chunks = [formatted_result[i:i+2000] for i in range(0, len(formatted_result), 2000)]
            await message.edit(content=chunks[0])
            for chunk in chunks[1:]:
                await ctx.send(chunk)
        else:
            await message.edit(content=formatted_result)
            
    except Exception as e:
        await message.edit(content=f"❌ Error during comprehensive scan: {str(e)}")

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

# Update the commands list to include the new command
@bot.event
async def on_ready():
    """Bot startup event - Updated to include learning data"""
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")
    print("Loading threat intelligence lists...")
    
    # Load threat intelligence lists in background
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, load_threat_lists)
    
    # Load learning data
    await loop.run_in_executor(None, load_learning_data)
    await loop.run_in_executor(None, load_pending_feedback)
    
    print("Ready to scan URLs, check threat intelligence, and learn from feedback!")

@bot.command(name="commands", help="Show available commands")
async def commands_list(ctx):
    """Discord command: !commands - Updated with learning commands"""
    help_text = """
🤖 **HydraDragon AV Discord Bot Commands:**

**🔍 Scanning Commands:**
• `!scan <url>` - Comprehensive scan using all engines
• `!gridinsoft <url>` - GridinSoft scan only
• `!bitdefender <url>` - Bitdefender scan only
• `!intel <domain/ip>` - Check threat intelligence lists

**📊 Information Commands:**
• `!stats` - Show threat intelligence statistics
• `!commands` - Show this help message

**🤖 Auto-Scanning Commands:**
• `!autoscan [on/off/status]` - Control automatic URL scanning

**🧠 Learning Mode Commands:**
• `!feedback <domain> <action> [category]` - Provide feedback on results
• `!learning [stats/enable/disable/reset]` - Control learning mode
• `!learned [category/all]` - Show learned domains

**🛡️ Features:**
• Multi-engine URL scanning
• Threat intelligence correlation
• Real-time threat detection
• **Automatic URL scanning in chat**
• **Machine learning from user feedback**
• Comprehensive reporting

**💾 Threat Intelligence Lists:**
• 22+ million threat indicators
• Domains, subdomains, and IPs
• Malware, phishing, spam, abuse
• Regular updates from multiple sources
• **User-trained whitelist/blacklist**

**🧠 Learning Examples:**
• `!feedback example.com wrong` - Mark as false positive
• `!feedback badsite.com block malware` - Add to malware blacklist
• `!feedback goodsite.com allow` - Add to whitelist
• `!learning stats` - Show learning statistics
"""
    await ctx.send(help_text)
