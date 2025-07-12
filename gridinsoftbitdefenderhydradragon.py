import discord
from discord.ext import commands
import asyncio
import time
import requests
import urllib3
import csv
import re
import html
import threading
import os
import gzip
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import ConnectionError, Timeout, HTTPError
from typing import Dict, List, Set, Optional, Tuple

# Suppress only the InsecureRequestWarning from requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Configuration ===
BOT_TOKEN = "YOUR_DISCORD_BOT_TOKEN_HERE"

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

def check_threat_intel(domain_or_ip: str) -> Dict[str, List[str]]:
    """Check domain/IP against threat intelligence lists"""
    domain_or_ip = domain_or_ip.lower()
    results = {
        'threats': [],
        'whitelist': [],
        'categories': []
    }
    
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
    """Scan domain using GridinSoft"""
    slug = domain.replace(".", "-")
    url = f"{GRIDINSOFT_URL}{slug}"

    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404 or "gridinsoft.com/410" in resp.url:
            return {"domain": domain, "review": "", "risk": "Unknown"}
        else:
            review, risk = extract_review_and_risk(resp.text)
            return {"domain": domain, "review": review, "risk": risk}
    except requests.RequestException as e:
        return {"domain": domain, "review": "", "risk": "Error", "error": str(e)}

def _make_request_with_retries(method, url, **kwargs):
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

def scan_bitdefender(url: str) -> Dict:
    """Scan URL using Bitdefender TrafficLight API"""
    params = {"url": url}
    headers = {
        CLIENT_ID_HEADER: CLIENT_ID,
        "Host": CLOUD_HOST,
    }
    for ip in NIMBUS_IPS:
        endpoint = f"https://{ip}{URL_STATUS_PATH}"
        try:
            resp = _make_request_with_retries(
                "GET", endpoint,
                params=params,
                headers=headers,
                verify=False
            )
            resp.raise_for_status()
            return resp.json()
        except HTTPError:
            continue
        except Exception:
            continue
    raise ConnectionError(f"All Nimbus IPs failed: {NIMBUS_IPS}")

def format_scan_results(url: str, gridinsoft_result: Dict, bitdefender_result: Dict, threat_intel: Dict) -> str:
    """Format comprehensive scan results"""
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
        result += "📊 **Threat Intelligence:** ✅ Not found in threat lists\n\n"
    
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
        status = bitdefender_result.get('status', 'Unknown')
        if status == 'clean':
            result += "✅ Status: Clean\n"
        elif status == 'malicious':
            result += "⚠️ Status: Malicious\n"
        else:
            result += f"❓ Status: {status}\n"
        
        if 'categories' in bitdefender_result and bitdefender_result['categories']:
            result += f"🏷️ Categories: {', '.join(bitdefender_result['categories'])}\n"
    else:
        result += f"❌ Error: {bitdefender_result}\n"
    
    return result

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
            status = result.get('status', 'Unknown')
            response += f"Status: {status}\n"
            if 'categories' in result and result['categories']:
                response += f"Categories: {', '.join(result['categories'])}"
        else:
            response += f"Result: {result}"
        
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

@bot.command(name="commands", help="Show available commands")
async def commands_list(ctx):
    """Discord command: !commands"""
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

**🛡️ Features:**
• Multi-engine URL scanning
• Threat intelligence correlation
• Real-time threat detection
• Comprehensive reporting

**💾 Threat Intelligence Lists:**
• 600+ million threat indicators
• Domains, subdomains, and IPs
• Malware, phishing, spam, abuse
• Regular updates from multiple sources
"""
    await ctx.send(help_text)

if __name__ == "__main__":
    bot.run(BOT_TOKEN)