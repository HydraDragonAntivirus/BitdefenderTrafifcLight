import discord
from discord.ext import commands
import asyncio
import time
import requests
import urllib3
from requests.exceptions import ConnectionError, Timeout, HTTPError

# Suppress only the InsecureRequestWarning from requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Configuration ===
BOT_TOKEN        = "YOUR_DISCORD_BOT_TOKEN_HERE"
CLOUD_HOST       = "nimbus.bitdefender.net"
URL_STATUS_PATH  = "/url/status"
CLIENT_ID_HEADER = "X-Nimbus-ClientId"
CLIENT_ID        = "a4c35c82-b0b5-46c3-b641-41ed04075269"
NIMBUS_IPS       = ["34.117.254.173", "34.120.243.77", "34.98.122.109"]

# Enable the message content intent so prefix commands work everywhere
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)

def _make_request_with_retries(method, url, **kwargs):
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

def scan_url_direct(url: str) -> dict:
    params  = {"url": url}
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

@bot.command(name="scan", help="Scan a URL via Bitdefender TrafficLight API")
async def scan(ctx, url: str):
    """Discord command: !scan <url>"""
    message = await ctx.send(f"🔍 Scanning `{url}`…")
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, scan_url_direct, url)
        await message.edit(content=f"✅ Result for `{url}`:\n```json\n{result}\n```")
    except Exception as e:
        await message.edit(content=f"❌ Error scanning `{url}`: {e}")

@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")
    print("Ready to scan URLs in any channel!")

if __name__ == "__main__":
    bot.run(BOT_TOKEN)
