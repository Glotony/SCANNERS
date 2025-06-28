import os
import json
import asyncio
import aiohttp
import socket
import time
import hashlib
import shutil
from urllib.parse import urlparse
from dotenv import load_dotenv
from torrentool.api import Torrent
from pymongo import MongoClient

# === Load environment ===
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
MONGO_URI = os.getenv("MONGO_URI")
QBIT_WEBUI_URL = os.getenv("Qbit_Web_Ui_URI")
QBIT_USERNAME = os.getenv("QBIT_USERNAME")
QBIT_PASSWORD = os.getenv("QBIT_PASSWORD")

# === MongoDB setup ===
client = MongoClient(MONGO_URI)
db = client["torrent_cleaner_db"]
blocklist_domains_col = db["blocked_domains"]
blocklist_ips_col = db["blocked_ips"]
scanned_exes_col = db["scanned_exes"]

# === Paths and files ===
TORRENT_DIR = "__torrent__"
CLEAN_DIR = "cleaned_torrents"
MALICIOUS_DIR = "malicious_torrents"
RESULT_FILE = "results.json"
EXE_DIR = "exes"
DELETE_EXE_DIR = "delete_exe"
PEERS_JSON = "peers.json"
DANGER_PEERS_JSON = "danger_peers.json"

# === Global sets ===
URL_RESULTS = []
KNOWN_BAD_DOMAINS = set()
KNOWN_BAD_IPS = set()

# === Load blocked domains and IPs from MongoDB ===
def load_blocklist_domains():
    docs = blocklist_domains_col.find({})
    return set(doc["domain"] for doc in docs)

def load_blocklist_ips():
    docs = blocklist_ips_col.find({})
    return set(doc["ip"] for doc in docs)

# === Append new blocked domain/ip to MongoDB and update sets ===
def append_to_blocklist_domain(domain):
    if domain and domain not in KNOWN_BAD_DOMAINS:
        blocklist_domains_col.insert_one({
            "domain": domain,
            "blocked_at": int(time.time())
        })
        KNOWN_BAD_DOMAINS.add(domain)
        print(f"🛑 Blocked domain saved in DB: {domain}")

def append_to_blocklist_ip(ip):
    if ip and ip not in KNOWN_BAD_IPS:
        blocklist_ips_col.insert_one({
            "ip": ip,
            "blocked_at": int(time.time())
        })
        KNOWN_BAD_IPS.add(ip)
        print(f"🛑 Blocked IP saved in DB: {ip}")

# === Check if domain/ip is known bad ===
def is_known_bad_domain(url: str) -> bool:
    try:
        domain = urlparse(url).hostname
        return domain in KNOWN_BAD_DOMAINS
    except:
        return False

def is_known_bad_ip(ip: str) -> bool:
    return ip in KNOWN_BAD_IPS

# === Record tracker check results ===
def record_result(url, status, file, safe):
    URL_RESULTS.append({
        "url": url,
        "status": status,
        "file": file,
        "safe": safe
    })

# === Resolve UDP trackers ===
async def resolve_udp(url):
    try:
        domain = urlparse(url).hostname
        await asyncio.get_event_loop().getaddrinfo(domain, None)
        return "udp_resolves"
    except socket.gaierror:
        return "udp_unreachable"
    except Exception as e:
        return f"udp_error:{type(e).__name__}"

# === Check tracker URL status ===
async def check_tracker(session, url):
    if url.startswith("udp://"):
        return await resolve_udp(url)
    try:
        async with session.get(url, timeout=10) as resp:
            if resp.status == 200:
                return "reachable"
            elif 400 <= resp.status < 500:
                return "client_error"
            elif 500 <= resp.status < 600:
                return "server_error"
            else:
                return f"http_{resp.status}"
    except asyncio.TimeoutError:
        return "timeout"
    except aiohttp.ClientConnectorError:
        return "unreachable"
    except aiohttp.ClientSSLError:
        return "ssl_error"
    except Exception as e:
        return f"error:{str(e).split(':')[0]}"

# === VirusTotal IP check ===
async def check_ip_vt(ip, session):
    if not VT_API_KEY:
        return {"ip": ip, "malicious": 0, "suspicious": 0}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        async with session.get(url, headers=headers, timeout=15) as resp:
            if resp.status != 200:
                return {"ip": ip, "error": f"HTTP {resp.status}"}
            data = await resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {"ip": ip, "malicious": stats["malicious"], "suspicious": stats["suspicious"]}
    except Exception as e:
        return {"ip": ip, "error": str(e)}

# === Torrent cleaning ===
async def clean_torrent(file_path, filename, session):
    try:
        torrent = Torrent.from_file(file_path)
        all_urls = [url for group in torrent.announce_urls for url in group]
        safe_urls, removed, issues = [], [], False

        print(f"\n🔎 {filename}")
        for url in all_urls:
            domain = urlparse(url).hostname or ""

            if is_known_bad_domain(url):
                status, safe = "malicious_known", False
            else:
                status = await check_tracker(session, url)
                safe = status in ["reachable", "udp_resolves"]
                if not safe:
                    append_to_blocklist_domain(domain)
                    status = "auto_blocked"

            record_result(url, status, filename, safe)
            print(f"→ {url} :: {'✅' if safe else '❌'} {status}")

            if safe:
                safe_urls.append([url])
            else:
                removed.append(url)
                issues = True

        torrent.announce_urls = safe_urls
        torrent.announce = safe_urls[0][0] if safe_urls else None
        torrent.comment = "Cleaned by scanner"

        out_dir = MALICIOUS_DIR if issues else CLEAN_DIR
        os.makedirs(out_dir, exist_ok=True)

        base, ext = os.path.splitext(filename)
        output = os.path.join(out_dir, f"{base}_cleaned{ext}")
        torrent.to_file(output)
        print(f"📂 Saved: {output}")

        if issues:
            with open(os.path.join(out_dir, f"{base}_removed.txt"), "w") as log:
                for r in removed:
                    log.write(r + "\n")

    except Exception as e:
        print(f"[!] Error: {e}")

# === Peer JSON → VirusTotal → danger_peers.json → MongoDB update pipeline ===
async def scan_peers_json():
    if not os.path.exists(PEERS_JSON):
        print(f"[!] {PEERS_JSON} missing, skipping peer scan")
        return

    with open(PEERS_JSON, "r") as f:
        peers = json.load(f)

    danger_peers = []

    async with aiohttp.ClientSession() as session:
        for ip in peers:
            if is_known_bad_ip(ip):
                print(f"🛑 {ip} already blocked, skipping VT check")
                continue

            print(f"Checking VT for peer {ip} ...", end=" ")
            result = await check_ip_vt(ip, session)
            if "error" in result:
                print(f"⚠️ {result['error']}")
                continue

            if result["malicious"] > 0 or result["suspicious"] > 1:
                print("🛑 Malicious/Suspicious!")
                danger_peers.append(ip)
                append_to_blocklist_ip(ip)
            else:
                print("✅ Clean")

            await asyncio.sleep(15)  # rate limit

    # Save dangerous peers to danger_peers.json
    with open(DANGER_PEERS_JSON, "w") as f:
        json.dump(danger_peers, f, indent=4)
    print(f"📝 Saved danger peers to {DANGER_PEERS_JSON}")

# === Peer MongoDB → VirusTotal → update blocklist pipeline ===
async def peer_check():
    ips = list(KNOWN_BAD_IPS)
    if not ips:
        print("[!] No blocked IPs found in MongoDB for peer_check")
        return

    async with aiohttp.ClientSession() as session:
        for i, ip in enumerate(ips, start=1):
            print(f"Rechecking blocked IP {ip} ...", end=" ")
            result = await check_ip_vt(ip, session)
            if "error" in result:
                print(f"⚠️ {result['error']}")
                continue

            if result["malicious"] == 0 and result["suspicious"] <= 1:
                print("✅ Cleaned or false positive? Remove from blocklist.")
                blocklist_ips_col.delete_one({"ip": ip})
                KNOWN_BAD_IPS.discard(ip)
            else:
                print("🛑 Still bad.")

            await asyncio.sleep(15 if i % 4 else 60)

# === EXE scanner ===
async def scan_exes():
    os.makedirs(DELETE_EXE_DIR, exist_ok=True)

    if not os.path.exists(EXE_DIR):
        print(f"[!] Missing {EXE_DIR} folder, skipping EXE scan")
        return

    async with aiohttp.ClientSession() as session:
        for exe_file in os.listdir(EXE_DIR):
            if not exe_file.lower().endswith(".exe"):
                continue

            full_path = os.path.join(EXE_DIR, exe_file)

            hash_sha256 = hashlib.sha256()
            with open(full_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_sha256.update(chunk)
            file_hash = hash_sha256.hexdigest()

            vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": VT_API_KEY}

            try:
                async with session.get(vt_url, headers=headers, timeout=15) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        stats = data["data"]["attributes"]["last_analysis_stats"]
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                    elif resp.status == 404:
                        malicious = 0
                        suspicious = 0
                    else:
                        print(f"⚠️ VT returned HTTP {resp.status} for {exe_file}")
                        malicious = 0
                        suspicious = 0
            except Exception as e:
                print(f"[!] VT scan error for {exe_file}: {e}")
                malicious = 0
                suspicious = 0

            scanned_exes_col.insert_one({
                "filename": exe_file,
                "sha256": file_hash,
                "malicious": malicious,
                "suspicious": suspicious,
                "scanned_at": int(time.time())
            })

            print(f"🔍 EXE {exe_file} — Malicious: {malicious}, Suspicious: {suspicious}")

            if malicious > 0 or suspicious > 0:
                dest = os.path.join(DELETE_EXE_DIR, exe_file)
                shutil.move(full_path, dest)
                print(f"🗑️ Moved {exe_file} to {DELETE_EXE_DIR}")

# === qBittorrent Web UI Login ===
async def qbit_login(session, retries=5, delay=5):
    login_url = f"{QBIT_WEBUI_URL.rstrip('/')}/api/v2/auth/login"
    data = {
        "username": QBIT_USERNAME,
        "password": QBIT_PASSWORD
    }
    
    for attempt in range(1, retries + 1):
        try:
            async with session.post(login_url, data=data) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "Ok." in text:
                        print("✅ Logged into qBittorrent Web UI")
                        return True
                print(f"❌ Failed to login (HTTP {resp.status}) attempt {attempt}/{retries}")
        except aiohttp.ClientConnectorError as e:
            print(f"⚠️ Connection error on attempt {attempt}/{retries}: {e}")
        except Exception as e:
            print(f"⚠️ Unexpected error on attempt {attempt}/{retries}: {e}")
        
        if attempt < retries:
            await asyncio.sleep(delay)
    print("❌ All login attempts failed.")
    return False

# === Sync blocked IPs to qBittorrent IP filter ===
async def sync_blocked_ips_to_qbit():
    if not QBIT_WEBUI_URL or not QBIT_USERNAME or not QBIT_PASSWORD:
        print("❌ qBittorrent credentials or URL missing, skipping IP sync")
        return

    async with aiohttp.ClientSession() as session:
        if not await qbit_login(session):
            print("❌ Could not login to qBittorrent, skipping IP sync")
            return

        # Get current IP filter rules
        ip_filter_url = f"{QBIT_WEBUI_URL.rstrip('/')}/api/v2/ip_filter/rules"
        try:
            async with session.get(ip_filter_url) as resp:
                if resp.status == 200:
                    existing_rules = await resp.json()
                else:
                    print(f"❌ Failed to get existing IP filter rules, HTTP {resp.status}")
                    existing_rules = []
        except Exception as e:
            print(f"❌ Exception while getting IP filter rules: {e}")
            existing_rules = []

        existing_ips = {rule.get("ip") for rule in existing_rules if rule.get("ip")}
        
        new_ips = KNOWN_BAD_IPS - existing_ips
        print(f"ℹ️ Syncing {len(new_ips)} new IPs to qBittorrent IP filter")

        for ip in new_ips:
            add_rule_url = f"{QBIT_WEBUI_URL.rstrip('/')}/api/v2/ip_filter/add_rule"
            params = {
                "ip": ip,
                "type": 1,  # 1 = block
                "comment": "Blocked by torrent_cleaner"
            }
            try:
                async with session.post(add_rule_url, params=params) as resp:
                    if resp.status == 200:
                        print(f"➕ Added IP filter rule: {ip}")
                    else:
                        print(f"❌ Failed to add IP filter rule for {ip}, HTTP {resp.status}")
            except Exception as e:
                print(f"❌ Exception adding IP filter rule for {ip}: {e}")

# === Torrent cleaning main ===
async def clean_all_torrents():
    global KNOWN_BAD_DOMAINS, KNOWN_BAD_IPS
    KNOWN_BAD_DOMAINS = load_blocklist_domains()
    KNOWN_BAD_IPS = load_blocklist_ips()

    if not os.path.exists(TORRENT_DIR):
        print(f"[!] Missing {TORRENT_DIR} folder")
        return

    os.makedirs(CLEAN_DIR, exist_ok=True)
    os.makedirs(MALICIOUS_DIR, exist_ok=True)

    async with aiohttp.ClientSession() as session:
        tasks = []
        for file in os.listdir(TORRENT_DIR):
            if file.endswith(".torrent"):
                full_path = os.path.join(TORRENT_DIR, file)
                tasks.append(clean_torrent(full_path, file, session))
        await asyncio.gather(*tasks)

    with open(RESULT_FILE, "w") as f:
        json.dump(URL_RESULTS, f, indent=4)
    print(f"📜 Saved results to {RESULT_FILE}")

# === Full run with both pipelines ===
async def full_run():
    global KNOWN_BAD_DOMAINS, KNOWN_BAD_IPS
    KNOWN_BAD_DOMAINS = load_blocklist_domains()
    KNOWN_BAD_IPS = load_blocklist_ips()

    await clean_all_torrents()
    await scan_peers_json()
    await peer_check()
    await scan_exes()
    await sync_blocked_ips_to_qbit()

if __name__ == "__main__":
    asyncio.run(full_run())
