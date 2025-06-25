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

# === MongoDB setup ===
client = MongoClient(MONGO_URI)
db = client["torrent_cleaner_db"]
blocklist_domains_col = db["blocked_domains"]
blocklist_ips_col = db["blocked_ips"]
scanned_exes_col = db["scanned_exes"]

# === Paths ===
TORRENT_DIR = "__torrent__"
CLEAN_DIR = "cleaned_torrents"
MALICIOUS_DIR = "malicious_torrents"
PEER_FILE = "peers.json"
CLEAN_PEER_FILE = "peers_cleaned.json"
RESULT_FILE = "results.json"
EXE_DIR = "exes"
DELETE_EXE_DIR = "delete_exe"

URL_RESULTS = []
KNOWN_BAD_DOMAINS = set()
KNOWN_BAD_IPS = set()

# === Helpers ===

def load_blocklist_domains():
    docs = blocklist_domains_col.find({})
    return set(doc["domain"] for doc in docs)

def load_blocklist_ips():
    docs = blocklist_ips_col.find({})
    return set(doc["ip"] for doc in docs)

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

def is_known_bad_domain(url: str) -> bool:
    try:
        domain = urlparse(url).hostname
        return domain in KNOWN_BAD_DOMAINS
    except:
        return False

def is_known_bad_ip(ip: str) -> bool:
    return ip in KNOWN_BAD_IPS

def record_result(url, status, file, safe):
    URL_RESULTS.append({
        "url": url,
        "status": status,
        "file": file,
        "safe": safe
    })

async def resolve_udp(url):
    try:
        domain = urlparse(url).hostname
        await asyncio.get_event_loop().getaddrinfo(domain, None)
        return "udp_resolves"
    except socket.gaierror:
        return "udp_unreachable"
    except Exception as e:
        return f"udp_error:{type(e).__name__}"

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

# === Torrent Cleaning ===
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

# === Peer Checker ===
async def peer_check():
    if not os.path.exists(PEER_FILE):
        print(f"[!] {PEER_FILE} missing")
        return

    with open(PEER_FILE, "r") as f:
        try:
            peers = json.load(f)
        except Exception:
            print(f"[!] Failed to load peers from {PEER_FILE}")
            return

    if not isinstance(peers, list):
        print(f"[!] {PEER_FILE} is not a list")
        return

    clean_peers = []
    async with aiohttp.ClientSession() as session:
        for i, ip in enumerate(peers, start=1):
            if is_known_bad_ip(ip):
                print(f"🛑 Peer {ip} is in manual IP blocklist")
                continue  # skip VT check, already blocked

            print(f"👁️ Peer {ip}", end=" ")
            result = await check_ip_vt(ip, session)
            if "error" in result:
                print(f"⚠️ {result['error']}")
            elif result["malicious"] > 0 or result["suspicious"] > 1:
                print(f"🛑 {result}")
                append_to_blocklist_ip(ip)
            else:
                print("✅")
                clean_peers.append(ip)

            # Rate limit delay: 4 requests then 60 sec, else 15 sec
            await asyncio.sleep(15 if i % 4 else 60)

    with open(CLEAN_PEER_FILE, "w") as f:
        json.dump(clean_peers, f, indent=2)
    print(f"✔️ Saved cleaned peers to {CLEAN_PEER_FILE}")

# === EXE Scanner ===
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

            # Calculate SHA256 hash
            hash_sha256 = hashlib.sha256()
            with open(full_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_sha256.update(chunk)
            file_hash = hash_sha256.hexdigest()

            # Check VT for the file hash
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
                        # File hash not found in VT
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

            # Log and save result in MongoDB
            scanned_exes_col.insert_one({
                "filename": exe_file,
                "sha256": file_hash,
                "malicious": malicious,
                "suspicious": suspicious,
                "scanned_at": int(time.time())
            })

            print(f"🔍 EXE {exe_file} — Malicious: {malicious}, Suspicious: {suspicious}")

            # Move malicious or suspicious exe to delete_exe folder
            if malicious > 0 or suspicious > 0:
                dest = os.path.join(DELETE_EXE_DIR, exe_file)
                shutil.move(full_path, dest)
                print(f"🗑️ Moved {exe_file} to {DELETE_EXE_DIR}")

# === Main Scan ===
async def main():
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

# === Entry Point ===
async def full_run():
    await main()
    await peer_check()
    await scan_exes()

if __name__ == "__main__":
    asyncio.run(full_run())
