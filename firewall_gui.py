"""
AI Firewall - Web GUI v7.0
REAL website detection using multiple RELIABLE methods:

1. Browser History (Chrome/Edge/Firefox SQLite DB) - reads actual URLs you visited
2. Browser Active Tabs via Windows APIs  
3. DNS Cache (ipconfig /displaydns) - only shown if ALSO in browser history
4. Hosts file check
5. Manual URL entry

NO fake reverse-DNS. NO guessing. ONLY real sites you visited.
"""

import threading
import time
import platform
import subprocess
import socket
import os
import sys
import re
import json
import webbrowser
import shutil
import tempfile
import sqlite3
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.request
import urllib.error
import hashlib

# ─────────────────────────────────────────────────────────────────────────────
# THREAT DETECTION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

# ── Local high-confidence threat blocklist (no API needed) ────────────────────
# Pattern-matched against visited domains. Updated manually below.
THREAT_PATTERNS = [
    # Phishing — fake brand domains (match domain containing brand + extra words)
    (r'paypa[l1][^.]*[-.]', 'Phishing', 'HIGH', 'Fake PayPal domain'),
    (r'app[l1]e[^.]*[-.]secure', 'Phishing', 'HIGH', 'Fake Apple domain'),
    (r'[-.]secure[-.].*login', 'Phishing', 'HIGH', 'Suspicious secure-login domain'),
    (r'account.*verify', 'Phishing', 'MEDIUM', 'Account verify phishing'),
    (r'login.*-update', 'Phishing', 'MEDIUM', 'Login update phishing'),
    (r'bank.*-.*secure', 'Phishing', 'HIGH', 'Fake bank domain'),
    (r'signin.*-.*confirm', 'Phishing', 'MEDIUM', 'Signin confirm phishing'),
    # High-risk TLDs (match exact TLD at end of domain)
    (r'\.xyz$', 'Malware', 'LOW', 'High-risk TLD (.xyz)'),
    (r'\.tk$', 'Malware', 'MEDIUM', 'High-risk TLD (.tk)'),
    (r'\.gq$', 'Malware', 'MEDIUM', 'High-risk TLD (.gq)'),
    (r'\.ml$', 'Malware', 'MEDIUM', 'High-risk TLD (.ml)'),
    (r'\.cf$', 'Malware', 'MEDIUM', 'High-risk TLD (.cf)'),
    (r'\.ga$', 'Malware', 'MEDIUM', 'High-risk TLD (.ga)'),
    (r'\.pw$', 'Malware', 'LOW', 'High-risk TLD (.pw)'),
    (r'\.top$', 'Malware', 'LOW', 'Commonly abused TLD (.top)'),
    (r'\.buzz$', 'Malware', 'LOW', 'Commonly abused TLD (.buzz)'),
    # Crypto miners
    (r'coinhive', 'Cryptominer', 'HIGH', 'Known crypto miner (Coinhive)'),
    (r'cryptonight', 'Cryptominer', 'HIGH', 'CryptoNight miner'),
    (r'webminer', 'Cryptominer', 'HIGH', 'Web-based miner'),
    (r'minero\.cc', 'Cryptominer', 'MEDIUM', 'Possible crypto miner'),
    # Malware / spyware keywords
    (r'keylogger', 'Spyware', 'HIGH', 'Keylogger indicator'),
    (r'stalkerware', 'Spyware', 'HIGH', 'Stalkerware indicator'),
    (r'eicar\.org', 'Malware', 'LOW', 'EICAR test domain (safe test)'),
    (r'wicar\.org', 'Malware', 'LOW', 'WiCAR test domain (safe test)'),
    (r'testsafebrowsing\.appspot\.com', 'Malware', 'LOW', 'Google Safe Browsing test (safe)'),
    # Ransomware / dark web
    (r'\.onion\.to$', 'Ransomware', 'HIGH', 'Tor2web bridge (dark web proxy)'),
    (r'\.onion$', 'Ransomware', 'HIGH', 'Tor hidden service'),
    # Typosquatting — common targets
    (r'^g[o0]{2}gle\.', 'Phishing', 'HIGH', 'Google typosquat'),
    (r'^faceb[o0]{2}k\.', 'Phishing', 'HIGH', 'Facebook typosquat'),
    (r'^amaz[o0]n-', 'Phishing', 'MEDIUM', 'Amazon typosquat'),
    (r'^micros[o0]ft-', 'Phishing', 'MEDIUM', 'Microsoft typosquat'),
    (r'^paypa1\.', 'Phishing', 'HIGH', 'PayPal typosquat (l→1)'),
    (r'^app1e\.', 'Phishing', 'HIGH', 'Apple typosquat (l→1)'),
    # Crack / warez / hack tools
    (r'warez', 'Malware', 'HIGH', 'Warez site'),
    (r'free.*crack', 'Malware', 'HIGH', 'Crack/keygen site'),
    (r'keygen', 'Malware', 'HIGH', 'Keygen site'),
    (r'hack.*tool', 'Malware', 'MEDIUM', 'Hack tool site'),
    # Badssl test domains (safe, informational)
    (r'badssl\.com$', 'SSL/TLS', 'LOW', 'SSL/TLS test domain (safe test)'),
]

# Threat pattern whitelist — only test/safety domains
# Real sites are NOT whitelisted — use custom domain blocker to block them
THREAT_WHITELIST = {
    'eicar.org','wicar.org','amtso.org',
    'testsafebrowsing.appspot.com',
    'badssl.com','expired.badssl.com','self-signed.badssl.com',
}

# Custom domain blocklist — populated at runtime via UI
CUSTOM_BLOCKED_DOMAINS = {}  # domain -> blocked_at

HOSTS_FILE = (
    r"C:\Windows\System32\drivers\etc\hosts"
    if platform.system() == "Windows"
    else "/etc/hosts"
)
HOSTS_MARKER = "# AIFirewall"


def block_domain(domain):
    domain = domain.lower().strip().rstrip(".")
    if not domain: return False, "No domain provided"
    try:
        try:
            with open(HOSTS_FILE, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except PermissionError:
            return False, "Permission denied — run as Administrator/sudo"
        for line in content.splitlines():
            if domain in line and HOSTS_MARKER in line:
                return False, f"{domain} is already blocked"
        entry = f"\n0.0.0.0 {domain} {HOSTS_MARKER}\n0.0.0.0 www.{domain} {HOSTS_MARKER}\n"
        with open(HOSTS_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
        try:
            if platform.system() == "Windows":
                subprocess.call(["ipconfig", "/flushdns"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW)
            elif platform.system() == "Darwin":
                subprocess.call(["dscacheutil", "-flushcache"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.call(["systemd-resolve", "--flush-caches"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception: pass
        CUSTOM_BLOCKED_DOMAINS[domain] = datetime.now().strftime("%H:%M:%S")
        add_log(f"DOMAIN BLOCKED: {domain} -> 0.0.0.0 (hosts file)", "blocked")
        with state_lock:
            state["stats"]["blocked"] += 1
            state["blocked_domains"][domain] = {
                "blocked_at": datetime.now().strftime("%H:%M:%S"),
                "method": "hosts"
            }
        return True, f"Blocked {domain}"
    except Exception as e:
        return False, str(e)


def unblock_domain(domain):
    domain = domain.lower().strip().rstrip(".")
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8", errors="ignore") as f:
            existing = f.readlines()
        cleaned = [l for l in existing
                   if not (domain in l and HOSTS_MARKER in l)]
        with open(HOSTS_FILE, "w", encoding="utf-8") as f:
            f.writelines(cleaned)
        try:
            if platform.system() == "Windows":
                subprocess.call(["ipconfig", "/flushdns"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception: pass
        CUSTOM_BLOCKED_DOMAINS.pop(domain, None)
        add_log(f"DOMAIN UNBLOCKED: {domain}", "info")
        with state_lock:
            state["blocked_domains"].pop(domain, None)
            if state["stats"]["blocked"] > 0:
                state["stats"]["blocked"] -= 1
        return True, f"Unblocked {domain}"
    except PermissionError:
        return False, "Permission denied — run as Administrator/sudo"
    except Exception as e:
        return False, str(e)


def get_hosts_blocked_domains():
    domains = []
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if HOSTS_MARKER in line and "0.0.0.0" in line:
                    parts = line.strip().split()
                    if len(parts) >= 2 and not parts[1].startswith("www."):
                        domains.append(parts[1])
    except Exception: pass
    return domains



# Google Safe Browsing API v4 (free, 10,000 req/day)
# Set your API key here or leave empty to use local detection only
GOOGLE_SB_API_KEY = ""   # Get free key: https://developers.google.com/safe-browsing

# Cache: domain -> threat result (so we don't re-check the same domain)
_threat_cache: dict = {}  # domain -> {level, type, detail, source} or None
_threat_queue: list = []  # domains waiting to be checked
_threat_lock = threading.Lock()


def check_threat_local(domain: str):
    """
    Check domain against local pattern list.
    Returns dict or None.
    """
    d = domain.lower().strip().rstrip('.')
    if d in THREAT_WHITELIST:
        return None
    # Also skip subdomains of whitelisted domains
    for w in THREAT_WHITELIST:
        if d.endswith('.' + w):
            return None

    for pattern, threat_type, level, detail in THREAT_PATTERNS:
        try:
            if re.search(pattern, d, re.IGNORECASE):
                return {
                    'level':  level,
                    'type':   threat_type,
                    'detail': detail,
                    'source': 'local',
                }
        except Exception:
            pass
    return None


def check_threat_google_sb(domain: str):
    """
    Check domain against Google Safe Browsing API v4.
    Returns dict or None. Only called if API key is set.
    """
    if not GOOGLE_SB_API_KEY:
        return None
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_API_KEY}"
    body = {
        "client": {"clientId": "ai-firewall", "clientVersion": "7.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION","THREAT_TYPE_UNSPECIFIED"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"http://{domain}/"}]
        }
    }
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            matches = data.get("matches", [])
            if matches:
                m = matches[0]
                ttype = m.get("threatType","UNKNOWN").replace("_"," ").title()
                return {
                    'level':  'HIGH',
                    'type':   ttype,
                    'detail': f"Google Safe Browsing: {ttype}",
                    'source': 'google_sb',
                }
    except Exception:
        pass
    return None


def threat_check_worker():
    """
    Background thread: drains _threat_queue, checks each domain,
    updates state['websites'] and fires alerts.
    """
    while True:
        domain = None
        with _threat_lock:
            if _threat_queue:
                domain = _threat_queue.pop(0)
        if not domain:
            time.sleep(0.2)
            continue

        # Skip if already checked
        with _threat_lock:
            if domain in _threat_cache:
                continue

        # Run checks
        result = check_threat_local(domain)
        if not result and GOOGLE_SB_API_KEY:
            result = check_threat_google_sb(domain)

        with _threat_lock:
            _threat_cache[domain] = result  # None means "clean"

        if result:
            level  = result['level']
            ttype  = result['type']
            detail = result['detail']

            # Find the IP for this domain
            found_ip = ''
            with state_lock:
                # Look in ip_to_domain mapping
                for k, v in state['ip_to_domain'].items():
                    if v == domain:
                        found_ip = k
                        break
                # Also check the website entry itself
                if not found_ip and domain in state['websites']:
                    found_ip = state['websites'][domain].get('ip', '')
                # Store threat result and update stats
                state['stats']['threats'] += 1
                if domain in state['websites']:
                    state['websites'][domain]['threat'] = result

            add_log(
                f"⚠ [{level}] {domain} — {ttype}: {detail}",
                'threat'
            )

            # Auto-block HIGH threats immediately
            if level == 'HIGH' and found_ip:
                add_log(f"AUTO-BLOCKING {found_ip} ({domain})", 'blocked')
                threading.Thread(target=block_ip, args=(found_ip, domain), daemon=True).start()
            elif level == 'HIGH' and not found_ip:
                add_log(f"HIGH threat on {domain} — IP not yet resolved, skipping auto-block", 'info')


def queue_threat_check(domain: str):
    """Add a domain to the threat check queue (non-blocking)."""
    with _threat_lock:
        if domain not in _threat_cache and domain not in _threat_queue:
            _threat_queue.append(domain)


# Start the background threat checker
threading.Thread(target=threat_check_worker, daemon=True).start()


try:
    from scapy.all import sniff, IP, TCP, DNS, DNSQR, DNSRR, Raw, get_if_list
    HAS_SCAPY = True
except Exception:
    HAS_SCAPY = False

# ─────────────────────────────────────────────────────────────────────────────
# Browser history database paths
# ─────────────────────────────────────────────────────────────────────────────

def get_browser_db_paths():
    """Return list of (browser_name, db_path) for installed browsers."""
    paths = []
    home = os.path.expanduser("~")

    if platform.system() == "Windows":
        appdata  = os.environ.get("APPDATA", "")
        local    = os.environ.get("LOCALAPPDATA", "")
        roaming  = appdata

        candidates = [
            ("Chrome",          os.path.join(local,   "Google", "Chrome", "User Data", "Default", "History")),
            ("Chrome Profile 1",os.path.join(local,   "Google", "Chrome", "User Data", "Profile 1", "History")),
            ("Edge",            os.path.join(local,   "Microsoft", "Edge", "User Data", "Default", "History")),
            ("Brave",           os.path.join(local,   "BraveSoftware", "Brave-Browser", "User Data", "Default", "History")),
            ("Opera",           os.path.join(roaming, "Opera Software", "Opera Stable", "History")),
            ("Vivaldi",         os.path.join(local,   "Vivaldi", "User Data", "Default", "History")),
            ("Firefox",         None),   # handled separately below
        ]

        # Firefox has a different structure
        ff_base = os.path.join(roaming, "Mozilla", "Firefox", "Profiles")
        if os.path.isdir(ff_base):
            for prof in os.listdir(ff_base):
                db = os.path.join(ff_base, prof, "places.sqlite")
                if os.path.isfile(db):
                    candidates.append((f"Firefox ({prof[:8]})", db))

    elif platform.system() == "Darwin":
        candidates = [
            ("Chrome",  os.path.join(home, "Library","Application Support","Google","Chrome","Default","History")),
            ("Edge",    os.path.join(home, "Library","Application Support","Microsoft Edge","Default","History")),
            ("Brave",   os.path.join(home, "Library","Application Support","BraveSoftware","Brave-Browser","Default","History")),
            ("Firefox", None),
        ]
        ff_base = os.path.join(home, "Library","Application Support","Firefox","Profiles")
        if os.path.isdir(ff_base):
            for prof in os.listdir(ff_base):
                db = os.path.join(ff_base, prof, "places.sqlite")
                if os.path.isfile(db):
                    candidates.append((f"Firefox ({prof[:8]})", db))
    else:
        candidates = [
            ("Chrome",   os.path.join(home, ".config","google-chrome","Default","History")),
            ("Chromium", os.path.join(home, ".config","chromium","Default","History")),
            ("Brave",    os.path.join(home, ".config","BraveSoftware","Brave-Browser","Default","History")),
            ("Firefox",  None),
        ]
        ff_base = os.path.join(home, ".mozilla","firefox")
        if os.path.isdir(ff_base):
            for prof in os.listdir(ff_base):
                db = os.path.join(ff_base, prof, "places.sqlite")
                if os.path.isfile(db):
                    candidates.append((f"Firefox ({prof[:8]})", db))

    for name, path in candidates:
        if path and os.path.isfile(path):
            paths.append((name, path))

    return paths


def read_chrome_history(db_path, since_ts=None):
    """
    Read Chrome/Edge/Brave history DB.
    Returns list of {url, title, visit_time, domain}
    since_ts: Python timestamp (float) — only return entries after this time
    """
    results = []
    tmp = None
    try:
        # Copy DB because Chrome locks it
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        shutil.copy2(db_path, tmp.name)

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Chrome stores time as microseconds since 1601-01-01
        # Convert since_ts (Unix) to Chrome time
        if since_ts:
            chrome_epoch_offset = 11644473600  # seconds between 1601 and 1970
            chrome_since = int((since_ts + chrome_epoch_offset) * 1_000_000)
            cur.execute("""
                SELECT u.url, u.title, v.visit_time
                FROM visits v JOIN urls u ON v.url = u.id
                WHERE v.visit_time > ?
                ORDER BY v.visit_time DESC
                LIMIT 500
            """, (chrome_since,))
        else:
            cur.execute("""
                SELECT u.url, u.title, v.visit_time
                FROM visits v JOIN urls u ON v.url = u.id
                ORDER BY v.visit_time DESC
                LIMIT 200
            """)

        for row in cur.fetchall():
            url   = row['url'] or ''
            title = row['title'] or ''
            vt    = row['visit_time'] or 0

            # Convert Chrome time to Unix timestamp
            unix_ts = (vt / 1_000_000) - 11644473600 if vt else 0

            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'): domain = domain[4:]

            if domain and not url.startswith('chrome://') and not url.startswith('about:'):
                results.append({
                    'url':    url,
                    'title':  title,
                    'ts':     unix_ts,
                    'domain': domain,
                    'browser': '',
                })
        conn.close()
    except Exception as e:
        pass
    finally:
        if tmp:
            try: os.unlink(tmp.name)
            except: pass
    return results


def read_firefox_history(db_path, since_ts=None):
    """Read Firefox places.sqlite history."""
    results = []
    tmp = None
    try:
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        shutil.copy2(db_path, tmp.name)

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Firefox stores time as microseconds since Unix epoch
        if since_ts:
            ff_since = int(since_ts * 1_000_000)
            cur.execute("""
                SELECT p.url, p.title, h.visit_date
                FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id
                WHERE h.visit_date > ?
                ORDER BY h.visit_date DESC
                LIMIT 500
            """, (ff_since,))
        else:
            cur.execute("""
                SELECT p.url, p.title, h.visit_date
                FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id
                ORDER BY h.visit_date DESC
                LIMIT 200
            """)

        for row in cur.fetchall():
            url   = row['url'] or ''
            title = row['title'] or ''
            vd    = row['visit_date'] or 0
            unix_ts = (vd / 1_000_000) if vd else 0

            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'): domain = domain[4:]

            if domain and not url.startswith('about:') and not url.startswith('moz-'):
                results.append({
                    'url':    url,
                    'title':  title,
                    'ts':     unix_ts,
                    'domain': domain,
                    'browser': '',
                })
        conn.close()
    except Exception:
        pass
    finally:
        if tmp:
            try: os.unlink(tmp.name)
            except: pass
    return results


def read_all_browser_history(since_ts=None):
    """Read history from all detected browsers. Returns list sorted by time desc."""
    all_results = []
    for browser_name, db_path in get_browser_db_paths():
        try:
            if 'Firefox' in browser_name or 'firefox' in db_path.lower():
                entries = read_firefox_history(db_path, since_ts)
            else:
                entries = read_chrome_history(db_path, since_ts)
            for e in entries:
                e['browser'] = browser_name
            all_results.extend(entries)
        except Exception:
            pass

    # Sort by time descending — DO NOT deduplicate here.
    # The caller (browser_history_poll) owns deduplication logic.
    return sorted(all_results, key=lambda x: x['ts'], reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# Shared state
# ─────────────────────────────────────────────────────────────────────────────
state = {
    "capturing":    False,
    "interface":    "Unknown",
    "wifi":         "Not Connected",
    "websites":     {},       # domain -> {count, last, type, ip, title, url, browser, threat}
    "live_log":     [],
    "stats":        {"total":0,"live":0,"blocked":0,"threats":0},
    "ip_to_domain": {},
    "dns_cache":    {},
    "blocked_ips":  {},       # ip -> {domain, blocked_at}
    "blocked_domains": {},    # domain -> {blocked_at, method}
    "capture_start_ts": 0.0, # Unix timestamp when capture started
    "browsers_found": [],    # list of browser names detected
}
state_lock     = threading.Lock()
client_log_pos = {}

# ─────────────────────────────────────────────────────────────────────────────
# IP blocking
# ─────────────────────────────────────────────────────────────────────────────

def _rule_name(ip):
    return f"AIFirewall_Block_{ip.replace('.','_')}"

def block_ip(ip, domain=""):
    rule = _rule_name(ip)
    try:
        if platform.system() == "Windows":
            for direction in ['out','in']:
                n = rule if direction=='out' else rule+'_IN'
                subprocess.check_call([
                    'netsh','advfirewall','firewall','add','rule',
                    f'name={n}',f'dir={direction}','action=block',
                    f'remoteip={ip}','enable=yes'
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   creationflags=subprocess.CREATE_NO_WINDOW)
        elif platform.system() == "Linux":
            subprocess.check_call(['iptables','-A','OUTPUT','-d',ip,'-j','DROP'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.check_call(['iptables','-A','INPUT','-s',ip,'-j','DROP'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif platform.system() == "Darwin":
            subprocess.check_call(
                f'echo "block drop quick from any to {ip}" | pfctl -a AIFirewall -f -',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with state_lock:
            state['blocked_ips'][ip] = {
                'domain': domain or ip,
                'blocked_at': datetime.now().strftime('%H:%M:%S'),
                'rule': rule,
            }
            state['stats']['blocked'] += 1
        add_log(f"BLOCKED {ip}  ({domain})", 'blocked')
        return True, "Blocked"
    except Exception as e:
        add_log(f"Block failed {ip}: {e}", 'err')
        return False, str(e)

def unblock_ip(ip):
    rule = _rule_name(ip)
    try:
        if platform.system() == "Windows":
            for n in [rule, rule+'_IN']:
                subprocess.call(['netsh','advfirewall','firewall','delete','rule',f'name={n}'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW)
        elif platform.system() == "Linux":
            subprocess.call(['iptables','-D','OUTPUT','-d',ip,'-j','DROP'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.call(['iptables','-D','INPUT','-s',ip,'-j','DROP'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with state_lock:
            state['blocked_ips'].pop(ip, None)
            if state['stats']['blocked'] > 0:
                state['stats']['blocked'] -= 1
        add_log(f"UNBLOCKED {ip}", 'info')
        return True, "Unblocked"
    except Exception as e:
        return False, str(e)


# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN BLOCKING  (blocks by domain name, not just IP)
# Uses Windows hosts file + firewall rules for all resolved IPs
# ─────────────────────────────────────────────────────────────────────────────

HOSTS_FILE = (
    r"C:\Windows\System32\drivers\etc\hosts"
    if platform.system() == "Windows"
    else "/etc/hosts"
)
HOSTS_MARKER = "# AIFirewall"

def block_domain(domain):
    """
    Block a domain by:
    1. Redirecting it to 0.0.0.0 in the hosts file (stops DNS resolution)
    2. Blocking all its currently resolved IPs via firewall
    """
    domain = domain.lower().strip().rstrip(".")
    if not domain:
        return False, "Empty domain"
    try:
        # ── Hosts file redirect ──────────────────────────────────────────
        try:
            with open(HOSTS_FILE, "r", encoding="utf-8", errors="ignore") as f:
                hosts_content = f.read()
        except Exception:
            hosts_content = ""

        entry      = f"0.0.0.0 {domain} {HOSTS_MARKER}"
        www_entry  = f"0.0.0.0 www.{domain} {HOSTS_MARKER}"

        new_lines = []
        if entry not in hosts_content:
            new_lines.append(entry)
        if www_entry not in hosts_content:
            new_lines.append(www_entry)

        if new_lines:
            with open(HOSTS_FILE, "a", encoding="utf-8") as f:
                f.write("\n" + "\n".join(new_lines) + "\n")

        # Flush DNS cache so the block takes effect immediately
        if platform.system() == "Windows":
            subprocess.call(["ipconfig", "/flushdns"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
        elif platform.system() == "Darwin":
            subprocess.call(["dscacheutil", "-flushcache"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.call(["systemd-resolve", "--flush-caches"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # ── Also block resolved IPs via firewall ─────────────────────────
        try:
            ips = socket.getaddrinfo(domain, None)
            blocked_ips_for_domain = []
            for item in ips:
                ip = item[4][0]
                if ip and not ip.startswith("0."):
                    block_ip(ip, domain)
                    blocked_ips_for_domain.append(ip)
        except Exception:
            blocked_ips_for_domain = []

        now = datetime.now().strftime("%H:%M:%S")
        with state_lock:
            state["blocked_domains"][domain] = {
                "blocked_at": now,
                "ips":        blocked_ips_for_domain,
            }

        add_log(f"DOMAIN BLOCKED: {domain} → 0.0.0.0 (hosts file)", "blocked")
        if blocked_ips_for_domain:
            add_log(f"  Also blocked IPs: {', '.join(blocked_ips_for_domain)}", "blocked")
        return True, "Blocked"

    except PermissionError:
        msg = "Permission denied — run as Administrator/root to block domains"
        add_log(f"Block failed ({domain}): {msg}", "err")
        return False, msg
    except Exception as e:
        add_log(f"Block failed ({domain}): {e}", "err")
        return False, str(e)


def unblock_domain(domain):
    """Remove domain from hosts file and unblock its IPs."""
    domain = domain.lower().strip().rstrip(".")
    try:
        # ── Remove from hosts file ───────────────────────────────────────
        try:
            with open(HOSTS_FILE, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            new_lines = [
                l for l in lines
                if not (HOSTS_MARKER in l and domain in l)
            ]
            with open(HOSTS_FILE, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
        except Exception:
            pass

        # Flush DNS cache
        if platform.system() == "Windows":
            subprocess.call(["ipconfig", "/flushdns"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)

        # ── Unblock IPs ──────────────────────────────────────────────────
        with state_lock:
            info = state["blocked_domains"].pop(domain, {})
            blocked_ips_list = info.get("ips", [])

        for ip in blocked_ips_list:
            unblock_ip(ip)

        add_log(f"DOMAIN UNBLOCKED: {domain}", "info")
        return True, "Unblocked"

    except PermissionError:
        return False, "Permission denied — run as Administrator/root"
    except Exception as e:
        return False, str(e)


def resolve_domain_to_ip(domain):
    """Non-blocking DNS resolve with 1s timeout via thread."""
    result = [None]
    def _resolve():
        try:
            result[0] = socket.gethostbyname(domain)
        except Exception:
            pass
    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(timeout=1.0)   # never block the poll loop for more than 1s
    return result[0]

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def add_log(msg, tag='info'):
    ts = datetime.now().strftime('%H:%M:%S')
    with state_lock:
        state['live_log'].append({'ts':ts, 'msg':msg.strip(), 'tag':tag})
        if len(state['live_log']) > 2000:
            state['live_log'] = state['live_log'][-1500:]

def record_site(domain, src_type, ip="", title="", url="", browser=""):
    domain = domain.lower().strip().rstrip('.')
    if not domain or '.' not in domain or len(domain) < 4: return False
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain): return False

    now = datetime.now().strftime('%H:%M:%S')
    with state_lock:
        if domain not in state['websites']:
            state['websites'][domain] = {
                'count': 1, 'last': now, 'type': src_type,
                'ip': ip, 'title': title, 'url': url, 'browser': browser
            }
            return True
        else:
            w = state['websites'][domain]
            w['count'] += 1
            w['last']   = now
            if ip:      w['ip']      = ip
            if title:   w['title']   = title
            if url:     w['url']     = url
            if browser: w['browser'] = browser
            return False

def get_wifi_name():
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(['netsh','wlan','show','interfaces'],
                text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if 'SSID' in line and 'BSSID' not in line:
                    return line.split(':',1)[1].strip()
        elif platform.system() == "Darwin":
            out = subprocess.check_output(
                ['/System/Library/PrivateFrameworks/Apple80211.framework'
                 '/Versions/Current/Resources/airport','-I'],
                text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if ' SSID:' in line: return line.split(':',1)[1].strip()
        else:
            return subprocess.check_output(['iwgetid','-r'],text=True).strip()
    except Exception: pass
    return "Not Connected"

def get_best_interface():
    if not HAS_SCAPY: return "Unknown"
    try:
        interfaces = get_if_list()
        if platform.system() == "Windows":
            try:
                from scapy.arch.windows import get_windows_if_list
                wifs = get_windows_if_list()
                for iface in wifs:
                    desc = iface.get('description','').lower()
                    if any(k in desc for k in ['wi-fi','wifi','wireless','wlan']):
                        guid = iface.get('guid','')
                        if guid:
                            c = "\\Device\\NPF_{"+guid+"}"
                            if c in interfaces: return c
                for iface in wifs:
                    if 'loopback' not in iface.get('description','').lower():
                        guid = iface.get('guid','')
                        if guid:
                            c = "\\Device\\NPF_{"+guid+"}"
                            if c in interfaces: return c
            except Exception: pass
            return next((i for i in interfaces
                if 'loopback' not in i.lower() and 'npf_lo' not in i.lower()), "Unknown")
        else:
            for kw in ['wlan','wifi','wlp','en0','eth']:
                for iface in interfaces:
                    if kw in iface.lower() and 'lo' not in iface.lower(): return iface
            return next((i for i in interfaces
                if i.lower() not in ('lo','loopback')), "Unknown")
    except Exception: pass
    return "Unknown"

# ─────────────────────────────────────────────────────────────────────────────
# Main capture: poll browser history every 2 seconds
# ─────────────────────────────────────────────────────────────────────────────

def browser_history_poll():
    """
    Polls browser SQLite history every 1 second.
    Shows a new site THE MOMENT it appears in browser history.

    Key design decisions:
    - Tracks visits by (domain, rounded_ts) not just domain — so revisiting
      a site after 2+ seconds shows up as a new log entry.
    - Uses a 15-second sliding window for since_ts to never miss a visit even
      if the DB copy is slow.
    - Pre-seeds known domains from state['websites'] on restart so old sites
      aren't re-logged, but new visits to old domains ARE logged.
    """
    session_id = state['capture_start_ts']

    # seen_visits: set of (domain, int(ts)) — tracks individual visit moments
    # Pre-seed with existing entries at ts=0 (old sessions) so they aren't re-logged
    seen_visits = set()
    with state_lock:
        for domain in state['websites']:
            seen_visits.add((domain, 0))   # 0 = "from before this session"

    is_restart  = len(state['websites']) > 0
    start_ts    = state['capture_start_ts']

    add_log("Reading browser history databases...", 'info')
    if is_restart:
        add_log(f"Restart — monitoring for NEW visits only.", 'info')

    dbs = get_browser_db_paths()
    if not dbs:
        add_log("No browser history found. Is Chrome/Edge/Firefox installed?", 'err')
    else:
        names = [n for n,_ in dbs]
        state['browsers_found'] = names
        add_log(f"Browsers found: {', '.join(names)}", 'info')
        add_log("Watching for new visits — browse something!", 'info')

    # Start reading from capture start time (minus 5s buffer on fresh start)
    since_ts = start_ts - (0 if is_restart else 5)

    while state['capturing'] and state['capture_start_ts'] == session_id:
        try:
            # Use a 15-second lookback window to never miss a visit
            window_since = time.time() - 15
            entries = read_all_browser_history(since_ts=min(since_ts, window_since))

            for e in entries:
                domain = e['domain']
                if not domain:
                    continue

                # Round visit timestamp to nearest 2 seconds to group rapid reloads
                # but still catch visits to the same site after a gap
                visit_key = (domain, int(e.get('ts', 0) / 2))

                if visit_key in seen_visits:
                    continue
                seen_visits.add(visit_key)

                # Only show visits that happened AFTER this session started
                entry_ts = e.get('ts', 0)
                if entry_ts > 0 and entry_ts < (start_ts - (5 if not is_restart else 0)):
                    continue

                # Record site immediately (no IP yet — speed matters)
                title_str = (e.get('title','') or domain)[:55]
                browser   = e.get('browser','')
                new = record_site(
                    domain, 'history',
                    ip='',
                    title=e.get('title',''),
                    url=e.get('url',''),
                    browser=browser
                )
                # Queue threat check for EVERY domain (new or revisit)
                # The worker caches results so it only does real work once per domain
                queue_threat_check(domain)

                if new:
                    suffix = f"  [{browser}]" if browser else ''
                    add_log(f"{domain}  —  {title_str}{suffix}", 'history')
                    with state_lock:
                        state['stats']['live'] += 1
                        state['stats']['total'] += 1
                else:
                    add_log(f"revisit: {domain}  —  {title_str}", 'history')
                    with state_lock:
                        state['stats']['total'] += 1

                # Resolve IP in background — fills into state without blocking
                def _fill_ip(d=domain):
                    ip = resolve_domain_to_ip(d) or ''
                    if ip:
                        with state_lock:
                            state['ip_to_domain'][ip] = d
                            if d in state['websites']:
                                state['websites'][d]['ip'] = ip
                threading.Thread(target=_fill_ip, daemon=True).start()

        except Exception as ex:
            add_log(f"History read error: {ex}", 'err')

        time.sleep(1)   # Poll every 1 second for near-instant detection


# Optional Scapy DNS — only to get IP mappings, not for showing fake sites
def scapy_dns_only():
    """Only uses Scapy to build IP<->domain cache from real DNS packets."""
    iface = state['interface']
    if iface == "Unknown":
        try:
            avail = [i for i in get_if_list()
                     if 'loopback' not in i.lower() and 'npf_lo' not in i.lower()]
            if avail:
                iface = avail[0]; state['interface'] = iface
        except Exception:
            return

    session_id = state['capture_start_ts']
    def pkt_cb(pkt):
        if not state['capturing'] or state['capture_start_ts'] != session_id: return
        try:
            from scapy.all import DNSRR, DNSQR
            if pkt.haslayer(DNSRR) and pkt.haslayer(DNSQR):
                q = pkt[DNSQR].qname.decode('utf-8',errors='ignore').rstrip('.')
                a = str(pkt[DNSRR].rdata)
                if q and a and re.match(r'^\d+\.\d+\.\d+\.\d+$', a):
                    with state_lock:
                        state['ip_to_domain'][a] = q
                        state['dns_cache'][a]     = q
                    # Update IP for any existing site entry
                    d = q.lower().strip().rstrip('.')
                    if d.startswith('www.'): d = d[4:]
                    with state_lock:
                        if d in state['websites'] and not state['websites'][d].get('ip'):
                            state['websites'][d]['ip'] = a
        except Exception: pass

    try:
        from scapy.all import sniff
        sniff(iface=iface, prn=pkt_cb, store=False, filter="udp port 53",
              stop_filter=lambda _: not state['capturing'] or state['capture_start_ts'] != session_id)
    except Exception:
        pass


def start_capture():
    if state['capturing']: return
    # Update session ID FIRST — any stale threads watching this will exit
    state['capture_start_ts'] = time.time()
    state['capturing'] = True
    add_log("="*52, 'header')
    add_log("CAPTURE STARTED  |  Reading Browser History + Threat Engine", 'header')
    add_log(f"WiFi: {state['wifi']}  |  Started: {datetime.now().strftime('%H:%M:%S')}", 'info')
    add_log("="*52, 'header')
    # Queue threat checks for any sites already in the table from a previous session
    with state_lock:
        existing_domains = list(state['websites'].keys())
    for d in existing_domains:
        queue_threat_check(d)
    if existing_domains:
        add_log(f"Re-checking {len(existing_domains)} existing site(s) for threats...", 'info')
    threading.Thread(target=browser_history_poll, daemon=True).start()
    if HAS_SCAPY:
        threading.Thread(target=scapy_dns_only, daemon=True).start()

def stop_capture():
    state['capturing'] = False
    add_log("Capture stopped.", 'info')

# ─────────────────────────────────────────────────────────────────────────────
# HTML Dashboard
# ─────────────────────────────────────────────────────────────────────────────

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AI Firewall v7.0</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;500;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg0:#020408;--bg1:#060d14;--bg2:#0a1520;--bg3:#0f1e2d;
  --panel:#081220;--border:#0e3a5a;
  --accent:#00e5ff;--green:#00ff9d;--red:#ff2d55;
  --orange:#ff9500;--purple:#bf5fff;--teal:#00ffe0;
  --dim:#3a6080;--text:#c8e8f8;
  --glow:0 0 18px #00e5ff55;--glow-g:0 0 18px #00ff9d55;--glow-r:0 0 18px #ff2d5555;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden}
body{background:var(--bg0);color:var(--text);font-family:'Rajdhani',sans-serif;
     font-size:15px;overflow:hidden}
body::before{content:'';position:fixed;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,
  rgba(0,229,255,.012) 2px,rgba(0,229,255,.012) 4px);
  pointer-events:none;z-index:1000}
body::after{content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(0,229,255,.03) 1px,transparent 1px),
  linear-gradient(90deg,rgba(0,229,255,.03) 1px,transparent 1px);
  background-size:48px 48px;pointer-events:none;z-index:0}

header{position:relative;z-index:10;
  background:linear-gradient(180deg,#020c18 0%,var(--bg1) 100%);
  border-bottom:1px solid var(--border);padding:14px 26px 12px;
  display:flex;align-items:center;justify-content:space-between;gap:20px}
.logo{display:flex;align-items:center;gap:14px}
.logo-icon{width:44px;height:44px;border:2px solid var(--accent);border-radius:50%;
  display:flex;align-items:center;justify-content:center;font-size:20px;
  box-shadow:var(--glow),inset 0 0 20px #00e5ff22;
  animation:pulse-border 3s ease-in-out infinite}
@keyframes pulse-border{0%,100%{box-shadow:var(--glow),inset 0 0 20px #00e5ff22}
  50%{box-shadow:0 0 30px #00e5ffaa,inset 0 0 30px #00e5ff44}}
.logo-text h1{font-family:'Orbitron',monospace;font-size:18px;font-weight:900;
  letter-spacing:3px;color:var(--accent);text-shadow:var(--glow);line-height:1}
.logo-text p{font-family:'Share Tech Mono',monospace;font-size:10px;
  color:var(--dim);letter-spacing:2px;margin-top:3px}
.header-meta{display:flex;gap:16px;align-items:center}
.meta-chip{font-family:'Share Tech Mono',monospace;font-size:11px;
  padding:4px 10px;border:1px solid var(--border);border-radius:3px;
  background:var(--bg2);color:var(--dim);letter-spacing:1px}
.meta-chip span{color:var(--green)}
#capture-badge{font-family:'Orbitron',monospace;font-size:10px;font-weight:700;
  letter-spacing:2px;padding:5px 14px;border-radius:3px;
  border:1px solid var(--dim);color:var(--dim);background:transparent;transition:all .3s}
#capture-badge.active{border-color:var(--red);color:var(--red);
  background:#ff2d5511;box-shadow:0 0 12px #ff2d5544;
  animation:blink-badge .8s step-end infinite}
@keyframes blink-badge{50%{opacity:.4}}

.app{position:relative;z-index:2;display:grid;
  grid-template-columns:275px 1fr;
  grid-template-rows:1fr 28px;
  height:calc(100vh - 78px);
  min-height:0;
  overflow:hidden}

.sidebar{grid-row:1/3;background:var(--panel);border-right:1px solid var(--border);
  display:flex;flex-direction:column;overflow-y:auto;min-height:0}
.sb-section{border-bottom:1px solid var(--border);padding:14px 13px}
.sec-title{font-family:'Orbitron',monospace;font-size:9px;font-weight:700;
  letter-spacing:3px;color:var(--dim);margin-bottom:10px;
  display:flex;align-items:center;gap:7px}
.sec-title::before{content:'';display:block;width:10px;height:1px;background:var(--accent)}

.btn{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:4px;
  background:var(--bg2);color:var(--text);font-family:'Orbitron',monospace;
  font-size:10px;font-weight:700;letter-spacing:2px;cursor:pointer;transition:all .2s;
  display:flex;align-items:center;gap:9px;margin-bottom:6px;text-transform:uppercase}
.btn:last-child{margin-bottom:0}
.btn-start{border-color:var(--green);color:var(--green);background:#00ff9d0a}
.btn-start:hover{background:#00ff9d22;box-shadow:var(--glow-g)}
.btn-stop{border-color:var(--red);color:var(--red);background:#ff2d550a}
.btn-stop:hover{background:#ff2d5522;box-shadow:var(--glow-r)}
.btn-neutral{border-color:var(--dim);color:var(--dim)}
.btn-neutral:hover{border-color:var(--accent);color:var(--accent);background:#00e5ff0a}
.btn-danger{border-color:var(--orange);color:var(--orange);background:#ff95000a}
.btn-danger:hover{background:#ff950022;box-shadow:0 0 14px #ff950044}

.stat-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.stat-card{background:var(--bg2);border:1px solid var(--border);
  border-radius:4px;padding:8px 6px;text-align:center}
.stat-label{font-family:'Share Tech Mono',monospace;font-size:9px;
  color:var(--dim);letter-spacing:1px;text-transform:uppercase;margin-bottom:3px}
.stat-value{font-family:'Orbitron',monospace;font-size:20px;font-weight:900;line-height:1}
.sv-blue{color:var(--accent);text-shadow:var(--glow)}
.sv-green{color:var(--green);text-shadow:var(--glow-g)}
.sv-red{color:var(--red);text-shadow:var(--glow-r)}
.sv-orange{color:var(--orange);text-shadow:0 0 14px #ff950055}
.sv-teal{color:var(--teal);text-shadow:0 0 14px #00ffe055}

.info-box{background:var(--bg2);border:1px solid var(--border);
  border-left:3px solid var(--accent);border-radius:3px;
  padding:9px 11px;font-family:'Share Tech Mono',monospace;
  font-size:10px;color:var(--dim);line-height:1.7}
.info-box strong{color:var(--accent);display:block;margin-bottom:3px;
  font-family:'Orbitron',monospace;font-size:9px;letter-spacing:2px}

.blocked-list{display:flex;flex-direction:column;gap:4px;max-height:150px;overflow-y:auto}
.blocked-list::-webkit-scrollbar{width:3px}
.blocked-list::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.blocked-item{background:var(--bg2);border:1px solid #ff2d5530;border-radius:3px;
  padding:5px 8px;display:flex;align-items:center;justify-content:space-between;gap:6px}
.blocked-ip{font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--red)}
.blocked-domain{font-family:'Share Tech Mono',monospace;font-size:9px;
  color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.unblock-btn{font-family:'Orbitron',monospace;font-size:8px;font-weight:700;
  letter-spacing:1px;padding:3px 7px;border:1px solid var(--dim);border-radius:2px;
  background:transparent;color:var(--dim);cursor:pointer;white-space:nowrap;
  transition:all .15s;flex-shrink:0}
.unblock-btn:hover{border-color:var(--green);color:var(--green)}
.no-blocked{font-family:'Share Tech Mono',monospace;font-size:10px;
  color:var(--dim);text-align:center;padding:10px 0}

.main-content{display:flex;flex-direction:column;overflow:hidden;min-height:0}
.tabs{display:flex;border-bottom:1px solid var(--border);
  background:var(--panel);padding:0 16px}
.tab{font-family:'Orbitron',monospace;font-size:9px;font-weight:700;
  letter-spacing:2px;padding:12px 15px;color:var(--dim);cursor:pointer;
  border-bottom:2px solid transparent;transition:all .2s;text-transform:uppercase}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-content{display:none;flex:1;overflow:hidden;min-height:0}
.tab-content.active{display:flex;flex-direction:column;flex:1;min-height:0;overflow:hidden}

.log-container{flex:1;overflow-y:auto;padding:10px 13px;
  background:var(--bg1);font-family:'Share Tech Mono',monospace;
  font-size:12px;line-height:1.9;min-height:0;
  user-select:none;-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none}
.log-container::-webkit-scrollbar{width:4px}
.log-container::-webkit-scrollbar-track{background:var(--bg0)}
.log-container::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.log-line{display:flex;gap:8px;align-items:baseline;padding:1px 0}
.log-ts{color:var(--dim);flex-shrink:0;font-size:10px}
.log-tag{flex-shrink:0;font-size:9px;padding:1px 5px;border-radius:2px;
  font-weight:700;letter-spacing:1px}
.log-msg{color:var(--text);word-break:break-all}
.tag-history{background:#00ff9d18;color:var(--green);border:1px solid #00ff9d33}
.tag-dns{background:#00ffe014;color:var(--teal);border:1px solid #00ffe02a}
.tag-blocked{background:#ff2d5520;color:var(--red);border:1px solid #ff2d5540;font-weight:700}
.tag-threat{background:#ff950028;color:var(--orange);border:1px solid #ff950055;
  font-weight:700;animation:threat-flash .6s step-end infinite}
@keyframes threat-flash{50%{background:#ff950055;color:#fff}}
.threat-badge{font-size:9px;padding:2px 8px;border-radius:2px;font-weight:700;letter-spacing:1px;margin-left:4px}
.threat-HIGH-badge{background:#ff2d5520;border:1px solid #ff2d5555;color:var(--red)}
.threat-MEDIUM-badge{background:#ff950018;border:1px solid #ff950044;color:var(--orange)}
.threat-LOW-badge{background:#ffe03318;border:1px solid #ffe03344;color:var(--yellow)}
.threat-panel{flex:1;overflow-y:auto;background:var(--bg1);padding:0;min-height:0}
.threat-panel::-webkit-scrollbar{width:4px}
.threat-panel::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.threat-card{margin:10px 12px;background:var(--bg2);
  border:1px solid #ff2d5530;border-left:3px solid var(--red);
  border-radius:4px;padding:12px 14px}
.threat-card.MEDIUM{border-left-color:var(--orange);border-color:#ff950030}
.threat-card.LOW{border-left-color:var(--yellow);border-color:#ffe03330}
.threat-domain{font-family:'Orbitron',monospace;font-size:12px;font-weight:700;color:var(--accent);margin-bottom:4px}
.threat-meta{font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--dim);line-height:1.7}
.threat-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;
  height:180px;gap:10px;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:12px}
.threat-count-badge{display:inline-flex;align-items:center;justify-content:center;
  width:18px;height:18px;border-radius:50%;background:var(--red);color:#fff;
  font-family:'Orbitron',monospace;font-size:9px;font-weight:700;margin-left:6px;
  vertical-align:middle;animation:pulse-red 1s ease infinite}
@keyframes pulse-red{0%,100%{box-shadow:0 0 0 0 #ff2d5566}50%{box-shadow:0 0 0 6px transparent}}
.tag-threat{background:#ff950028;color:var(--orange);border:1px solid #ff950055;
  font-weight:700;font-size:9px;letter-spacing:1px;animation:threat-flash .6s step-end infinite}
@keyframes threat-flash{50%{background:#ff950055;color:#fff}}
.threat-HIGH  {color:var(--red);    font-weight:700}
.threat-MEDIUM{color:var(--orange); font-weight:700}
.threat-LOW   {color:var(--yellow); font-weight:700}
.threat-badge {font-size:9px;padding:2px 8px;border-radius:2px;font-weight:700;
  letter-spacing:1px;margin-left:4px}
.threat-HIGH-badge  {background:#ff2d5520;border:1px solid #ff2d5555;color:var(--red)}
.threat-MEDIUM-badge{background:#ff950018;border:1px solid #ff950044;color:var(--orange)}
.threat-LOW-badge   {background:#ffe03318;border:1px solid #ffe03344;color:var(--yellow)}
.threat-panel{flex:1;overflow-y:auto;background:var(--bg1);padding:0}
.threat-panel::-webkit-scrollbar{width:4px}
.threat-panel::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.threat-card{margin:10px 12px;background:var(--bg2);
  border:1px solid #ff2d5530;border-left:3px solid var(--red);
  border-radius:4px;padding:12px 14px}
.threat-card.MEDIUM{border-left-color:var(--orange);border-color:#ff950030}
.threat-card.LOW   {border-left-color:var(--yellow);border-color:#ffe03330}
.threat-domain{font-family:'Orbitron',monospace;font-size:12px;font-weight:700;
  color:var(--accent);margin-bottom:4px}
.threat-meta{font-family:'Share Tech Mono',monospace;font-size:11px;
  color:var(--dim);line-height:1.6}
.threat-empty{display:flex;flex-direction:column;align-items:center;
  justify-content:center;height:180px;gap:10px;color:var(--dim);
  font-family:'Share Tech Mono',monospace;font-size:12px}
.threat-count-badge{display:inline-flex;align-items:center;justify-content:center;
  width:18px;height:18px;border-radius:50%;background:var(--red);
  color:#fff;font-family:'Orbitron',monospace;font-size:9px;font-weight:700;
  margin-left:6px;vertical-align:middle;animation:pulse-red 1s ease infinite}
@keyframes pulse-red{0%,100%{box-shadow:0 0 0 0 #ff2d5566}50%{box-shadow:0 0 0 6px transparent}}
.tag-err{background:#ff2d5514;color:var(--red);border:1px solid #ff2d552a}
.tag-info{background:#ffffff07;color:var(--dim);border:1px solid #ffffff10}
.tag-hdr{background:#00e5ff22;color:var(--accent);border:1px solid #00e5ff44;font-weight:900}

.sites-wrap{flex:1;overflow-y:auto;background:var(--bg1);min-height:0}
.sites-wrap::-webkit-scrollbar{width:4px}
.sites-wrap::-webkit-scrollbar-track{background:var(--bg0)}
.sites-wrap::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.sites-table{width:100%;border-collapse:collapse;
  font-family:'Share Tech Mono',monospace;font-size:12px}
.sites-table thead{position:sticky;top:0;background:var(--bg0);
  border-bottom:1px solid var(--border)}
.sites-table th{padding:9px 12px;font-family:'Orbitron',monospace;font-size:8px;
  font-weight:700;letter-spacing:2px;color:var(--dim);text-align:left;text-transform:uppercase}
.sites-table td{padding:7px 12px;border-bottom:1px solid #0e3a5a22;vertical-align:middle}
.sites-table tr:hover td{background:#00e5ff05}
.sites-table tr.is-blocked td{background:#ff2d5508}
.domain-cell{color:var(--accent);font-size:13px;font-weight:700}
.title-cell{color:var(--dim);font-size:10px;max-width:200px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ip-cell{color:var(--purple);font-size:10px;font-family:'Share Tech Mono',monospace}
.browser-cell{font-size:9px;color:var(--teal)}
.count-cell{color:var(--green);text-align:right;font-weight:700}
.block-btn{font-family:'Orbitron',monospace;font-size:8px;font-weight:700;
  letter-spacing:1px;padding:4px 9px;border-radius:3px;cursor:pointer;
  border:1px solid var(--red);color:var(--red);background:#ff2d550a;
  transition:all .15s;white-space:nowrap}
.block-btn:hover{background:#ff2d5522;box-shadow:var(--glow-r)}
.block-btn.unblock{border-color:var(--dim);color:var(--dim);background:transparent}
.block-btn.unblock:hover{border-color:var(--green);color:var(--green)}
.empty-state{display:flex;flex-direction:column;align-items:center;
  justify-content:center;height:200px;gap:10px;color:var(--dim);
  font-family:'Share Tech Mono',monospace;font-size:12px;text-align:center;padding:20px}
.empty-icon{font-size:32px;opacity:.22}

.modal-overlay{display:none;position:fixed;inset:0;background:#00000099;
  backdrop-filter:blur(4px);z-index:999;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--accent);border-radius:6px;
  padding:24px;width:500px;box-shadow:0 0 40px #00e5ff22}
.modal.danger{border-color:var(--red);box-shadow:0 0 40px #ff2d5522}
.modal h2{font-family:'Orbitron',monospace;font-size:12px;letter-spacing:3px;
  color:var(--accent);margin-bottom:6px}
.modal.danger h2{color:var(--red)}
.modal p{font-family:'Share Tech Mono',monospace;font-size:11px;
  color:var(--dim);margin-bottom:14px;line-height:1.6}
.modal-input{width:100%;padding:10px 12px;background:var(--bg0);
  border:1px solid var(--border);border-radius:3px;
  font-family:'Share Tech Mono',monospace;font-size:13px;
  color:var(--accent);outline:none;margin-bottom:10px;letter-spacing:1px}
.modal-input:focus{border-color:var(--accent)}
.iface-list{background:var(--bg0);border:1px solid var(--border);border-radius:4px;
  max-height:180px;overflow-y:auto;margin-bottom:14px}
.iface-item{padding:9px 13px;font-family:'Share Tech Mono',monospace;font-size:11px;
  color:var(--text);cursor:pointer;border-bottom:1px solid var(--border);transition:background .15s}
.iface-item:last-child{border-bottom:none}
.iface-item:hover,.iface-item.selected{background:#00e5ff11;color:var(--accent)}
.modal-btns{display:flex;gap:9px;justify-content:flex-end}
.modal-btn{padding:7px 16px;border-radius:3px;font-family:'Orbitron',monospace;
  font-size:9px;font-weight:700;letter-spacing:2px;cursor:pointer;border:1px solid;transition:all .2s}
.modal-btn-ok-red{border-color:var(--red);color:var(--red);background:#ff2d550a}
.modal-btn-ok-red:hover{background:#ff2d5522}
.modal-btn-ok{border-color:var(--green);color:var(--green);background:#00ff9d0a}
.modal-btn-ok:hover{background:#00ff9d22}
.modal-btn-cancel{border-color:var(--dim);color:var(--dim);background:transparent}
.modal-btn-cancel:hover{border-color:var(--text);color:var(--text)}

.toast{position:fixed;bottom:38px;right:28px;z-index:9999;
  font-family:'Orbitron',monospace;font-size:10px;font-weight:700;letter-spacing:2px;
  padding:10px 18px;border-radius:4px;border:1px solid;
  animation:toast-in .3s ease;pointer-events:none}
.toast-ok{background:#00ff9d14;border-color:var(--green);color:var(--green);box-shadow:var(--glow-g)}
.toast-err{background:#ff2d5514;border-color:var(--red);color:var(--red);box-shadow:var(--glow-r)}
@keyframes toast-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}

.blocked-domain-item{background:var(--bg2);border:1px solid #ff2d5530;
  border-left:3px solid var(--red);border-radius:3px;
  padding:8px 11px;display:flex;align-items:center;justify-content:space-between;gap:8px;
  margin-bottom:5px}
.blocked-domain-name{font-family:'Share Tech Mono',monospace;font-size:12px;
  color:var(--red);font-weight:700}
.blocked-domain-meta{font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--dim)}
.block-domain-input{width:100%;padding:9px 11px;background:var(--bg0);
  border:1px solid var(--border);border-radius:3px;
  font-family:'Share Tech Mono',monospace;font-size:12px;
  color:var(--accent);outline:none;letter-spacing:.5px;margin-bottom:7px}
.block-domain-input:focus{border-color:var(--red);box-shadow:0 0 8px #ff2d5522}
.blocker-panel{flex:1;overflow-y:auto;background:var(--bg1);padding:14px 16px;min-height:0}
.blocker-panel::-webkit-scrollbar{width:4px}
.blocker-panel::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.quick-sites{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:14px}
.quick-btn{font-family:'Share Tech Mono',monospace;font-size:10px;
  padding:4px 10px;border-radius:3px;cursor:pointer;transition:all .15s;
  border:1px solid var(--border);background:var(--bg2);color:var(--dim)}
.quick-btn:hover{border-color:var(--red);color:var(--red);background:#ff2d5508}
.quick-btn.is-blocked{border-color:var(--red);color:var(--red);background:#ff2d5514}
.section-hdr{font-family:'Orbitron',monospace;font-size:9px;font-weight:700;
  letter-spacing:2px;color:var(--dim);margin-bottom:8px;
  display:flex;align-items:center;gap:6px}
.section-hdr::before{content:'';display:block;width:8px;height:1px;background:var(--red)}
.blocked-domain-item{background:var(--bg2);border:1px solid #ff2d5530;
  border-left:3px solid var(--red);border-radius:3px;
  padding:8px 11px;display:flex;align-items:center;justify-content:space-between;gap:8px;
  margin-bottom:5px}
.blocked-domain-name{font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--red);font-weight:700}
.blocked-domain-meta{font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--dim)}
.block-domain-input{width:100%;padding:9px 11px;background:var(--bg0);
  border:1px solid var(--border);border-radius:3px;
  font-family:'Share Tech Mono',monospace;font-size:12px;
  color:var(--accent);outline:none;letter-spacing:.5px;margin-bottom:7px}
.block-domain-input:focus{border-color:var(--red);box-shadow:0 0 8px #ff2d5522}
.blocker-panel{flex:1;overflow-y:auto;background:var(--bg1);padding:14px 16px;min-height:0}
.blocker-panel::-webkit-scrollbar{width:4px}
.blocker-panel::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.quick-sites{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:14px}
.quick-btn{font-family:'Share Tech Mono',monospace;font-size:10px;
  padding:4px 10px;border-radius:3px;cursor:pointer;transition:all .15s;
  border:1px solid var(--border);background:var(--bg2);color:var(--dim)}
.quick-btn:hover{border-color:var(--red);color:var(--red);background:#ff2d5508}
.quick-btn.is-blocked{border-color:var(--red);color:var(--red);background:#ff2d5514}
.section-hdr{font-family:'Orbitron',monospace;font-size:9px;font-weight:700;
  letter-spacing:2px;color:var(--dim);margin-bottom:8px;
  display:flex;align-items:center;gap:6px}
.section-hdr::before{content:'';display:block;width:8px;height:1px;background:var(--red)}
.statusbar{background:var(--bg0);border-top:1px solid var(--border);
  padding:0 16px;display:flex;align-items:center;justify-content:space-between;
  font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--dim);
  letter-spacing:1px;grid-column:2;grid-row:2}
.sdot{display:inline-block;width:6px;height:6px;border-radius:50%;
  background:var(--dim);margin-right:6px;vertical-align:middle}
.sdot.active{background:var(--red);box-shadow:0 0 8px var(--red);
  animation:blink-dot .6s step-end infinite}
@keyframes blink-dot{50%{opacity:0}}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:var(--bg0)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
</style>
</head>
<body>
<header>
  <div class="logo">
    <div class="logo-icon">🛡</div>
    <div class="logo-text">
      <h1>AI FIREWALL</h1>
      <p>REAL BROWSER HISTORY MONITOR v7.0</p>
    </div>
  </div>
  <div class="header-meta">
    <div class="meta-chip">WIFI <span id="h-wifi">—</span></div>
    <div class="meta-chip">BROWSERS <span id="h-browsers">—</span></div>
    <div id="capture-badge">● IDLE</div>
  </div>
</header>

<div class="app">
  <aside class="sidebar">
    <div class="sb-section">
      <div class="sec-title">Control</div>
      <button class="btn btn-start" id="btn-capture" onclick="toggleCapture()">
        <span>▶</span> START CAPTURE
      </button>
      <button class="btn btn-danger" onclick="openBlockModal()">
        <span>⊘</span> BLOCK AN IP
      </button>
      <button class="btn btn-danger" onclick="openDomainBlockModal()">
        <span>🚫</span> BLOCK A DOMAIN
      </button>
      <button class="btn btn-neutral" onclick="clearData()">
        <span>✕</span> CLEAR &amp; STOP
      </button>
    </div>

    <div class="sb-section">
      <div class="sec-title">Statistics</div>
      <div class="stat-grid">
        <div class="stat-card"><div class="stat-label">Total</div>
          <div class="stat-value sv-blue" id="s-total">0</div></div>
        <div class="stat-card"><div class="stat-label">Sites</div>
          <div class="stat-value sv-green" id="s-live">0</div></div>
        <div class="stat-card"><div class="stat-label">Blocked</div>
          <div class="stat-value sv-red" id="s-blocked">0</div></div>
        <div class="stat-card"><div class="stat-label">Threats</div>
          <div class="stat-value sv-orange" id="s-threats">0</div></div>
      </div>
      <div style="margin-top:6px">
        <div class="stat-card"><div class="stat-label">Unique Sites</div>
          <div class="stat-value sv-teal" id="s-sites">0</div></div>
      </div>
    </div>

    <div class="sb-section">
      <div class="sec-title">Blocked IPs <span id="blocked-count" style="color:var(--red);margin-left:4px"></span></div>
      <div class="blocked-list" id="blocked-list">
        <div class="no-blocked">No IPs blocked yet</div>
      </div>
    </div>

    <div class="sb-section">
      <div class="sec-title">Blocked Domains <span id="dom-blocked-count" style="color:var(--red);margin-left:4px"></span></div>
      <div class="blocked-list" id="domain-blocked-list">
        <div class="no-blocked">No domains blocked yet</div>
      </div>
    </div>

    <div class="sb-section">
      <div class="sec-title">Blocked Domains <span id="dom-blocked-count" style="color:var(--orange);margin-left:4px"></span></div>
      <div class="blocked-list" id="domain-blocked-list">
        <div class="no-blocked">No domains blocked yet</div>
      </div>
    </div>

    <div class="sb-section">
      <div class="sec-title">How It Works</div>
      <div class="info-box">
        <strong>BROWSER HISTORY MODE</strong>
        Reads directly from Chrome,<br>
        Edge, Firefox, Brave SQLite<br>
        history databases.<br><br>
        Shows REAL URLs + titles.<br>
        No guessing. No fake IPs.<br>
        Updates every 2 seconds.
      </div>
    </div>

    <div class="sb-section">
      <div class="sec-title">Threat Engine</div>
      <div class="info-box" style="border-left-color:var(--orange);margin-bottom:8px">
        <strong style="color:var(--orange)">LOCAL DETECTION ACTIVE</strong>
        35+ threat patterns checked.<br>Phishing, malware, cryptominers,<br>
        typosquatting, bad TLDs.<br>HIGH threats auto-blocked.
      </div>
      <div style="font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--dim);
           margin-bottom:5px;letter-spacing:1px">GOOGLE SAFE BROWSING API KEY</div>
      <input id="sb-api-key" type="text" placeholder="Optional — paste key here"
             style="width:100%;padding:7px 9px;background:var(--bg0);border:1px solid var(--border);
             border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:10px;
             color:var(--accent);outline:none;letter-spacing:1px;margin-bottom:6px"
             oninput="saveSBKey()">
      <div style="font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--dim)">
        Free key → <span style="color:var(--teal)">developers.google.com/safe-browsing</span>
      </div>
    </div>
  </aside>

  <div class="main-content">
    <div class="tabs">
      <div class="tab active" onclick="switchTab('log',this)">Live Log</div>
      <div class="tab" onclick="switchTab('sites',this)">Websites Visited</div>
      <div class="tab" onclick="switchTab('threats',this)" id="threats-tab">
        Threats<span id="threat-count-badge" class="threat-count-badge" style="display:none">0</span>
      </div>
      <div class="tab" onclick="switchTab('blocker',this)">Block Sites</div>
    </div>

    <div class="tab-content active" id="tab-log">
      <div class="log-container" id="log-box">
        <div class="log-line">
          <span class="log-ts">--:--:--</span>
          <span class="log-tag tag-info">INFO</span>
          <span class="log-msg">Click START CAPTURE — reads your real browser history every 2 seconds.</span>
        </div>
      </div>
    </div>

    <div class="tab-content" id="tab-sites">
      <div class="sites-wrap">
        <table class="sites-table">
          <thead>
            <tr>
              <th>#</th><th>Domain</th><th>Page Title</th>
              <th>IP</th><th>Browser</th><th>Visits</th><th>Last</th><th>Threat</th><th>Action</th>
            </tr>
          </thead>
          <tbody id="sites-tbody">
            <tr><td colspan="8">
              <div class="empty-state">
                <div class="empty-icon">🌐</div>
                <span>Start capture and browse the web.<br>
                Real visited sites will appear here with their page titles.</span>
              </div>
            </td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

    <div class="tab-content" id="tab-threats">
      <div class="threat-panel" id="threat-panel">
        <div class="threat-empty">
          <div style="font-size:36px;opacity:.2">🛡</div>
          <span>No threats detected yet.</span>
          <span style="font-size:10px;color:var(--dim)">Browse the web — suspicious domains will be flagged here.</span>
        </div>
      </div>
    </div>

    <div class="tab-content" id="tab-blocker">
      <div class="blocker-panel">
        <div class="section-hdr">Quick Block</div>
        <div class="quick-sites">
          <button class="quick-btn" onclick="quickBlock('facebook.com')">facebook.com</button>
          <button class="quick-btn" onclick="quickBlock('instagram.com')">instagram.com</button>
          <button class="quick-btn" onclick="quickBlock('youtube.com')">youtube.com</button>
          <button class="quick-btn" onclick="quickBlock('twitter.com')">twitter.com</button>
          <button class="quick-btn" onclick="quickBlock('tiktok.com')">tiktok.com</button>
          <button class="quick-btn" onclick="quickBlock('reddit.com')">reddit.com</button>
          <button class="quick-btn" onclick="quickBlock('classroom.google.com')">google classroom</button>
          <button class="quick-btn" onclick="quickBlock('whatsapp.com')">whatsapp.com</button>
          <button class="quick-btn" onclick="quickBlock('snapchat.com')">snapchat.com</button>
          <button class="quick-btn" onclick="quickBlock('discord.com')">discord.com</button>
          <button class="quick-btn" onclick="quickBlock('twitch.tv')">twitch.tv</button>
          <button class="quick-btn" onclick="quickBlock('netflix.com')">netflix.com</button>
        </div>
        <div class="section-hdr" style="margin-top:12px">Block Any Domain</div>
        <div style="display:flex;gap:8px;margin-bottom:14px">
          <input class="block-domain-input" id="custom-domain-input"
                 placeholder="e.g. facebook.com or classroom.google.com"
                 onkeydown="if(event.key==='Enter')blockCustomDomain()"
                 style="margin-bottom:0;flex:1">
          <button class="btn btn-stop" style="width:auto;padding:0 16px;margin:0;white-space:nowrap"
                  onclick="blockCustomDomain()">&#8856; BLOCK</button>
        </div>
        <div class="section-hdr">Currently Blocked Sites <span id="blocked-domain-count" style="color:var(--red);margin-left:4px"></span></div>
        <div id="blocked-domains-list">
          <div style="font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--dim);padding:8px 0">
            No sites blocked yet.
          </div>
        </div>
        <div style="margin-top:16px;padding:12px;background:var(--bg2);border:1px solid var(--border);
             border-left:3px solid var(--orange);border-radius:3px;
             font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--dim);line-height:1.7">
          <strong style="color:var(--orange);font-family:'Orbitron',monospace;font-size:9px;
                  letter-spacing:2px;display:block;margin-bottom:4px">HOW IT WORKS</strong>
          Redirects domain to 0.0.0.0 in your hosts file AND blocks all IPs via Windows Firewall.<br>
          Requires <strong style="color:var(--red)">Administrator</strong> privileges to work.<br>
          Unblock removes all rules instantly.
        </div>
      </div>
    </div>

  <div class="statusbar">
    <div><span class="sdot" id="sdot"></span><span id="smsg">Ready — reads real browser history</span></div>
    <div style="color:var(--dim)">AI FIREWALL v7.0 — HISTORY + IP BLOCKING</div>
  </div>
</div>

<!-- Block Domain modal -->
<div class="modal-overlay" id="domain-block-modal">
  <div class="modal danger">
    <h2>🚫 BLOCK A DOMAIN</h2>
    <p>Enter a domain to block. It will be redirected to 0.0.0.0 in your system hosts file.<br>
    This blocks ALL connections to that domain — Chrome, Firefox, apps, everything.<br>
    <strong style="color:var(--orange)">Requires Administrator / root to modify hosts file.</strong></p>
    <input class="modal-input" id="domain-block-input" type="text"
           placeholder="e.g. facebook.com or classroom.google.com"
           onkeydown="if(event.key==='Enter')doDomainBlock()">
    <div id="domain-block-hint" style="font-family:'Share Tech Mono',monospace;font-size:10px;
         color:var(--dim);margin-bottom:12px">
      Both <span style="color:var(--accent)">facebook.com</span> and
      <span style="color:var(--accent)">www.facebook.com</span> will be blocked.
    </div>
    <div class="modal-btns">
      <button class="modal-btn modal-btn-cancel" onclick="closeModal('domain-block-modal')">CANCEL</button>
      <button class="modal-btn modal-btn-ok-red" onclick="doDomainBlock()">BLOCK DOMAIN</button>
    </div>
  </div>
</div>

<!-- Block Domain modal -->
<div class="modal-overlay" id="domain-block-modal">
  <div class="modal danger">
    <h2>🚫 BLOCK A DOMAIN</h2>
    <p>Redirects the domain to 0.0.0.0 in your system hosts file.<br>
    Blocks Chrome, Firefox, all apps — everything.<br>
    <strong style="color:var(--orange)">Requires Administrator/sudo.</strong></p>
    <input class="modal-input" id="domain-block-input" type="text"
           placeholder="e.g. facebook.com  or  classroom.google.com"
           onkeydown="if(event.key==='Enter')doDomainBlock()">
    <div style="font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--dim);margin-bottom:12px">
      Both domain and www.domain will be blocked automatically.
    </div>
    <div class="modal-btns">
      <button class="modal-btn modal-btn-cancel" onclick="closeModal('domain-block-modal')">CANCEL</button>
      <button class="modal-btn modal-btn-ok-red" onclick="doDomainBlock()">BLOCK DOMAIN</button>
    </div>
  </div>
</div>

<!-- Block IP modal -->
<div class="modal-overlay" id="block-modal">
  <div class="modal danger">
    <h2>⊘ BLOCK AN IP ADDRESS</h2>
    <p>Enter an IP or domain to block via Windows Firewall / iptables.<br>Requires Administrator / root privileges.</p>
    <input class="modal-input" id="block-ip-input" type="text"
           placeholder="IP address or domain name"
           oninput="resolveBlockInput()"
           onkeydown="if(event.key==='Enter')doBlock()">
    <div id="block-resolve" style="font-family:'Share Tech Mono',monospace;font-size:10px;
         color:var(--dim);margin-bottom:12px;min-height:14px"></div>
    <div class="modal-btns">
      <button class="modal-btn modal-btn-cancel" onclick="closeModal('block-modal')">CANCEL</button>
      <button class="modal-btn modal-btn-ok-red" onclick="doBlock()">BLOCK</button>
    </div>
  </div>
</div>

<script>
let capturing=false, selIface=null, blockedIPs={};

/* ── Tabs ── */
function switchTab(n,el){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tab-'+n).classList.add('active');
}

/* ── Tag maps ── */
const TC={history:'tag-history',dns:'tag-dns',blocked:'tag-blocked',
  threat:'tag-threat',err:'tag-err',info:'tag-info',header:'tag-hdr'};
const TL={history:'VISIT',dns:'DNS',blocked:'BLOCKED',
  threat:'THREAT',err:'ERR',info:'INFO',header:'SYS'};
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

/* ── Live log ── */
function appendLogs(entries){
  const box=document.getElementById('log-box');
  const atBottom=box.scrollHeight-box.scrollTop-box.clientHeight<60;
  entries.forEach(e=>{
    const d=document.createElement('div');d.className='log-line';
    const tc=TC[e.tag]||'tag-info',tl=TL[e.tag]||e.tag.toUpperCase();
    d.innerHTML='<span class="log-ts">'+e.ts+'</span>'+
      '<span class="log-tag '+tc+'">'+tl+'</span>'+
      '<span class="log-msg">'+esc(e.msg)+'</span>';
    box.appendChild(d);
  });
  while(box.children.length>900)box.removeChild(box.firstChild);
  if(atBottom)box.scrollTop=box.scrollHeight;
}

/* ── Threat badge ── */
function threatBadge(threat){
  if(!threat)return '<span style="color:var(--dim);font-size:10px">—</span>';
  const lvl=threat.level;
  return '<span class="threat-badge threat-'+lvl+'-badge">'+lvl+': '+esc(threat.type)+'</span>';
}

/* ── Sites table ── */
function renderSites(sites){
  const tb=document.getElementById('sites-tbody');
  if(!sites||!sites.length){
    tb.innerHTML='<tr><td colspan="9"><div class="empty-state"><div class="empty-icon">🌐</div><span>Start capture and browse.</span></div></td></tr>';
    return;
  }
  tb.innerHTML=sites.map(function(s,i){
    const isBlocked=s.ip&&blockedIPs[s.ip]!==undefined;
    const btnTxt=isBlocked?'UNBLOCK IP':'BLOCK IP';
    const btnCls=isBlocked?'block-btn unblock':'block-btn';
    const lvl=s.threat?s.threat.level:'';
    const rowBg=lvl==='HIGH'?'background:#ff2d5509':lvl==='MEDIUM'?'background:#ff950506':'';
    const url=s.url?'href="'+esc(s.url)+'" target="_blank"':'';
    const ipDisp=s.ip||'resolving...';
    return '<tr style="'+rowBg+'">'
      +'<td style="color:var(--dim);font-size:10px">'+(i+1)+'</td>'
      +'<td class="domain-cell"><a '+url+' style="color:inherit;text-decoration:none">'+esc(s.domain)+'</a></td>'
      +'<td class="title-cell" title="'+esc(s.title)+'">'+esc(s.title||'—')+'</td>'
      +'<td class="ip-cell">'+esc(ipDisp)+'</td>'
      +'<td class="browser-cell">'+esc(s.browser||'—')+'</td>'
      +'<td class="count-cell">'+s.count+'</td>'
      +'<td style="color:var(--dim);font-size:10px">'+s.last+'</td>'
      +'<td>'+threatBadge(s.threat)+'</td>'
      +'<td style="display:flex;gap:4px;flex-wrap:wrap;align-items:center">'
        +(s.ip?'<button class="'+btnCls+'" onclick="toggleBlockSite(\''+esc(s.ip)+'\',\''+esc(s.domain)+'\')">'+btnTxt+'</button>':'')
        +'<button class="block-btn" style="border-color:var(--orange);color:var(--orange)" onclick="blockSiteDomain(\''+esc(s.domain)+'\')">BLOCK DOMAIN</button>'
      +'</td>'
      +'</tr>';
  }).join('');
}

/* ── Blocked IPs sidebar ── */
function renderBlocked(blocked){
  blockedIPs=blocked||{};
  const list=document.getElementById('blocked-list');
  const cnt=Object.keys(blockedIPs).length;
  document.getElementById('blocked-count').textContent=cnt?'('+cnt+')':'';
  if(!cnt){list.innerHTML='<div class="no-blocked">No IPs blocked yet</div>';return;}
  list.innerHTML=Object.entries(blockedIPs).map(function(e){
    const ip=e[0],info=e[1];
    return '<div class="blocked-item">'
      +'<div style="flex:1;min-width:0">'
        +'<div class="blocked-ip">'+esc(ip)+'</div>'
        +'<div class="blocked-domain">'+esc(info.domain||ip)+'</div>'
      +'</div>'
      +'<button class="unblock-btn" onclick="doUnblock(\''+esc(ip)+'\')">UNBLOCK</button>'
      +'</div>';
  }).join('');
}

/* ── Blocked Domains sidebar ── */
function renderBlockedDomains(blocked){
  const list=document.getElementById('domain-blocked-list');
  if(!list)return;
  const cnt=Object.keys(blocked||{}).length;
  const el=document.getElementById('dom-blocked-count');
  if(el)el.textContent=cnt?'('+cnt+')':'';
  if(!cnt){list.innerHTML='<div class="no-blocked">No domains blocked yet</div>';return;}
  list.innerHTML=Object.entries(blocked).map(function(e){
    const domain=e[0],info=e[1];
    return '<div class="blocked-item">'
      +'<div style="flex:1;min-width:0">'
        +'<div class="blocked-ip" style="color:var(--orange)">'+esc(domain)+'</div>'
        +'<div class="blocked-domain">'+(info.method||'hosts')+' · '+(info.blocked_at||'')+'</div>'
      +'</div>'
      +'<button class="unblock-btn" onclick="doUnblockDomain(\''+esc(domain)+'\')">REMOVE</button>'
      +'</div>';
  }).join('');
}

/* ── Threats panel ── */
function renderThreats(sites){
  const panel=document.getElementById('threat-panel');
  if(!panel)return;
  const threats=(sites||[]).filter(function(s){return !!s.threat;});
  const badge=document.getElementById('threat-count-badge');
  if(badge){badge.style.display=threats.length?'inline-flex':'none';badge.textContent=threats.length;}
  if(!threats.length){
    panel.innerHTML='<div class="threat-empty"><div style="font-size:36px;opacity:.2">🛡</div><span>No threats detected yet.</span><span style="font-size:10px;color:var(--dim)">Browse the web — suspicious domains appear here.</span></div>';
    return;
  }
  const sorted=threats.sort(function(a,b){
    const o={HIGH:0,MEDIUM:1,LOW:2};
    return (o[a.threat.level]||9)-(o[b.threat.level]||9);
  });
  panel.innerHTML=sorted.map(function(s){
    const lvl=s.threat.level;
    const src=s.threat.source==='google_sb'?'Google Safe Browsing':'Local Pattern';
    const blockBtn=s.ip&&s.ip!=='—'
      ?'<button class="block-btn" style="margin-top:8px" onclick="toggleBlockSite(\''+esc(s.ip)+'\',\''+esc(s.domain)+'\')">BLOCK IP</button>'
      :'';
    return '<div class="threat-card '+lvl+'">'
      +'<div class="threat-domain">⚠ '+esc(s.domain)+'</div>'
      +'<div class="threat-meta">'
        +'<span class="threat-badge threat-'+lvl+'-badge">'+lvl+'</span>'
        +'<strong style="color:var(--text);margin-left:6px">'+esc(s.threat.type)+'</strong><br>'
        +esc(s.threat.detail)+'<br>'
        +'<span style="color:var(--dim);font-size:10px">Source: '+src+' · IP: '+esc(s.ip||'unknown')+' · Last: '+s.last+' · Browser: '+esc(s.browser||'unknown')+'</span>'
        +blockBtn
      +'</div>'
      +'</div>';
  }).join('');
}

/* ── Poll server ── */
async function poll(){
  try{
    const r=await fetch('/api/state');
    const d=await r.json();
    document.getElementById('h-wifi').textContent=d.wifi||'—';
    const bf=d.browsers_found||[];
    document.getElementById('h-browsers').textContent=bf.length?bf.join(', '):'none found';
    document.getElementById('s-total').textContent=d.stats.total||0;
    document.getElementById('s-live').textContent=d.stats.live||0;
    document.getElementById('s-blocked').textContent=d.stats.blocked||0;
    document.getElementById('s-threats').textContent=d.stats.threats||0;
    document.getElementById('s-sites').textContent=d.sites_count||0;
    if(d.new_log&&d.new_log.length)appendLogs(d.new_log);
    renderSites(d.sites||[]);
    renderThreats(d.sites||[]);
    renderBlocked(d.blocked_ips||{});
    renderBlockedDomains(d.blocked_domains||{});
    if(d.capturing!==capturing){capturing=d.capturing;updateUI();}
  }catch(e){}
}

/* ── Capture UI ── */
function updateUI(){
  const btn=document.getElementById('btn-capture');
  const badge=document.getElementById('capture-badge');
  const dot=document.getElementById('sdot');
  const msg=document.getElementById('smsg');
  if(capturing){
    btn.innerHTML='<span>■</span> STOP CAPTURE';btn.className='btn btn-stop';
    badge.textContent='● LIVE';badge.classList.add('active');
    dot.classList.add('active');msg.textContent='Capturing — threat engine active';
  }else{
    btn.innerHTML='<span>▶</span> START CAPTURE';btn.className='btn btn-start';
    badge.textContent='● IDLE';badge.classList.remove('active');
    dot.classList.remove('active');msg.textContent='Capture stopped';
  }
}
async function toggleCapture(){
  const action=capturing?'stop':'start';
  await fetch('/api/capture/'+action,{method:'POST'});
  capturing=!capturing;updateUI();
}

/* ── Clear & stop ── */
async function clearData(){
  if(capturing){
    await fetch('/api/capture/stop',{method:'POST'});
    capturing=false;updateUI();
  }
  await fetch('/api/clear',{method:'POST'});
  document.getElementById('log-box').innerHTML='';
  showToast('Cleared & stopped','ok');
}

/* ── Block IP ── */
async function toggleBlockSite(ip,domain){
  if(!ip||ip==='—'||ip==='resolving...'){showToast('IP not resolved yet','err');return;}
  if(blockedIPs[ip])await doUnblock(ip);
  else await blockIPCall(ip,domain);
}
async function blockIPCall(ip,domain){
  const r=await fetch('/api/block',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ip:ip,domain:domain})});
  const d=await r.json();
  showToast(d.ok?'Blocked '+ip:d.msg,d.ok?'ok':'err');
}
async function doUnblock(ip){
  const r=await fetch('/api/unblock',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ip:ip})});
  const d=await r.json();
  showToast(d.ok?'Unblocked '+ip:d.msg,d.ok?'ok':'err');
}

/* ── Block IP modal ── */
let resolveTimer=null;
function openBlockModal(){
  document.getElementById('block-ip-input').value='';
  document.getElementById('block-resolve').textContent='';
  document.getElementById('block-modal').classList.add('open');
  setTimeout(function(){document.getElementById('block-ip-input').focus();},80);
}
function resolveBlockInput(){
  clearTimeout(resolveTimer);
  const val=document.getElementById('block-ip-input').value.trim();
  const el=document.getElementById('block-resolve');
  if(!val){el.textContent='';return;}
  if(/^\d+\.\d+\.\d+\.\d+$/.test(val)){el.textContent='Valid IP';el.style.color='var(--green)';return;}
  el.textContent='Resolving...';el.style.color='var(--dim)';
  resolveTimer=setTimeout(async function(){
    try{
      const r=await fetch('/api/resolve?domain='+encodeURIComponent(val));
      const d=await r.json();
      if(d.ip){el.textContent='→ '+d.ip;el.style.color='var(--teal)';document.getElementById('block-ip-input').value=d.ip;}
      else{el.textContent='Could not resolve';el.style.color='var(--red)';}
    }catch(e){el.textContent='';}
  },500);
}
async function doBlock(){
  const ip=document.getElementById('block-ip-input').value.trim();
  if(!ip){showToast('Enter an IP','err');return;}
  closeModal('block-modal');
  await blockIPCall(ip,'');
}

/* ── Block Domain modal ── */
function openDomainBlockModal(){
  document.getElementById('domain-block-input').value='';
  document.getElementById('domain-block-modal').classList.add('open');
  setTimeout(function(){document.getElementById('domain-block-input').focus();},80);
}
async function doDomainBlock(){
  let domain=document.getElementById('domain-block-input').value.trim().toLowerCase();
  domain=domain.replace(/^https?:\/\//,'').replace(/\/.*/,'').replace(/^www\./,'');
  if(!domain){showToast('Enter a domain','err');return;}
  closeModal('domain-block-modal');
  const r=await fetch('/api/block_domain',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({domain:domain})});
  const d=await r.json();
  showToast(d.ok?'Blocked '+domain:d.msg,d.ok?'ok':'err');
}
async function doUnblockDomain(domain){
  const r=await fetch('/api/unblock_domain',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({domain:domain})});
  const d=await r.json();
  showToast(d.ok?'Unblocked '+domain:d.msg,d.ok?'ok':'err');
}
async function blockSiteDomain(domain){
  if(!domain){showToast('No domain','err');return;}
  const r=await fetch('/api/block_domain',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({domain:domain})});
  const d=await r.json();
  showToast(d.ok?'Blocked '+domain:d.msg,d.ok?'ok':'err');
}

/* ── Interface modal ── */
async function openIfaceModal(){
  const r=await fetch('/api/interfaces');const d=await r.json();
  const list=document.getElementById('iface-list');
  list.innerHTML=(d.interfaces||[]).map(function(i){
    return '<div class="iface-item" onclick="selIfaceFn(this,\''+esc(i)+'\')">'+esc(i)+'</div>';
  }).join('')||'<div class="iface-item" style="color:var(--red)">No interfaces found</div>';
  document.getElementById('iface-modal').classList.add('open');
}
function selIfaceFn(el,name){
  document.querySelectorAll('.iface-item').forEach(function(i){i.classList.remove('selected');});
  el.classList.add('selected');selIface=name;
}
async function applyIface(){
  if(!selIface)return;
  await fetch('/api/set_interface',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({interface:selIface})});
  document.getElementById('h-iface')?document.getElementById('h-iface').textContent=selIface:null;
  closeModal('iface-modal');
}

/* ── Google SB key ── */
async function saveSBKey(){
  const key=document.getElementById('sb-api-key').value.trim();
  await fetch('/api/set_sb_key',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({key:key})});
  showToast(key?'Google SB key saved':'API key cleared','ok');
}

/* ── Close any modal ── */
function closeModal(id){
  const el=document.getElementById(id);
  if(el)el.classList.remove('open');
}

/* ── Toast notification ── */
function showToast(msg,type){
  const t=document.createElement('div');
  t.className='toast toast-'+(type==='ok'?'ok':'err');
  t.textContent=msg;document.body.appendChild(t);
  setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t);},2800);
}

/* ── Dynamic height fix ── */
function fixHeight(){
  const h=document.querySelector('header');
  const app=document.querySelector('.app');
  if(h&&app)app.style.height=(window.innerHeight-h.offsetHeight)+'px';
}
fixHeight();
window.addEventListener('resize',fixHeight);
document.fonts&&document.fonts.ready&&document.fonts.ready.then(fixHeight);

setInterval(poll,800);poll();
</script>
</body>

"""


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Server
# ─────────────────────────────────────────────────────────────────────────────

class FirewallHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        if path in ('/', '/index.html'):
            self._send(200, 'text/html', HTML_PAGE.encode())

        elif path == '/api/state':
            with state_lock:
                log_copy    = list(state['live_log'])
                sites_raw   = dict(state['websites'])
                stats       = dict(state['stats'])
                blocked_raw = dict(state['blocked_ips'])
                browsers    = list(state.get('browsers_found', []))

            client  = self.client_address[0]
            pos     = client_log_pos.get(client, 0)
            new_log = log_copy[pos:]
            client_log_pos[client] = len(log_copy)

            sites_list = sorted(
                [{'domain': k, **v} for k, v in sites_raw.items()],
                key=lambda x: x['last'], reverse=True
            )

            payload = {
                'capturing':     state['capturing'],
                'wifi':          state['wifi'],
                'iface':         state['interface'],
                'stats':         stats,
                'sites_count':   len(sites_raw),
                'sites':         sites_list,
                'new_log':       new_log,
                'blocked_ips':   blocked_raw,
                'blocked_domains': dict(state.get('blocked_domains', {})),
                'blocked_domains': dict(state.get('blocked_domains',{})),
                'browsers_found':browsers,
                'threats_count': sum(1 for v in sites_raw.values() if v.get('threat')),
            }
            self._send(200, 'application/json', json.dumps(payload).encode())

        elif path == '/api/interfaces':
            try:
                ifaces = get_if_list() if HAS_SCAPY else []
            except Exception:
                ifaces = []
            self._send(200, 'application/json', json.dumps({'interfaces': ifaces}).encode())

        elif path.startswith('/api/resolve'):
            qs     = parse_qs(parsed.query)
            domain = qs.get('domain', [''])[0]
            ip     = resolve_domain_to_ip(domain) if domain else None
            self._send(200, 'application/json', json.dumps({'ip': ip}).encode())

        else:
            self._send(404, 'text/plain', b'Not found')

    def do_POST(self):
        path   = urlparse(self.path).path
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length) if length else b'{}'
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}

        if path == '/api/capture/start':
            start_capture()
            self._send(200, 'application/json', b'{"ok":true}')

        elif path == '/api/capture/stop':
            stop_capture()
            self._send(200, 'application/json', b'{"ok":true}')

        elif path == '/api/clear':
            stop_capture()
            with state_lock:
                state['live_log'].clear()
                state['websites'].clear()
                state['stats'] = {'total':0,'live':0,'blocked':0,'threats':0}
                # Note: keep blocked_ips and blocked_domains — user didn't ask to unblock
                client_log_pos.clear()
            with _threat_lock:
                _threat_cache.clear()
                _threat_queue.clear()
            self._send(200, 'application/json', b'{"ok":true}')

        elif path == '/api/block':
            ip     = data.get('ip', '').strip()
            domain = data.get('domain', '').strip()
            if ip:
                ok, msg = block_ip(ip, domain)
                self._send(200, 'application/json',
                           json.dumps({'ok': ok, 'msg': msg}).encode())
            else:
                self._send(400, 'application/json', b'{"ok":false,"msg":"No IP"}')

        elif path == '/api/unblock':
            ip = data.get('ip', '').strip()
            if ip:
                ok, msg = unblock_ip(ip)
                self._send(200, 'application/json',
                           json.dumps({'ok': ok, 'msg': msg}).encode())
            else:
                self._send(400, 'application/json', b'{"ok":false,"msg":"No IP"}')

        elif path == '/api/set_interface':
            state['interface'] = data.get('interface', state['interface'])
            self._send(200, 'application/json', b'{"ok":true}')

        elif path == '/api/block_domain':
            domain = data.get('domain', '').strip()
            if domain:
                ok, msg = block_domain(domain)
                self._send(200, 'application/json',
                           json.dumps({'ok': ok, 'msg': msg}).encode())
            else:
                self._send(400, 'application/json', b'{"ok":false,"msg":"No domain"}')

        elif path == '/api/unblock_domain':
            domain = data.get('domain', '').strip()
            if domain:
                ok, msg = unblock_domain(domain)
                self._send(200, 'application/json',
                           json.dumps({'ok': ok, 'msg': msg}).encode())
            else:
                self._send(400, 'application/json', b'{"ok":false,"msg":"No domain"}')

        elif path == '/api/block_domain':
            domain = data.get('domain','').strip()
            if domain:
                ok,msg = block_domain(domain)
                self._send(200,'application/json', json.dumps({'ok':ok,'msg':msg}).encode())
            else:
                self._send(400,'application/json', b'{"ok":false,"msg":"No domain"}')

        elif path == '/api/unblock_domain':
            domain = data.get('domain','').strip()
            if domain:
                ok,msg = unblock_domain(domain)
                self._send(200,'application/json', json.dumps({'ok':ok,'msg':msg}).encode())
            else:
                self._send(400,'application/json', b'{"ok":false,"msg":"No domain"}')

        elif path == '/api/set_sb_key':
            key = data.get('key', '').strip()
            global GOOGLE_SB_API_KEY
            GOOGLE_SB_API_KEY = key
            self._send(200, 'application/json', b'{"ok":true}')

        elif path == '/api/block_domain':
            domain = data.get('domain', '').strip().lower().rstrip('.')
            if domain:
                ok, msg = block_domain(domain)
                self._send(200, 'application/json',
                           json.dumps({'ok': ok, 'msg': msg}).encode())
            else:
                self._send(400, 'application/json', b'{"ok":false,"msg":"No domain"}')

        elif path == '/api/unblock_domain':
            domain = data.get('domain', '').strip().lower().rstrip('.')
            if domain:
                ok, msg = unblock_domain(domain)
                self._send(200, 'application/json',
                           json.dumps({'ok': ok, 'msg': msg}).encode())
            else:
                self._send(400, 'application/json', b'{"ok":false,"msg":"No domain"}')

        elif path == '/api/block_domain':
            domain = data.get('domain', '').strip().lower().rstrip('.')
            if domain:
                ok, msg = block_domain(domain)
                self._send(200, 'application/json',
                           json.dumps({'ok': ok, 'msg': msg}).encode())
            else:
                self._send(400, 'application/json', b'{"ok":false,"msg":"No domain"}')

        elif path == '/api/unblock_domain':
            domain = data.get('domain', '').strip().lower().rstrip('.')
            if domain:
                ok, msg = unblock_domain(domain)
                self._send(200, 'application/json',
                           json.dumps({'ok': ok, 'msg': msg}).encode())
            else:
                self._send(400, 'application/json', b'{"ok":false,"msg":"No domain"}')

        else:
            self._send(404, 'text/plain', b'Not found')

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if platform.system() == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("\n[!] WARNING: Not running as Administrator.")
            print("    IP blocking and packet capture will not work.")
            print("    Re-run from an Admin Command Prompt.\n")
    else:
        if os.geteuid() != 0:
            print("\n[!] WARNING: Run with: sudo python3 firewall_gui.py\n")

    # Load any domains already blocked in hosts file from previous sessions
    existing_blocked = get_hosts_blocked_domains()
    for d in existing_blocked:
        state['blocked_domains'][d] = {'blocked_at': 'previous session', 'method': 'hosts'}
    if existing_blocked:
        print(f"  Loaded {len(existing_blocked)} previously blocked domain(s) from hosts file")

    existing = get_hosts_blocked_domains()
    for d in existing:
        state['blocked_domains'][d] = {'blocked_at': 'previous session', 'method': 'hosts'}
    if existing:
        print(f"  Loaded {len(existing)} previously blocked domain(s) from hosts file")

    state['wifi']      = get_wifi_name()
    state['interface'] = get_best_interface()

    PORT   = 8765
    server = HTTPServer(('127.0.0.1', PORT), FirewallHandler)

    print("=" * 60)
    print("  AI Firewall v7.0 — Threat Detection + IP Blocking")
    print("=" * 60)
    print(f"\n  Dashboard : http://localhost:{PORT}")
    print(f"  WiFi      : {state['wifi']}")
    print(f"  Interface : {state['interface']}")
    print(f"  Scapy     : {'OK (DNS mapping)' if HAS_SCAPY else 'not installed'}")
    print("\n  Threat engine: LOCAL patterns active")
    print("  Add Google Safe Browsing key in the dashboard for cloud checks.")
    print("\n  Opening browser... Press Ctrl+C to stop.\n")

    threading.Timer(1.0, lambda: webbrowser.open(f"http://localhost:{PORT}")).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        stop_capture()
        server.shutdown()

if __name__ == "__main__":
    main()