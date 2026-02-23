import requests
import os
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import tldextract

# ==========================================================
# CONFIG
# ==========================================================

MAX_WORKERS = 6
OUTPUT_FILE = "output/adguard-additional-dns-filter.txt"

SOURCES = {
    "base": [
        "https://filters.adtidy.org/dns/filter_1.txt",
        "https://filters.adtidy.org/android/filters/15_optimized.txt",
    ],
    "main": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt",
    ],
    "tif": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    ],
    "nrd": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd-7.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd-14.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd-30.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd-90.txt",
    ],
    "allow": [
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-native.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-connectivity.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-apple.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-google.txt",
        "https://local.oisd.nl/extract/commonly_whitelisted.php",
    ],
}

CUSTOM_ALLOW_DOMAINS = {
    "account.heytap.com",
    "id.heytap.com",
    "cloud.heytap.com",
    "ota.oneplus.com",
    "oxygenos.oneplus.com",
    "coloros.com",
}

DOMAIN_PATTERN = re.compile(r"\|\|([a-zA-Z0-9.-]+)\^")

# ==========================================================
# PSL ROOT CACHE
# ==========================================================

extractor = tldextract.TLDExtract(suffix_list_urls=None)
root_cache = {}

def get_root(domain):
    if domain in root_cache:
        return root_cache[domain]
    ext = extractor(domain)
    root = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else domain
    root_cache[domain] = root
    return root

# ==========================================================
# NETWORK
# ==========================================================

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
session.mount("http://", adapter)
session.mount("https://", adapter)

def fetch(url):
    try:
        r = session.get(url, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception:
        print(f"Failed: {url}")
        return []

def fetch_group(group):
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(fetch, group))
    return [line for result in results for line in result]

# ==========================================================
# PARSING
# ==========================================================

def extract_domains(lines):
    domains = set()
    for rule in lines:
        rule = rule.strip()
        if not rule or rule.startswith("!"):
            continue
        if rule.startswith("@@"):
            rule = rule[2:]
        m = DOMAIN_PATTERN.search(rule)
        if m:
            domains.add(m.group(1).lower())
    return domains

# ==========================================================
# TRIE COLLAPSE
# ==========================================================

class TrieNode:
    __slots__ = ("children", "blocked")
    def __init__(self):
        self.children = {}
        self.blocked = False

def collapse_domains(domains):
    root = TrieNode()
    collapsed = set()

    for domain in sorted(domains):
        parts = domain.split(".")[::-1]  # reverse
        node = root
        skip = False

        for part in parts:
            if node.blocked:
                skip = True
                break
            node = node.children.setdefault(part, TrieNode())

        if not skip:
            node.blocked = True
            node.children.clear()  # prune children
            collapsed.add(domain)

    return collapsed

# ==========================================================
# MAIN
# ==========================================================

def main():
    os.makedirs("output", exist_ok=True)

    base_lines = fetch_group(SOURCES["base"])
    tif_lines = fetch_group(SOURCES["tif"])
    nrd_lines = fetch_group(SOURCES["nrd"])
    allow_lines = fetch_group(SOURCES["allow"])
    main_lines = fetch_group(SOURCES["main"])

    # Safety: avoid pushing broken build
    if len(main_lines) < 1000:
        print("Main source incomplete. Aborting.")
        return

    base_domains = extract_domains(base_lines)
    intelligence_domains = extract_domains(tif_lines + nrd_lines)
    allow_domains = extract_domains(allow_lines)
    allow_domains.update(CUSTOM_ALLOW_DOMAINS)

    intel_roots = {get_root(d) for d in intelligence_domains}

    main_domains = set()
    for d in extract_domains(main_lines):
        if d in base_domains:
            continue
        if get_root(d) in intel_roots:
            continue
        main_domains.add(d)

    collapsed = collapse_domains(main_domains)

    blocked_set = collapsed | base_domains

    allow_rules = []
    for allow in sorted(allow_domains):
        if allow in blocked_set:
            continue
        parts = allow.split(".")
        if any(".".join(parts[i:]) in blocked_set for i in range(len(parts))):
            allow_rules.append(f"@@||{allow}^")

    allow_rules = sorted(set(allow_rules))

    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")

    # STREAM WRITE (no large block_rules list stored)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: AdGuard Additional DNS filter (v4)\n")
        f.write(f"! Version: {version}\n")
        f.write("! Expires: 6 hours\n")
        f.write(f"! Block rules: {len(collapsed)}\n")
        f.write(f"! Allow rules: {len(allow_rules)}\n")
        f.write("!\n")

        for rule in allow_rules:
            f.write(rule + "\n")

        f.write("!\n")

        for domain in sorted(collapsed):
            f.write(f"||{domain}^\n")

    print("Build successful")

if __name__ == "__main__":
    main()
