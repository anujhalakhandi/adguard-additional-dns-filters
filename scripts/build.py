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

# OEM-safe minimal allow
CUSTOM_ALLOW_DOMAINS = {
    "account.heytap.com",
    "id.heytap.com",
    "cloud.heytap.com",
    "ota.oneplus.com",
    "oxygenos.oneplus.com",
    "coloros.com",
}

TELEMETRY_PATTERNS = [
    re.compile(r"(^|[-.])(analytics|tracking|telemetry|metrics|stats|log)([-.]|$)")
]

DOMAIN_PATTERN = re.compile(r"\|\|([a-zA-Z0-9.-]+)\^")

# PSL extractor (offline)
extractor = tldextract.TLDExtract(suffix_list_urls=None)
root_cache = {}

def get_root(domain):
    if domain in root_cache:
        return root_cache[domain]
    ext = extractor(domain)
    if ext.domain and ext.suffix:
        root = f"{ext.domain}.{ext.suffix}"
    else:
        root = domain
    root_cache[domain] = root
    return root

# ==========================================================
# NETWORK
# ==========================================================

session = requests.Session()

def fetch(url):
    try:
        r = session.get(url, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception:
        print(f"Failed: {url}")
        return []

def fetch_all(urls):
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(fetch, set(urls)))
    return [line for result in results for line in result]

# ==========================================================
# PARSING
# ==========================================================

def clean_rule(rule):
    rule = rule.strip()
    if not rule or rule.startswith("!"):
        return None
    return rule

def extract_domain(rule):
    r = rule
    if r.startswith("@@"):
        r = r[2:]
    match = DOMAIN_PATTERN.search(r)
    if match:
        return match.group(1).lower()
    return None

# ==========================================================
# FAST COLLAPSE
# ==========================================================

def collapse_domains(domains):
    domains = sorted(domains, key=lambda x: x.count("."))
    collapsed = set()

    for domain in domains:
        parts = domain.split(".")
        skip = False
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in collapsed:
                skip = True
                break
        if not skip:
            collapsed.add(domain)

    return collapsed

# ==========================================================
# MAIN BUILD
# ==========================================================

def main():
    os.makedirs("output", exist_ok=True)

    base_domains = set()
    intelligence_domains = set()
    allow_domains = set()
    main_domains = set()

    # BASE
    for rule in fetch_all(SOURCES["base"]):
        c = clean_rule(rule)
        if not c:
            continue
        d = extract_domain(c)
        if d:
            base_domains.add(d)

    # INTELLIGENCE
    for category in ["tif", "nrd"]:
        for rule in fetch_all(SOURCES[category]):
            c = clean_rule(rule)
            if not c:
                continue
            d = extract_domain(c)
            if d:
                intelligence_domains.add(d)

    intel_roots = set(get_root(d) for d in intelligence_domains)

    # ALLOW
    for rule in fetch_all(SOURCES["allow"]):
        c = clean_rule(rule)
        if not c:
            continue
        d = extract_domain(c)
        if d:
            allow_domains.add(d)

    allow_domains.update(CUSTOM_ALLOW_DOMAINS)

    # MAIN
    for rule in fetch_all(SOURCES["main"]):
        c = clean_rule(rule)
        if not c:
            continue
        d = extract_domain(c)
        if not d:
            continue

        if d in base_domains:
            continue

        if get_root(d) in intel_roots:
            continue

        main_domains.add(d)

    collapsed = collapse_domains(main_domains)
    block_rules = sorted(f"||{d}^" for d in collapsed)

    blocked_set = set(collapsed) | base_domains
    allow_rules = []

    for allow in allow_domains:
        if allow in blocked_set:
            continue
        parts = allow.split(".")
        for i in range(len(parts)):
            parent = ".".join(parts[i:])
            if parent in blocked_set:
                allow_rules.append(f"@@||{allow}^")
                break

    allow_rules = sorted(set(allow_rules))

    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: AdGuard Additional DNS filter (v2)\n")
        f.write("! Version: " + version + "\n")
        f.write("! Expires: 6 hours\n")
        f.write(f"! Block rules: {len(block_rules)}\n")
        f.write(f"! Allow rules: {len(allow_rules)}\n")
        f.write("!\n")

        for r in allow_rules:
            f.write(r + "\n")

        f.write("!\n")

        for r in block_rules:
            f.write(r + "\n")

    print("Build successful")

if __name__ == "__main__":
    main()
