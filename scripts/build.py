import requests
import os
import time
from datetime import datetime

# ==========================================================
# SOURCE REGISTRY
# ==========================================================

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
        "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/firefox.txt",
        "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/mac.txt",
        "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/banks.txt",
        "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/windows.txt",
        "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/issues.txt",
        "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/android.txt",
        "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/sensitive.txt",
        "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",
        "https://raw.githubusercontent.com/anujhalakhandi/adguard-additional-dns-filters/main/whitelist-oneplus.txt",
    ],
}

OUTPUT_FILE = "output/adguard-additional-dns-filter.txt"
RAW_LINK = "https://raw.githubusercontent.com/anujhalakhandi/adguard-additional-dns-filters/main/output/adguard-additional-dns-filter.txt"

# ==========================================================
# HELPERS
# ==========================================================

def fetch_category(urls):
    results = []
    # Using a session with a standard User-Agent prevents CDN rate-limiting/tarpitting
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })
    
    for url in urls:
        print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Fetching: {url}")
        try:
            r = session.get(url, timeout=30)
            r.raise_for_status()
            results.extend(r.text.splitlines())
        except Exception as e:
            print(f" -> Failed: {e}")
    return results

def clean_rule(rule):
    rule = rule.strip()
    if not rule or rule.startswith("!") or rule.startswith("#"):
        return None
    return rule

def extract_domain(rule):
    r = rule.strip()
    
    # Strip standard AdGuard/AdBlock wrappers
    if r.startswith("@@"):
        r = r[2:]
    if r.startswith("||"):
        r = r[2:]
    
    # Strip path or modifier artifacts
    r = r.split('^')[0]
    r = r.split('$')[0]
    r = r.split('/')[0]

    if " " not in r and "." in r:
        return r
    return None

# ==========================================================
# MAIN BUILD
# ==========================================================

def main():
    start_time = time.time()
    os.makedirs("output", exist_ok=True)

    base_domains = set()
    allow_domains = set()
    intelligence_domains = set()
    main_blocked_domains = set()
    block_rules = []
    seen = set()

    # ---------------- BASE DOMAINS ----------------
    print("\n--- Processing Base Sources ---")
    for rule in fetch_category(SOURCES["base"]):
        c = clean_rule(rule)
        if c:
            d = extract_domain(c)
            if d: base_domains.add(d)

    # ---------------- INTELLIGENCE DOMAINS ----------------
    print("\n--- Processing Intelligence Sources ---")
    for category in ["tif", "nrd"]:
        for rule in fetch_category(SOURCES[category]):
            c = clean_rule(rule)
            if c:
                d = extract_domain(c)
                if d: intelligence_domains.add(d)

    # ---------------- ALLOW DOMAINS ----------------
    print("\n--- Processing Allow Sources ---")
    for rule in fetch_category(SOURCES["allow"]):
        c = clean_rule(rule)
        if c:
            d = extract_domain(c)
            if d: allow_domains.add(d)

    # ---------------- MAIN BLOCK BUILD ----------------
    print("\n--- Building Main Blocklist ---")
    for rule in fetch_category(SOURCES["main"]):
        c = clean_rule(rule)
        if not c:
            continue

        d = extract_domain(c)

        if d and d in base_domains:
            continue
        if d and d in intelligence_domains:
            continue
        if c in seen:
            continue

        seen.add(c)
        block_rules.append(c)

        if d:
            main_blocked_domains.add(d)

    block_rules = sorted(block_rules)

    # ---------------- SMART ALLOW (O(1) OPTIMIZED) ----------------
    print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Calculating Smart Allow logic...")
    all_blocked = base_domains | main_blocked_domains
    
    blocked_parents = set()
    for b in all_blocked:
        parts = b.split('.')
        # Pre-compute every parent domain layer (e.g., a.b.com -> b.com, com)
        for i in range(1, len(parts)):
            blocked_parents.add('.'.join(parts[i:]))

    needed_allow = set()
    for d in allow_domains:
        # 1. Exact match OR allow domain is a parent of a blocked subdomain
        if d in all_blocked or d in blocked_parents:
            needed_allow.add(d)
        else:
            # 2. A parent of the allow domain is explicitly blocked
            parts = d.split('.')
            for i in range(1, len(parts)):
                if '.'.join(parts[i:]) in all_blocked:
                    needed_allow.add(d)
                    break

    allow_rules = sorted([f"@@||{d}^" for d in needed_allow])

    # ---------------- OUTPUT ----------------
    print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Writing output files...")
    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: AdGuard Additional DNS filter\n")
        f.write("! Description: Pro++ minus TIF and NRD intelligence feeds.\n")
        f.write(f"! Version: {version}\n")
        f.write("! Expires: 2 hours\n")
        f.write(f"! Block rules: {len(block_rules)}\n")
        f.write(f"! Allow rules: {len(allow_rules)}\n!\n")
        for r in allow_rules: f.write(r + "\n")
        f.write("!\n")
        for r in block_rules: f.write(r + "\n")

    readme = f"""# AdGuard Additional DNS Filter

Block rules: {len(block_rules)}  
Allow rules: {len(allow_rules)}

## Filter URL
{RAW_LINK}
"""
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme)

    elapsed = round(time.time() - start_time, 2)
    print(f"\n✅ Build successful in {elapsed} seconds.")

if __name__ == "__main__":
    main()
