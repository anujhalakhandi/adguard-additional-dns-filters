import requests
import os
import re
from datetime import datetime

# ==========================================================
# SOURCE REGISTRY (Optimized for AdGuard Apps Personal Use)
# ==========================================================

SOURCES = {
    "base": [
        "https://filters.adtidy.org/dns/filter_1.txt",
        "https://filters.adtidy.org/android/filters/15_optimized.txt",
    ],

    # Switched to Hagezi Pro (NOT Pro++)
    "main": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
        # Uncomment below if you really want DynDNS blocked
        # "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt",
    ],

    # Intelligence feeds (we REMOVE these from output)
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
    ],
}

OUTPUT_FILE = "output/adguard-additional-dns-filter.txt"

RAW_LINK = "https://raw.githubusercontent.com/anujhalakhandi/adguard-additional-dns-filters/main/output/adguard-additional-dns-filter.txt"

# ==========================================================
# NETWORK
# ==========================================================

session = requests.Session()

def fetch(url):
    print("Downloading:", url)
    try:
        r = session.get(url, timeout=40)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print("Failed:", url, "|", e)
        return []

def fetch_all(urls):
    lines = []
    for url in set(urls):  # dedupe URLs
        lines.extend(fetch(url))
    return lines

# ==========================================================
# DOMAIN PARSING (Strict DNS Style Only)
# ==========================================================

DOMAIN_PATTERN = re.compile(r"^\|\|([a-zA-Z0-9.-]+)\^")

def clean_rule(rule):
    rule = rule.strip()
    if not rule or rule.startswith("!"):
        return None
    return rule

def extract_domain(rule):
    r = rule.strip()

    if r.startswith("@@"):
        r = r[2:]

    match = DOMAIN_PATTERN.match(r)
    if match:
        return match.group(1).lower()

    return None

def is_subdomain(child, parent):
    return child == parent or child.endswith("." + parent)

# ==========================================================
# MAIN BUILD
# ==========================================================

def main():

    os.makedirs("output", exist_ok=True)

    base_domains = set()
    intelligence_domains = set()
    allow_domains = set()
    main_domains = {}
    final_rules = []

    # ---------------- BASE ----------------
    for rule in fetch_all(SOURCES["base"]):
        c = clean_rule(rule)
        if not c:
            continue
        d = extract_domain(c)
        if d:
            base_domains.add(d)

    # ---------------- INTELLIGENCE (TIF + NRD) ----------------
    for category in ["tif", "nrd"]:
        for rule in fetch_all(SOURCES[category]):
            c = clean_rule(rule)
            if not c:
                continue
            d = extract_domain(c)
            if d:
                intelligence_domains.add(d)

    # ---------------- ALLOW ----------------
    for rule in fetch_all(SOURCES["allow"]):
        c = clean_rule(rule)
        if not c:
            continue
        d = extract_domain(c)
        if d:
            allow_domains.add(d)

    # ---------------- MAIN BLOCK BUILD ----------------
    for rule in fetch_all(SOURCES["main"]):
        c = clean_rule(rule)
        if not c:
            continue

        d = extract_domain(c)
        if not d:
            continue

        # Skip if covered by base
        if any(is_subdomain(d, b) for b in base_domains):
            continue

        # Skip intelligence feeds
        if any(is_subdomain(d, i) for i in intelligence_domains):
            continue

        # Skip if parent already added (collapse subdomains)
        if any(is_subdomain(d, existing) for existing in main_domains):
            continue

        main_domains[d] = c

    # Convert to sorted block rules
    block_rules = sorted(main_domains.values())

    # ---------------- SMART ALLOW (Parent-aware) ----------------
    all_blocked = set(main_domains.keys()) | base_domains
    allow_rules = []

    for allow in allow_domains:
        for blocked in all_blocked:
            if is_subdomain(blocked, allow) or is_subdomain(allow, blocked):
                allow_rules.append(f"@@||{allow}^")
                break

    allow_rules = sorted(set(allow_rules))

    # ---------------- VERSION ----------------
    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")

    # ---------------- WRITE FILTER FILE ----------------
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: AdGuard Additional DNS filter\n")
        f.write("! Description: Hagezi Pro minus TIF & NRD. Optimized for AdGuard apps.\n")
        f.write(f"! Version: {version}\n")
        f.write("! Expires: 2 hours\n")
        f.write(f"! Block rules: {len(block_rules)}\n")
        f.write(f"! Allow rules: {len(allow_rules)}\n")
        f.write("!\n")

        for r in allow_rules:
            f.write(r + "\n")

        f.write("!\n")

        for r in block_rules:
            f.write(r + "\n")

    # ---------------- UPDATE README ----------------
    readme = f"""# AdGuard Additional DNS Filter

Optimized for AdGuard Android & macOS apps.

Block rules: {len(block_rules)}  
Allow rules: {len(allow_rules)}

## Filter URL
{RAW_LINK}
"""

    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme)

    print("Build successful")

if __name__ == "__main__":
    main()
