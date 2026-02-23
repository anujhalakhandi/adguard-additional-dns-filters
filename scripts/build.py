import requests
import os
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ==========================================================
# SOURCE REGISTRY
# ==========================================================

SOURCES = {
    "base": [
        "https://filters.adtidy.org/dns/filter_1.txt",
        "https://filters.adtidy.org/android/filters/15_optimized.txt",
    ],

    "main": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
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
    ],
}

OUTPUT_FILE = "output/adguard-additional-dns-filter.txt"

RAW_LINK = "https://raw.githubusercontent.com/anujhalakhandi/adguard-additional-dns-filters/main/output/adguard-additional-dns-filter.txt"

# ==========================================================
# NETWORK
# ==========================================================

session = requests.Session()

def fetch(url):
    try:
        r = session.get(url, timeout=40)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception:
        return []

def fetch_all(urls):
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(fetch, set(urls)))
    return [line for result in results for line in result]

# ==========================================================
# DOMAIN PARSING (Strict DNS-only rules)
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

# ==========================================================
# SUBDOMAIN COLLAPSE (Efficient)
# ==========================================================

def collapse_domains(domain_dict):
    """
    Removes subdomains if parent domain exists.
    Works in O(n log n).
    """
    sorted_domains = sorted(domain_dict.keys())
    collapsed = {}
    previous = None

    for domain in sorted_domains:
        if previous and domain.endswith("." + previous):
            continue
        collapsed[domain] = domain_dict[domain]
        previous = domain

    return collapsed

# ==========================================================
# MAIN BUILD
# ==========================================================

def main():

    os.makedirs("output", exist_ok=True)

    base_domains = set()
    intelligence_domains = set()
    allow_domains = set()
    main_domains = {}

    # BASE
    for rule in fetch_all(SOURCES["base"]):
        c = clean_rule(rule)
        if not c:
            continue
        d = extract_domain(c)
        if d:
            base_domains.add(d)

    # INTELLIGENCE (TIF + NRD)
    for category in ["tif", "nrd"]:
        for rule in fetch_all(SOURCES[category]):
            c = clean_rule(rule)
            if not c:
                continue
            d = extract_domain(c)
            if d:
                intelligence_domains.add(d)

    # ALLOW
    for rule in fetch_all(SOURCES["allow"]):
        c = clean_rule(rule)
        if not c:
            continue
        d = extract_domain(c)
        if d:
            allow_domains.add(d)

    # MAIN BUILD (fast O(1) checks)
    for rule in fetch_all(SOURCES["main"]):
        c = clean_rule(rule)
        if not c:
            continue

        d = extract_domain(c)
        if not d:
            continue

        if d in base_domains:
            continue

        if d in intelligence_domains:
            continue

        main_domains[d] = c

    # Collapse subdomains efficiently
    main_domains = collapse_domains(main_domains)

    block_rules = sorted(main_domains.values())

    # SMART ALLOW (exact only — fast & safe)
    blocked_domains = set(main_domains.keys()) | base_domains
    allow_rules = sorted(
        f"@@||{d}^" for d in allow_domains if d in blocked_domains
    )

    # VERSION
    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")

    # WRITE FILTER FILE
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        f.write("! Title: AdGuard Additional DNS filter\n")
        f.write("! Description: Hagezi Pro + DynDNS minus TIF & NRD (subdomains collapsed).\n")
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

    # UPDATE README
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(f"""# AdGuard Additional DNS Filter

Optimized for personal AdGuard Android & macOS usage.

Block rules: {len(block_rules)}  
Allow rules: {len(allow_rules)}

## Filter URL
{RAW_LINK}
""")

    print("Build successful")


if __name__ == "__main__":
    main()
