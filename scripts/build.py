import requests
import os
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

def fetch(url):
    print("Downloading:", url)
    try:
        r = requests.get(url, timeout=40)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print("Failed:", url, "|", e)
        return []


def fetch_all(urls):
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(fetch, urls))
    return [line for result in results for line in result]


def clean_rule(rule):
    rule = rule.strip()
    if not rule or rule.startswith("!"):
        return None
    return rule


def extract_domain(rule):
    r = rule.strip()

    if r.startswith("@@"):
        r = r[2:]

    if r.startswith("||"):
        return r[2:].split("^")[0]

    if " " not in r and "." in r:
        return r

    return None


# ==========================================================
# MAIN BUILD
# ==========================================================

def main():

    os.makedirs("output", exist_ok=True)

    base_domains = set()
    allow_domains = set()
    intelligence_domains = set()
    main_blocked_domains = set()
    block_rules = []
    seen = set()

    # ---------------- BASE DOMAINS ----------------
    for rule in fetch_all(SOURCES["base"]):
        c = clean_rule(rule)
        if not c:
            continue

        d = extract_domain(c)
        if d:
            base_domains.add(d)

    # ---------------- TIF + NRD DOMAINS ----------------
    for category in ["tif", "nrd"]:
        for rule in fetch_all(SOURCES[category]):
            c = clean_rule(rule)
            if not c:
                continue

            d = extract_domain(c)
            if d:
                intelligence_domains.add(d)

    # ---------------- ALLOW DOMAINS ----------------
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

    # ---------------- SMART ALLOW (OPTIMIZED) ----------------
    all_blocked = base_domains | main_blocked_domains
    
    # Pre-compute parent variations of blocked domains for instant lookups
    blocked_parents = set()
    for b in all_blocked:
        parts = b.split('.')
        if len(parts) > 2:
            for i in range(1, len(parts) - 1):
                blocked_parents.add('.'.join(parts[i:]))

    needed_allow = set()
    for d in allow_domains:
        # Check if exact domain is blocked OR if the allow domain is a parent of a blocked domain
        if d in all_blocked or d in blocked_parents:
            needed_allow.add(d)
        else:
            # Check if any parent of the allow domain is explicitly blocked
            parts = d.split('.')
            for i in range(1, len(parts)):
                parent_domain = '.'.join(parts[i:])
                if parent_domain in all_blocked:
                    needed_allow.add(d)
                    break

    allow_rules = sorted([f"@@||{d}^" for d in needed_allow])

    # ---------------- VERSION ----------------
    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")

    # ---------------- WRITE FILTER FILE ----------------
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        f.write("! Title: AdGuard Additional DNS filter\n")
        f.write("! Description: Pro++ minus TIF and NRD intelligence feeds.\n")
        f.write(
