import requests
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ==========================================================
# SOURCE REGISTRY
# ==========================================================

SOURCES = {
    # AdGuard base filters (avoid duplicating them)
    "base": [
        "https://filters.adtidy.org/dns/filter_1.txt",
        "https://filters.adtidy.org/android/filters/15_optimized.txt",
    ],

    # MAIN BLOCK LIST (Pro++ replaces Pro)
    "main": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt",
    ],

    # TIF (Threat Intelligence Feed)
    "tif": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    ],

    # ALL NRD LISTS (treated same as TIF → removal set)
    "nrd": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd-7.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd-14.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd-30.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd-90.txt",
    ],

    # Allow lists
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
    intelligence_domains = set()  # TIF + NRD
    main_blocked_domains = set()
    block_rules = []
    seen = set()

    # ---------------- BASE FILTER DOMAINS ----------------
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

    # ---------------- MAIN BLOCK LIST (Pro++) ----------------
    for rule in fetch_all(SOURCES["main"]):
        c = clean_rule(rule)
        if not c:
            continue

        d = extract_domain(c)

        # Remove anything in base filters
        if d and d in base_domains:
            continue

        # Remove anything in TIF or NRD
        if d and d in intelligence_domains:
            continue

        if c in seen:
            continue

        seen.add(c)
        block_rules.append(c)

        if d:
            main_blocked_domains.add(d)

    block_rules = sorted(block_rules)

    # ---------------- SMART ALLOW RULES ----------------
    all_blocked = base_domains | main_blocked_domains
    needed_allow = allow_domains.intersection(all_blocked)

    allow_rules = sorted([f"@@||{d}^" for d in needed_allow])

    # ---------------- VERSION ----------------
    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")

    # ---------------- WRITE FILTER FILE ----------------
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        f.write("! Title: AdGuard Additional DNS filter\n")
        f.write("! Description: Pro++ minus TIF and NRD intelligence feeds.\n")
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

    print("Build successful")


if __name__ == "__main__":
    main()
