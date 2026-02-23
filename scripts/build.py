import requests
import os
from datetime import datetime

# ======================================
# SOURCES
# ======================================

BASE_URLS = [
    "https://filters.adtidy.org/dns/filter_1.txt",
    "https://filters.adtidy.org/android/filters/15_optimized.txt"
]

MAIN_LISTS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt",
]

TIF_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt"

ALLOWLIST_URLS = [
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
]

OUTPUT_FILE = "output/adguard-additional-dns-filter.txt"

RAW_LINK = "https://raw.githubusercontent.com/anujhalakhandi/adguard-additional-dns-filters/main/output/adguard-additional-dns-filter.txt"


# ======================================
# HELPERS
# ======================================

def fetch(url):
    print("Downloading:", url)
    try:
        return requests.get(url, timeout=40).text.splitlines()
    except:
        return []


def clean_rule(rule):
    rule = rule.strip()
    if not rule or rule.startswith("!"):
        return None
    return rule


def extract_domain(rule):
    r = rule.strip()

    if r.startswith("||"):
        return r[2:].split("^")[0]

    if " " not in r and "." in r and not r.startswith("@@"):
        return r

    return None


# ======================================
# MAIN BUILD
# ======================================

def main():

    os.makedirs("output", exist_ok=True)

    exclusion_rules = set()
    base_blocked_domains = set()
    allow_domains = set()

    # ---------- BASE FILTERS ----------
    for url in BASE_URLS:
        for r in fetch(url):
            c = clean_rule(r)
            if not c:
                continue

            exclusion_rules.add(c)

            d = extract_domain(c)
            if d:
                base_blocked_domains.add(d)

    # ---------- TIF ----------
    for r in fetch(TIF_URL):
        c = clean_rule(r)
        if c:
            exclusion_rules.add(c)

    # ---------- ALLOWLISTS ----------
    for url in ALLOWLIST_URLS:
        for r in fetch(url):
            c = clean_rule(r)
            if not c:
                continue

            exclusion_rules.add(c)

            d = extract_domain(c)
            if d:
                allow_domains.add(d)

    # ---------- BUILD BLOCK RULES ----------
    block_rules = []
    seen = set()

    for main_url in MAIN_LISTS:

        for rule in fetch(main_url):

            c = clean_rule(rule)

            if not c:
                continue

            if c in exclusion_rules:
                continue

            if c in seen:
                continue

            seen.add(c)
            block_rules.append(c)

    block_rules = sorted(block_rules)

    # ---------- BUILD SMART ALLOW RULES ----------
    needed_allow = allow_domains.intersection(base_blocked_domains)

    allow_rules = sorted([f"@@||{d}^" for d in needed_allow])

    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")

    # ---------- WRITE FILTER ----------
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        f.write("! Title: AdGuard Additional DNS filter\n")
        f.write("! Description: Additional DNS filter not included in the default list.\n")
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

    # ---------- README ----------
    readme = f"""# AdGuard Additional DNS filter

Block rules: {len(block_rules)}  
Allow rules: {len(allow_rules)}

Filter URL:
{RAW_LINK}
"""

    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme)

    print("Build successful")


if __name__ == "__main__":
    main()
