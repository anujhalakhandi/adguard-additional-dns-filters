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

# MAIN SOURCE LISTS
MAIN_LISTS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",
]

TIF_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt"

ALLOWLIST_URLS = [

    # HaGeZi
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt",

    # OISD
    "https://local.oisd.nl/extract/commonly_whitelisted.php",

    # AdGuard exclusions
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/firefox.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/mac.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/banks.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/windows.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/issues.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/android.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/sensitive.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",

    # Community allowlists
    "https://raw.githubusercontent.com/notracking/hosts-blocklists-scripts/master/hostnames.whitelist.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/referral-sites.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt",
    "https://raw.githubusercontent.com/freekers/whitelist/master/domains/whitelist.txt",
    "https://raw.githubusercontent.com/ookangzheng/blahdns/master/hosts/whitelist.txt",
    "https://raw.githubusercontent.com/DandelionSprout/AdGuard-Home-Whitelist/master/whitelist.txt",
    "https://raw.githubusercontent.com/TogoFire-Home/AD-Settings/main/Filters/whitelist.txt",

    # Extra
    "https://raw.githubusercontent.com/Dogino/Discord-Phishing-URLs/main/official-domains.txt",
    "https://raw.githubusercontent.com/boutetnico/url-shorteners/master/list.txt",
    "https://raw.githubusercontent.com/mawenjian/china-cdn-domain-whitelist/master/china-cdn-domain-whitelist.txt",
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


# ======================================
# MAIN BUILD
# ======================================

def main():

    os.makedirs("output", exist_ok=True)

    exclusion_rules = set()

    # BASE FILTERS
    for url in BASE_URLS:
        for r in fetch(url):
            c = clean_rule(r)
            if c:
                exclusion_rules.add(c)

    # TIF
    for r in fetch(TIF_URL):
        c = clean_rule(r)
        if c:
            exclusion_rules.add(c)

    # ALLOWLISTS
    for url in ALLOWLIST_URLS:
        for r in fetch(url):
            c = clean_rule(r)
            if c:
                exclusion_rules.add(c)

    # BUILD FINAL FROM ALL MAIN LISTS
    final_rules = []
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
            final_rules.append(c)

    final_rules = sorted(final_rules)

    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")

    # WRITE FILTER
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        f.write("! Title: AdGuard Additional DNS filter\n")
        f.write("! Description: Additional DNS filter not included in the default list.\n")
        f.write(f"! Version: {version}\n")
        f.write("! Expires: 2 hours\n")
        f.write(f"! Total rules: {len(final_rules)}\n")
        f.write("!\n")

        for r in final_rules:
            f.write(r + "\n")

    # README
    readme = f"""# AdGuard Additional DNS filter

Rules: {len(final_rules)}

Filter URL:
{RAW_LINK}
"""

    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme)

    print("Build successful:", len(final_rules))


if __name__ == "__main__":
    main()
