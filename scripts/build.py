import requests
import re
import os
from datetime import datetime
from urllib.parse import quote

# ======================================
# SOURCES (BACKEND ONLY)
# ======================================

BASE_URLS = [
    "https://filters.adtidy.org/dns/filter_1.txt",
    "https://filters.adtidy.org/android/filters/15_optimized.txt"
]

PRO_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt"
TIF_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt"

ALLOWLIST_URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt",
    "https://local.oisd.nl/extract/commonly_whitelisted.php",

    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/firefox.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/mac.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/banks.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/windows.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/issues.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/android.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/sensitive.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",

    "https://raw.githubusercontent.com/notracking/hosts-blocklists-scripts/master/hostnames.whitelist.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/referral-sites.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt",
    "https://raw.githubusercontent.com/freekers/whitelist/master/domains/whitelist.txt",
    "https://raw.githubusercontent.com/ookangzheng/blahdns/master/hosts/whitelist.txt",
    "https://raw.githubusercontent.com/DandelionSprout/AdGuard-Home-Whitelist/master/whitelist.txt",
    "https://raw.githubusercontent.com/TogoFire-Home/AD-Settings/main/Filters/whitelist.txt",

    "https://raw.githubusercontent.com/Dogino/Discord-Phishing-URLs/main/official-domains.txt",
    "https://raw.githubusercontent.com/boutetnico/url-shorteners/master/list.txt",
    "https://raw.githubusercontent.com/mawenjian/china-cdn-domain-whitelist/master/china-cdn-domain-whitelist.txt",
]

OUTPUT_FILE = "output/adguard-additional-dns.txt"

RAW_LINK = "https://raw.githubusercontent.com/anujhalakhandi/adguard-additional-dns-filters/main/output/adguard-additional-dns.txt"


# ======================================
# HELPERS
# ======================================

def fetch(url):
    try:
        return requests.get(url, timeout=40).text.splitlines()
    except:
        return []


def normalize_rule(rule):
    """
    SAFE NORMALIZATION (comparison only)
    Implements optimization methods 1–6.
    """

    rule = rule.strip().lower()

    # remove empty / comments
    if not rule or rule.startswith("!"):
        return None

    # remove whitelist marker
    rule = rule.replace("@@", "")

    # remove protocol
    rule = re.sub(r"^https?://", "", rule)

    # hosts format
    if rule.startswith(("0.0.0.0", "127.0.0.1")):
        parts = rule.split()
        if len(parts) >= 2:
            rule = parts[1]

    # adblock syntax cleanup
    rule = rule.replace("||", "")
    rule = rule.replace("|", "")

    # remove modifiers (DNS safe)
    rule = rule.split("^")[0]
    rule = rule.split("$")[0]

    # remove wildcard prefix
    rule = rule.replace("*.", "")

    # remove paths
    rule = rule.split("/")[0]

    # invalid domain check
    if "." not in rule:
        return None

    return rule


# ======================================
# MAIN BUILD
# ======================================

def main():

    os.makedirs("output", exist_ok=True)

    exclusion_domains = set()

    # ===============================
    # Build exclusion set
    # ===============================

    for url in BASE_URLS:
        for r in fetch(url):
            d = normalize_rule(r)
            if d:
                exclusion_domains.add(d)

    for r in fetch(TIF_URL):
        d = normalize_rule(r)
        if d:
            exclusion_domains.add(d)

    for url in ALLOWLIST_URLS:
        for r in fetch(url):
            d = normalize_rule(r)
            if d:
                exclusion_domains.add(d)

    # ===============================
    # Build final rules
    # ===============================

    final_rules = []
    seen_domains = set()

    for rule in fetch(PRO_URL):

        d = normalize_rule(rule)

        if not d:
            continue

        # remove base/tif/allowlist overlap
        if d in exclusion_domains:
            continue

        # remove duplicates (safe)
        if d in seen_domains:
            continue

        seen_domains.add(d)
        final_rules.append(rule)

    final_rules = sorted(final_rules)

    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")

    # ===============================
    # Write filter (professional header)
    # ===============================

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        f.write("! Title: AdGuard Additional DNS Filters\n")
        f.write("! Description: Additional DNS filters not included in the default list.\n")
        f.write("! Homepage: https://github.com/anujhalakhandi/adguard-additional-dns-filters\n")
        f.write(f"! Version: {version}\n")
        f.write("! Expires: 2 hours\n")
        f.write(f"! Total rules: {len(final_rules)}\n")
        f.write("!\n")

        for r in final_rules:
            f.write(r + "\n")

    # ===============================
    # README + BADGE
    # ===============================

    badge_value = quote(f"{len(final_rules)} rules")
    badge = f"https://img.shields.io/badge/Rules-{badge_value}-brightgreen"

    readme = f"""# AdGuard Additional DNS Filters

![Rule Count]({badge})

Additional DNS filters not included in the default list.

## 🔗 Filter URL

{RAW_LINK}

## ⏱ Update Frequency

Every 2 hours.
"""

    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme)


if __name__ == "__main__":
    main()
