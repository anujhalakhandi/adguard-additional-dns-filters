import requests
import re

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


def fetch(url):
    print("Downloading:", url)
    return requests.get(url, timeout=30).text.splitlines()


def normalize_rule(rule):
    rule = rule.strip().lower()

    if not rule or rule.startswith("!"):
        return None

    rule = rule.replace("@@", "")
    rule = re.sub(r"^https?://", "", rule)

    if rule.startswith(("0.0.0.0", "127.0.0.1")):
        parts = rule.split()
        if len(parts) >= 2:
            rule = parts[1]

    rule = rule.replace("||", "")
    rule = rule.replace("|", "")
    rule = rule.split("^")[0]
    rule = rule.split("$")[0]
    rule = rule.replace("*.", "")
    rule = rule.split("/")[0]

    if "." not in rule:
        return None

    return rule


def main():

    exclusion_domains = set()

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

    final_rules = []

    for rule in fetch(PRO_URL):
        d = normalize_rule(rule)
        if d and d not in exclusion_domains:
            final_rules.append(rule)

    import os
    os.makedirs("output", exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! AdGuard Additional DNS Filters\n")
        f.write("! Auto-generated\n\n")
        for r in final_rules:
            f.write(r + "\n")


if __name__ == "__main__":
    main()
