#!/usr/bin/env python3

import requests
import os
import hashlib
from datetime import datetime

# ============================================================
# CONFIGURATION
# ============================================================

BASE_URLS = [
    "https://filters.adtidy.org/dns/filter_1.txt",
    "https://filters.adtidy.org/android/filters/15_optimized.txt",
]

MAIN_URLS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
]

TIF_URLS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
]

FORCE_ALLOW_URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/facebook.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/microsoft.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/ultimate-known-issues.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",
]

PERMANENT_EXCLUDE = {
    "promos.makemytrip.com",
    "calculator-api-in.allawnos.com",
    "calculator-api-fr.allawnos.com",
}

OUTPUT_FILE = "output/adguard-additional-dns.txt"
README_FILE = "README.md"

FILTER_NAME = "AdGuard Additional DNS filter"
FILTER_DESCRIPTION = (
    "Additional DNS filtering rules extending AdGuard Default filters "
    "with enhanced protection while preserving compatibility."
)

SUBSCRIPTION_URL = "https://raw.githubusercontent.com/anujhalakhandi/adguard-additional-dns-filters/main/output/adguard-additional-dns.txt"

# ============================================================
# NETWORK
# ============================================================

def fetch(url):
    print(f"Downloading: {url}")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AdGuardListBuilder/1.0"}
    r = requests.get(url, headers=headers, timeout=120)
    r.raise_for_status()
    return r.text

# ============================================================
# STRICT DNS PARSER
# ============================================================

def normalize(domain):
    return domain.lower().strip().strip(".")


def is_valid_domain(domain):
    if "." not in domain:
        return False
    if " " in domain:
        return False
    if "/" in domain:
        return False
    if domain.startswith("-") or domain.endswith("-"):
        return False
    if len(domain) < 4:
        return False
    return True


def extract_dns_domains(text):
    domains = set()

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("!"):
            continue

        if "##" in line or "#@#" in line:
            continue

        line = line.split("#")[0].strip()

        if "$" in line:
            line = line.split("$")[0]

        # Improved handling for hosts files (supports both tabs and spaces)
        if line.startswith(("0.0.0.0", "127.0.0.1")):
            parts = line.split()
            if len(parts) >= 2:
                line = parts[1]
            else:
                continue

        if line.startswith("@@"):
            line = line[2:]

        if line.startswith("||"):
            line = line[2:]

        line = line.split("^")[0]

        if "/" in line:
            continue

        domain = normalize(line)

        if is_valid_domain(domain):
            domains.add(domain)

    return domains


def build_set(urls):
    result = set()
    for url in urls:
        try:
            result |= extract_dns_domains(fetch(url))
        except Exception as e:
            print(f"Failed {url}: {e}")
    return result


def file_hash(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

# ============================================================
# OPTIMIZED BASE SHADOW CHECK
# ============================================================

def build_base_index(base_set):
    base_index = set(base_set)
    base_depths = {len(d.split(".")) for d in base_set}
    shadow_cache = {}
    return base_index, base_depths, shadow_cache


def is_blocked_by_base(domain, base_index, base_depths, shadow_cache):
    if domain in shadow_cache:
        return shadow_cache[domain]

    parts = domain.split(".")
    depth = len(parts)

    for parent_depth in base_depths:
        if parent_depth > depth:
            continue

        parent = ".".join(parts[-parent_depth:])

        if parent in base_index:
            shadow_cache[domain] = True
            return True

    shadow_cache[domain] = False
    return False


# ============================================================
# FORCE_ALLOW SHADOW CHECK (OPTIMIZED)
# ============================================================

def is_under_force_allow(domain, force_allow_set):
    parts = domain.split(".")
    for i in range(len(parts)):
        parent = ".".join(parts[i:])
        if parent in force_allow_set:
            return True
    return False


# ============================================================
# BUILD PROCESS
# ============================================================

print("Building DNS-strict additional filter...")

BASE_SET = build_set(BASE_URLS)
MAIN_SET = build_set(MAIN_URLS)
TIF_SET = build_set(TIF_URLS)
FORCE_ALLOW_SET = build_set(FORCE_ALLOW_URLS)

PERMANENT_EXCLUDE = {normalize(d) for d in PERMANENT_EXCLUDE}

print("BASE:", len(BASE_SET))
print("MAIN:", len(MAIN_SET))
print("TIF:", len(TIF_SET))
print("FORCE_ALLOW:", len(FORCE_ALLOW_SET))

# ------------------------------------------------------------
# ADDITIONAL BLOCK RULES
# ------------------------------------------------------------

FINAL_BLOCK_SET = MAIN_SET - BASE_SET - TIF_SET
FINAL_BLOCK_SET -= PERMANENT_EXCLUDE

# Remove FORCE_ALLOW domains and their subdomains (FAST)
if FORCE_ALLOW_SET:
    FINAL_BLOCK_SET = {
        d for d in FINAL_BLOCK_SET
        if not is_under_force_allow(d, FORCE_ALLOW_SET)
    }

# ------------------------------------------------------------
# ALLOW RULES (BASE SHADOW AWARE)
# ------------------------------------------------------------

base_index, base_depths, shadow_cache = build_base_index(BASE_SET)

FINAL_ALLOW_SET = {
    d for d in FORCE_ALLOW_SET
    if is_blocked_by_base(d, base_index, base_depths, shadow_cache)
}

# Sanity: ensure no overlap
FINAL_BLOCK_SET -= FINAL_ALLOW_SET

print("FINAL BLOCK:", len(FINAL_BLOCK_SET))
print("FINAL ALLOW:", len(FINAL_ALLOW_SET))

# ============================================================
# GENERATE OUTPUT & README
# ============================================================

os.makedirs("output", exist_ok=True)

block_rules = sorted(f"||{d}^" for d in FINAL_BLOCK_SET)
allow_rules = sorted(f"@@||{d}^" for d in FINAL_ALLOW_SET)

# Hash ONLY the rules payload to detect actual changes
rules_payload = "\n".join(block_rules) + "\n\n" + "\n".join(allow_rules)
new_hash = file_hash(rules_payload)
old_hash = None

if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        existing_content = f.read()
        # Extract everything after the header to get the old rules payload
        if "! Total rules:" in existing_content:
            old_rules_payload = existing_content.split("! Total rules:", 1)[1].strip()
            old_hash = file_hash(old_rules_payload)

if new_hash != old_hash:
    # 1. Update Filter File
    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")
    last_modified = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    header = f"""! Title: {FILTER_NAME}
! Description: {FILTER_DESCRIPTION}
! Version: {version}
! Expires: 6 hours
! Last modified: {last_modified}
! License: MIT
!
! Block rules: {len(block_rules)}
! Allow rules: {len(allow_rules)}
! Total rules: {len(block_rules) + len(allow_rules)}
!
"""
    output_content = header + rules_payload

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(output_content)
    
    # 2. Update README File
    readme_content = f"""# {FILTER_NAME}

{FILTER_DESCRIPTION}

## Filter Statistics

- Block rules: **{len(block_rules)}**
- Allow rules: **{len(allow_rules)}**
- Total rules: **{len(block_rules) + len(allow_rules)}**

## Subscription URL

{SUBSCRIPTION_URL}

Auto-updated every 6 hours via GitHub Actions.
"""
    with open(README_FILE, "w", encoding="utf-8") as f:
        f.write(readme_content)

    print("Filter and README updated.")
else:
    print("No changes detected. Skipping file writes.")

print("Build complete.")
