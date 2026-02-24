#!/usr/bin/env python3

import requests
import os
import hashlib
from datetime import datetime
from collections import defaultdict

# ============================================================
# CONFIGURATION
# ============================================================

BASE_URLS = [
    "https://filters.adtidy.org/dns/filter_1.txt",
    "https://filters.adtidy.org/android/filters/15_optimized.txt",
]

MAIN_URLS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
]

TIF_URLS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
]

ALLOWLIST_URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-native.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-connectivity.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-apple.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-google.txt",
    "https://local.oisd.nl/extract/commonly_whitelisted.php",
]

OUTPUT_FILE = "output/adguard-additional-dns.txt"
README_FILE = "README.md"

FILTER_NAME = "AdGuard Additional DNS filters"
FILTER_DESCRIPTION = (
    "Additional DNS filtering rules extending AdGuard Default filters "
    "with enhanced protection while preserving compatibility."
)

SUBSCRIPTION_URL = "https://raw.githubusercontent.com/anujhalakhandi/adguard-additional-dns-filters/main/output/adguard-additional-dns.txt"

# ============================================================
# HELPERS
# ============================================================

def fetch(url):
    print(f"Downloading: {url}")
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    return r.text


def normalize(domain):
    return domain.lower().strip().strip(".")


def is_valid_domain(domain):
    if "." not in domain:
        return False
    if domain.count(".") < 1:
        return False
    if len(domain) < 4:
        return False
    return True


def extract_domains(text):
    domains = set()

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("!"):
            continue

        line = line.split("#")[0].strip()

        # Adblock format
        if line.startswith("||"):
            domain = line[2:]
            domain = domain.split("^")[0]
            domain = domain.split("$")[0]
            domain = normalize(domain)
            if is_valid_domain(domain):
                domains.add(domain)
            continue

        # Hosts format
        parts = line.split()
        if len(parts) >= 2:
            candidate = normalize(parts[-1])
            if is_valid_domain(candidate):
                domains.add(candidate)
            continue

        # Plain domain
        if "." in line and " " not in line and "/" not in line:
            candidate = normalize(line)
            if is_valid_domain(candidate):
                domains.add(candidate)

    return domains


def build_set(urls):
    result = set()
    for url in urls:
        try:
            result |= extract_domains(fetch(url))
        except Exception as e:
            print(f"Failed {url}: {e}")
    return result


def file_hash(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# ============================================================
# BUILD PROCESS
# ============================================================

print("Building filter sets...")

BASE_SET = build_set(BASE_URLS)
MAIN_SET = build_set(MAIN_URLS)
TIF_SET = build_set(TIF_URLS)
ALLOWLIST_SET = build_set(ALLOWLIST_URLS)

print("BASE:", len(BASE_SET))
print("MAIN:", len(MAIN_SET))
print("TIF:", len(TIF_SET))
print("ALLOWLIST:", len(ALLOWLIST_SET))

FINAL_SET = (MAIN_SET - BASE_SET) - TIF_SET
BLOCKED_SET = FINAL_SET | BASE_SET

print("FINAL:", len(FINAL_SET))

# ============================================================
# BUILD DOMAIN TREE (ONCE)
# ============================================================

tree = defaultdict(set)

for domain in BLOCKED_SET:
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        tree[parent].add(domain)

# ============================================================
# SHADOW-SAFE EXPANSION (Optimized)
# ============================================================

ALLOW_TARGET = ALLOWLIST_SET & BLOCKED_SET
final_allow = set()

for allow in ALLOW_TARGET:
    if allow in BLOCKED_SET:
        final_allow.add(allow)

    children = tree.get(allow)
    if children:
        final_allow.update(children)

# ============================================================
# SAFE DOMAIN COMPRESSION
# ============================================================

for parent, children in tree.items():
    if children and children.issubset(final_allow):
        final_allow.difference_update(children)
        final_allow.add(parent)

print("ALLOW:", len(final_allow))

# ============================================================
# GENERATE OUTPUT
# ============================================================

os.makedirs("output", exist_ok=True)

block_rules = sorted(f"||{d}^" for d in FINAL_SET)
allow_rules = sorted(f"@@||{d}^" for d in final_allow)

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

output_content = header + "\n".join(block_rules) + "\n\n" + "\n".join(allow_rules)

new_hash = file_hash(output_content)
old_hash = None

if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        old_hash = file_hash(f.read())

if new_hash != old_hash:
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(output_content)
    print("Filter updated.")
else:
    print("No changes detected.")

# ============================================================
# UPDATE README
# ============================================================

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

print("Build complete.")
