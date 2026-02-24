#!/usr/bin/env python3

import requests
import re
import os
from datetime import datetime

# -----------------------------
# CONFIG
# -----------------------------

BASE = [
    "https://filters.adtidy.org/dns/filter_1.txt",
    "https://filters.adtidy.org/android/filters/15_optimized.txt",
]

MAIN = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
]

TIF = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
]

ALLOWLIST = [
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


# -----------------------------
# HELPERS
# -----------------------------

def fetch(url):
    print(f"Downloading: {url}")
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    return r.text


def extract_domains(text):
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue

        # Adblock format: ||domain^
        match = re.search(r"\|\|([^\^/]+)\^?", line)
        if match:
            domain = match.group(1).lower().strip(".")
            if domain.count(".") >= 1:
                domains.add(domain)

    return domains


def build_set(urls):
    result = set()
    for url in urls:
        text = fetch(url)
        result |= extract_domains(text)
    return result


# -----------------------------
# BUILD LOGIC
# -----------------------------

print("Building sets...")

BASE_SET = build_set(BASE)
MAIN_SET = build_set(MAIN)
TIF_SET = build_set(TIF)
ALLOW_SET = build_set(ALLOWLIST)

# FINAL = MAIN − BASE − TIF
FINAL_SET = (MAIN_SET - BASE_SET) - TIF_SET

# BLOCKED_SET = FINAL ∪ BASE
BLOCKED_SET = FINAL_SET | BASE_SET

# ALLOW = allowlist ∩ BLOCKED_SET
ALLOW_FINAL = ALLOW_SET & BLOCKED_SET

# -----------------------------
# OUTPUT GENERATION
# -----------------------------

os.makedirs("output", exist_ok=True)

block_rules = sorted([f"||{d}^" for d in FINAL_SET])
allow_rules = sorted([f"@@||{d}^" for d in ALLOW_FINAL])

header = f"""! Title: AdGuard Additional DNS filters
! Description: Additional DNS filtering rules extending AdGuard Default filters with enhanced protection while preserving compatibility.
! Version: {datetime.utcnow().strftime('%Y.%m.%d.%H%M')}
! Expires: 6 hours
! Homepage: https://github.com/YOUR_USERNAME/YOUR_REPO
! Last modified: {datetime.utcnow().isoformat()}Z
! License: MIT
!
! Block rules: {len(block_rules)}
! Allow rules: {len(allow_rules)}
! Total rules: {len(block_rules) + len(allow_rules)}
!
"""

with open(OUTPUT_FILE, "w") as f:
    f.write(header)
    f.write("\n".join(block_rules))
    f.write("\n\n")
    f.write("\n".join(allow_rules))

# -----------------------------
# UPDATE README
# -----------------------------

readme_content = f"""
# AdGuard Additional DNS filters

Additional DNS filtering rules extending AdGuard Default filters with enhanced protection while preserving compatibility.

## Filter Statistics

- Block rules: **{len(block_rules)}**
- Allow rules: **{len(allow_rules)}**
- Total rules: **{len(block_rules) + len(allow_rules)}**

## Subscription URL
