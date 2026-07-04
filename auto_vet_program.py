#!/usr/bin/env python3
"""
auto_vet_program.py — Semi-automated program vetting for HackerOne.
"""
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request

HOME = os.path.expanduser("~")
TOKEN_PATH = os.path.join(HOME, ".hackerone_token")
MIN_ACCEPTABLE_RATE_LIMIT = 5

PROHIBITION_PATTERNS = [
    r"no\s+automated\s+scan",
    r"automated\s+scan(ning|ners)?\s+(is\s+|are\s+)?not\s+(permitted|allowed)",
    r"do\s+not\s+use\s+automated\s+(tools|scanners)",
    r"manual\s+testing\s+only",
    r"scanners?\s+(is|are)\s+prohibited",
]

RATE_LIMIT_PATTERNS = [
    r"(\d+)\s*requests?\s*per\s*second",
    r"(\d+)\s*req(?:uests)?\s*/\s*s(?:ec)?\b",
    r"rate\s*limit\s*(?:of\s*)?(\d+)",
]


def get_token():
    val = os.environ.get("HACKERONE_TOKEN")
    if val:
        return val.strip()
    with open(TOKEN_PATH) as f:
        return f.read().strip()


def api_get(url, token):
    auth = base64.b64encode(f"oxidizer:{token}".encode()).decode()
    req = urllib.request.Request(
        url, headers={"Authorization": f"Basic {auth}", "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())


def get_program_info(handle, token):
    url = f"https://api.hackerone.com/v1/hackers/programs/{handle}"
    data = api_get(url, token)
    attrs = data["attributes"]
    return attrs.get("submission_state", "unknown"), attrs.get("policy", "")


def get_scannable_scope(handle, token):
    scannable = []
    url = f"https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes?page[size]=100"
    while url:
        data = api_get(url, token)
        for item in data.get("data", []):
            a = item["attributes"]
            if a["asset_type"] in ("URL", "WILDCARD") and a.get("eligible_for_submission"):
                scannable.append((a["asset_type"], a["asset_identifier"]))
        url = data.get("links", {}).get("next")
    return scannable


def check_policy_text(policy_text):
    lower = policy_text.lower()

    for pattern in PROHIBITION_PATTERNS:
        m = re.search(pattern, lower)
        if m:
            start = max(0, m.start() - 60)
            end = min(len(policy_text), m.end() + 60)
            return "reject", f"Prohibition phrase found: \"...{policy_text[start:end].strip()}...\""

    for pattern in RATE_LIMIT_PATTERNS:
        m = re.search(pattern, lower)
        if m:
            try:
                rate = int(m.group(1))
            except (ValueError, IndexError):
                continue
            start = max(0, m.start() - 60)
            end = min(len(policy_text), m.end() + 60)
            snippet = f"\"...{policy_text[start:end].strip()}...\""
            if rate >= MIN_ACCEPTABLE_RATE_LIMIT:
                return "pass", f"Rate limit {rate} req/s found (>= {MIN_ACCEPTABLE_RATE_LIMIT}): {snippet}"
            else:
                return "review", f"Rate limit {rate} req/s found, BELOW your {MIN_ACCEPTABLE_RATE_LIMIT} req/s standard: {snippet}"

    return "review", "No explicit rate-limit number or scanning prohibition found in policy text — needs a human glance."


def vet_program(handle, token):
    print("=" * 70)
    print(f"Vetting: {handle}")
    print("=" * 70)

    try:
        status, policy = get_program_info(handle, token)
    except urllib.error.HTTPError as e:
        print(f"[ERROR] Could not fetch program info: HTTP {e.code}")
        return
    except Exception as e:
        print(f"[ERROR] Could not fetch program info: {e}")
        return

    is_open = status.lower() == "open"
    print(f"Program status: {status.upper()} {'(OK)' if is_open else '(SKIP - not open)'}")
    if not is_open:
        print("Verdict: AUTO-REJECT (program not open for submissions)\n")
        return

    try:
        scope = get_scannable_scope(handle, token)
    except Exception as e:
        print(f"[ERROR] Could not fetch scope: {e}")
        return

    print(f"Scannable in-scope assets found: {len(scope)}")
    for asset_type, identifier in scope:
        print(f"    [{asset_type}] {identifier}")

    if not scope:
        print("Verdict: NEEDS REVIEW (no URL/WILDCARD scannable assets found — check manually)\n")
        return

    policy_verdict, reason = check_policy_text(policy)
    print(f"\nPolicy check: {reason}")

    print()
    if policy_verdict == "pass":
        print("VERDICT: AUTO-PASS — ready to add to pipeline")
        print("\nSuggested domains.txt additions:")
        for _, identifier in scope:
            clean = identifier.lstrip("*.")
            print(f"    {clean}")
        print("\nSuggested scope.txt block:")
        print(f"# ─── {handle} ───")
        for asset_type, identifier in scope:
            print(f"IN:{identifier}")
    elif policy_verdict == "reject":
        print("VERDICT: AUTO-REJECT — do not add")
    else:
        print("VERDICT: NEEDS REVIEW — read the flagged snippet above before deciding")
    print()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 auto_vet_program.py <handle> [<handle2> ...]")
        sys.exit(1)

    try:
        token = get_token()
    except FileNotFoundError:
        print(f"ERROR: token not found at {TOKEN_PATH} and HACKERONE_TOKEN not set")
        sys.exit(1)

    for handle in sys.argv[1:]:
        vet_program(handle, token)


if __name__ == "__main__":
    main()
