#!/usr/bin/env python3
import csv, json, urllib.request, urllib.error, re, os, sys, base64

HOME = os.path.expanduser("~")
MAPPING_PATH = os.environ.get("MAPPING_CSV_PATH") or os.path.join(HOME, "bug-bounty-hunter", "domain_program_map.csv")
EXCLUDE_OUTPUT_PATH = os.environ.get("EXCLUDED_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "excluded_domains.txt")

def get_token(env_name, file_path):
    val = os.environ.get(env_name)
    if val:
        return val.strip()
    with open(file_path) as f:
        return f.read().strip()

def fetch_hackerone_programs(token):
    auth = base64.b64encode(f"oxidizer:{token}".encode()).decode()
    programs = []
    url = "https://api.hackerone.com/v1/hackers/programs?page[size]=100"
    while url:
        req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}", "Accept": "application/json"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        for p in data.get("data", []):
            a = p["attributes"]
            programs.append({"handle": a["handle"], "name": a["name"], "status": a["submission_state"]})
        url = data.get("links", {}).get("next")
    return programs

def fetch_hackerone_scope(handle, token):
    auth = base64.b64encode(f"oxidizer:{token}".encode()).decode()
    url = f"https://api.hackerone.com/v1/hackers/programs/{handle}"
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        return {"scope": [], "safe_harbor": None, "error": str(e)}

    scopes = data.get("relationships", {}).get("structured_scopes", {}).get("data", [])
    in_scope_domains = []
    for s in scopes:
        a = s.get("attributes", {})
        if a.get("asset_type") in ("URL", "WILDCARD") and a.get("eligible_for_submission") is True:
            in_scope_domains.append(a.get("asset_identifier"))

    safe_harbor = data.get("attributes", {}).get("gold_standard_safe_harbor")
    return {"scope": in_scope_domains, "safe_harbor": safe_harbor, "error": None}

def fetch_intigriti_programs(token):
    url = "https://api.intigriti.com/external/researcher/v1/programs?limit=500"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
    programs = []
    for p in data.get("records", []):
        programs.append({"handle": p["handle"], "name": p["name"], "status": p["status"]["value"], "id": p["id"]})
    return programs

import itertools

def extract_ywh_domains(scope_entries):
    domains = []
    skip_hosts = ("apps.apple.com", "play.google.com", "itunes.apple.com")
    for entry in scope_entries:
        s = entry.get("scope", "")
        if not s:
            continue
        # strip protocol
        s2 = re.sub(r'^https?://', '', s)
        # skip app store / play store links
        if any(h in s2 for h in skip_hosts):
            continue
        # skip pure prose (no dot, or starts with a capital word + space, no domain-like token)
        if not re.search(r'[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}', s2):
            continue
        # strip path/query after domain
        s2 = re.split(r'[/?]', s2)[0]
        # strip trailing junk like ") (see ...)" already handled by split below
        # find group syntax: prefix(a|b|c)suffix
        m = re.match(r'^([a-zA-Z0-9_\-\.\*]+)\(([a-zA-Z0-9\-\.\|]+)\)([a-zA-Z0-9_\-\.]*)$', s2)
        if m:
            prefix, group, suffix = m.groups()
            for opt in group.split('|'):
                domains.append(f"{prefix}{opt}{suffix}")
            continue
        # plain wildcard or domain (strip any leftover parens/junk)
        s3 = re.sub(r'[()"].*$', '', s2).strip()
        if re.match(r'^[a-zA-Z0-9\*][a-zA-Z0-9\-\.\*]*\.[a-zA-Z]{2,}$', s3):
            domains.append(s3)
    return sorted(set(domains))

def fetch_intigriti_scope(program_id, token):
    url = f"https://api.intigriti.com/external/researcher/v1/programs/{program_id}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        return {"scope": [], "safe_harbor": None, "rate_limit": None, "error": str(e)}

    domains = data.get("domains", {}).get("content", [])
    in_scope = []
    for d in domains:
        asset_type = d.get("type", {}).get("value", "")
        endpoint = d.get("endpoint")
        if asset_type in ("Wildcard", "Url") and endpoint:
            in_scope.append(endpoint)

    roe = data.get("rulesOfEngagement", {}).get("content", {})
    safe_harbor = roe.get("safeHarbour")
    rate_limit = roe.get("testingRequirements", {}).get("automatedTooling")

    return {"scope": in_scope, "safe_harbor": safe_harbor, "rate_limit": rate_limit, "error": None}

def find_match(programs, keyword):
    exact = [p for p in programs if p["handle"].lower() == keyword.lower()]
    if exact:
        return exact
    return [p for p in programs if keyword.lower() in p["name"].lower()]

def check_yeswehack(slug):
    url = f"https://api.yeswehack.com/programs/{slug}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        disabled = data.get("disabled", False)
        title = data.get("title", slug)
        return ("blocked" if disabled else "open", title)
    except urllib.error.HTTPError as e:
        return ("error", f"HTTP {e.code}")
    except Exception as e:
        return ("error", str(e))

def check_bugcrowd(slug):
    url = f"https://bugcrowd.com/engagements/{slug}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode()
        match = re.search(r"&quot;state&quot;:&quot;([^&]+)&quot;", html)
        if not match:
            match = re.search(r'"state":"([^"]+)"', html)
        if not match:
            return ("error", "state field not found")
        state = match.group(1)
        return ("open" if state == "in_progress" else "blocked", state)
    except urllib.error.HTTPError as e:
        return ("error", f"HTTP {e.code}")
    except Exception as e:
        return ("error", str(e))
def main():
    try:
        h1_token = get_token("HACKERONE_TOKEN", os.path.join(HOME, ".hackerone_token"))
        intigriti_token = get_token("INTIGRITI_TOKEN", os.path.join(HOME, ".intigriti_token"))
    except FileNotFoundError as e:
        print(f"ERROR: missing token (no env var set, no local file found) - {e}")
        sys.exit(1)

    print("Fetching HackerOne programs...")
    h1_programs = fetch_hackerone_programs(h1_token)
    print(f"  -> {len(h1_programs)} programs retrieved\n")

    print("Fetching Intigriti programs...")
    intigriti_programs = fetch_intigriti_programs(intigriti_token)
    print(f"  -> {len(intigriti_programs)} programs retrieved\n")

    rows = []
    with open(MAPPING_PATH) as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    groups = {}
    for row in rows:
        key = (row["platform"], row["keyword"])
        groups.setdefault(key, []).append(row["domain"])

    print(f"Checking {len(groups)} unique program groups across {len(rows)} domains...\n")
    print("=" * 70)

    excluded_domains = []
    no_match = []
    ambiguous = []
    hackerone_scope_lines = []
    intigriti_scope_lines = []
    yeswehack_scope_lines = []

    for (platform, keyword), domains in sorted(groups.items()):
        if platform == "yeswehack":
            status, detail = check_yeswehack(keyword)
            if status == "error":
                print(f"[ERROR]   {platform}/{keyword} -> {detail} ({len(domains)} domain(s))")
                no_match.append((platform, keyword, domains))
            else:
                tag = "OPEN  " if status == "open" else "BLOCKED"
                print(f"[{tag}]  {platform}/{keyword} -> {detail} ({len(domains)} domain(s))")
                if status == "blocked":
                    excluded_domains.extend(domains)
                elif status == "open":
                    ywh_url = f"https://api.yeswehack.com/programs/{keyword}"
                    ywh_req = urllib.request.Request(ywh_url, headers={"Accept": "application/json"})
                    try:
                        with urllib.request.urlopen(ywh_req, timeout=15) as resp:
                            ywh_data = json.loads(resp.read().decode())
                        ywh_domains = extract_ywh_domains(ywh_data.get("scopes", []))
                        for d in ywh_domains:
                            yeswehack_scope_lines.append(d)
                        print(f"    [SCOPE] {len(ywh_domains)} in-scope asset(s) found")
                    except Exception as e:
                        print(f"    [SCOPE ERROR] {e}")
            continue
        if platform == "bugcrowd":
            status, detail = check_bugcrowd(keyword)
            if status == "error":
                print(f"[ERROR]   {platform}/{keyword} -> {detail} ({len(domains)} domain(s))")
                no_match.append((platform, keyword, domains))
            else:
                tag = "OPEN  " if status == "open" else "BLOCKED"
                print(f"[{tag}]  {platform}/{keyword} -> state={detail} ({len(domains)} domain(s))")
                if status == "blocked":
                    excluded_domains.extend(domains)
            continue
        programs = h1_programs if platform == "hackerone" else intigriti_programs
        matches = find_match(programs, keyword)

        if len(matches) == 0:
            print(f"[NO MATCH]  {platform}/{keyword} -> 0 programs found for {len(domains)} domain(s)")
            no_match.append((platform, keyword, domains))
            continue

        if len(matches) > 1:
            names = [m["name"] for m in matches]
            print(f"[AMBIGUOUS] {platform}/{keyword} -> {len(matches)} programs matched: {names}")
            ambiguous.append((platform, keyword, matches, domains))
            continue

        m = matches[0]
        is_open = (m["status"].lower() == "open")
        tag = "OPEN  " if is_open else "BLOCKED"
        print(f"[{tag}]  {platform}/{keyword} -> '{m['name']}' (handle={m['handle']}) status={m['status']} ({len(domains)} domain(s))")
        if not is_open:
            excluded_domains.extend(domains)

        if platform == "hackerone" and is_open:
            scope_result = fetch_hackerone_scope(m["handle"], h1_token)
            if scope_result["error"]:
                print(f"    [SCOPE ERROR] {scope_result['error']}")
            else:
                for asset in scope_result["scope"]:
                    hackerone_scope_lines.append(asset)
                print(f"    [SCOPE] {len(scope_result['scope'])} in-scope asset(s) found")

        if platform == "intigriti" and is_open:
            scope_result = fetch_intigriti_scope(m["id"], intigriti_token)
            if scope_result["error"]:
                print(f"    [SCOPE ERROR] {scope_result['error']}")
            else:
                for asset in scope_result["scope"]:
                    intigriti_scope_lines.append(asset)
                print(f"    [SCOPE] {len(scope_result['scope'])} in-scope asset(s) found | safe_harbor={scope_result['safe_harbor']} | rate_limit={scope_result['rate_limit']}")

    print("=" * 70)
    print(f"\nSUMMARY: {len(excluded_domains)} domains would be EXCLUDED")
    for d in excluded_domains:
        print(f"    - {d}")
    print(f"\n  No API match found: {len(no_match)} groups")
    print(f"  Ambiguous matches: {len(ambiguous)} groups")

    with open(EXCLUDE_OUTPUT_PATH, "w") as f:
        for d in excluded_domains:
            f.write(d + "\n")
    print(f"\nWrote {len(excluded_domains)} domains to {EXCLUDE_OUTPUT_PATH}")

    hackerone_scope_lines = sorted(set(hackerone_scope_lines))
    scope_output_path = os.environ.get("HACKERONE_SCOPE_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "hackerone_scope.txt")
    with open(scope_output_path, "w") as f:
        for asset in hackerone_scope_lines:
            f.write(f"IN:{asset}\n")
    print(f"Wrote {len(hackerone_scope_lines)} HackerOne in-scope assets to {scope_output_path}")

    intigriti_scope_lines = sorted(set(intigriti_scope_lines))
    intigriti_scope_output_path = os.environ.get("INTIGRITI_SCOPE_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "intigriti_scope.txt")
    with open(intigriti_scope_output_path, "w") as f:
        for asset in intigriti_scope_lines:
            f.write(f"IN:{asset}\n")
    print(f"Wrote {len(intigriti_scope_lines)} Intigriti in-scope assets to {intigriti_scope_output_path}")

    yeswehack_scope_lines = sorted(set(yeswehack_scope_lines))
    yeswehack_scope_output_path = os.environ.get("YESWEHACK_SCOPE_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "yeswehack_scope.txt")
    with open(yeswehack_scope_output_path, "w") as f:
        for asset in yeswehack_scope_lines:
            f.write(f"IN:{asset}\n")
    print(f"Wrote {len(yeswehack_scope_lines)} YesWeHack in-scope assets to {yeswehack_scope_output_path}")

if __name__ == "__main__":
    main()

