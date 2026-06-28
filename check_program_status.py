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

def fetch_intigriti_programs(token):
    url = "https://api.intigriti.com/external/researcher/v1/programs?limit=500"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
    programs = []
    for p in data.get("records", []):
        programs.append({"handle": p["handle"], "name": p["name"], "status": p["status"]["value"]})
    return programs

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

if __name__ == "__main__":
    main()

