#!/usr/bin/env python3
"""
discover_all_programs.py

Monthly full-discovery + auto-vetting across HackerOne, Intigriti, YesWeHack,
and Bugcrowd. Pulls every public program, applies safety/scope conditions,
and writes clean, scan-ready domain lists.
"""

import argparse
import base64
import csv
import json
import os
import shutil
from datetime import datetime
import re
import hashlib
import socket
import time
import urllib.error
import urllib.request
import tldextract

HOME = os.path.expanduser("~")
CEREBRAS_API_KEY = os.environ.get("CEREBRAS_API_KEY")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR") or os.path.join(HOME, "bug-bounty-hunter")
MAPPING_PATH = os.environ.get("MAPPING_CSV_PATH") or os.path.join(HOME, "bug-bounty-hunter", "domain_program_map.csv")

MIN_RATE_LIMIT = 5
DOMAINS_TXT_PATH = os.environ.get("DOMAINS_TXT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "domains.txt")

FETCH_EXCEPTIONS = (
    urllib.error.HTTPError,
    urllib.error.URLError,
    json.JSONDecodeError,
    KeyError,
    TypeError,
    socket.timeout,
)

AUTOMATION_BAN_PATTERNS = [
    r"do not use automat\w*",
    r"no automated (?:scan\w*|tool\w*|test)",
    r"not permitted to use automat\w*",
    r"prohibited from using automat\w*",
    r"automated tools? (?:is|are) not (?:allowed|permitted)",
    r"do not use scanners",
]

RATE_LIMIT_PATTERN = re.compile(
    r"(\d+)\s*(?:requests?|reqs?)\s*(?:per|/)\s*(?:second|sec|s\b)", re.I
)


def log(msg):
    print(msg, flush=True)


def fetch_json(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode()
        data = json.loads(body)
        return data, None
    except FETCH_EXCEPTIONS as e:
        code = getattr(e, "code", None)
        return None, f"{type(e).__name__}" + (f" {code}" if code else f": {e}")


def check_automation_ban(text):
    if not text:
        return False, None
    for pat in AUTOMATION_BAN_PATTERNS:
        m = re.search(pat, text, re.I)
        if m:
            start = max(0, m.start() - 100)
            end = min(len(text), m.end() + 100)
            return True, text[start:end].strip()
    return False, None


def check_rate_limit(text):
    if not text:
        return None
    m = RATE_LIMIT_PATTERN.search(text)
    if m:
        return int(m.group(1))
    return None


def clean_html(text):
    return re.sub(r"<[^<]+?>", " ", text or "")


def discover_hackerone(token):
    auth = base64.b64encode(f"oxidizer:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    programs = []
    url = "https://api.hackerone.com/v1/hackers/programs?page[size]=100"
    while url:
        data, err = fetch_json(url, headers)
        if err:
            log(f"[H1] pagination fetch failed: {err}")
            break
        for p in data.get("data", []):
            a = p["attributes"]
            programs.append({
                "handle": a.get("handle"),
                "name": a.get("name"),
                "submission_state": a.get("submission_state"),
                "offers_bounties": a.get("offers_bounties"),
            })
        url = data.get("links", {}).get("next")
        time.sleep(0.3)
    log(f"[H1] discovered {len(programs)} total programs")
    return programs, auth


def vet_hackerone_program(handle, auth, results):
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    data, err = fetch_json(f"https://api.hackerone.com/v1/hackers/programs/{handle}", headers)
    time.sleep(0.3)
    if err:
        results["skipped"].append((handle, err))
        return
    a = data.get("attributes", {})
    policy = a.get("policy", "") or ""
    if a.get("submission_state") != "open":
        results["excluded"].append((handle, "not open"))
        return
    banned, snippet = check_automation_ban_two_layer(policy, handle)
    if banned == "review":
        results["skipped"].append((handle, snippet))
        return
    if banned:
        results["excluded"].append((handle, f"automation ban: {snippet[:80]}"))
        return
    rate = check_rate_limit(policy)
    if rate is not None and rate < MIN_RATE_LIMIT:
        results["excluded"].append((handle, f"rate limit too strict: {rate}/s"))
        return
    domains = []
    for s in data.get("relationships", {}).get("structured_scopes", {}).get("data", []):
        sa = s.get("attributes", {})
        if sa.get("eligible_for_submission") and sa.get("asset_type") in ("URL", "WILDCARD"):
            domains.append(sa.get("asset_identifier"))
    results["included"].append({
        "handle": handle,
        "offers_bounties": a.get("offers_bounties"),
        "domains": domains,
    })


def discover_intigriti(token):
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data, err = fetch_json(
        "https://api.intigriti.com/external/researcher/v1/programs?limit=500", headers
    )
    if err:
        log(f"[Intigriti] discovery failed: {err}")
        return []
    items = data.get("records", [])
    log(f"[Intigriti] discovered {len(items)} total programs")
    return items


def vet_intigriti_program(program, token, results):
    pid = program["id"]
    name = program.get("name", pid)
    if program.get("confidentialityLevel", {}).get("value") == "Application":
        results["excluded"].append((name, "Application tier, no access"))
        return
    if program.get("status", {}).get("value") != "Open":
        results["excluded"].append((name, "not open"))
        return
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data, err = fetch_json(
        f"https://api.intigriti.com/external/researcher/v1/programs/{pid}", headers
    )
    if err:
        results["skipped"].append((name, err))
        return
    roe = data.get("rulesOfEngagement", {}).get("content", {})
    testing = roe.get("testingRequirements", {})
    rate = testing.get("automatedTooling")
    if rate is not None and rate < MIN_RATE_LIMIT:
        results["excluded"].append((name, f"rate limit too strict: {rate}/s"))
        return
    roe_text = json.dumps(roe)
    banned, snippet = check_automation_ban_two_layer(roe_text, name)
    if banned == "review":
        results["skipped"].append((name, snippet))
        return
    if banned:
        results["excluded"].append((name, f"automation ban: {snippet[:80]}"))
        return
    domains = []
    for d in data.get("domains", {}).get("content", []):
        endpoint = d.get("endpoint") or d.get("content")
        if endpoint:
            domains.append(endpoint)
    results["included"].append({
        "handle": pid,
        "safe_harbor": roe.get("safeHarbour"),
        "rate_limit": rate,
        "domains": domains,
    })


def extract_ywh_domains(scope_entries):
    domains = []
    skip_hosts = ("apps.apple.com", "play.google.com", "itunes.apple.com")
    for entry in scope_entries:
        s = entry.get("scope", "")
        if not s:
            continue
        s2 = re.sub(r"^https?://", "", s)
        if any(h in s2 for h in skip_hosts):
            continue
        if not re.search(r"[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}", s2):
            continue
        s2 = re.split(r"[/?]", s2)[0]
        m = re.match(r"^([a-zA-Z0-9_\-.*]+)\(([a-zA-Z0-9\-.|]+)\)([a-zA-Z0-9_\-.]*)$", s2)
        if m:
            prefix, group, suffix = m.groups()
            for opt in group.split("|"):
                domains.append(f"{prefix}{opt}{suffix}")
            continue
        s3 = re.sub(r'[()"].*$', "", s2).strip()
        if re.match(r"^[a-zA-Z0-9*][a-zA-Z0-9\-.*]*\.[a-zA-Z]{2,}$", s3):
            domains.append(s3)
    return sorted(set(domains))


def discover_yeswehack():
    programs = []
    page = 1
    nb_pages = 1
    while page <= nb_pages:
        data, err = fetch_json(
            f"https://api.yeswehack.com/programs?page={page}",
            {"Accept": "application/json"},
        )
        if err:
            log(f"[YWH] page {page} fetch failed: {err}")
            page += 1
            continue
        programs.extend(data.get("items", []))
        nb_pages = data.get("pagination", {}).get("nb_pages", nb_pages)
        page += 1
        time.sleep(0.3)
    log(f"[YWH] discovered {len(programs)} total programs")
    return programs


def vet_yeswehack_program(program, results):
    slug = program["slug"]
    data, err = fetch_json(
        f"https://api.yeswehack.com/programs/{slug}",
        {"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
    )
    time.sleep(0.3)
    if err:
        results["skipped"].append((slug, err))
        return
    if data.get("disabled", False):
        results["excluded"].append((slug, "disabled"))
        return
    rules = data.get("rules", "") or ""
    banned, snippet = check_automation_ban_two_layer(rules, slug)
    if banned == "review":
        results["skipped"].append((slug, snippet))
        return
    if banned:
        results["excluded"].append((slug, f"automation ban: {snippet[:80]}"))
        return
    rate = check_rate_limit(rules)
    if rate is not None and rate < MIN_RATE_LIMIT:
        results["excluded"].append((slug, f"rate limit too strict: {rate}/s"))
        return
    domains = extract_ywh_domains(data.get("scopes", []))
    results["included"].append({
        "slug": slug,
        "bounty": program.get("bounty"),
        "safe_harbor": bool(re.search(r"safe.?harbor", rules, re.I)) and not re.search(
            r"no\s+safe.?harbor|safe.?harbor\s+is\s+not|not\s+provid\w*\s+.{0,20}safe.?harbor|without\s+safe.?harbor",
            rules, re.I),
        "domains": domains,
    })


def discover_bugcrowd():
    programs = []
    for page in range(1, 11):
        data, err = fetch_json(
            f"https://bugcrowd.com/engagements?category=bug_bounty&page={page}",
            {"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        if err:
            log(f"[Bugcrowd] page {page} fetch failed: {err}")
            continue
        programs.extend(data.get("engagements", []))
        time.sleep(0.3)
    log(f"[Bugcrowd] discovered {len(programs)} total programs")
    return programs


def vet_bugcrowd_program(program, results):
    slug = program["briefUrl"].rstrip("/").split("/")[-1]
    cl_data, err = fetch_json(
        f"https://bugcrowd.com/engagements/{slug}/changelog.json",
        {"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
    )
    if err:
        results["skipped"].append((slug, err))
        return
    changelogs = cl_data.get("changelogs", [])
    if not changelogs:
        results["skipped"].append((slug, "no changelog entries"))
        return
    latest = next((c for c in changelogs if c.get("changelogState") == "Latest"), changelogs[0])
    full, err2 = fetch_json(
        f"https://bugcrowd.com/engagements/{slug}/changelog/{latest['id']}.json",
        {"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
    )
    if err2:
        results["skipped"].append((slug, err2))
        return
    state = full.get("data", {}).get("engagement", {}).get("state")
    if state != "in_progress":
        results["excluded"].append((slug, f"state={state}"))
        return
    brief = full.get("data", {}).get("brief", {})
    desc = clean_html(brief.get("description", ""))
    overview = clean_html(brief.get("targetsOverview", ""))
    text = desc + overview
    banned, snippet = check_automation_ban_two_layer(text, slug)
    if banned == "review":
        results["skipped"].append((slug, snippet))
        return
    if banned:
        results["excluded"].append((slug, f"automation ban: {snippet[:80]}"))
        return
    rate = check_rate_limit(text)
    if rate is not None and rate < MIN_RATE_LIMIT:
        results["excluded"].append((slug, f"rate limit too strict: {rate}/s"))
        return
    domains = []
    for grp in full.get("data", {}).get("scope", []):
        if not grp.get("inScope"):
            continue
        for t in grp.get("targets", []):
            uri = t.get("uri")
            name = t.get("name", "") or ""
            if uri:
                domains.append(re.sub(r"^https?://", "", uri).split("/")[0])
            elif re.match(r"^[a-zA-Z0-9*][a-zA-Z0-9\-.*]*\.[a-zA-Z]{2,}$", name.strip()):
                domains.append(name.strip())
    results["included"].append({
        "slug": slug,
        "safe_harbor": (brief.get("safeHarborStatus") or {}).get("status"),
        "domains": sorted(set(domains)),
    })


def new_results():
    return {"included": [], "excluded": [], "skipped": []}


def merge_scope_file(path, entries_by_program, max_removal_pct=20):
    new_domains = set()
    for p in entries_by_program:
        new_domains.update(p.get("domains", []))
    old_domains = set()
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("IN:"):
                    old_domains.add(line[3:])
    added = new_domains - old_domains
    removed = old_domains - new_domains
    removal_pct = (len(removed) / len(old_domains) * 100) if old_domains else 0
    if removal_pct > max_removal_pct:
        log(f"  [GUARD] {path}: would remove {len(removed)}/{len(old_domains)} "
            f"({removal_pct:.1f}%) - exceeds {max_removal_pct}% threshold. "
            f"NOT applying. Old scope file left untouched.")
        log(f"  [GUARD] Would-be added: {len(added)}, would-be removed: {len(removed)}")
        return {"applied": False, "added": len(added), "removed": len(removed), "total": len(old_domains)}
    if os.path.exists(path):
        backup_path = f"{path}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(path, backup_path)
        log(f"  [BACKUP] {path} -> {backup_path}")
    with open(path, "w") as f:
        for d in sorted(new_domains):
            f.write(f"IN:{d}\n")
    if added or removed:
        diff_path = path.replace(".txt", "_diff.log")
        with open(diff_path, "a") as f:
            f.write(f"\n=== {datetime.now().isoformat()} ===\n")
            for d in sorted(added):
                f.write(f"+ {d}\n")
            for d in sorted(removed):
                f.write(f"- {d}\n")
        log(f"  [DIFF] logged to {diff_path}")
    log(f"  [APPLIED] {path}: {len(new_domains)} total ({len(added)} added, {len(removed)} removed)")
    return {"applied": True, "added": len(added), "removed": len(removed), "total": len(new_domains)}
def write_scope_file(path, entries_by_program):
    all_domains = set()
    for p in entries_by_program:
        all_domains.update(p.get("domains", []))
    with open(path, "w") as f:
        for d in sorted(all_domains):
            f.write(f"IN:{d}\n")
    return len(all_domains)


def summarize(platform, results):
    log(f"\n=== {platform} summary ===")
    log(f"  included: {len(results['included'])}")
    log(f"  excluded (failed a condition): {len(results['excluded'])}")
    log(f"  skipped (fetch/parse error): {len(results['skipped'])}")
    if results["excluded"]:
        log("  exclusion reasons (first 10):")
        for name, reason in results["excluded"][:10]:
            log(f"    - {name}: {reason}")
    if results["skipped"]:
        log("  skip reasons (first 10):")
        for name, reason in results["skipped"][:10]:
            log(f"    - {name}: {reason}")


def update_domain_program_map(h1_results, int_results, ywh_results, bc_results, ran_platforms):
    """Rebuild domain_program_map.csv rows for every platform that actually ran this
    invocation (dropping stale/removed programs for those platforms), while leaving
    rows for skipped platforms (e.g. a manual --platform test run, or no token set)
    completely untouched."""
    existing_rows = []
    if os.path.exists(MAPPING_PATH):
        with open(MAPPING_PATH, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_rows.append((row["domain"], row["platform"], row["keyword"]))

    kept_rows = [row for row in existing_rows if row[1] not in ran_platforms]

    fresh_rows = []
    seen = set()
    platform_sources = [
        ("hackerone", h1_results, "handle"),
        ("intigriti", int_results, "handle"),
        ("yeswehack", ywh_results, "slug"),
        ("bugcrowd", bc_results, "slug"),
    ]
    for platform_name, results, key_field in platform_sources:
        if platform_name not in ran_platforms:
            continue
        for entry in results.get("included", []):
            keyword = entry.get(key_field)
            if not keyword:
                continue
            for domain in entry.get("domains", []):
                row = (domain, platform_name, keyword)
                if row not in seen:
                    fresh_rows.append(row)
                    seen.add(row)

    all_rows = kept_rows + fresh_rows

    with open(MAPPING_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "platform", "keyword"])
        for row in all_rows:
            writer.writerow(row)
    log(f"[CSV] domain_program_map.csv: rebuilt {len(fresh_rows)} rows for "
        f"{sorted(ran_platforms)}, kept {len(kept_rows)} rows untouched for skipped platforms")

def extract_root_domain(asset):
    """Extract the registrable root domain from a scope asset (URL, wildcard,
    or bare host). Returns None if it can't be parsed as a domain."""
    asset = asset.strip()
    if not asset:
        return None
    asset = asset.lstrip("*.").replace("https://", "").replace("http://", "")
    asset = asset.split("/")[0].split(":")[0]
    ext = tldextract.extract(asset)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def update_domains_txt(h1_results, int_results, ywh_results, bc_results, ran_platforms):
    """Collect root domains from all newly-included programs (across platforms
    that actually ran) and append any genuinely new ones to domains.txt.
    Never removes existing entries - additive only."""
    platform_sources = [
        ("hackerone", h1_results),
        ("intigriti", int_results),
        ("yeswehack", ywh_results),
        ("bugcrowd", bc_results),
    ]
    discovered_roots = set()
    for platform_name, results in platform_sources:
        if platform_name not in ran_platforms:
            continue
        for entry in results.get("included", []):
            for asset in entry.get("domains", []):
                root = extract_root_domain(asset)
                if root:
                    discovered_roots.add(root)

    existing = set()
    if os.path.exists(DOMAINS_TXT_PATH):
        with open(DOMAINS_TXT_PATH) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    existing.add(line)

    new_roots = sorted(discovered_roots - existing)
    if not new_roots:
        log("[DOMAINS.TXT] No new root domains discovered this run")
        return []

    with open(DOMAINS_TXT_PATH, "a") as f:
        for d in new_roots:
            f.write(f"{d}\n")
    log(f"[DOMAINS.TXT] Added {len(new_roots)} new root domain(s): {new_roots[:10]}"
        f"{'...' if len(new_roots) > 10 else ''}")
    return new_roots


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=["hackerone", "intigriti", "yeswehack", "bugcrowd"], default=None,
                         help="Run only one platform instead of all four")
    args = parser.parse_args()
    h1_token = os.environ.get("HACKERONE_TOKEN")
    int_token = os.environ.get("INTIGRITI_TOKEN")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    ran_platforms = set()
    h1_results = new_results()
    if args.platform in (None, "hackerone") and h1_token:
        ran_platforms.add("hackerone")
        programs, auth = discover_hackerone(h1_token)
        for p in programs:
            vet_hackerone_program(p["handle"], auth, h1_results)
        summarize("HackerOne", h1_results)
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "hackerone_scope.txt"), h1_results["included"])
        log(f"[H1] merge result: {r}")
    else:
        if args.platform not in (None, "hackerone"):
            log("[H1] skipped due to --platform filter")
        else:
            log("[H1] no HACKERONE_TOKEN set, skipping platform")

    int_results = new_results()
    if args.platform in (None, "intigriti") and int_token:
        ran_platforms.add("intigriti")
        programs = discover_intigriti(int_token)
        for p in programs:
            vet_intigriti_program(p, int_token, int_results)
        summarize("Intigriti", int_results)
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "intigriti_scope.txt"), int_results["included"])
        log(f"[Intigriti] merge result: {r}")
    else:
        if args.platform not in (None, "intigriti"):
            log("[Intigriti] skipped due to --platform filter")
        else:
            log("[Intigriti] no INTIGRITI_TOKEN set, skipping platform")

    ywh_results = new_results()
    if args.platform in (None, "yeswehack"):
        ran_platforms.add("yeswehack")
        programs = discover_yeswehack()
        for p in programs:
            vet_yeswehack_program(p, ywh_results)
        summarize("YesWeHack", ywh_results)
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "yeswehack_scope.txt"), ywh_results["included"])
        log(f"[YWH] merge result: {r}")

    bc_results = new_results()
    if args.platform in (None, "bugcrowd"):
        ran_platforms.add("bugcrowd")
        programs = discover_bugcrowd()
        for p in programs:
            vet_bugcrowd_program(p, bc_results)
        summarize("Bugcrowd", bc_results)
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "bugcrowd_scope.txt"), bc_results["included"])
        log(f"[Bugcrowd] merge result: {r}")
    update_domain_program_map(h1_results, int_results, ywh_results, bc_results, ran_platforms)
    update_domains_txt(h1_results, int_results, ywh_results, bc_results, ran_platforms)

    save_cerebras_cache(_CEREBRAS_CACHE)
    log(f"[CEREBRAS CACHE] saved {len(_CEREBRAS_CACHE)} cached decisions to {CEREBRAS_CACHE_PATH}")

    log("\n=== All platforms complete ===")

# ==========================================================================
# Cerebras second-layer automation-ban detection
# ==========================================================================

CEREBRAS_URL = "https://api.cerebras.ai/v1/chat/completions"
CEREBRAS_LOG_PATH = os.path.join(OUTPUT_DIR, "cerebras_review_log.txt")
CEREBRAS_CACHE_PATH = os.path.join(OUTPUT_DIR, "cerebras_ban_cache.json")

def load_cerebras_cache():
    if os.path.exists(CEREBRAS_CACHE_PATH):
        try:
            with open(CEREBRAS_CACHE_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}

def save_cerebras_cache(cache):
    with open(CEREBRAS_CACHE_PATH, "w") as f:
        json.dump(cache, f, indent=2, sort_keys=True)

_CEREBRAS_CACHE = load_cerebras_cache()

AMBIGUOUS_SIGNAL_PATTERN = re.compile(
    r"automat\w*|scanner\w*|\bbot\b|\bscript\w*|fuzz\w*", re.I
)
def check_automation_ban_two_layer(text, program_name):
    banned, snippet = check_automation_ban(text)
    if not banned and text and AMBIGUOUS_SIGNAL_PATTERN.search(text):
        m = AMBIGUOUS_SIGNAL_PATTERN.search(text)
        start = max(0, m.start() - 150)
        end = min(len(text), m.end() + 150)
        snippet = text[start:end].strip()
        banned = True
    if not banned:
        return False, None
    result = cerebras_check_ban(snippet, program_name)
    if result is None:
        return "review", f"[Cerebras call failed — needs manual review] {snippet[:80]}"
    if result:
        return True, f"[Cerebras-confirmed ban] {snippet[:80]}"
    return False, None

if __name__ == "__main__":
    main()
