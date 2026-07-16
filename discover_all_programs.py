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
from datetime import datetime, timezone
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
EXCLUDED_OUTPUT_PATH = os.environ.get("EXCLUDED_OUTPUT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "excluded_domains.txt")

MIN_RATE_LIMIT = 5
DOMAINS_TXT_PATH = os.environ.get("DOMAINS_TXT_PATH") or os.path.join(HOME, "bug-bounty-hunter", "domains.txt")
CANDIDATE_DOMAINS_REVIEW_CAP = int(os.environ.get("CANDIDATE_DOMAINS_REVIEW_CAP") or 100)

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

ID_VERIFICATION_PATTERNS = [
    r"government[- ]issued id",
    r"proof of identity",
    r"\bkyc\b",
    r"know your customer",
    r"identity verification",
    r"verify your identity",
    r"upload (?:a )?(?:copy of )?(?:your )?(?:passport|id\b|national id|driver)",
    r"background check",
    r"social security number",
    r"\bssn\b",
]
ID_VERIFICATION_PATTERN = re.compile("|".join(ID_VERIFICATION_PATTERNS), re.I)


def log(msg):
    print(msg, flush=True)


def fetch_json(url, headers=None, timeout=15, max_retries=5):
    req = urllib.request.Request(url, headers=headers or {})
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode()
            data = json.loads(body)
            return data, None
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt < max_retries - 1:
                retry_after = e.headers.get("Retry-After") if e.headers else None
                wait = float(retry_after) if retry_after else (2 ** attempt)
                log(f"[RATE LIMIT] {url} -> {e.code}, retrying in {wait}s (attempt {attempt+1}/{max_retries})")
                time.sleep(wait)
                continue
            return None, f"HTTPError {e.code}"
        except FETCH_EXCEPTIONS as e:
            code = getattr(e, "code", None)
            return None, f"{type(e).__name__}" + (f" {code}" if code else f": {e}")
    return None, "HTTPError max_retries_exceeded"


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


def check_id_verification_required(text):
    if not text:
        return False, None
    m = ID_VERIFICATION_PATTERN.search(text)
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
        skipped_private = 0
        for p in data.get("data", []):
            a = p["attributes"]
            if a.get("state") != "public_mode":
                skipped_private += 1
                continue
            programs.append({
                "handle": a.get("handle"),
                "name": a.get("name"),
                "submission_state": a.get("submission_state"),
                "offers_bounties": a.get("offers_bounties"),
            })
        if skipped_private:
            log(f"[H1] skipped {skipped_private} non-public (private/invite-only) programs this page")
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
    if a.get("offers_bounties") is not True:
        results["excluded"].append((handle, "not BBP (VDP or other)"))
        return
    banned, snippet = check_automation_ban_two_layer(policy, handle)
    if banned == "review":
        results["skipped"].append((handle, snippet))
        return
    if banned:
        results["excluded"].append((handle, f"automation ban: {snippet[:80]}"))
        return
    id_req, id_snippet = check_id_verification_required(policy)
    if id_req:
        results["excluded"].append((handle, f"requires ID verification: {id_snippet[:80]}"))
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
    if program.get("type", {}).get("value") != "Bug Bounty":
        results["excluded"].append((name, "not BBP (VDP or other)"))
        return
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data, err = fetch_json(
        f"https://api.intigriti.com/external/researcher/v1/programs/{pid}", headers, max_retries=1
    )
    time.sleep(0.3)
    if err:
        if "403" in err:
            results["excluded"].append((name, "private/invite-gated program, no API access"))
        else:
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
    id_req, id_snippet = check_id_verification_required(roe_text)
    if id_req:
        results["excluded"].append((name, f"requires ID verification: {id_snippet[:80]}"))
        return
    domains = []
    for d in data.get("domains", {}).get("content", []):
        asset_type = d.get("type", {}).get("value")
        tier = d.get("tier", {}).get("value")
        if asset_type not in ("Url", "Wildcard"):
            continue
        if tier == "No Bounty":
            continue
        endpoint = d.get("endpoint") or d.get("content")
        if endpoint:
            domains.append(endpoint.strip())
    results["included"].append({
        "handle": pid,
        "safe_harbor": roe.get("safeHarbour"),
        "rate_limit": rate,
        "domains": domains,
    })


def extract_ywh_domains(scope_entries, slug="unknown"):
    domains = []
    unmatched = []
    skip_types = ("mobile-application", "mobile-application-android", "mobile-application-ios")
    skip_hosts = ("apps.apple.com", "play.google.com", "itunes.apple.com")
    for entry in scope_entries:
        if entry.get("scope_type") in skip_types:
            continue
        s = entry.get("scope", "")
        if not s:
            continue
        s2 = re.sub(r"^https?://", "", s)
        if any(h in s2 for h in skip_hosts):
            continue
        if not re.search(r"[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}", s2):
            unmatched.append(s)
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
        else:
            unmatched.append(s)
    if unmatched:
        with open("yeswehack_unmatched.log", "a") as f:
            for u in unmatched:
                f.write(f"{slug}\t{u}\n")
    return sorted(set(domains))


def discover_yeswehack():
    programs = []
    page = 1
    nb_pages = 1
    while page <= nb_pages:
        data, err = fetch_json(
            f"https://api.yeswehack.com/programs?page={page}",
            {"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
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
    if program.get("bounty") is not True:
        results["excluded"].append((slug, "not BBP (VDP or other)"))
        return
    rules = data.get("rules", "") or ""
    banned, snippet = check_automation_ban_two_layer(rules, slug)
    if banned == "review":
        results["skipped"].append((slug, snippet))
        return
    if banned:
        results["excluded"].append((slug, f"automation ban: {snippet[:80]}"))
        return
    id_req, id_snippet = check_id_verification_required(rules)
    if id_req:
        results["excluded"].append((slug, f"requires ID verification: {id_snippet[:80]}"))
        return
    rate = check_rate_limit(rules)
    if rate is not None and rate < MIN_RATE_LIMIT:
        results["excluded"].append((slug, f"rate limit too strict: {rate}/s"))
        return
    domains = extract_ywh_domains(data.get("scopes", []), slug)
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
    time.sleep(0.3)
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
    time.sleep(0.3)
    if err2:
        results["skipped"].append((slug, err2))
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
    id_req, id_snippet = check_id_verification_required(text)
    if id_req:
        results["excluded"].append((slug, f"requires ID verification: {id_snippet[:80]}"))
        return
    rate = check_rate_limit(text)
    if rate is not None and rate < MIN_RATE_LIMIT:
        results["excluded"].append((slug, f"rate limit too strict: {rate}/s"))
        return
    skip_categories = ("android", "ios", "ip_address", "network")
    domains = []
    for grp in full.get("data", {}).get("scope", []):
        if not grp.get("inScope"):
            continue
        for t in grp.get("targets", []):
            if t.get("category") in skip_categories:
                continue
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
    force_apply = os.environ.get("SCOPE_GUARD_OVERRIDE") == "true"
    if removal_pct > max_removal_pct and not force_apply:
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


def summarize(platform, results, total_discovered):
    log(f"\n=== {platform} summary ===")
    log(f"  total discovered from platform: {total_discovered}")
    log(f"  included: {len(results['included'])}")
    log(f"  excluded (failed a condition): {len(results['excluded'])}")
    log(f"  skipped (fetch/parse error): {len(results['skipped'])}")

    excluded_path = f"{platform.lower()}_excluded_full.txt"
    skipped_path = f"{platform.lower()}_skipped_full.txt"
    with open(excluded_path, "w") as ef:
        for name, reason in results["excluded"]:
            ef.write(f"{name}\t{reason}\n")
    with open(skipped_path, "w") as sf:
        for name, reason in results["skipped"]:
            sf.write(f"{name}\t{reason}\n")
    n_excluded = len(results["excluded"])
    n_skipped = len(results["skipped"])
    log(f"  [FULL LIST] excluded -> {excluded_path} ({n_excluded} rows)")
    log(f"  [FULL LIST] skipped -> {skipped_path} ({n_skipped} rows)")

    if results["excluded"]:
        log("  exclusion reasons (first 10):")
        for name, reason in results["excluded"][:10]:
            log(f"    - {name}: {reason}")
    if results["skipped"]:
        log("  skip reasons (first 10):")
        for name, reason in results["skipped"][:10]:
            log(f"    - {name}: {reason}")

    stats_path = os.path.join(OUTPUT_DIR, "discovery_stats.csv")
    is_new = not os.path.exists(stats_path)
    with open(stats_path, "a", newline="") as sf:
        w = csv.writer(sf)
        if is_new:
            w.writerow(["timestamp_utc", "platform", "total_discovered", "included", "excluded", "skipped"])
        w.writerow([
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            platform,
            total_discovered,
            len(results["included"]),
            n_excluded,
            n_skipped,
        ])
    log(f"  [STATS] appended to {stats_path}")


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

    write_excluded_domains_file(EXCLUDED_OUTPUT_PATH, existing_rows, platform_sources, ran_platforms)

def write_excluded_domains_file(path, existing_rows, platform_sources, ran_platforms):
    """Write every domain whose program was excluded/skipped this run
    (for platforms that actually ran) to a persisted file, so downstream
    workflows (recon/scan) can trust this instead of re-vetting."""
    included_keywords = {}
    for platform_name, results, key_field in platform_sources:
        if platform_name not in ran_platforms:
            continue
        included_keywords[platform_name] = {
            entry.get(key_field) for entry in results.get("included", []) if entry.get(key_field)
        }

    excluded_domains = set()
    for domain, platform, keyword in existing_rows:
        if platform not in ran_platforms:
            continue
        if keyword not in included_keywords.get(platform, set()):
            excluded_domains.add(domain)

    with open(path, "w") as f:
        for d in sorted(excluded_domains):
            f.write(f"{d}\n")
    log(f"[EXCLUDED] {path}: {len(excluded_domains)} domain(s) excluded this run "
        f"(closed/banned/rate-limited programs)")
    return len(excluded_domains)


def extract_root_domain(asset):
    """Extract the registrable root domain from a scope asset (URL, wildcard,
    or bare host). Returns None if it can't be parsed as a domain."""
    asset = asset.strip()
    if not asset:
        return None
    asset = asset.lstrip("*.").replace("https://", "").replace("http://", "")
    asset = asset.split("/")[0].split(":")[0].lower()
    if "*" in asset:
        print(f"[SKIP] malformed asset (embedded wildcard, not parseable): {asset!r}")
        return None
    if "[" in asset or "]" in asset:
        print(f"[SKIP] malformed asset (bracket/optional-group notation, not parseable): {asset!r}")
        return None
    ext = tldextract.extract(asset)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def rebuild_domains_txt(scope_paths, max_removal_pct=20):
    """Fresh rebuild: domains.txt = root domains derived from the union of the
    4 committed scope files (already individually guarded). Never built from a
    single run's ran_platforms results, so a manual --platform run can't wipe
    out the other platforms' domains. Same 20% removal guard + backup as
    merge_scope_file."""
    new_roots = set()
    for path in scope_paths:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("IN:"):
                    root = extract_root_domain(line[3:])
                    if root:
                        new_roots.add(root)

    old_roots = set()
    if os.path.exists(DOMAINS_TXT_PATH):
        with open(DOMAINS_TXT_PATH) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    old_roots.add(line)

    added = new_roots - old_roots
    removed = old_roots - new_roots
    removal_pct = (len(removed) / len(old_roots) * 100) if old_roots else 0
    force_apply = os.environ.get("SCOPE_GUARD_OVERRIDE") == "true"
    if removal_pct > max_removal_pct and not force_apply:
        log(f"[GUARD] {DOMAINS_TXT_PATH}: would remove {len(removed)}/{len(old_roots)} "
            f"({removal_pct:.1f}%) - exceeds {max_removal_pct}% threshold. "
            f"NOT applying. Old domains.txt left untouched.")
        log(f"[GUARD] Would-be added: {len(added)}, would-be removed: {len(removed)}")
        return {"applied": False, "added": len(added), "removed": len(removed), "total": len(old_roots)}

    if os.path.exists(DOMAINS_TXT_PATH):
        backup_path = f"{DOMAINS_TXT_PATH}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(DOMAINS_TXT_PATH, backup_path)
        log(f"[BACKUP] {DOMAINS_TXT_PATH} -> {backup_path}")

    with open(DOMAINS_TXT_PATH, "w") as f:
        for d in sorted(new_roots):
            f.write(f"{d}\n")

    if added or removed:
        diff_path = DOMAINS_TXT_PATH.replace(".txt", "_diff.log")
        with open(diff_path, "a") as f:
            f.write(f"\n=== {datetime.now().isoformat()} ===\n")
            for d in sorted(added):
                f.write(f"+ {d}\n")
            for d in sorted(removed):
                f.write(f"- {d}\n")
        log(f"[DIFF] logged to {diff_path}")

    log(f"[APPLIED] {DOMAINS_TXT_PATH}: {len(new_roots)} total ({len(added)} added, {len(removed)} removed)")
    return {"applied": True, "added": len(added), "removed": len(removed), "total": len(new_roots)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=["hackerone", "intigriti", "yeswehack", "bugcrowd"], default=None,
                         help="Run only one platform instead of all four")
    args = parser.parse_args()
    h1_token = os.environ.get("HACKERONE_TOKEN")
    int_token = os.environ.get("INTIGRITI_TOKEN")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    ran_platforms = set()
    applied_platforms = set()
    h1_results = new_results()
    if args.platform in (None, "hackerone") and h1_token:
        ran_platforms.add("hackerone")
        programs, auth = discover_hackerone(h1_token)
        for p in programs:
            vet_hackerone_program(p["handle"], auth, h1_results)
        summarize("HackerOne", h1_results, len(programs))
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "hackerone_scope.txt"), h1_results["included"])
        log(f"[H1] merge result: {r}")
        if r["applied"]:
            applied_platforms.add("hackerone")
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
        summarize("Intigriti", int_results, len(programs))
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "intigriti_scope.txt"), int_results["included"])
        log(f"[Intigriti] merge result: {r}")
        if r["applied"]:
            applied_platforms.add("intigriti")
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
        summarize("YesWeHack", ywh_results, len(programs))
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "yeswehack_scope.txt"), ywh_results["included"])
        log(f"[YWH] merge result: {r}")
        if r["applied"]:
            applied_platforms.add("yeswehack")

    bc_results = new_results()
    if args.platform in (None, "bugcrowd"):
        ran_platforms.add("bugcrowd")
        programs = discover_bugcrowd()
        for p in programs:
            vet_bugcrowd_program(p, bc_results)
        summarize("Bugcrowd", bc_results, len(programs))
        r = merge_scope_file(os.path.join(OUTPUT_DIR, "bugcrowd_scope.txt"), bc_results["included"])
        log(f"[Bugcrowd] merge result: {r}")
        if r["applied"]:
            applied_platforms.add("bugcrowd")
    update_domain_program_map(h1_results, int_results, ywh_results, bc_results, applied_platforms)
    scope_paths = [os.path.join(OUTPUT_DIR, f"{p}_scope.txt")
                   for p in ("hackerone", "intigriti", "yeswehack", "bugcrowd")]
    r = rebuild_domains_txt(scope_paths)
    log(f"[domains.txt] rebuild result: {r}")

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
def cerebras_check_ban(snippet, program_name):
    cache_key = hashlib.sha256(snippet.encode()).hexdigest()
    if cache_key in _CEREBRAS_CACHE:
        cached = _CEREBRAS_CACHE[cache_key]
        log_cerebras_call(program_name, snippet, cached["is_ban"], cached["reason"] + " [CACHED]", error=None)
        return cached["is_ban"]
    if not CEREBRAS_API_KEY:
        return None
    prompt = (
        "You are reviewing a single snippet from a bug bounty program's "
        "policy text. Answer ONLY with valid JSON, no other text, in this "
        'exact format: {"is_ban": true or false, "reason": "one short sentence"}.\n\n'
        "Question: Does this snippet ban the ACT of using automated "
        "scanners/tools against their systems?\n\n"
        "THE KEY TEST - identify the subject of the restriction:\n"
        "- If the subject is YOU / THE TESTER / THE ACTION ('do not use', "
        "'avoid scanning', 'don't automate testing', 'no automated attacks "
        "against our systems') -> this restricts the ACT of scanning -> true.\n"
        "- If the subject is the REPORT / SUBMISSION / RESULT / OUTPUT "
        "('reports will be rejected', 'submissions from automated tools "
        "won't be accepted', 'results without manual confirmation', "
        "'do not submit unverified output', 'scanner-generated reports', "
        "'must be validated manually before submission') -> this restricts "
        "what you may SUBMIT, not what tools you may run -> false. These "
        "are report-quality/triage rules, not scanning bans, even when the "
        "word 'automated' or the phrase 'manually' appears.\n\n"
        "A simple check: could you legally run the scanner and just "
        "manually verify/write up the finding yourself before submitting? "
        "If yes, the snippet is NOT a ban (false) - it only gates what "
        "gets submitted, not what tooling is allowed.\n\n"
        "Examples:\n"
        "BAN (true): 'Do not use automated scanners against our applications.'\n"
        "BAN (true): 'Don't brute-force or automate testing, challenges are "
        "made for manual solving.'\n"
        "BAN (true): 'Avoid automated scanning, DAST, fuzzing.'\n"
        "NOT A BAN (false): 'Reports generated purely by automated tools "
        "without manual verification will be closed.'\n"
        "NOT A BAN (false): 'Reports from automated tools or scans without "
        "a working Proof of Concept.'\n"
        "NOT A BAN (false): 'All reports must be validated manually, "
        "submission from automated tools wont be accepted.' (the ban targets "
        "the submission, not the act of scanning)\n"
        "NOT A BAN (false): 'Any report generated by automatic tool without "
        "a POC.' (short form of a submission/report-quality rule, not a "
        "tool-use ban)\n\n"
        "Also answer false if the mention of automation is in an unrelated "
        "context (e.g. CSRF, DoS-only sub-policies, or automated account "
        "creation) rather than about testing/scanning tools.\n\n"
        f"Snippet:\n{snippet}"
    )
    body = json.dumps({
        "model": "gpt-oss-120b",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 700,
    }).encode()
    req = urllib.request.Request(
        CEREBRAS_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {CEREBRAS_API_KEY}",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Python-urllib-client",
        },
        method="POST",
    )
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            finish_reason = data["choices"][0].get("finish_reason")
            if finish_reason and finish_reason != "stop":
                with open(os.path.join(OUTPUT_DIR, "cerebras_parse_fail_debug.log"), "a") as pf:
                    pf.write(f"--- {program_name} ---\n")
                    pf.write(f"finish_reason: {finish_reason}\n")
                    pf.write(f"RAW: {json.dumps(data)}\n\n")
            text = data["choices"][0]["message"]["content"].strip()
            text = text.strip("`")
            if text.startswith("json"):
                text = text[4:].strip()
            m = re.search(r'"is_ban"\s*:\s*(true|false)', text, re.IGNORECASE)
            if not m:
                with open(os.path.join(OUTPUT_DIR, "cerebras_parse_fail_debug.log"), "a") as pf:
                    pf.write(f"--- {program_name} ---\n")
                    pf.write(f"FULL RESPONSE: {text!r}\n\n")
                raise ValueError(f"could not find is_ban in response: {text[:150]}")
            is_ban = m.group(1).lower() == "true"
            rm = re.search(r'"reason"\s*:\s*"(.*?)"\s*}', text, re.DOTALL)
            reason = rm.group(1) if rm else text[:150]
            log_cerebras_call(program_name, snippet, is_ban, reason, error=None)
            _CEREBRAS_CACHE[cache_key] = {"is_ban": is_ban, "reason": reason}
            return is_ban
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                try:
                    body = e.read().decode()
                except Exception:
                    body = "<could not read body>"
                retry_after = e.headers.get("Retry-After") if e.headers else None
                with open(os.path.join(OUTPUT_DIR, "cerebras_429_debug.log"), "a") as df:
                    df.write(f"--- {program_name} ---\n")
                    df.write(f"retry_after: {retry_after}\n")
                    df.write(f"body: {body}\n\n")
            if e.code in (503, 429) and attempt < 2:
                wait = 5 * (attempt + 1)
                if e.code == 429:
                    try:
                        ra = e.headers.get("Retry-After") if e.headers else None
                        if ra is not None:
                            wait = max(wait, min(int(float(ra)) + 1, 90))
                    except (TypeError, ValueError):
                        pass
                time.sleep(wait)
                continue
            break
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            break
    log_cerebras_call(program_name, snippet, None, None, error=str(last_err))
    return None
def log_cerebras_call(program_name, snippet, is_ban, reason, error):
    with open(CEREBRAS_LOG_PATH, "a") as f:
        f.write(f"--- {program_name} ---\n")
        f.write(f"snippet: {snippet[:200]!r}\n")
        if error:
            f.write(f"ERROR: {error} -> defaulted to REVIEW/SKIP\n")
        else:
            f.write(f"decision: {'BAN' if is_ban else 'NOT A BAN'} | reason: {reason}\n")
        f.write("\n")


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
