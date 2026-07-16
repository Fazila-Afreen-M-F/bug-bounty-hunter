import re

path = "discover_all_programs.py"
with open(path) as f:
    src = f.read()

old1 = '''        data, err = fetch_json(
            f"https://api.yeswehack.com/programs?page={page}",
            {"Accept": "application/json"},
        )'''
new1 = '''        data, err = fetch_json(
            f"https://api.yeswehack.com/programs?page={page}",
            {"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )'''
assert old1 in src, "Fix 1 anchor not found"
src = src.replace(old1, new1)

old2 = '''def extract_ywh_domains(scope_entries):
    domains = []
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
        if not re.search(r"[a-zA-Z0-9\\-]+\\.[a-zA-Z]{2,}", s2):
            continue
        s2 = re.split(r"[/?]", s2)[0]
        m = re.match(r"^([a-zA-Z0-9_\\-.*]+)\\(([a-zA-Z0-9\\-.|]+)\\)([a-zA-Z0-9_\\-.]*)$", s2)
        if m:
            prefix, group, suffix = m.groups()
            for opt in group.split("|"):
                domains.append(f"{prefix}{opt}{suffix}")
            continue
        s3 = re.sub(r'[()"].*$', "", s2).strip()
        if re.match(r"^[a-zA-Z0-9*][a-zA-Z0-9\\-.*]*\\.[a-zA-Z]{2,}$", s3):
            domains.append(s3)
    return sorted(set(domains))'''

new2 = '''def extract_ywh_domains(scope_entries, slug="unknown"):
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
        if not re.search(r"[a-zA-Z0-9\\-]+\\.[a-zA-Z]{2,}", s2):
            unmatched.append(s)
            continue
        s2 = re.split(r"[/?]", s2)[0]
        m = re.match(r"^([a-zA-Z0-9_\\-.*]+)\\(([a-zA-Z0-9\\-.|]+)\\)([a-zA-Z0-9_\\-.]*)$", s2)
        if m:
            prefix, group, suffix = m.groups()
            for opt in group.split("|"):
                domains.append(f"{prefix}{opt}{suffix}")
            continue
        s3 = re.sub(r'[()"].*$', "", s2).strip()
        if re.match(r"^[a-zA-Z0-9*][a-zA-Z0-9\\-.*]*\\.[a-zA-Z]{2,}$", s3):
            domains.append(s3)
        else:
            unmatched.append(s)
    if unmatched:
        with open("yeswehack_unmatched.log", "a") as f:
            for u in unmatched:
                f.write(f"{slug}\\t{u}\\n")
    return sorted(set(domains))'''

assert old2 in src, "Fix 2 anchor not found"
src = src.replace(old2, new2)

old3 = 'domains = extract_ywh_domains(data.get("scopes", []))'
new3 = 'domains = extract_ywh_domains(data.get("scopes", []), slug)'
assert old3 in src, "Fix 3 anchor not found"
src = src.replace(old3, new3)

with open(path, "w") as f:
    f.write(src)

print("Patched successfully: 3 changes applied to", path)
