import sys, shutil, datetime

path = "discover_all_programs.py"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_publiconly_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

old = '''        for p in data.get("data", []):
            a = p["attributes"]
            programs.append({
                "handle": a.get("handle"),
                "name": a.get("name"),
                "submission_state": a.get("submission_state"),
                "offers_bounties": a.get("offers_bounties"),
            })'''

count = content.count(old)
if count == 0:
    print("ERROR: marker block not found. Aborting, no changes made.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: marker block found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = '''        skipped_private = 0
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
            log(f"[H1] skipped {skipped_private} non-public (private/invite-only) programs this page")'''

content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
