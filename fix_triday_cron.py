import sys, shutil, datetime

path = ".github/workflows/triday-scan.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_cronfix_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

old = "    - cron: '30 18 * * 0-4'   # 12:00am IST Mon-Fri (UTC Sun-Thu 18:30, +5:30 rolls to next day IST)"
count = content.count(old)
if count == 0:
    print("ERROR: marker not found. Aborting.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = "    - cron: '30 18 * * 2-4'   # 12:00am IST Wed-Fri (UTC Tue-Thu 18:30, +5:30 rolls to next day IST)"
content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
