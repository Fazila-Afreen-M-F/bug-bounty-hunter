import sys, shutil, datetime

path = ".github/workflows/triday-scan.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_namefix_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

old = "name: Weekday Scan"
count = content.count(old)
if count == 0:
    print("ERROR: marker not found. Aborting.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = "name: Triday Scan"
content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
