import sys, shutil, datetime

path = ".github/workflows/scan-template.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_concurrencyfix_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

old = """            -bulk-size 50 \\
            -concurrency 50 \\"""

count = content.count(old)
if count == 0:
    print("ERROR: marker string not found. Aborting, no changes made.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: marker string found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = """            -bulk-size 5 \\
            -concurrency 5 \\"""

content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
