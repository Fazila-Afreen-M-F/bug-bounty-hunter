import sys, shutil, datetime

path = ".github/workflows/weekend-scan.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_batchsize20_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

old = "          target_per_batch=25"
count = content.count(old)
if count == 0:
    print("ERROR: marker not found. Aborting.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = "          target_per_batch=20"
content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
