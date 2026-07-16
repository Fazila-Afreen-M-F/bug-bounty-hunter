import sys, shutil, datetime

path = ".github/workflows/weekend-scan.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_finalizeneeds_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

old = """  finalize_progress:
    needs: [prepare, weekend_combined]
    if: always() && needs.weekend_combined.result != 'cancelled'
    runs-on: ubuntu-latest"""

count = content.count(old)
if count == 0:
    print("ERROR: marker block not found. Aborting, no changes made.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: marker block found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = """  finalize_progress:
    needs: [prepare, weekend_combined, weekend_custom_batched, weekend_js_secrets_batched]
    if: always() && needs.weekend_combined.result != 'cancelled'
    runs-on: ubuntu-latest"""

content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
