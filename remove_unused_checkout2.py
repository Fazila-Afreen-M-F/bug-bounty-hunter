import sys, shutil, datetime

path = ".github/workflows/weekend-scan.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_removecheckout2_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

old = """      - name: Checkout domains branch host list
        uses: actions/checkout@v4
        with:
          ref: domains
          token: ${{ secrets.GITHUB_TOKEN }}
          fetch-depth: 0
          path: domains-branch

      - name: Download host list"""

count = content.count(old)
if count == 0:
    print("ERROR: marker block not found. Aborting, no changes made.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: marker block found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = "      - name: Download host list"

content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
