import re, sys, shutil, datetime

path = ".github/workflows/weekend-scan.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_timeoutfix_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

old = 'echo "$NUCLEI_EXIT" > nuclei_exit_code.txt'
count = content.count(old)
if count == 0:
    print("ERROR: marker string not found. Aborting, no changes made.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: marker string found {count} times (expected 1). Aborting - ambiguous.")
    sys.exit(1)

new = (
    'echo "$NUCLEI_EXIT" > nuclei_exit_code.txt\n'
    '          if [ "$NUCLEI_EXIT" -eq 124 ]; then\n'
    '            echo "::error::Nuclei timed out (exit 124) - failing step so batch is NOT marked done"\n'
    '            exit 1\n'
    '          fi'
)

content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
