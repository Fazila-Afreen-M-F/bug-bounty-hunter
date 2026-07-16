import sys, shutil, datetime

path = ".github/workflows/scan-template.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_timeoutfix_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

old = """            -no-color \\
            -o results.txt || true

          echo "Findings: $(wc -l < results.txt 2>/dev/null || echo 0)\""""

count = content.count(old)
if count == 0:
    print("ERROR: marker string not found. Aborting, no changes made.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: marker string found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = """            -no-color \\
            -o results.txt
          NUCLEI_EXIT=$?
          if [ "$NUCLEI_EXIT" -eq 124 ]; then
            echo "::error::Nuclei timed out (exit 124) - failing step, results.txt may be incomplete"
            exit 1
          fi

          echo "Findings: $(wc -l < results.txt 2>/dev/null || echo 0)\""""

content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
