import sys, shutil, datetime

path = ".github/workflows/weekend-scan.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_katanafix_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

old = '''            -o urls.txt || true
          if [ -f urls.txt ]; then
            sort -u urls.txt | head -1000 > urls_capped.txt
            mv urls_capped.txt urls.txt
          else
            touch urls.txt
          fi
          echo "URLs found: $(wc -l < urls.txt 2>/dev/null || echo 0)"'''

count = content.count(old)
if count == 0:
    print("ERROR: marker block not found. Aborting, no changes made.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: marker block found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = '''            -o urls.txt
          KATANA_EXIT=$?
          if [ "$KATANA_EXIT" -eq 124 ]; then
            echo "::warning::Katana timed out (exit 124) - proceeding with partial/no crawled URLs, nuclei will still run"
          fi
          if [ -f urls.txt ]; then
            sort -u urls.txt | head -1000 > urls_capped.txt
            mv urls_capped.txt urls.txt
          else
            touch urls.txt
          fi
          echo "URLs found: $(wc -l < urls.txt 2>/dev/null || echo 0)"'''

content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
