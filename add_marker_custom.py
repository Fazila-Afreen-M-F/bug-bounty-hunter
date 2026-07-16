import sys, shutil, datetime

path = ".github/workflows/weekend-scan.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_addmarkercustom_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

anchor = '''          subject: "[Weekend Custom ${{ matrix.batch }}] ${{ steps.check.outputs.count }} Finding(s)"
          body: file://results.txt
          to: ${{ secrets.EMAIL_TO }}
          from: BugBountyBot
'''

count = content.count(anchor)
if count == 0:
    print("ERROR: marker not found. Aborting, no changes made.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: marker found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = anchor + '''
      - name: Mark batch complete
        if: success()
        run: |
          echo "${{ matrix.batch }}" > batch_marker.txt

      - name: Upload batch completion marker
        if: success()
        uses: actions/upload-artifact@v4
        with:
          name: batch-marker-custom-${{ matrix.batch }}
          path: batch_marker.txt
          retention-days: 1
'''

content = content.replace(anchor, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
