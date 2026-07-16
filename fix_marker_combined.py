import sys, shutil, datetime

path = ".github/workflows/weekend-scan.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_markercombined_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

# This exact block currently appears 3 times (combined, custom_batched, js_secrets_batched)
# We only want to change the FIRST occurrence (weekend_combined). Find it by preceding context.
anchor = '''subject: "[Weekend Combined ${{ matrix.batch }}] ${{ steps.check.outputs.count }} Finding(s)"
          body: file://results.txt
          to: ${{ secrets.EMAIL_TO }}
          from: BugBountyBot

      - name: Mark batch complete
        if: success()
        run: |
          echo "${{ matrix.batch }}" > batch_marker.txt

      - name: Upload batch completion marker
        if: success()
        uses: actions/upload-artifact@v4
        with:
          name: batch-marker-${{ matrix.batch }}
          path: batch_marker.txt
          retention-days: 1'''

count = content.count(anchor)
if count == 0:
    print("ERROR: marker block not found. Aborting, no changes made.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: marker block found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = anchor.replace(
    'name: batch-marker-${{ matrix.batch }}',
    'name: batch-marker-combined-${{ matrix.batch }}'
)

content = content.replace(anchor, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
