import sys, shutil, datetime

path = ".github/workflows/weekend-scan.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_custombatched_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

old = '''  weekend_custom:
    needs: weekend_combined
    if: always() && !cancelled() && needs.weekend_combined.result != 'failure'
    uses: ./.github/workflows/scan-template.yml
    with:
      scan_name: "Custom Templates"
      use_custom_only: true
      severity: "low,medium,high,critical"
      input_file: "new_first"
    secrets:
      EMAIL_USER: ${{ secrets.EMAIL_USER }}
      EMAIL_PASS: ${{ secrets.EMAIL_PASS }}
      EMAIL_TO: ${{ secrets.EMAIL_TO }}
      HACKERONE_TOKEN: ${{ secrets.HACKERONE_TOKEN }}
      INTIGRITI_TOKEN: ${{ secrets.INTIGRITI_TOKEN }}
'''

count = content.count(old)
if count == 0:
    print("ERROR: marker block not found. Aborting, no changes made.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: marker block found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = '''  weekend_custom_batched:
    needs: [prepare, weekend_combined]
    if: always() && !cancelled() && needs.weekend_combined.result != 'failure' && needs.prepare.outputs.has_hosts == 'true'
    runs-on: ubuntu-latest
    timeout-minutes: 350
    env:
      FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true
    strategy:
      fail-fast: false
      max-parallel: 20
      matrix:
        batch: ${{ fromJson(needs.prepare.outputs.batches) }}
    steps:
      - name: Checkout main branch (custom-templates live here)
        uses: actions/checkout@v4
        with:
          ref: main
          fetch-depth: 1

      - name: Checkout domains branch host list
        uses: actions/checkout@v4
        with:
          ref: domains
          token: ${{ secrets.GITHUB_TOKEN }}
          fetch-depth: 0
          path: domains-branch

      - name: Download host list
        uses: actions/download-artifact@v4
        with:
          name: weekend-hosts

      - name: Slice hosts for this batch
        run: |
          total=$(wc -l < combined.txt)
          num_batches=${{ needs.prepare.outputs.num_batches }}
          batch_num=${{ matrix.batch }}
          batch_size=$(( (total + num_batches - 1) / num_batches ))
          start=$(( (batch_num - 1) * batch_size + 1 ))
          end=$(( batch_num * batch_size ))
          sed -n "${start},${end}p" combined.txt > input.txt
          echo "Batch $batch_num/$num_batches: $(wc -l < input.txt) of $total hosts"

      - name: Pre-filter dead hosts (liveness check)
        run: |
          echo "Hosts before liveness filter: $(wc -l < input.txt)"
          cat input.txt | xargs -P 30 -I @@H@@ bash -c 'code=$(curl -s -o /dev/null -m 2 -w "%{http_code}" "@@H@@" 2>/dev/null || echo 000); if [ "$code" != "000" ]; then echo "@@H@@"; fi' > input_live.txt || true
          if [ -s input_live.txt ]; then mv input_live.txt input.txt; fi
          echo "Hosts after liveness filter: $(wc -l < input.txt)"

      - name: Get week number
        id: date
        run: echo "week=$(date +'%Y-%U')" >> $GITHUB_OUTPUT

      - name: Cache Go tools
        uses: actions/cache@v4
        id: cache-go
        with:
          path: ~/go/bin
          key: go-tools-${{ runner.os }}-v4

      - name: Install nuclei
        if: steps.cache-go.outputs.cache-hit != 'true'
        run: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

      - name: Ensure nuclei installed
        run: |
          export PATH=$PATH:$(go env GOPATH)/bin
          if ! command -v nuclei &>/dev/null; then
            go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
          fi

      - name: Run nuclei (custom templates only)
        run: |
          export PATH=$PATH:$(go env GOPATH)/bin
          touch results.txt

          if [ ! -s input.txt ]; then
            echo "No targets for this batch"
            exit 0
          fi

          if [ ! -d custom-templates ] || [ -z "$(ls -A custom-templates)" ]; then
            echo "No custom templates found, skipping"
            exit 0
          fi

          echo "[TIMING] Batch hosts: $(wc -l < input.txt)"
          echo "[TIMING] Scan start: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
          SCAN_START=$(date +%s)
          set +e

          timeout 20700 nuclei -l input.txt \\
            -t custom-templates \\
            -severity low,medium,high,critical \\
            -H "User-Agent: Mozilla/5.0 BugBounty/42 (YWH) Chemical Oxidizer CS_YWH/BB" \\
            -H "X-Bug-Bounty: HackerOne-Chemical, HackerOne-Oxidizer" \\
            -H "X-Bugcrowd-Research: Chemical, Oxidizer" \\
            -H "X-Intigriti-Research: Chemical, Oxidizer" \\
            -H "X-YesWeHack-Research: Chemical, Oxidizer" \\
            -silent -retries 0 -timeout 3 \\
            -bulk-size 5 -concurrency 5 \\
            -rate-limit 5 -fhr -max-host-error 30 \\
            -stats -si 30 \\
            -no-color -o results.txt
          NUCLEI_EXIT=$?
          echo "$NUCLEI_EXIT" > nuclei_exit_code.txt
          if [ "$NUCLEI_EXIT" -eq 124 ]; then
            echo "::error::Nuclei timed out (exit 124) - failing step so batch is NOT marked done"
            exit 1
          fi

          SCAN_END=$(date +%s)
          echo "[TIMING] Scan end: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
          echo "[TIMING] Elapsed seconds: $(( SCAN_END - SCAN_START ))"
          echo "Findings: $(wc -l < results.txt)"

      - name: Show results
        if: always()
        run: |
          count=$(wc -l < results.txt 2>/dev/null || echo 0)
          echo "Total findings: $count"
          if [ "$count" -gt "0" ]; then cat results.txt; else echo "No findings"; fi

      - name: Check for results
        id: check
        run: |
          if [ -s results.txt ]; then
            echo "found=true" >> $GITHUB_OUTPUT
            echo "count=$(wc -l < results.txt)" >> $GITHUB_OUTPUT
          else
            echo "found=false" >> $GITHUB_OUTPUT
            echo "count=0" >> $GITHUB_OUTPUT
          fi

      - name: Send email alert
        if: steps.check.outputs.found == 'true'
        uses: dawidd6/action-send-mail@v3
        with:
          server_address: smtp.gmail.com
          server_port: 465
          username: ${{ secrets.EMAIL_USER }}
          password: ${{ secrets.EMAIL_PASS }}
          subject: "[Weekend Custom ${{ matrix.batch }}] ${{ steps.check.outputs.count }} Finding(s)"
          body: file://results.txt
          to: ${{ secrets.EMAIL_TO }}
          from: BugBountyBot
'''

content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
