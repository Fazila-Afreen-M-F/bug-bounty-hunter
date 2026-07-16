import sys, shutil, datetime

path = ".github/workflows/weekend-scan.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_finalizemerge_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    content = f.read()

old = '''      - name: Merge markers into weekend_progress.txt
        run: |
          git config --global user.email "bugbountybot@github.com"
          git config --global user.name "BugBountyBot"
          touch weekend_progress.txt weekend_offset.txt
          find batch_markers -name "batch_marker.txt" -exec cat {} \\; >> weekend_progress.txt
          sort -n -u weekend_progress.txt -o weekend_progress.txt
          done_count=$(wc -l < weekend_progress.txt)
          echo "Batches marked complete this run: $done_count"

          NUM_BATCHES="${{ needs.prepare.outputs.num_batches }}"
          CHUNK_END="${{ needs.prepare.outputs.chunk_end }}"
          FULL_TOTAL="${{ needs.prepare.outputs.full_total }}"

          if [ -n "$NUM_BATCHES" ] && [ "$done_count" -ge "$NUM_BATCHES" ]; then
            NEW_OFFSET=$(( CHUNK_END + 1 ))
            if [ "$NEW_OFFSET" -gt "$FULL_TOTAL" ]; then
              NEW_OFFSET=1
            fi
            echo "Chunk complete ($done_count/$NUM_BATCHES) - advancing offset to $NEW_OFFSET"
            echo "$NEW_OFFSET" > weekend_offset.txt
            > weekend_progress.txt
          else
            echo "Chunk not yet complete ($done_count/$NUM_BATCHES) - offset unchanged, resuming same chunk next trigger"
          fi

          git add weekend_progress.txt weekend_offset.txt
          git diff --staged --quiet || git commit -m "Weekend scan progress update $(date +'%Y-%m-%d')"
          git push origin domains || (git pull --rebase origin domains && git push origin domains) || echo "::warning::Push failed for weekend_progress.txt"'''

count = content.count(old)
if count == 0:
    print("ERROR: marker block not found. Aborting, no changes made.")
    sys.exit(1)
if count > 1:
    print(f"ERROR: marker block found {count} times (expected 1). Aborting.")
    sys.exit(1)

new = '''      - name: Merge markers into weekend_progress.txt
        run: |
          git config --global user.email "bugbountybot@github.com"
          git config --global user.name "BugBountyBot"
          touch weekend_progress.txt weekend_offset.txt

          for d in batch_markers/batch-marker-*; do
            [ -d "$d" ] || continue
            name=$(basename "$d")
            job=$(echo "$name" | sed -E 's/^batch-marker-(combined|custom|jssecrets)-[0-9]+$/\\1/')
            num=$(echo "$name" | sed -E 's/^batch-marker-(combined|custom|jssecrets)-([0-9]+)$/\\2/')
            if [ -n "$job" ] && [ -n "$num" ] && [ "$job" != "$name" ]; then
              echo "${num}:${job}" >> weekend_progress.txt
            fi
          done

          sort -u weekend_progress.txt -o weekend_progress.txt
          done_count=$(cut -d: -f1 weekend_progress.txt | sort -n | uniq -c | awk '$1 == 3 {print $2}' | wc -l)
          echo "Batches with all 3 scan types complete this run: $done_count"

          NUM_BATCHES="${{ needs.prepare.outputs.num_batches }}"
          CHUNK_END="${{ needs.prepare.outputs.chunk_end }}"
          FULL_TOTAL="${{ needs.prepare.outputs.full_total }}"

          if [ -n "$NUM_BATCHES" ] && [ "$done_count" -ge "$NUM_BATCHES" ]; then
            NEW_OFFSET=$(( CHUNK_END + 1 ))
            if [ "$NEW_OFFSET" -gt "$FULL_TOTAL" ]; then
              NEW_OFFSET=1
            fi
            echo "Chunk complete ($done_count/$NUM_BATCHES) - advancing offset to $NEW_OFFSET"
            echo "$NEW_OFFSET" > weekend_offset.txt
            > weekend_progress.txt
          else
            echo "Chunk not yet complete ($done_count/$NUM_BATCHES) - offset unchanged, resuming same chunk next trigger"
          fi

          git add weekend_progress.txt weekend_offset.txt
          git diff --staged --quiet || git commit -m "Weekend scan progress update $(date +'%Y-%m-%d')"
          git push origin domains || (git pull --rebase origin domains && git push origin domains) || echo "::warning::Push failed for weekend_progress.txt"'''

content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patch applied.")
