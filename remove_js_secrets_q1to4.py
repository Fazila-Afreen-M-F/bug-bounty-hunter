import sys, shutil, datetime

path = ".github/workflows/weekend-scan.yml"
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
backup = f"{path}.bak_removeq1to4_{ts}"
shutil.copy(path, backup)
print(f"Backed up to {backup}")

with open(path) as f:
    lines = f.readlines()

start_marker = "  weekend_js_secrets_q1:\n"
end_marker = "  # ─── CUSTOM TEMPLATES ──────────────────────────────────────────\n"

start_idx = None
end_idx = None
for i, line in enumerate(lines):
    if line == start_marker and start_idx is None:
        start_idx = i
    if line == end_marker and start_idx is not None and end_idx is None:
        end_idx = i
        break

if start_idx is None or end_idx is None:
    print(f"ERROR: markers not found cleanly (start={start_idx}, end={end_idx}). Aborting.")
    sys.exit(1)

removed = lines[start_idx:end_idx]
print(f"Removing lines {start_idx+1} to {end_idx} ({len(removed)} lines)")

new_lines = lines[:start_idx] + lines[end_idx:]

with open(path, "w") as f:
    f.writelines(new_lines)

print("Patch applied.")
