import csv
import json
from pathlib import Path
import re

# -----------------------------
# CONFIG
# -----------------------------
EPSS_CSV = Path("src/catalogues/epss.csv")  # your downloaded EPSS CSV
WINDOWS_CVE_JSON = Path("src/catalogues/windows7-10_cves.json")  # your NVD Windows CVEs
OUTPUT_JSON = Path("src/catalogues/epss_windows.json")  # filtered output

# -----------------------------
# LOAD WINDOWS CVEs
# -----------------------------
with open(WINDOWS_CVE_JSON, "r", encoding="utf-8") as f:
    windows_cve_data = json.load(f)

# Create a set of normalized CVE IDs for fast lookup
def normalize_cve(cve_id):
    if not cve_id:
        return None
    cve_id = cve_id.strip().upper()
    # Ensure CVE-YYYY-NNNN format (pad with zeros to at least 4 digits)
    match = re.match(r"(CVE-\d{4}-)(\d+)", cve_id)
    if match:
        prefix, num = match.groups()
        num = num.zfill(4)
        return f"{prefix}{num}"
    return cve_id

windows_cve_ids = {normalize_cve(item["id"]) for item in windows_cve_data}
print(f"Loaded {len(windows_cve_ids)} Windows CVEs (Win7-10).")

# -----------------------------
# FILTER EPSS CSV
# -----------------------------
filtered_records = []

with open(EPSS_CSV, "r", newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    # auto-detect CVE column
    cve_column = None
    for col in reader.fieldnames:
        if "cve" in col.lower():
            cve_column = col
            break
    if not cve_column:
        raise ValueError("Could not detect CVE column in EPSS CSV")

    for row in reader:
        raw_cve = row.get(cve_column)
        cve_id = normalize_cve(raw_cve)
        if cve_id and cve_id in windows_cve_ids:
            try:
                filtered_records.append({
                    "cve_id": cve_id,
                    "epss": float(row.get("epss", 0)),
                    "percentile": float(row.get("percentile", 0))
                })
            except ValueError:
                continue  # skip rows with invalid numbers

# Sort descending by EPSS score
filtered_records.sort(key=lambda x: x["epss"], reverse=True)
print(f"Filtered EPSS records for Windows: {len(filtered_records)}")

# -----------------------------
# SAVE JSON
# -----------------------------
with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
    json.dump(filtered_records, f, indent=2)

print(f"Saved filtered Windows EPSS JSON to {OUTPUT_JSON}")