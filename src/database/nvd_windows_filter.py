import json
import glob
from pathlib import Path
import argparse
import sys

WINDOWS_PRODUCTS = [
    "windows_7",
    "windows_8",
    "windows_8.1",
    "windows_10"
]

def cpe_matches_windows(cpe_uri):
    """Check if a CPE URI (2.2 or 2.3) indicates Windows OS."""
    cpe_lower = cpe_uri.lower()
    # Must be an OS (part = 'o' in either format)
    # CPE 2.3: "cpe:2.3:o:microsoft:windows_7..."
    # CPE 2.2: "cpe:/o:microsoft:windows_7..."
    if not (cpe_lower.startswith("cpe:/o:") or cpe_lower.startswith("cpe:2.3:o:")):
        return False
    # Now check if the product name is in our list
    for product in WINDOWS_PRODUCTS:
        if f":{product}" in cpe_lower or f"/{product}" in cpe_lower:
            return True
    return False

def node_contains_windows(node):
    """Recursively check a node and its children for Windows CPEs."""
    for cpe_entry in node.get("cpeMatch", []):
        cpe_uri = cpe_entry.get("criteria", "")
        if cpe_matches_windows(cpe_uri):
            return True
    for child in node.get("children", []):
        if node_contains_windows(child):
            return True
    return False

def main():
    parser = argparse.ArgumentParser(description="Filter NVD JSON (API 2.0 format) for Windows OS CVEs.")
    parser.add_argument("--input-dir", default="src/catalogues", help="Directory containing NVD JSON files")
    parser.add_argument("--output", default="src/catalogues/windows7-10_cves.json", help="Output JSON file")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_file = Path(args.output)

    nvd_files = sorted(glob.glob(str(input_dir / "nvdcve-2.0-*.json")))
    if not nvd_files:
        print(f"No NVD files found in {input_dir}", file=sys.stderr)
        sys.exit(1)

    filtered_cves = {}
    total_processed = 0

    for file_path in nvd_files:
        print(f"Processing {file_path} ...")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error reading {file_path}: {e}", file=sys.stderr)
            continue

        # In API 2.0 format, CVEs are under "vulnerabilities" array
        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            total_processed += 1
            cve_item = vuln.get("cve")
            if not cve_item:
                continue
            cve_id = cve_item.get("id")
            if not cve_id or cve_id in filtered_cves:
                continue

            # Configurations are inside cve_item under "configurations" (array of objects)
            configs = cve_item.get("configurations", [])
            windows_affected = False
            for config in configs:
                nodes = config.get("nodes", [])
                if any(node_contains_windows(node) for node in nodes):
                    windows_affected = True
                    break
            if windows_affected:
                filtered_cves[cve_id] = cve_item  # store the whole cve object

    # Optional: show a sample matched CVE for verification
    if filtered_cves:
        sample_cve = next(iter(filtered_cves.values()))
        print("\nSample CVE that matched:")
        print(f"  ID: {sample_cve['id']}")
        # Show first matching CPE
        configs = sample_cve.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if cpe_matches_windows(cpe["criteria"]):
                        print(f"  Matching CPE: {cpe['criteria']}")
                        break
                break
            break
    else:
        print("\nNo CVEs matched. Checking first few CVEs for Windows CPEs...")
        # Debug: look at first 5 CVEs from the first file
        if nvd_files:
            with open(nvd_files[0], "r", encoding="utf-8") as f:
                data = json.load(f)
            for i, vuln in enumerate(data.get("vulnerabilities", [])[:5]):
                cve_item = vuln.get("cve", {})
                cve_id = cve_item.get("id", "unknown")
                print(f"  CVE {cve_id}:")
                configs = cve_item.get("configurations", [])
                for config in configs:
                    for node in config.get("nodes", []):
                        for cpe in node.get("cpeMatch", []):
                            print(f"    CPE: {cpe['criteria']}")
                print()

    # Convert to list and save
    output_list = list(filtered_cves.values())
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_list, f, indent=2)

    print(f"\nDone! Processed {total_processed} CVEs, found {len(output_list)} unique Windows OS CVEs. Saved to {output_file}")

if __name__ == "__main__":
    main()