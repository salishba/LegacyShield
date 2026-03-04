import os
import json
import pandas as pd

BASE_PATH = "src/catalogues"
START_YEAR = 2021
END_YEAR = 2025

OUTPUT_FILE = os.path.join(
    BASE_PATH,
    "windows10_security_2021_2025.json"
)

# Columns we want in final JSON
REQUIRED_FIELDS = [
    "Impact",
    "Max Severity",
    "Article",
    "Supercedence",
    "Download",
    "Build Number",
    "Details",
    "CWE",
    "Customer Action Required"
]

def is_security_update(row: pd.Series) -> bool:
    """
    Filter only security updates.
    Accept rows where Impact or Max Severity is populated.
    """
    if pd.notna(row.get("Impact")):
        return True

    if pd.notna(row.get("Max Severity")):
        return True

    return False


def is_kernel_related(row: pd.Series) -> bool:
    """
    Exclude anything mentioning kernel in Details or Impact.
    """
    fields_to_check = [
        str(row.get("Details", "")).lower(),
        str(row.get("Impact", "")).lower()
    ]

    for field in fields_to_check:
        if "kernel" in field:
            return True

    return False


def clean_row(row: pd.Series) -> dict:
    """
    Keep only required fields.
    """
    cleaned = {}

    for field in REQUIRED_FIELDS:
        value = row.get(field)

        if pd.isna(value):
            cleaned[field] = None
        else:
            cleaned[field] = str(value).strip()

    return cleaned


def process_year(year: int) -> list:
    file_path = os.path.join(
        BASE_PATH,
        f"windows10_{year}.xlsx"
    )

    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return []

    print(f"[+] Processing {file_path}")

    df = pd.read_excel(file_path)

    results = []

    for _, row in df.iterrows():

        # Keep only security updates
        if not is_security_update(row):
            continue

        # Remove kernel-related
        if is_kernel_related(row):
            continue

        cleaned = clean_row(row)
        results.append(cleaned)

    print(f"[+] {year}: {len(results)} security entries kept")
    return results


def main():
    all_results = []

    for year in range(START_YEAR, END_YEAR + 1):
        year_data = process_year(year)
        all_results.extend(year_data)

    # Remove duplicates based on Article (KB)
    seen_articles = set()
    deduped = []

    for entry in all_results:
        article = entry.get("Article")

        if article and article not in seen_articles:
            seen_articles.add(article)
            deduped.append(entry)

    print(f"[+] Total unique security entries: {len(deduped)}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(deduped, f, indent=2)

    print(f"[✓] JSON saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()