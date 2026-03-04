import json
import os
import random
from pathlib import Path
from typing import List, Dict, Any

# ----------------------------
# Configuration
# ----------------------------

CVE_DATA_PATH = "src/catalogues/processed_cve_dataset.json"
KB_DATA_PATH = "src/catalogues/windows7_kb_dataset.json"  # optional
OUTPUT_DIR = "data/summarizer"

TRAIN_SPLIT = 0.8
VAL_SPLIT = 0.1
TEST_SPLIT = 0.1

RANDOM_SEED = 42

# ----------------------------
# Utility Functions
# ----------------------------

def load_json(path: str):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def normalize_bool(value):
    return "Yes" if value else "No"

def build_input_prompt(cve: Dict[str, Any], context: Dict[str, Any] = None) -> str:
    """
    Builds the structured instruction-style input prompt.
    """

    os_context = ""
    if context:
        os_context = (
            f"Target OS: {context.get('name')} "
            f"({context.get('version')}), "
            f"Architecture: {context.get('architecture')}\n"
        )

    prompt = f"""You are a security analyst. Explain the following vulnerability in clear human-readable language.

CVE ID: {cve.get('cve_id')}
Published: {cve.get('published_date')}
CVSS Score: {cve.get('cvss_score')} (v{cve.get('cvss_version')})
Attack Vector: {cve.get('attack_vector')}
Attack Complexity: {cve.get('attack_complexity')}
Privileges Required: {cve.get('privileges_required')}
User Interaction: {cve.get('user_interaction')}
Scope: {cve.get('scope')}
Confidentiality Impact: {cve.get('confidentiality_impact')}
Integrity Impact: {cve.get('integrity_impact')}
Availability Impact: {cve.get('availability_impact')}
Exploit Available: {normalize_bool(cve.get('exploit_available'))}
Known Exploited (KEV): {normalize_bool(cve.get('kev_flag'))}
EPSS Score: {cve.get('epss_score')}
Vulnerability Type: {cve.get('vuln_type')}
Affected Component: {cve.get('affected_component')}

Description:
{cve.get('description')}

{os_context}
Provide:
1. What the vulnerability is
2. Why it is dangerous
3. Likely attack scenario
4. Business/system impact
5. Recommended mitigation strategy
"""
    return prompt.strip()


def build_output_summary(cve: Dict[str, Any]) -> str:
    """
    Basic deterministic summary (used as training target).
    This can later be replaced with curated explanations.
    """

    severity = "Critical" if cve.get("cvss_score", 0) >= 9 else \
               "High" if cve.get("cvss_score", 0) >= 7 else \
               "Medium" if cve.get("cvss_score", 0) >= 4 else "Low"

    remote = "remotely exploitable" if cve.get("is_remote") else "locally exploitable"

    summary = (
        f"{cve.get('cve_id')} is a {severity}-severity vulnerability affecting "
        f"{cve.get('affected_component')}. "
        f"It is {remote} with attack complexity rated as "
        f"{cve.get('attack_complexity')}. "
        f"The vulnerability impacts confidentiality ({cve.get('confidentiality_impact')}), "
        f"integrity ({cve.get('integrity_impact')}), and availability "
        f"({cve.get('availability_impact')}). "
        f"An attacker may exploit this issue to execute malicious code, escalate privileges, "
        f"or compromise system stability. "
        f"Organizations should prioritize patching, restrict unnecessary privileges, "
        f"monitor exploit activity, and apply vendor-provided mitigations."
    )

    return summary


def extract_windows7_cve_ids(kb_data: Dict[str, Any]) -> set:
    """
    Extract CVE IDs referenced in Windows 7 SP1 KB dataset.
    """
    cve_ids = set()
    if not kb_data:
        return cve_ids

    for kb in kb_data.get("kb", []):
        if "win7_sp1" in str(kb.get("os_targets", "")):
            for cve in kb.get("cve_ids", []):
                cve_ids.add(cve)
    return cve_ids


# ----------------------------
# Main Processing
# ----------------------------

def main():
    random.seed(RANDOM_SEED)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    cve_data = load_json(CVE_DATA_PATH)
    kb_data = load_json(KB_DATA_PATH)

    if not cve_data:
        raise FileNotFoundError("CVE dataset not found.")

    win7_cve_ids = extract_windows7_cve_ids(kb_data)

    dataset = []

    win7_context = {
        "name": "Windows 7 SP1",
        "version": "6.1 SP1",
        "architecture": "x86/x64"
    }

    for cve in cve_data:
        is_win7_related = (
            "windows_7" in str(cve.get("affected_component", "")).lower()
            or cve.get("cve_id") in win7_cve_ids
        )

        context = win7_context if is_win7_related else None

        entry = {
            "input": build_input_prompt(cve, context),
            "output": build_output_summary(cve)
        }

        dataset.append(entry)

    # Shuffle
    random.shuffle(dataset)

    total = len(dataset)
    train_end = int(total * TRAIN_SPLIT)
    val_end = train_end + int(total * VAL_SPLIT)

    train_set = dataset[:train_end]
    val_set = dataset[train_end:val_end]
    test_set = dataset[val_end:]

    # Write JSONL
    def write_jsonl(path, data):
        with open(path, "w", encoding="utf-8") as f:
            for item in data:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")

    write_jsonl(f"{OUTPUT_DIR}/train.json", train_set)
    write_jsonl(f"{OUTPUT_DIR}/val.json", val_set)
    write_jsonl(f"{OUTPUT_DIR}/test.json", test_set)

    print("Dataset preparation complete.")
    print(f"Train: {len(train_set)}")
    print(f"Validation: {len(val_set)}")
    print(f"Test: {len(test_set)}")


if __name__ == "__main__":
    main()