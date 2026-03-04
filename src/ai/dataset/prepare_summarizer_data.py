"""
prepare_summarizer_data.py - Context-aware dataset generator for SmartPatch summarizer + mitigation recommender.

Produces train/val/test JSONL with entries shaped for two downstream tasks:
 - summarization: convert CVE record -> human readable summary
 - mitigation decision: given CVE + SystemContext -> recommended action, priority, confidence

Usage example:
  python tools/prepare_summarizer_data.py \
    --cve_json src/catalogues/processed_cve_dataset.json \
    --kb_json src/catalogues/windows7_kb_catalogue.json \
    --hosts_dir runtime/test_hosts \
    --out_dir data/summarizer_context \
    --seed 42 \
    --val_frac 0.10 \
    --test_frac 0.10

Notes:
 - This script generates deterministic "pseudo-labels" for priority/action using simple rules.
 - Replace pseudo-labels with human-reviewed labels later for best model quality.
 - If --kb_json is provided the script will attempt to match CVE -> KB and include mitigation hints.
"""

from __future__ import annotations
import argparse
import json
import math
import random
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Set

# --------------------
# Utility functions
# --------------------
def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def write_jsonl(items: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for it in items:
            fh.write(json.dumps(it, ensure_ascii=False) + "\n")

def safe_get(d: Dict, *keys, default=None):
    for k in keys:
        if isinstance(d, dict) and k in d:
            return d[k]
    return default

# --------------------
# Normalizers
# --------------------
def normalize_cve(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize incoming CVE record to expected fields."""
    return {
        "cve_id": rec.get("cve_id") or rec.get("CVE") or rec.get("id"),
        "published_date": rec.get("published_date"),
        "description": rec.get("description") or rec.get("summary") or "",
        "cvss_score": rec.get("cvss_score") if rec.get("cvss_score") is not None else None,
        "epss_score": rec.get("epss_score") if rec.get("epss_score") is not None else None,
        "exploit_available": bool(rec.get("exploit_available")),
        "attack_vector": rec.get("attack_vector") or "UNKNOWN",
        "affected_component": rec.get("affected_component") or rec.get("affected_components") or "",
        "_raw": rec
    }

def normalize_kb_catalog(kb_json: Dict[str, Any]) -> Tuple[Dict[str, Dict], Dict[str, List[str]]]:
    """
    Return:
      kb_index: kb_id -> kb_record
      cve_to_kbs: cve_id -> [kb_id,...]
    """
    kb_index: Dict[str, Dict] = {}
    cve_to_kbs: Dict[str, List[str]] = {}
    kb_list = kb_json.get("kb") or kb_json.get("kbs") or []
    for kb in kb_list:
        kb_id = kb.get("kb_id")
        if not kb_id:
            continue
        kb_index[kb_id.upper()] = kb
        for cid in kb.get("cve_ids", []) or []:
            cve_list = cve_to_kbs.setdefault(cid, [])
            cve_list.append(kb_id.upper())
        # also inspect cve_details list if present
        for cd in kb.get("cve_details", []) or []:
            cid = cd.get("cve_id")
            if cid:
                cve_to_kbs.setdefault(cid, []).append(kb_id.upper())
    return kb_index, cve_to_kbs

# --------------------
# Context helpers
# --------------------
def load_host_contexts(host_json: Optional[Path], hosts_dir: Optional[Path]) -> List[Dict[str, Any]]:
    """
    Return list of host context dicts. Each host dict must contain:
      host_id, hostname, os.name/os.version/build_number, architecture, installed_kbs (list), system_role
    If none provided, return one generic placeholder host (legacy-friendly).
    """
    hosts: List[Dict[str, Any]] = []
    if host_json:
        h = load_json(host_json)
        hosts.append(h)
    if hosts_dir:
        for p in sorted(hosts_dir.glob("*.json")):
            if host_json and host_json.resolve() == p.resolve():
                continue
            hosts.append(load_json(p))
    if not hosts:
        # generic legacy host: Windows 7 SP1
        hosts.append({
            "host_id": "GENERIC_WIN7_1",
            "hostname": "WIN7-TEST",
            "os": {"name": "Windows 7 SP1", "version": "6.1", "build_number": 7601},
            "architecture": "x64",
            "installed_kbs": [],
            "system_role": "workstation"
        })
    return hosts

# --------------------
# Prompt / label generation
# --------------------
def build_input_prompt(cve: Dict[str, Any], host: Dict[str, Any]) -> str:
    """
    Create a single text prompt that contains:
      - compact CVE structured lines
      - a SystemContext block (OS, build, arch, installed_kbs, system_role)
    The model will see both and should produce summary + recommendation.
    """
    lines = []
    lines.append(f"CVE: {cve['cve_id']}")
    lines.append(f"CVSS: {cve.get('cvss_score') or 'N/A'}")
    lines.append(f"EPSS: {cve.get('epss_score') or 'N/A'}")
    lines.append(f"exploit: {'yes' if cve.get('exploit_available') else 'no'}")
    lines.append(f"vector: {cve.get('attack_vector') or 'UNKNOWN'}")
    affected = cve.get("affected_component") or "unspecified"
    if isinstance(affected, list):
        affected = ", ".join(affected)
    lines.append(f"component: {affected}")
    desc = cve.get("description", "").strip().replace("\n", " ")
    lines.append(f"details: {desc if desc else 'no description available'}")
    # System Context block (structured but plain text)
    sc = host
    osname = safe_get(sc, "os", "name") or sc.get("os_name") or "unknown"
    osver = safe_get(sc, "os", "version") or sc.get("os_version") or str(safe_get(sc, "os", "build_number") or sc.get("build_number") or "unknown")
    arch = sc.get("architecture") or "unknown"
    installed = sc.get("installed_kbs") or []
    role = sc.get("system_role") or "workstation"
    lines.append("--- SystemContext ---")
    lines.append(f"os: {osname}")
    lines.append(f"version/build: {osver}")
    lines.append(f"architecture: {arch}")
    lines.append(f"installed_kbs: {','.join(installed) if installed else '[]'}")
    lines.append(f"system_role: {role}")
    return "\n".join(lines)

def deterministic_priority_and_action(cve: Dict[str, Any], host: Dict[str, Any],
                                      kb_index: Dict[str, Dict], cve_to_kbs: Dict[str, List[str]]) -> Tuple[str, str, float]:
    """
    Deterministic rule-based mapping -> (priority, recommended_action, confidence)
    Rules (explainable):
      - base_score = normalized CVSS (cvss/10) if present else 0.2
      - epss_bonus = epss (0..1) * 0.2 (if present)
      - exploit_bonus = +0.15 if exploit_available true
      - final_score = clamp(base_score + epss_bonus + exploit_bonus, 0, 1)
      - PRIORITY: HIGH if final_score >= 0.70; MEDIUM if >= 0.35; else LOW
      - If we find KBs in cve_to_kbs and any KB is applicable to host.arch/os -> recommend "install KB {kb_id}"
      - Else if kb exists but not applicable -> recommend "investigate vendor fix / mitigation"
      - Else fallback -> "apply temporary mitigation or monitor"
      - confidence: map final_score to [0.5..0.98] (higher score => higher confidence)
    """
    cvss = cve.get("cvss_score") or 0.0
    epss = cve.get("epss_score") or 0.0
    exploit = 1.0 if cve.get("exploit_available") else 0.0

    base = float(cvss) / 10.0 if cvss is not None else 0.2
    epss_bonus = float(epss) * 0.2
    exploit_bonus = exploit * 0.15
    final = max(0.0, min(1.0, base + epss_bonus + exploit_bonus))

    if final >= 0.70:
        pr = "HIGH"
    elif final >= 0.35:
        pr = "MEDIUM"
    else:
        pr = "LOW"

    # KB matching: look up CVE -> KBs
    cve_id = cve["cve_id"]
    candidate_kbs = cve_to_kbs.get(cve_id) or []
    host_arch = (host.get("architecture") or "").lower()
    host_os = safe_get(host, "os", "name") or ""
    chosen_action = None
    if candidate_kbs:
        # try to pick applicable KB for host by checking kb_index.os_targets if present
        for kb in candidate_kbs:
            kbrec = kb_index.get(kb.upper())
            if not kbrec:
                # if no kbrec metadata, prefer to recommend installing KB and flag lower confidence
                chosen_action = f"install KB {kb} (verify OS applicability)"
                break
            # inspect os_targets if present
            os_targets = kbrec.get("os_targets") or []
            # common heuristic: match architecture and os_id substring
            for ot in os_targets:
                arch = (ot.get("architecture") or "").lower()
                os_id = (ot.get("os_id") or "").lower()
                if (not arch or host_arch in arch) and (not os_id or (host_os and os_id in host_os.lower()) or ("win7" in host_os.lower() and "win7" in os_id)):
                    chosen_action = f"install KB {kb}"
                    break
            if chosen_action:
                break
        if not chosen_action:
            # KBs exist but none clearly applicable
            chosen_action = f"KBs found {', '.join(candidate_kbs)} - verify vendor applicability / apply mitigation"
    else:
        # no KB mapping: check if mitigation hints exist in kb_index by scanning nearby controls (best effort)
        # fallback action depends on severity
        if pr == "HIGH":
            chosen_action = "apply temporary mitigation (configuration change / service disable) and escalate for emergency patch development"
        elif pr == "MEDIUM":
            chosen_action = "investigate vendor advisory; apply recommended mitigations if safe"
        else:
            chosen_action = "monitor and schedule remediation in regular maintenance window"

    # confidence mapping: final_score -> [0.5..0.98]
    conf = 0.5 + 0.48 * final
    conf = max(0.0, min(0.99, round(conf, 2)))

    return pr, chosen_action, conf

def make_target_summary(cve: Dict[str, Any]) -> str:
    """Concise 1-3 sentence summary for the CVE."""
    cveid = cve.get("cve_id") or "UNKNOWN"
    desc = (cve.get("description") or "").strip().replace("\n", " ")
    cvss = cve.get("cvss_score")
    vec = cve.get("attack_vector") or "UNKNOWN"
    expl = "exploit reported" if cve.get("exploit_available") else "no public exploit reported"
    if desc:
        s1 = f"{cveid} — {desc}"
    else:
        s1 = f"{cveid} — Description not available."
    meta = []
    if cvss is not None:
        meta.append(f"CVSS {cvss}/10")
    meta.append(f"vector: {vec}")
    meta.append(expl)
    s2 = ". ".join(meta) + "."
    s3 = f"Affects {cve.get('affected_component') or 'unspecified component'}. Check vendor advisory for patch."
    return " ".join([s1, s2, s3])

# --------------------
# Main builder
# --------------------
def build(
    cve_json_path: Path,
    kb_json_path: Optional[Path],
    host_json: Optional[Path],
    hosts_dir: Optional[Path],
    out_dir: Path,
    seed: int,
    val_frac: float,
    test_frac: float
) -> Tuple[int,int,int]:
    # load CVEs
    raw = load_json(cve_json_path)
    if isinstance(raw, list):
        cve_list = raw
    elif isinstance(raw, dict):
        # try common wrappers
        if "cves" in raw:
            cve_list = raw["cves"]
        elif "items" in raw:
            cve_list = raw["items"]
        else:
            cve_list = [v for v in raw.values() if isinstance(v, list)][0] if any(isinstance(v, list) for v in raw.values()) else []
    else:
        raise SystemExit("Unrecognized CVE JSON format")

    cves = [normalize_cve(r) for r in cve_list if r.get("cve_id")]

    kb_index, cve_to_kbs = ({}, {}) if not kb_json_path else normalize_kb_catalog(load_json(kb_json_path))

    hosts = load_host_contexts(host_json, hosts_dir)

    # create examples: for each host x each cve -> one example (if too large, you can sample later)
    examples: List[Dict[str, Any]] = []
    for host in hosts:
        host_id = host.get("host_id") or host.get("hostname") or f"host_{random.randint(1,1_000_000)}"
        for cve in cves:
            input_text = build_input_prompt(cve, host)
            summary = make_target_summary(cve)
            priority, action, confidence = deterministic_priority_and_action(cve, host, kb_index, cve_to_kbs)
            ex = {
                "input": input_text,
                "target_summary": summary,
                "target_action": action,
                "priority": priority,
                "confidence": confidence,
                "metadata": {
                    "cve_id": cve.get("cve_id"),
                    "host_id": host_id,
                    "host_os": safe_get(host, "os", "name") or host.get("os_name"),
                    "host_arch": host.get("architecture"),
                    "kb_matches": cve_to_kbs.get(cve.get("cve_id")) or []
                }
            }
            examples.append(ex)

    # shuffle + split deterministic
    random.seed(seed)
    random.shuffle(examples)
    n = len(examples)
    n_test = int(n * test_frac)
    n_val = int(n * val_frac)
    n_train = n - n_val - n_test

    train = examples[:n_train]
    val = examples[n_train:n_train + n_val]
    test = examples[n_train + n_val:]

    # write files
    out_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(train, out_dir / "train.jsonl")
    write_jsonl(val, out_dir / "val.jsonl")
    write_jsonl(test, out_dir / "test.jsonl")

    manifest = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "cve_source": str(cve_json_path),
        "kb_source": str(kb_json_path) if kb_json_path else None,
        "hosts_count": len(hosts),
        "examples_total": n,
        "counts": {"train": len(train), "val": len(val), "test": len(test)}
    }
    with (out_dir / "manifest.json").open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    return len(train), len(val), len(test)

# --------------------
# CLI
# --------------------
def parse_args():
    p = argparse.ArgumentParser(prog="prepare_summarizer_data.py")
    p.add_argument("--cve_json", type=Path, required=True)
    p.add_argument("--kb_json", type=Path, required=False, help="Optional KB catalogue JSON to enrich KB->CVE mapping")
    p.add_argument("--host_json", type=Path, required=False, help="Single host context JSON")
    p.add_argument("--hosts_dir", type=Path, required=False, help="Directory of host JSONs (one file per host)")
    p.add_argument("--out_dir", type=Path, default=Path("data/summarizer_context"))
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--val_frac", type=float, default=0.1)
    p.add_argument("--test_frac", type=float, default=0.1)
    return p.parse_args()

def main():
    args = parse_args()
    if not args.cve_json.exists():
        raise SystemExit(f"cve_json not found: {args.cve_json}")
    if args.kb_json and not args.kb_json.exists():
        raise SystemExit(f"kb_json not found: {args.kb_json}")
    if args.host_json and not args.host_json.exists():
        raise SystemExit(f"host_json not found: {args.host_json}")
    if args.hosts_dir and not args.hosts_dir.exists():
        raise SystemExit(f"hosts_dir not found: {args.hosts_dir}")

    train_n, val_n, test_n = build(
        cve_json_path=args.cve_json,
        kb_json_path=args.kb_json,
        host_json=args.host_json,
        hosts_dir=args.hosts_dir,
        out_dir=args.out_dir,
        seed=args.seed,
        val_frac=args.val_frac,
        test_frac=args.test_frac
    )

    print(f"Written: train={train_n}, val={val_n}, test={test_n}")
    print(f"Files: {args.out_dir}/train.jsonl | val.jsonl | test.jsonl | manifest.json")

if __name__ == "__main__":
    main()