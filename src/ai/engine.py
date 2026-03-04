# src/ai/engine.py for database
import json
import logging
from pathlib import Path
from typing import List, Dict, Any
import sqlite3
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

LOG = logging.getLogger("ai.engine")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Config - adjust paths if needed
MODEL_PATH = Path("models/model.pkl")
PRIORITIZATION_DB = Path("prioritization.db")       
CATALOGUE_DB = Path("smartpatch_cataloguecv.sqlite")  
RUNTIME_DB = Path("runtime_scan.sqlite")            

AI_MODEL_VERSION = "severity_reg_v1"

# Feature keys expected by the model
FEATURE_COLUMNS = [
    "cvss_score",
    "epss_probability",
    "exploited_flag",
    "poc_flag",
    "ransomware_flag",
    "patch_missing_flag",
    "detection_confidence"
    # add more if you later extend features (exposure, system_role_onehot, etc.)
]


def _connect(path: Path):
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_ai_table(conn):
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_hash TEXT NOT NULL,
            cve_id TEXT,
            ml_score REAL,
            hars_score REAL,
            final_score REAL,
            ml_rank INTEGER,
            ml_confidence REAL,
            top_features_json TEXT,
            model_version TEXT,
            inserted_at TEXT,
            UNIQUE(host_hash, cve_id, model_version)
        );
        """
    )
    conn.commit()


def _load_model():
    if not MODEL_PATH.exists():
        LOG.warning(f"Model file not found at {MODEL_PATH}. Predictions will be deterministic fallbacks.")
        return None
    model = joblib.load(MODEL_PATH)
    LOG.info(f"Loaded model from {MODEL_PATH}")
    return model


def _fetch_candidates(host_hash: str) -> List[Dict[str, Any]]:
    """
    Fetch candidate CVEs/rows to rank from prioritization DB.
    Uses the risk_scores table (HARS output) as canonical source.
    """
    with _connect(PRIORITIZATION_DB) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT cve_id, final_score as hars_score,
                   cvss_score, epss_probability, exploited_flag, poc_flag,
                   ransomware_flag, patch_missing_flag, detection_confidence
            FROM risk_scores
            WHERE host_hash = ?
            AND entity_type = 'CVE'
            """,
            (host_hash,),
        )
        rows = [dict(r) for r in cur.fetchall()]
    return rows


def _build_feature_dataframe(rows: List[Dict[str, Any]]) -> pd.DataFrame:
    # Build DataFrame with FEATURE_COLUMNS; fill missing with sensible defaults.
    df = pd.DataFrame(rows)
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0
    # coerce to float
    df = df[FEATURE_COLUMNS + ["cve_id", "hars_score"]].copy()
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].astype(float).fillna(0.0)
    return df


def _explain_top_features(model, X_row: pd.Series, top_n: int = 3) -> List[str]:
    # Lightweight "explainability" without SHAP: show largest absolute contribution using feature * feature_importance
    try:
        if hasattr(model, "feature_importances_"):
            fi = model.feature_importances_
            feat_names = list(X_row.index)
            contributions = {feat: float(X_row[feat]) * float(fi[idx]) for idx, feat in enumerate(feat_names)}
            sorted_feats = sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)
            return [f"{k}={X_row[k]:.3g}" for k, _ in sorted_feats[:top_n]]
        else:
            # fallback: show top raw features
            vals = X_row.sort_values(ascending=False)
            return [f"{idx}={vals[idx]:.3g}" for idx in vals.index[:top_n]]
    except Exception as e:
        LOG.debug(f"Explain failed: {e}")
        return []


def rank_host_vulnerabilities(host_hash: str, persist: bool = True) -> Dict[str, Any]:
    """
    Main entrypoint: rank vulnerabilities for a given host_hash.
    Returns a dict with ranked_vulnerabilities list and metadata.
    """
    model = _load_model()
    candidates = _fetch_candidates(host_hash)
    if not candidates:
        return {"host_hash": host_hash, "ranked_vulnerabilities": [], "model_version": AI_MODEL_VERSION}

    df = _build_feature_dataframe(candidates)
    X = df[FEATURE_COLUMNS].values

    if model is None:
        # fallback: use hars_score as ml_score (identity) if no model
        ml_scores = df["hars_score"].values
    else:
        try:
            ml_preds = model.predict(X)
            # ensure normalized 0..1
            ml_scores = np.clip(ml_preds, 0.0, 1.0)
        except Exception as e:
            LOG.error(f"Model prediction failed: {e}")
            ml_scores = df["hars_score"].values

    # Fusion with deterministic hars_score
    hars_scores = df["hars_score"].astype(float).values
    final_scores = 0.7 * ml_scores + 0.3 * hars_scores

    # Build result rows
    results = []
    for i, row in df.iterrows():
        cve = row["cve_id"]
        ml = float(ml_scores[i])
        hars = float(hars_scores[i])
        final = float(final_scores[i])
        confidence = max(0.0, 1.0 - abs(ml - hars))  # simple proxy; closer => higher confidence
        top_feats = _explain_top_features(model, pd.Series(row[FEATURE_COLUMNS], index=FEATURE_COLUMNS)) if model else []
        results.append({
            "cve_id": cve,
            "ml_score": ml,
            "hars_score": hars,
            "final_score": final,
            "ml_confidence": confidence,
            "top_features": top_feats
        })

    # sort by final_score desc
    results_sorted = sorted(results, key=lambda r: r["final_score"], reverse=True)

    # assign ranks
    for idx, r in enumerate(results_sorted, start=1):
        r["ml_rank"] = idx

    # persist to prioritization DB ai_decisions table if requested
    if persist:
        with _connect(PRIORITIZATION_DB) as conn:
            _ensure_ai_table(conn)
            cur = conn.cursor()
            now = datetime.utcnow().isoformat()
            for r in results_sorted:
                try:
                    cur.execute(
                        """
                        INSERT OR REPLACE INTO ai_decisions
                        (host_hash, cve_id, ml_score, hars_score, final_score, ml_rank,
                         ml_confidence, top_features_json, model_version, inserted_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            host_hash,
                            r["cve_id"],
                            r["ml_score"],
                            r["hars_score"],
                            r["final_score"],
                            r["ml_rank"],
                            r["ml_confidence"],
                            json.dumps(r["top_features"]),
                            AI_MODEL_VERSION,
                            now
                        )
                    )
                except Exception as e:
                    LOG.error(f"Failed to persist ai_decision for {r['cve_id']}: {e}")
            conn.commit()

    return {
        "host_hash": host_hash,
        "model_version": AI_MODEL_VERSION,
        "ranked_vulnerabilities": results_sorted,
        "generated_at": datetime.utcnow().isoformat()
    }


# quick CLI
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI engine: rank host vulnerabilities")
    p.add_argument("--host-hash", required=True)
    p.add_argument("--no-persist", dest="persist", action="store_false", default=True)
    args = p.parse_args()
    out = rank_host_vulnerabilities(args.host_hash, persist=args.persist)
    print(json.dumps(out, indent=2))