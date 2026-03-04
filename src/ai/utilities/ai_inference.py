# ai_inference.py
import joblib
import sqlite3
import numpy as np
import pandas as pd
from datetime import datetime

MODEL_PATH = "models/ai_recommender.pkl"
DB_PATH = "path/to/runtime.sqlite"
MODEL_VERSION = "rf_v1"

model = joblib.load(MODEL_PATH)

def infer_and_write(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Select recent findings without derived_vulnerabilities entry
    q = """
    SELECT f.finding_id, f.cve_id, f.description, f.host_hash
    FROM raw_security_findings f
    LEFT JOIN derived_vulnerabilities dv ON dv.derived_from_finding_id = f.finding_id
    WHERE dv.vuln_id IS NULL AND f.cve_id IS NOT NULL
    """
    rows = cursor.execute(q).fetchall()
    if not rows:
        conn.close()
        return

    # Build df with the same features used in training
    import ai_features
    df_all = ai_features.load_features_from_db(db_path)
    # filter to rows we need
    finding_ids = [r['finding_id'] for r in rows]
    df = df_all[df_all['finding_id'].isin(finding_ids)].copy()
    df_prepped = prepare_inference_df(df)  # same prep logic as to training (function below)

    # predict probabilities
    probs = model.predict_proba(df_prepped)
    preds = model.predict(df_prepped)
    classes = model.classes_

    # map to remediation suggestions
    for idx, finding_id in enumerate(df['finding_id'].tolist()):
        pred = preds[idx]
        prob_arr = probs[idx]
        # confidence = top probability
        top_p = float(np.max(prob_arr))
        # compose reasoning string
        reasoning = generate_explanation(df.iloc[idx], model, prob_arr, classes, top_p)
        # insert derived_vulnerabilities
        cursor.execute("""
            INSERT INTO derived_vulnerabilities (cve_id, confidence_score, derived_from_finding_id, reasoning, model_version, host_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            df.iloc[idx]['cve_id'],
            top_p,
            finding_id,
            reasoning,
            MODEL_VERSION,
            df.iloc[idx]['host_hash']
        ))
        vuln_rowid = cursor.lastrowid

        # map predicted label -> mitigation type & text (simple mapping; extend with RecommendationEngine)
        mitigation_map = {
            'Immediate': ('IMMEDIATE_PATCH', 'Recommend immediate patch: follow KB/patch instructions'),
            'Soon': ('SCHEDULE_PATCH', 'Schedule patch in next maintenance window'),
            'Monitor': ('MONITOR', 'Monitor and collect telemetry')
        }
        mitig_type, text = mitigation_map.get(pred, ('INVESTIGATE', 'Manual review required'))

        cursor.execute("""
            INSERT INTO derived_mitigations (vuln_id, mitigation_type, recommendation, reversible, requires_reboot, confidence_score, model_version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (vuln_rowid, mitig_type, text, 1, 0, top_p, MODEL_VERSION))

        # Optionally insert/update hars_scores table with ML-assisted final_score
        # Use deterministic HARS final_score if present + ML confidence to compute adjusted final_score
        final_score = float(df.iloc[idx].get('final_score') or 0.0)
        # small blend: blended_score = 0.8 * final_score + 0.2 * top_p
        blended = min(1.0, 0.8 * final_score + 0.2 * top_p)
        # priority mapping
        priority = 'HIGH' if blended >= 0.7 else ('MEDIUM' if blended>=0.35 else 'LOW')
        cursor.execute("""
            INSERT INTO hars_scores (finding_id, cve_id, a_score, r_score, c_score, final_score, priority, scoring_model)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (finding_id, df.iloc[idx]['cve_id'], df.iloc[idx].get('a_score') or 0.0,
              df.iloc[idx].get('r_score') or 0.0, df.iloc[idx].get('c_score') or 0.0,
              blended, priority, MODEL_VERSION))
    conn.commit()
    conn.close()

# helper functions used above
def prepare_inference_df(df: pd.DataFrame) -> pd.DataFrame:
    # replicate the exact column order & transformations used in training
    df = df.copy()
    df['installed_kb_count'] = df['installed_kb_count'].fillna(0).astype(int)
    df['critical_findings_on_host'] = df['critical_findings_on_host'].fillna(0).astype(int)
    df['patch_available'] = df['patch_state'].apply(lambda s: 0 if s in (None, 'UNKNOWN','NOT_APPLICABLE') else 1)
    conf_map = {'HIGH':1.0,'MEDIUM':0.7,'LOW':0.4}
    df['patch_confidence'] = df['patch_confidence_text'].map(conf_map).fillna(0.5)
    cat_features = ['finding_type', 'patch_state', 'source_scanner', 'os_version']
    num_features = ['r_score','a_score','c_score','final_score','installed_kb_count','critical_findings_on_host','patch_confidence']
    X = df[cat_features + num_features]
    return X

def generate_explanation(row, model, prob_arr, classes, top_p):
    # simple explanation: HARS breakdown + top model features contribution
    # get most probable class and probability
    top_idx = prob_arr.argmax()
    top_label = classes[top_idx]
    # feature importance from RF (if available)
    try:
        import numpy as np
        # model is a pipeline; get clf
        clf = model.named_steps['clf']
        pre = model.named_steps['pre']
        # get feature names
        ohe = pre.named_transformers_['cat']
        cat_names = ohe.get_feature_names_out().tolist() if hasattr(ohe, 'get_feature_names_out') else []
        numeric_names = ['r_score','a_score','c_score','final_score','installed_kb_count','critical_findings_on_host','patch_confidence']
        feat_names = list(cat_names) + numeric_names
        importances = clf.feature_importances_
        # pick top numeric contributions intersection
        imp_pairs = sorted(zip(feat_names, importances), key=lambda x: -x[1])
        top_feats = ', '.join([f"{k}" for k,_ in imp_pairs[:3]])
    except Exception:
        top_feats = "feature importance unavailable"

    hars_parts = []
    for k in ['r_score','a_score','c_score','final_score']:
        if k in row and row[k] is not None:
            hars_parts.append(f"{k}={row[k]:.2f}")
    hars_text = "; ".join(hars_parts) if hars_parts else "HARS not available"

    explanation = (f"Model recommends: {top_label} (confidence {top_p:.2%}). "
                   f"HARS: {hars_text}. Top features: {top_feats}. "
                   f"Description excerpt: {row.get('description', '')[:200]}")

    return explanation