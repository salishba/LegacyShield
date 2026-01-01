#script to generate training data for AI model from dev_db and mitigation catalogues  
import os
import sqlite3
from typing import List, Dict, Any
import json
import random   
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras

# Constants
DATA_DIR = "training_data"
DB_PATH = "ai_training_data.sqlite"
MODEL_PATH = "ai_model.h5"
BATCH_SIZE = 32
EPOCHS = 50
TEST_SIZE = 0.2
RANDOM_SEED = 42

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)
# -----------------------------
# DATA GENERATION
def generate_synthetic_data(num_samples: int) -> pd.DataFrame:
    data = {
        "feature1": np.random.rand(num_samples),
        "feature2": np.random.rand(num_samples),
        "feature3": np.random.rand(num_samples),
        "label": np.random.randint(0, 2, num_samples)
    }
    return pd.DataFrame(data)

def save_data_to_db(df: pd.DataFrame, db_path: str):
    conn = sqlite3.connect(db_path)
    df.to_sql("training_data", conn, if_exists="replace", index=False)
    conn.close()
    cat_cur.execute("SELECT kb_id, cvss_score, affected_os FROM patches")
    patches = cat_cur.fetchall()
    training_samples = []
    for patch in patches:
        kb_id, cvss_score, affected_os = patch
        if kb_id in installed_kbs:
            continue

        if system['os_version'] not in affected_os.split(','):
            continue

        supersedence_chain = resolve_supersedence(cat, kb_id)
        is_installed = any(kb in installed_kbs for kb in supersedence_chain)

        training_samples.append({
            "kb_id": kb_id,
            "cvss_score": cvss_score,
            "is_installed": int(is_installed)
        })
    cat.close()
    run.close()
    df = generate_synthetic_data(1000)
    save_data_to_db(df, DB_PATH)

