# train_model.py
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix

from ai_features import load_features_from_db

DB_PATH = "path/to/runtime.sqlite"
MODEL_OUT = "models/ai_recommender.pkl"
ENC_OUT = "models/encoders.joblib"

def prepare_training_df(df: pd.DataFrame) -> pd.DataFrame:
    # Basic cleaning
    df = df.copy()
    # fillna for numeric fields
    for col in ['r_score','a_score','c_score','final_score']:
        if col in df.columns:
            df[col] = df[col].fillna(0.0)
    df['installed_kb_count'] = df['installed_kb_count'].fillna(0).astype(int)
    df['critical_findings_on_host'] = df['critical_findings_on_host'].fillna(0).astype(int)
    # derive patch_available and patch_confidence numeric
    df['patch_available'] = df['patch_state'].apply(lambda s: 0 if s in (None, 'UNKNOWN','NOT_APPLICABLE') else 1)
    # convert patch_confidence_text => numeric
    conf_map = {'HIGH':1.0,'MEDIUM':0.7,'LOW':0.4}
    df['patch_confidence'] = df['patch_confidence_text'].map(conf_map).fillna(0.5)
    # label column: use hars if present
    df['label'] = df['final_score'].apply(lambda x: 'Immediate' if x>=0.70 else ('Soon' if x>=0.35 else 'Monitor'))
    return df

def train():
    df = load_features_from_db(DB_PATH)
    df = prepare_training_df(df)
    # select features
    cat_features = ['finding_type', 'patch_state', 'source_scanner', 'os_version']
    num_features = ['r_score','a_score','c_score','final_score','installed_kb_count','critical_findings_on_host','patch_confidence']
    X = df[cat_features + num_features]
    y = df['label']

    # train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # pipeline: one-hot encode categorical
    pre = ColumnTransformer(transformers=[
        ('cat', OneHotEncoder(handle_unknown='ignore', sparse=False), cat_features)
    ], remainder='passthrough')

    pipeline = Pipeline([
        ('pre', pre),
        ('clf', RandomForestClassifier(n_estimators=200, random_state=42, class_weight='balanced'))
    ])

    pipeline.fit(X_train, y_train)

    # evaluation
    preds = pipeline.predict(X_test)
    print("Classification report:\n", classification_report(y_test, preds))
    print("Confusion matrix:\n", confusion_matrix(y_test, preds))

    # cross-val
    scores = cross_val_score(pipeline, X, y, cv=5, scoring='f1_macro')
    print("5-fold F1 macro:", scores.mean())

    # save model
    joblib.dump(pipeline, MODEL_OUT)
    print("Saved model:", MODEL_OUT)

if __name__ == "__main__":
    train()