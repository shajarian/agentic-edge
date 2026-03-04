"""
Train the RandomForest classifiers used by the classify_flow agent tool.

Run once from the project root to produce model artifacts in results/models/:
    python -m code.train

Artifacts produced:
    results/models/rf_multiclass.joblib   — multi-class attack-type classifier
    results/models/rf_binary.joblib       — binary benign/attack gate
    results/models/scaler.joblib          — fitted StandardScaler
    results/models/feature_cols.json      — ordered feature column list
"""

import json
import time
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, f1_score,
)

# ── Paths ──────────────────────────────────────────────────────────────────
ROOT       = Path(__file__).resolve().parent.parent
BASE_PATH  = ROOT / "CIC_IoT_Dataset" / "Anomaly Detection - Flow Based features"
MODEL_DIR  = ROOT / "results" / "models"
FIGURE_DIR = ROOT / "results" / "figures"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
FIGURE_DIR.mkdir(parents=True, exist_ok=True)

# ── Dataset config ─────────────────────────────────────────────────────────
CATEGORIES          = ["Benign", "BruteForce", "DDoS", "DoS", "Mirai", "Recon", "Spoofing", "Web-Based"]
SAMPLE_PER_CATEGORY = 50_000
RANDOM_STATE        = 42

META_COLS  = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp"]
LABEL_COLS = ["Label", "attack_type", "label"]

# ── Artifact paths ─────────────────────────────────────────────────────────
MODEL_MULTICLASS = MODEL_DIR / "rf_multiclass.joblib"
MODEL_BINARY     = MODEL_DIR / "rf_binary.joblib"
SCALER_PATH      = MODEL_DIR / "scaler.joblib"
FEAT_COLS_PATH   = MODEL_DIR / "feature_cols.json"


def load_data() -> pd.DataFrame:
    """Load up to SAMPLE_PER_CATEGORY rows from each attack category."""
    file_list = []
    for cat in CATEGORIES:
        cat_dir = BASE_PATH / cat
        if not cat_dir.exists():
            print(f"  WARNING: {cat} folder not found — skipping")
            continue
        for p in cat_dir.rglob("*.csv"):
            file_list.append((p, cat))

    print(f"Total CSV files found: {len(file_list)}")
    frames = []

    for cat in CATEGORIES:
        cat_files = [p for p, c in file_list if c == cat]
        if not cat_files:
            continue

        cat_frames, rows_loaded = [], 0
        for csv_path in cat_files:
            if rows_loaded >= SAMPLE_PER_CATEGORY:
                break
            remaining = SAMPLE_PER_CATEGORY - rows_loaded
            chunk = pd.read_csv(csv_path, nrows=remaining, low_memory=False)
            chunk["attack_type"] = cat
            cat_frames.append(chunk)
            rows_loaded += len(chunk)

        if cat_frames:
            cat_df = pd.concat(cat_frames, ignore_index=True)
            frames.append(cat_df)
            print(f"  {cat:15s}  {len(cat_df):>7,} rows")

    data = pd.concat(frames, ignore_index=True)
    data["label"] = (data["attack_type"] != "Benign").astype(int)
    print(f"\nTotal rows: {len(data):,}  |  Columns: {len(data.columns)}")
    return data


def clean_data(data: pd.DataFrame, num_cols: list[str]) -> pd.DataFrame:
    """Replace ±inf with column finite max, then fill remaining NaN with 0."""
    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    for col in num_cols:
        finite_max = data[col].dropna().max()
        data[col] = data[col].fillna(finite_max).fillna(0)
    remaining = data[num_cols].isnull().sum().sum()
    print(f"Remaining NaN after cleaning: {remaining}")
    return data


def train(data: pd.DataFrame) -> tuple:
    """
    Feature engineering, train/test split, train both classifiers.
    Returns (rf_multi, rf_binary, scaler, feat_cols, X_test, y_test_m, y_test_b).
    """
    feat_cols = [c for c in data.columns if c not in META_COLS + LABEL_COLS]
    num_cols  = [c for c in feat_cols if data[c].dtype in [np.float64, np.float32, np.int64, np.int32]]

    data = clean_data(data, num_cols)

    # Engineered feature: SYN-to-FIN ratio (high ratio = SYN flood signal)
    if "SYN Flag Count" in data.columns and "FIN Flag Count" in data.columns:
        data["SYN_FIN_Ratio"] = data["SYN Flag Count"] / (data["FIN Flag Count"] + 1)
        if "SYN_FIN_Ratio" not in feat_cols:
            feat_cols.append("SYN_FIN_Ratio")
    print(f"Total features for training: {len(feat_cols)}")

    X        = data[feat_cols].values
    y_multi  = data["attack_type"].values
    y_binary = data["label"].values

    X_train, X_test, y_train_m, y_test_m, y_train_b, y_test_b = train_test_split(
        X, y_multi, y_binary,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y_multi,
    )
    print(f"Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # Fit scaler (RF is scale-invariant, but saved for future scale-aware models)
    scaler = StandardScaler()
    scaler.fit(X_train)

    # Multi-class classifier
    print("\nTraining multi-class RandomForest ...")
    t0 = time.time()
    rf_multi = RandomForestClassifier(
        n_estimators=200, class_weight="balanced", n_jobs=-1, random_state=RANDOM_STATE,
    )
    rf_multi.fit(X_train, y_train_m)
    print(f"  Done in {time.time() - t0:.1f}s")

    # Binary classifier
    print("Training binary RandomForest ...")
    t0 = time.time()
    rf_binary = RandomForestClassifier(
        n_estimators=200, class_weight="balanced", n_jobs=-1, random_state=RANDOM_STATE,
    )
    rf_binary.fit(X_train, y_train_b)
    print(f"  Done in {time.time() - t0:.1f}s")

    return rf_multi, rf_binary, scaler, feat_cols, X_test, y_test_m, y_test_b


def evaluate(rf_multi, rf_binary, X_test, y_test_m, y_test_b):
    """Print classification report and save confusion matrix + F1 bar chart."""
    y_pred_m = rf_multi.predict(X_test)
    y_pred_b = rf_binary.predict(X_test)

    print("\n" + "=" * 60)
    print("MULTI-CLASS CLASSIFICATION REPORT")
    print("=" * 60)
    print(classification_report(y_test_m, y_pred_m, digits=4))

    f1_mac = f1_score(y_test_m, y_pred_m, average="macro")
    f1_wt  = f1_score(y_test_m, y_pred_m, average="weighted")
    print(f"Macro F1    : {f1_mac:.4f}")
    print(f"Weighted F1 : {f1_wt:.4f}")
    print(f"Binary accuracy: {accuracy_score(y_test_b, y_pred_b):.4f}")

    # Confusion matrix
    cm = confusion_matrix(y_test_m, y_pred_m, labels=rf_multi.classes_)
    fig, ax = plt.subplots(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=rf_multi.classes_, yticklabels=rf_multi.classes_, ax=ax)
    ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    ax.set_title("Confusion Matrix — Multi-class RandomForest", fontweight="bold")
    plt.tight_layout()
    plt.savefig(FIGURE_DIR / "confusion_matrix.png", dpi=150, bbox_inches="tight")
    plt.close()

    # Per-class F1 bar chart
    per_class_f1 = f1_score(y_test_m, y_pred_m, average=None, labels=rf_multi.classes_)
    fig, ax = plt.subplots(figsize=(10, 4))
    colors = ["#E53935" if f < 0.85 else "#43A047" for f in per_class_f1]
    ax.bar(rf_multi.classes_, per_class_f1, color=colors)
    ax.axhline(0.85, color="gray", linestyle="--", label="F1 = 0.85 threshold")
    ax.set_ylim(0, 1.05); ax.set_ylabel("F1 Score")
    ax.set_title("Per-Class F1 Score", fontweight="bold")
    ax.tick_params(axis="x", rotation=30); ax.legend()
    plt.tight_layout()
    plt.savefig(FIGURE_DIR / "per_class_f1.png", dpi=150, bbox_inches="tight")
    plt.close()

    print(f"\nFigures saved to {FIGURE_DIR}")


def save_artifacts(rf_multi, rf_binary, scaler, feat_cols):
    """Persist model artifacts to results/models/."""
    joblib.dump(rf_multi,  MODEL_MULTICLASS)
    joblib.dump(rf_binary, MODEL_BINARY)
    joblib.dump(scaler,    SCALER_PATH)
    with open(FEAT_COLS_PATH, "w") as f:
        json.dump(feat_cols, f, indent=2)

    print("\nSaved artifacts:")
    for path in [MODEL_MULTICLASS, MODEL_BINARY, SCALER_PATH, FEAT_COLS_PATH]:
        size_mb = path.stat().st_size / 1_048_576
        print(f"  {path.name:30s}  {size_mb:.2f} MB")


def smoke_test(feat_cols):
    """Basic assertion check to verify saved models load correctly."""
    # Reload models and test a high-SYN flow (should be flagged as attack)
    rf_multi = joblib.load(MODEL_MULTICLASS)
    rf_binary = joblib.load(MODEL_BINARY)
    
    dos_flow = {col: 0.0 for col in feat_cols}
    dos_flow["SYN Flag Count"] = 500
    dos_flow["FIN Flag Count"] = 0
    dos_flow["Flow Packets/s"] = 50_000
    dos_flow["SYN_FIN_Ratio"] = 500.0  # High ratio indicates SYN flood
    
    X = np.array([[dos_flow.get(col, 0.0) for col in feat_cols]]).reshape(1, -1)
    is_attack = int(rf_binary.predict(X)[0]) == 1
    
    assert is_attack, "Smoke test failed — high-SYN flow not flagged as attack"
    print("\nSmoke test passed — high-SYN flow correctly flagged as attack.")


if __name__ == "__main__":
    print("=" * 60)
    print("Agentic Edge — Classifier Training")
    print("=" * 60)

    data = load_data()
    rf_multi, rf_binary, scaler, feat_cols, X_test, y_test_m, y_test_b = train(data)
    evaluate(rf_multi, rf_binary, X_test, y_test_m, y_test_b)
    save_artifacts(rf_multi, rf_binary, scaler, feat_cols)
    smoke_test(feat_cols)

    print("\nDone. Run the monitoring agent with: python -m code.agents.incident_manager")
