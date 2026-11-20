#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import (
    RandomForestClassifier,
    IsolationForest,
    HistGradientBoostingClassifier
)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


def load_dataset(path):
    path = Path(path)

    if path.suffix == ".parquet":
        return pd.read_parquet(path)

    if path.suffix == ".csv":
        return pd.read_csv(path)

    return pd.read_json(path, lines=True)


def prepare_dataframe(df, labeled_only=True):
    df = df.copy()

    required = [
        "full_log",
        "rule_level",
        "agent_name",
        "rule_id",
        "multi_class_label",
        "binary_label",
        "confidence",
        "correlation_status"
    ]

    for col in required:
        if col not in df.columns:
            df[col] = ""

    df["full_log"] = df["full_log"].fillna("").astype(str)

    df["rule_level"] = pd.to_numeric(
        df["rule_level"], errors="coerce"
    ).fillna(0)

    for col in ["agent_name", "rule_id", "correlation_status"]:
        df[col] = df[col].fillna("unknown").astype(str)

    df["binary_label"] = df["binary_label"].fillna("unlabeled")

    # Supervised training hanya memakai label terverifikasi.
    if labeled_only:
        df = df[
            df["binary_label"].isin(["benign", "malicious"])
        ].copy()

    return df


def make_supervised_pipeline(model):
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "text",
                TfidfVectorizer(
                    max_features=2000,
                    ngram_range=(1, 2)
                ),
                "full_log"
            ),
            (
                "num",
                StandardScaler(),
                ["rule_level"]
            ),
            (
                "cat",
                OneHotEncoder(
                    handle_unknown="ignore",
                    sparse_output=False
                ),
                ["agent_name", "rule_id", "correlation_status"]
            )
        ],
        sparse_threshold=0.0
    )

    return Pipeline(
        steps=[
            ("features", preprocessor),
            ("model", model)
        ]
    )


def false_rates(cm):
    if cm.shape != (2, 2):
        return {
            "false_positive_rate": None,
            "false_negative_rate": None
        }

    tn, fp, fn, tp = cm.ravel()

    return {
        "false_positive_rate": round(
            fp / (fp + tn), 4
        ) if fp + tn else 0.0,
        "false_negative_rate": round(
            fn / (fn + tp), 4
        ) if fn + tp else 0.0
    }


def train_supervised_models(df, outdir):
    X = df[
        [
            "full_log",
            "rule_level",
            "agent_name",
            "rule_id",
            "correlation_status"
        ]
    ]

    y = df["binary_label"]

    label_counts = y.value_counts().to_dict()

    # Jangan memaksakan training jika kelas minoritas
    # belum memiliki cukup sampel.
    if len(label_counts) < 2 or min(label_counts.values()) < 2:
        return {
            "status": "skipped",
            "reason": (
                "Minimal dua sampel per kelas diperlukan "
                "untuk supervised train/test split."
            ),
            "label_distribution": label_counts
        }

    test_size = 0.3 if len(df) >= 20 else 0.5

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=42,
        stratify=y
    )

    models = {
        "logistic_regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced"
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            random_state=42
        )
    }

    results = {}
    labels = ["benign", "malicious"]

    for name, model in models.items():
        try:
            pipe = make_supervised_pipeline(model)
            pipe.fit(X_train, y_train)

            pred = pipe.predict(X_test)

            cm = confusion_matrix(
                y_test, pred, labels=labels
            )

            report = classification_report(
                y_test,
                pred,
                labels=labels,
                output_dict=True,
                zero_division=0
            )

            results[name] = {
                "status": "trained",
                "labels": labels,
                "confusion_matrix": cm.tolist(),
                "classification_report": report,
                **false_rates(cm),
                "train_records": len(X_train),
                "test_records": len(X_test)
            }

            joblib.dump(pipe, outdir / f"{name}.joblib")

        except Exception as e:
            results[name] = {
                "status": "failed",
                "error": str(e)
            }

    return {
        "status": "completed",
        "models": results
    }


def train_isolation_forest(df, outdir):
    if len(df) < 2:
        return {
            "status": "skipped",
            "reason": "Insufficient records"
        }

    features = pd.DataFrame({
        "rule_level": pd.to_numeric(
            df["rule_level"], errors="coerce"
        ).fillna(0),
        "full_log_length": df["full_log"].str.len()
    })

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42
    )

    model.fit(features)

    scores = model.decision_function(features)
    pred = model.predict(features)

    result = {
        "status": "trained",
        "records": len(df),
        "score_min": float(scores.min()),
        "score_max": float(scores.max()),
        "anomaly_count": int((pred == -1).sum()),
        "normal_count": int((pred == 1).sum()),
        "note": (
            "Isolation Forest merupakan anomaly baseline, "
            "bukan classifier final."
        )
    }

    joblib.dump(
        model,
        outdir / "isolation_forest.joblib"
    )

    return result


def rule_based_baseline(df):
    if df.empty:
        return {"status": "skipped"}

    y_true = df["binary_label"]

    y_pred = df["rule_level"].apply(
        lambda x: "malicious" if x >= 7 else "benign"
    )

    labels = ["benign", "malicious"]

    cm = confusion_matrix(
        y_true, y_pred, labels=labels
    )

    report = classification_report(
        y_true,
        y_pred,
        labels=labels,
        output_dict=True,
        zero_division=0
    )

    return {
        "status": "evaluated",
        "rule": "rule_level >= 7 -> malicious else benign",
        "labels": labels,
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
        **false_rates(cm)
    }


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--dataset",
        default="datasets/final/dataset.parquet"
    )

    parser.add_argument(
        "--output-dir",
        default="models"
    )

    parser.add_argument(
        "--report",
        default="reports/final/model_baseline_report.json"
    )

    args = parser.parse_args()

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    raw_df = load_dataset(args.dataset)
    df = prepare_dataframe(raw_df, labeled_only=True)
    all_df = prepare_dataframe(raw_df, labeled_only=False)

    results = {
        "dataset": args.dataset,
        "dataset_records": len(all_df),
        "records_used": len(df),
        "label_distribution": (
            df["binary_label"].value_counts().to_dict()
        ),
        "supervised_models": train_supervised_models(
            df, outdir
        ),
        "isolation_forest": train_isolation_forest(
            all_df, outdir
        ),
        "rule_based_baseline": rule_based_baseline(df)
    }

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    report_path.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
