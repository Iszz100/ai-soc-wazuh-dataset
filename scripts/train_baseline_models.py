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
from sklearn.metrics import classification_report, confusion_matrix
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


def prepare_dataframe(df):
    df = df.copy()

    required = [
        "full_log", "rule_level", "agent_name", "rule_id",
        "multi_class_label", "binary_label", "confidence",
        "correlation_status"
    ]

    for col in required:
        if col not in df.columns:
            df[col] = None

    df["full_log"] = df["full_log"].fillna("").astype(str)
    df["rule_level"] = pd.to_numeric(
        df["rule_level"], errors="coerce"
    )
    df["agent_name"] = df["agent_name"].fillna("unknown")
    df["rule_id"] = df["rule_id"].fillna("unknown").astype(str)
    df["correlation_status"] = (
        df["correlation_status"].fillna("unknown")
    )
    df["binary_label"] = df["binary_label"].fillna("unlabeled")

    return df[
        df["binary_label"].isin(["benign", "malicious"])
    ].copy()


def make_supervised_pipeline(model):
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "text",
                TfidfVectorizer(max_features=2000, ngram_range=(1, 2)),
                "full_log"
            ),
            ("num", StandardScaler(), ["rule_level"]),
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore"),
                ["agent_name", "rule_id", "correlation_status"]
            )
        ],
        sparse_threshold=0.0
    )

    return Pipeline([
        ("features", preprocessor),
        ("model", model)
    ])


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
        ) if fp + tn else None,
        "false_negative_rate": round(
            fn / (fn + tp), 4
        ) if fn + tp else None
    }


def train_supervised_models(df, outdir):
    X = df[
        ["full_log", "rule_level", "agent_name",
         "rule_id", "correlation_status"]
    ].copy()

    X["rule_level"] = X["rule_level"].fillna(0)
    y = df["binary_label"]

    counts = y.value_counts()

    if len(counts) < 2 or min(counts.values) < 2:
        reason = (
            "Skipped: each class needs at least two records "
            "for a meaningful stratified split."
        )
        return {
            name: {"status": "skipped", "reason": reason}
            for name in [
                "logistic_regression",
                "random_forest",
                "hist_gradient_boosting"
            ]
        }

    test_size = 0.3 if len(df) >= 20 else 0.5

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=42,
        stratify=y
    )

    models = {
        "logistic_regression": LogisticRegression(
            max_iter=1000, class_weight="balanced"
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

    for name, model in models.items():
        try:
            pipe = make_supervised_pipeline(model)
            pipe.fit(X_train, y_train)
            pred = pipe.predict(X_test)

            labels = ["benign", "malicious"]
            cm = confusion_matrix(y_test, pred, labels=labels)
            report = classification_report(
                y_test, pred,
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

        except Exception as exc:
            results[name] = {
                "status": "failed",
                "reason": str(exc)
            }

    return results


def train_isolation_forest(df, outdir):
    features = pd.DataFrame({
        "rule_level": df["rule_level"].fillna(0),
        "full_log_length": df["full_log"].str.len()
    })

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42
    )

    model.fit(features)
    scores = model.decision_function(features)
    predictions = model.predict(features)

    joblib.dump(model, outdir / "isolation_forest.joblib")

    return {
        "status": "trained_exploratory",
        "records": len(df),
        "score_min": float(scores.min()),
        "score_max": float(scores.max()),
        "anomaly_count": int((predictions == -1).sum()),
        "normal_count": int((predictions == 1).sum()),
        "note": (
            "Anomaly baseline only; small sample and not "
            "a production classifier."
        )
    }


def rule_based_baseline(df):
    evaluated = df[df["rule_level"].notna()].copy()

    if evaluated.empty:
        return {
            "status": "not_evaluable",
            "rule": "rule_level >= 7 -> malicious else benign",
            "records": len(df),
            "records_with_rule_level": 0,
            "note": (
                "Labeled Ground Truth records have no Wazuh "
                "rule_level. Performance metrics are not claimed."
            )
        }

    y_true = evaluated["binary_label"]
    y_pred = evaluated["rule_level"].apply(
        lambda x: "malicious" if x >= 7 else "benign"
    )

    labels = ["benign", "malicious"]
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    return {
        "status": "evaluated",
        "rule": "rule_level >= 7 -> malicious else benign",
        "confusion_matrix": cm.tolist(),
        "classification_report": classification_report(
            y_true, y_pred,
            labels=labels,
            output_dict=True,
            zero_division=0
        ),
        **false_rates(cm)
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset", default="datasets/final/dataset.parquet"
    )
    parser.add_argument("--output-dir", default="models")
    parser.add_argument(
        "--report",
        default="reports/final/model_baseline_report.json"
    )
    args = parser.parse_args()

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = prepare_dataframe(load_dataset(args.dataset))

    results = {
        "dataset": args.dataset,
        "records_used": len(df),
        "label_distribution": {
            str(k): int(v)
            for k, v in df["binary_label"].value_counts().items()
        },
        "supervised_models": train_supervised_models(df, outdir),
        "isolation_forest": (
            train_isolation_forest(df, outdir)
            if len(df) >= 2 else {"status": "skipped"}
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
