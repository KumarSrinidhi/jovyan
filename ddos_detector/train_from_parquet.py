"""Train LightGBM models from CIC collection parquet without notebook edits.

Usage example:
    /home/jovyan/.venv/bin/python train_from_parquet.py \
        --file-path cic-collection.parquet \
        --dataset dhoogla/cicidscollection \
        --output-dir model \
        --max-rows 300000
"""

from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path
from typing import Tuple

import kagglehub
import numpy as np
import pandas as pd
from kagglehub import KaggleDatasetAdapter
from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


def parse_args() -> argparse.Namespace:
    """Parse CLI args."""
    parser = argparse.ArgumentParser(description="Train LightGBM from cic-collection.parquet")
    parser.add_argument("--dataset", type=str, default="dhoogla/cicidscollection")
    parser.add_argument("--file-path", type=str, default="cic-collection.parquet")
    parser.add_argument("--output-dir", type=str, default="model")
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--max-rows", type=int, default=0, help="0 means use full dataset")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--val-size", type=float, default=0.5, help="Applied to temp split")
    parser.add_argument("--n-estimators", type=int, default=500)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    return parser.parse_args()


def load_dataframe(dataset: str, file_path: str) -> pd.DataFrame:
    """Load parquet from KaggleHub as pandas DataFrame."""
    df = kagglehub.load_dataset(
        KaggleDatasetAdapter.PANDAS,
        dataset,
        file_path,
        pandas_kwargs={"engine": "pyarrow"},
    )
    return df


def preprocess_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Apply basic cleaning compatible with existing notebook workflow."""
    out = df.copy()
    out.columns = (
        out.columns.str.strip().str.lower().str.replace(" ", "_", regex=False).str.replace("(", "", regex=False).str.replace(")", "", regex=False)
    )

    required = {"label", "classlabel"}
    missing = required - set(out.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    numeric_cols = out.select_dtypes(include=[np.number]).columns
    out[numeric_cols] = out[numeric_cols].replace([np.inf, -np.inf], np.nan)
    out = out.dropna(axis=0)

    label_cols = ["label", "classlabel"]
    constant_cols = [c for c in out.columns if c not in label_cols and out[c].nunique(dropna=False) <= 1]
    if constant_cols:
        out = out.drop(columns=constant_cols)

    return out


def split_data(
    df: pd.DataFrame,
    random_state: int,
    test_size: float,
    val_size: float,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series, pd.Series, pd.Series, pd.Series, LabelEncoder]:
    """Create train/val/test for both binary and multiclass tasks."""
    y_bin = df["classlabel"].apply(lambda x: 0 if str(x) == "Benign" else 1)

    le = LabelEncoder()
    y_multi = pd.Series(le.fit_transform(df["classlabel"]), index=df.index)

    x = df.drop(columns=["label", "classlabel"], errors="ignore")

    x_train, x_temp, y_train_bin, y_temp_bin = train_test_split(
        x,
        y_bin,
        test_size=test_size,
        stratify=y_bin,
        random_state=random_state,
    )
    x_val, x_test, y_val_bin, y_test_bin = train_test_split(
        x_temp,
        y_temp_bin,
        test_size=val_size,
        stratify=y_temp_bin,
        random_state=random_state,
    )

    y_train_multi = y_multi.loc[x_train.index]
    y_val_multi = y_multi.loc[x_val.index]
    y_test_multi = y_multi.loc[x_test.index]

    return (
        x_train,
        x_val,
        x_test,
        y_train_bin,
        y_val_bin,
        y_test_bin,
        y_train_multi,
        y_val_multi,
        y_test_multi,
        le,
    )


def train_binary(
    x_train: pd.DataFrame,
    y_train: pd.Series,
    x_val: pd.DataFrame,
    y_val: pd.Series,
    n_estimators: int,
    learning_rate: float,
    random_state: int,
) -> LGBMClassifier:
    """Train binary LightGBM classifier."""
    pos = int((y_train == 1).sum())
    neg = int((y_train == 0).sum())
    scale_pos_weight = (neg / pos) if pos > 0 else 1.0

    model = LGBMClassifier(
        objective="binary",
        n_estimators=n_estimators,
        learning_rate=learning_rate,
        num_leaves=64,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(
        x_train,
        y_train,
        eval_set=[(x_val, y_val)],
        eval_metric="auc",
        callbacks=[],
    )
    return model


def train_multiclass(
    x_train: pd.DataFrame,
    y_train: pd.Series,
    x_val: pd.DataFrame,
    y_val: pd.Series,
    n_estimators: int,
    learning_rate: float,
    random_state: int,
) -> LGBMClassifier:
    """Train multiclass LightGBM classifier."""
    num_class = int(y_train.nunique())
    model = LGBMClassifier(
        objective="multiclass",
        num_class=num_class,
        n_estimators=n_estimators,
        learning_rate=learning_rate,
        num_leaves=128,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(
        x_train,
        y_train,
        eval_set=[(x_val, y_val)],
        eval_metric="multi_logloss",
        callbacks=[],
    )
    return model


def main() -> None:
    """Run full training and export artifacts."""
    args = parse_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading dataset {args.dataset} -> {args.file_path}")
    df = load_dataframe(args.dataset, args.file_path)
    print(f"Raw shape: {df.shape}")

    df = preprocess_dataframe(df)
    print(f"After cleaning: {df.shape}")

    if args.max_rows and args.max_rows > 0 and len(df) > args.max_rows:
        df = df.sample(n=args.max_rows, random_state=args.random_state)
        print(f"Using sampled subset: {df.shape}")

    (
        x_train,
        x_val,
        x_test,
        y_train_bin,
        y_val_bin,
        y_test_bin,
        y_train_multi,
        y_val_multi,
        y_test_multi,
        le,
    ) = split_data(df, args.random_state, args.test_size, args.val_size)

    feature_names = x_train.columns.tolist()
    with (out_dir / "features.json").open("w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2)

    print("Training binary LightGBM...")
    binary_model = train_binary(
        x_train,
        y_train_bin,
        x_val,
        y_val_bin,
        args.n_estimators,
        args.learning_rate,
        args.random_state,
    )

    bin_prob = binary_model.predict_proba(x_test)[:, 1]
    bin_pred = (bin_prob >= 0.5).astype(int)
    print(f"Binary Test AUC: {roc_auc_score(y_test_bin, bin_prob):.5f}")
    print(f"Binary Test F1 : {f1_score(y_test_bin, bin_pred):.5f}")

    print("Training multiclass LightGBM...")
    multi_model = train_multiclass(
        x_train,
        y_train_multi,
        x_val,
        y_val_multi,
        args.n_estimators,
        args.learning_rate,
        args.random_state,
    )

    multi_pred = multi_model.predict(x_test)
    print(f"Multiclass Macro F1   : {f1_score(y_test_multi, multi_pred, average='macro'):.5f}")
    print(f"Multiclass Weighted F1: {f1_score(y_test_multi, multi_pred, average='weighted'):.5f}")
    print(classification_report(y_test_multi, multi_pred, target_names=le.classes_))

    with (out_dir / "lgbm_binary_model.pkl").open("wb") as f:
        pickle.dump(binary_model, f)
    with (out_dir / "lgbm_multiclass_model.pkl").open("wb") as f:
        pickle.dump(multi_model, f)
    with (out_dir / "label_encoder.pkl").open("wb") as f:
        pickle.dump(le, f)

    # Default detector artifact points to multiclass model; override with --model-path for binary.
    with (out_dir / "lgbm_model.pkl").open("wb") as f:
        pickle.dump(multi_model, f)

    print(f"Artifacts written to: {out_dir.resolve()}")
    print("- features.json")
    print("- lgbm_binary_model.pkl")
    print("- lgbm_multiclass_model.pkl")
    print("- lgbm_model.pkl (default multiclass)")
    print("- label_encoder.pkl")


if __name__ == "__main__":
    main()
