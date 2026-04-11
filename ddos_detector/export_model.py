"""Export LightGBM model artifacts for runtime detector usage.

This script can be used in two ways:
1) Imported in a notebook and called with in-memory objects.
2) Executed as a CLI to package existing model/features files.
"""

from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path
from typing import Any, Iterable, Optional

import lightgbm as lgb


def export_from_objects(
    model: Any,
    feature_names: Iterable[str],
    output_dir: str,
    label_encoder: Optional[Any] = None,
) -> None:
    """Export model, ordered feature list, and optional label encoder.

    Args:
        model: Trained model object (LGBMClassifier, Booster, sklearn wrapper).
        feature_names: Ordered feature names exactly used during training.
        output_dir: Destination folder.
        label_encoder: Optional sklearn LabelEncoder for multiclass decoding.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    model_path = out / "lgbm_model.pkl"
    with model_path.open("wb") as f:
        pickle.dump(model, f)

    features_path = out / "features.json"
    with features_path.open("w", encoding="utf-8") as f:
        json.dump(list(feature_names), f, indent=2)

    if label_encoder is not None:
        le_path = out / "label_encoder.pkl"
        with le_path.open("wb") as f:
            pickle.dump(label_encoder, f)



def _load_model_for_cli(model_input: str) -> Any:
    model_file = Path(model_input)
    suffix = model_file.suffix.lower()

    if suffix in {".txt", ".json", ".model"}:
        return lgb.Booster(model_file=str(model_file))

    with model_file.open("rb") as f:
        return pickle.load(f)



def _load_features_for_cli(features_input: str) -> list[str]:
    p = Path(features_input)
    text = p.read_text(encoding="utf-8").strip()

    if p.suffix.lower() == ".json":
        data = json.loads(text)
        if isinstance(data, dict) and "features" in data:
            data = data["features"]
        if not isinstance(data, list):
            raise ValueError("JSON features file must be a list or {'features': [...]}.")
        return [str(x) for x in data]

    # Fallback: newline-delimited feature names.
    return [line.strip() for line in text.splitlines() if line.strip()]



def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Export detector artifacts")
    parser.add_argument("--model-input", type=str, required=True, help="Input model file (.pkl/.txt/.json)")
    parser.add_argument("--features-input", type=str, required=True, help="Feature names file (.json or .txt)")
    parser.add_argument("--output-dir", type=str, default="model", help="Output directory")
    parser.add_argument(
        "--label-encoder-input",
        type=str,
        default=None,
        help="Optional pickle file containing fitted LabelEncoder",
    )
    return parser.parse_args()



def main() -> None:
    """CLI entrypoint for artifact export."""
    args = parse_args()

    model = _load_model_for_cli(args.model_input)
    features = _load_features_for_cli(args.features_input)

    label_encoder = None
    if args.label_encoder_input:
        with open(args.label_encoder_input, "rb") as f:
            label_encoder = pickle.load(f)

    export_from_objects(
        model=model,
        feature_names=features,
        output_dir=args.output_dir,
        label_encoder=label_encoder,
    )

    print(f"Exported lgbm_model.pkl and features.json to: {args.output_dir}")
    if label_encoder is not None:
        print("Exported label_encoder.pkl")


if __name__ == "__main__":
    main()
