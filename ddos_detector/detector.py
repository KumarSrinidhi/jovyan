"""Model loading and flow-level inference for LightGBM artifacts."""

from __future__ import annotations

import json
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd


@dataclass
class PredictionResult:
    """Normalized prediction payload for alerting and logging."""

    label: str
    confidence: float
    is_attack: bool
    top_probabilities: Dict[str, float]


class LGBMFlowDetector:
    """Load model artifacts and perform binary/multiclass inference."""

    def __init__(
        self,
        model_path: str,
        features_path: str,
        mode: str,
        threshold: float = 0.5,
        label_encoder_path: Optional[str] = None,
    ) -> None:
        self.mode = mode.lower().strip()
        if self.mode not in {"binary", "multiclass"}:
            raise ValueError("mode must be 'binary' or 'multiclass'")

        self.threshold = float(threshold)
        self.model = self._load_pickle(model_path)
        self.feature_names = self._load_features(features_path)
        self.label_encoder = self._load_pickle(label_encoder_path) if label_encoder_path else None

    @staticmethod
    def _load_pickle(path: Optional[str]) -> Any:
        if not path:
            return None
        with open(path, "rb") as f:
            return pickle.load(f)

    @staticmethod
    def _load_features(path: str) -> List[str]:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and "features" in data:
            data = data["features"]
        if not isinstance(data, list):
            raise ValueError("features.json must be a list or {'features': [...]}.")
        return [str(item) for item in data]

    def _prepare_row(self, features: Dict[str, float]) -> pd.DataFrame:
        row = {name: float(features.get(name, 0.0)) for name in self.feature_names}
        return pd.DataFrame([row], columns=self.feature_names)

    def _predict_proba(self, row: pd.DataFrame) -> np.ndarray:
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(row)
            return np.asarray(proba)

        if hasattr(self.model, "predict"):
            pred = self.model.predict(row)
            pred_arr = np.asarray(pred)
            if pred_arr.ndim == 1:
                return pred_arr.reshape(-1, 1)
            return pred_arr

        raise TypeError("Loaded model does not expose predict or predict_proba")

    def predict(self, features: Dict[str, float]) -> PredictionResult:
        """Predict label and confidence for a flow feature dictionary."""
        row = self._prepare_row(features)
        proba_arr = self._predict_proba(row)

        if self.mode == "binary":
            if proba_arr.ndim == 2 and proba_arr.shape[1] >= 2:
                attack_proba = float(proba_arr[0, 1])
                benign_proba = float(proba_arr[0, 0])
            else:
                attack_proba = float(proba_arr.ravel()[0])
                benign_proba = 1.0 - attack_proba

            is_attack = attack_proba >= self.threshold
            label = "ATTACK" if is_attack else "BENIGN"
            return PredictionResult(
                label=label,
                confidence=attack_proba if is_attack else benign_proba,
                is_attack=is_attack,
                top_probabilities={
                    "BENIGN": max(0.0, benign_proba),
                    "ATTACK": max(0.0, attack_proba),
                },
            )

        probs = proba_arr[0] if proba_arr.ndim == 2 else proba_arr.ravel()
        pred_idx = int(np.argmax(probs))
        confidence = float(probs[pred_idx]) if probs.size else 0.0

        if self.label_encoder is not None and hasattr(self.label_encoder, "inverse_transform"):
            label = str(self.label_encoder.inverse_transform([pred_idx])[0])
        else:
            label = str(pred_idx)

        normalized_label = label.upper().strip()
        is_attack_label = normalized_label not in {"BENIGN", "BENIGNTRAFFIC", "NORMAL"}
        is_attack = is_attack_label and confidence >= self.threshold

        top_probabilities: Dict[str, float] = {}
        for idx, prob in enumerate(probs):
            if self.label_encoder is not None and hasattr(self.label_encoder, "inverse_transform"):
                cls_name = str(self.label_encoder.inverse_transform([idx])[0])
            else:
                cls_name = str(idx)
            top_probabilities[cls_name] = float(prob)

        return PredictionResult(
            label=label,
            confidence=confidence,
            is_attack=is_attack,
            top_probabilities=top_probabilities,
        )

    @staticmethod
    def default_paths(base_dir: str) -> Dict[str, str]:
        base = Path(base_dir)
        return {
            "model": str(base / "model" / "lgbm_model.pkl"),
            "features": str(base / "model" / "features.json"),
            "label_encoder": str(base / "model" / "label_encoder.pkl"),
        }
