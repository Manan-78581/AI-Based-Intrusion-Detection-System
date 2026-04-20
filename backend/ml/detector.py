# -------------------------------------------------
#  AI-IDS  -  Isolation Forest ML Detector
#  Trains (or loads) an Isolation Forest model and
#  scores each node's feature vector in real time.
# -------------------------------------------------
import os
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH      = "models/isolation_forest.pkl"
CONTAMINATION   = 0.1      # expected fraction of anomalies (10 %)
N_ESTIMATORS    = 100

# Feature columns (must match aggregator output)
FEATURE_COLS = [
    "packets_per_sec",
    "avg_packet_size",
    "unique_destinations",
    "tcp_ratio",
    "udp_ratio",
    "connection_count",
]


def _risk_label(score: float) -> str:
    if score < 0.4:
        return "safe"
    elif score < 0.7:
        return "suspicious"
    else:
        return "malicious"


class IFDetector:
    """Wraps Isolation Forest with online-style partial fit buffer."""

    def __init__(self):
        self._model: IsolationForest | None = None
        self._buffer: list[list[float]] = []   # training buffer
        self._min_train = 20                    # samples before first fit

        if os.path.exists(MODEL_PATH):
            self._load()
        else:
            # Create a default untrained model
            self._model = IsolationForest(
                n_estimators=N_ESTIMATORS,
                contamination=CONTAMINATION,
                random_state=42,
            )
            print("[Detector] No saved model found — will train after"
                  f" {self._min_train} samples")

    # -- Public API --------------------------------
    def score(self, features: dict) -> tuple[float, str]:
        """
        Returns (anomaly_score 0–1, risk_level).
        Appends to training buffer and re-fits periodically.
        """
        vector = self._to_vector(features)
        self._buffer.append(vector)

        if len(self._buffer) >= self._min_train:
            self._fit()

        if self._model is None:
            return 0.0, "safe"   # not enough data yet

        raw = self._model.decision_function([vector])[0]
        # decision_function: positive = normal, negative = anomaly
        # Map to 0–1 where 1 = most anomalous
        score = float(np.clip(0.5 - raw / 2, 0.0, 1.0))
        return round(score, 3), _risk_label(score)

    # -- Internal ----------------------------------
    def _to_vector(self, features: dict) -> list[float]:
        return [float(features.get(c, 0)) for c in FEATURE_COLS]

    def _fit(self):
        X = np.array(self._buffer)
        self._model = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=CONTAMINATION,
            random_state=42,
        )
        self._model.fit(X)
        self._buffer.clear()
        self._save()
        print(f"[Detector] (RE-TRAIN) Model re-trained on {len(X)} samples")

    def _save(self):
        os.makedirs("models", exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self._model, f)

    def _load(self):
        with open(MODEL_PATH, "rb") as f:
            self._model = pickle.load(f)
        print(f"[Detector] (OK) Model loaded from {MODEL_PATH}")

    def reset(self):
        """Reset the detector to its initial untrained state."""
        self._model = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=CONTAMINATION,
            random_state=42,
        )
        self._buffer.clear()
        print("[Detector] (RESET) ML model and buffer cleared")


# -- Singleton -------------------------------------
detector = IFDetector()
